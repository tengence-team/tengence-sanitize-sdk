/**
 * Sanitizer 主入口：配置 → 引擎 → IO（流式） → 审计 → 上传
 */
import { loadConfig, computeConfigFingerprint } from "./config";
import { createEngine } from "./engine";
import { tokenizePath, getPathValues } from "./field";
import { detectInputFormat, detectOutputFormat, readRowsIter, probeHeader, writeRows, type InputFormat, type OutputFormat } from "./io";
import { appendErrorRow, exportAudit, newBatchId, readAudit, resolveAuditDir, writeAudit } from "./audit";
import { resolveUploadContext, uploadRows, DEFAULT_PUSH_URL } from "./upload";
import type {
  AuditRecord,
  DryRunReport,
  Row,
  SanitizeConfig,
  SanitizeFileResult,
  SanitizeMethod,
  Sanitizer,
  UploadResult
} from "./types";

export interface SanitizerOptions {
  /** 配置文件路径或配置对象 */
  config: string | SanitizeConfig;
  /** 直连 apiKey（优先于 upload.apiKeyEnv） */
  apiKey?: string;
  /** 覆盖批量推送接口地址 */
  pushUrl?: string;
  /** 可选日志 */
  logger?: (msg: string) => void;
}

export function createSanitizer(options: SanitizerOptions): Sanitizer {
  const config = loadConfig(options.config);
  const engine = createEngine(config);
  const fingerprint = computeConfigFingerprint(config);
  const auditDir = resolveAuditDir(config.audit?.dir);
  const auditEnabled = config.audit?.enabled !== false;

  const log = (msg: string): void => {
    if (options.logger) options.logger(msg);
  };

  const transformRows = async function* (source: AsyncIterable<Row>) {
    for await (const row of source) {
      const r = engine.sanitizeRow(row);
      yield r.row;
    }
  };

  const sanitizer: Sanitizer = {
    sanitizeRows(rows: Row[]): Row[] {
      return rows.map((r) => engine.sanitizeRow(r).row);
    },

    async sanitizeFile(input: string, output: string, opts?: { format?: "csv" | "json" | "jsonl" | "excel" }): Promise<SanitizeFileResult> {
      const inFormat: InputFormat = detectInputFormat(input);
      const outFormat: OutputFormat = opts?.format ?? detectOutputFormat(output, inFormat === "excel" ? "csv" : inFormat);
      log(`sanitizeFile: ${input} → ${output} (${inFormat} → ${outFormat})`);

      // 表头探测：csv/excel 写出需要固定列
      const header = outFormat === "csv" || outFormat === "excel" ? await probeHeader(input, inFormat) : [];

      let fieldHits: Record<string, number> = {};
      let warnings: Record<string, number> = {};
      let inputRows = 0;
      let errorRows = 0;
      const unmatched = new Set<string>();
      let outputRows = 0;

      const { rows } = await writeRows(
        output,
        outFormat,
        header,
        (async function* () {
          for await (const row of readRowsIter(input, inFormat)) {
            inputRows++;
            for (const key of Object.keys(row)) {
              if (!engine.declaredTopLevel().has(key)) unmatched.add(key);
            }
            try {
              const r = engine.sanitizeRow(row);
              for (const [k, v] of Object.entries(r.fieldHits)) fieldHits[k] = (fieldHits[k] ?? 0) + v;
              for (const [k, v] of Object.entries(r.warnings)) warnings[k] = (warnings[k] ?? 0) + v;
              yield r.row;
            } catch (e) {
              errorRows++;
              appendErrorRow(output, inputRows, e instanceof Error ? e.message : String(e));
            }
          }
        })()
      );
      outputRows = rows;

      let batchId = newBatchId();
      let auditFile: string | undefined;
      if (auditEnabled) {
        batchId = newBatchId();
        auditFile = writeAudit(auditDir, {
          batchId,
          configFingerprint: fingerprint,
          ruleVersion: config.version,
          inputRows,
          outputRows,
          fieldHits,
          unmatchedFields: [...unmatched],
          dryRun: false,
          ts: new Date().toISOString(),
          exitCode: errorRows > 0 ? 3 : 0
        });
      }

      log(`完成：${inputRows} 行输入，${outputRows} 行输出，${errorRows} 行错误`);
      if (unmatched.size > 0) log(`未声明字段：${[...unmatched].join(", ")}（请确认是否漏配）`);
      return { batchId, inputRows, outputRows, errorRows, auditFile, warnings };
    },

    async dryRun(input: string | Row[], opts?: { format?: "csv" | "json" | "jsonl" | "excel" }): Promise<DryRunReport> {
      const fieldStats = new Map<
        string,
        { field: string; method: SanitizeMethod; hits: number; samples: { before: unknown; after: unknown }[] }
      >();
      const unmatched = new Set<string>();
      let inputRows = 0;

      const handleRow = (row: Row): void => {
        inputRows++;
        for (const key of Object.keys(row)) {
          if (!engine.declaredTopLevel().has(key)) unmatched.add(key);
        }
        const sanitized = engine.sanitizeRow({ ...row }).row;
        for (const rule of config.rules) {
          for (const field of rule.fields) {
            const tokens = tokenizePath(field);
            const before = getPathValues(row, tokens);
            const after = getPathValues(sanitized, tokens);
            const stat = fieldStats.get(field) ?? { field, method: rule.method, hits: 0, samples: [] };
            for (let i = 0; i < before.length; i++) {
              if (typeof before[i] === "string" && before[i] !== "" && before[i] !== after[i]) stat.hits++;
            }
            if (stat.samples.length < 3 && before.length > 0) {
              stat.samples.push({ before: before[0], after: after[0] });
            }
            fieldStats.set(field, stat);
          }
        }
      };

      if (typeof input === "string") {
        const format: InputFormat = opts?.format ?? detectInputFormat(input);
        for await (const row of readRowsIter(input, format)) handleRow(row);
      } else {
        for (const r of input) handleRow(r);
      }

      return {
        dryRun: true,
        inputRows,
        fieldStats: [...fieldStats.values()],
        unmatchedFields: [...unmatched]
      };
    },

    restore(field: string, value: string): string {
      return engine.restoreValue(field, value);
    },

    async upload(rows: Row[]): Promise<UploadResult> {
      const ctx = resolveUploadContext(config.upload, options.apiKey);
      if (options.pushUrl) ctx.pushUrl = options.pushUrl;
      const batchId = newBatchId();
      const result = await uploadRows(ctx, rows, batchId, fingerprint, engine.maskingMeta());
      if (auditEnabled) {
        writeAudit(auditDir, {
          batchId,
          configFingerprint: fingerprint,
          ruleVersion: config.version,
          inputRows: rows.length,
          outputRows: rows.length,
          fieldHits: {},
          unmatchedFields: [],
          dryRun: false,
          ts: new Date().toISOString(),
          uploadResult: result,
          exitCode: result.rejected && result.rejected.length > 0 ? 2 : 0
        });
      }
      return result;
    },

    auditLog(): AuditRecord[] {
      return readAudit(auditDir);
    },

    exportAudit(dir?: string): string {
      return exportAudit(dir ?? auditDir, "json");
    }
  };

  return sanitizer;
}

export { DEFAULT_PUSH_URL };
