#!/usr/bin/env node
/**
 * tengence-sanitize CLI：本地脱敏前置工具
 * 退出码：0 成功；1 配置/参数错误；2 上传被拒；3 部分行失败
 */
import { Command, CommanderError } from "commander";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createSanitizer, ConfigError, parseKey, decryptValue, readRowsIter, detectInputFormat, exportAudit, type Row } from "@tengence/sanitize-sdk";

const program = new Command();

program
  .name("tengence-sanitize")
  .description("tengence 本地脱敏前置工具：明文不出用户环境，本地脱敏后调用批量推送接口")
  .version("0.1.0");

program
  .command("run")
  .description("脱敏文件（可预览 / 可上传）")
  .requiredOption("--config <path>", "sanitize.config.json 路径")
  .requiredOption("--input <path>", "输入文件（.csv / .json / .jsonl / .xlsx）")
  .option("--output <path>", "输出文件（缺省 = 输入同目录 sanitized-<name>）")
  .option("--dry-run", "仅预览（命中统计 + 样例 + 未命中字段清单），不输出文件")
  .option("--upload", "脱敏后调用批量推送接口上传")
  .option("--api-key <key>", "应用 apiKey（优先于环境变量 TENGENCE_API_KEY）")
  .option("--push-url <url>", "批量推送接口地址（默认 https://api.mossego.com/v1/push/data）")
  .action(async (opts) => {
    try {
      const apiKey = opts.apiKey || undefined;
      const sanitizer = createSanitizer({
        config: opts.config,
        apiKey,
        pushUrl: opts.pushUrl,
        logger: (m) => process.stderr.write(`[sanitize] ${m}\n`)
      });

      if (opts.dryRun) {
        const report = await sanitizer.dryRun(opts.input);
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
        if (report.unmatchedFields.length > 0) {
          process.stderr.write(`[warn] 未声明字段：${report.unmatchedFields.join(", ")}（请确认是否漏配）\n`);
        }
        return;
      }

      const output = opts.output ?? defaultOutput(opts.input);
      const result = await sanitizer.sanitizeFile(opts.input, output);
      process.stdout.write(
        JSON.stringify(
          { batchId: result.batchId, inputRows: result.inputRows, outputRows: result.outputRows, errorRows: result.errorRows, auditFile: result.auditFile, warnings: result.warnings },
          null,
          2
        ) + "\n"
      );
      if (result.errorRows > 0) process.exitCode = 3;

      if (opts.upload) {
        const rows: Row[] = [];
        const format = detectInputFormat(output);
        for await (const row of readRowsIter(output, format)) rows.push(row);
        const upload = await sanitizer.upload(rows);
        process.stdout.write(JSON.stringify(upload, null, 2) + "\n");
        if (upload.rejected && upload.rejected.length > 0) process.exitCode = 2;
      }
    } catch (e) {
      fail(e);
    }
  });

program
  .command("restore")
  .description("本地还原单个可逆字段值（凭自持 key）")
  .requiredOption("--field <field>", "字段名")
  .requiredOption("--value <value>", "enc 脱敏值（纯 hex）")
  .option("--key-env <name>", "加密密钥环境变量名（默认 TENGENCE_SANITIZE_KEY）")
  .action(async (opts) => {
    try {
      const keyEnv = opts.keyEnv || "TENGENCE_SANITIZE_KEY";
      const keyRaw = process.env[keyEnv];
      if (!keyRaw) throw new ConfigError(`环境变量 ${keyEnv} 未设置`, keyEnv);
      const plain = decryptValue(parseKey(keyRaw), opts.value);
      process.stdout.write(plain + "\n");
    } catch (e) {
      fail(e);
    }
  });

program
  .command("gen-key")
  .description("生成 32 字节随机密钥（64 hex）")
  .option("--out <path>", "写入文件（缺省输出到 stdout）")
  .action((opts) => {
    const key = crypto.randomBytes(32).toString("hex");
    if (opts.out) {
      fs.mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
      fs.writeFileSync(opts.out, key + "\n", "utf8");
      process.stdout.write(`密钥已写入 ${opts.out}\n`);
    } else {
      process.stdout.write(key + "\n");
    }
  });

program
  .command("audit")
  .description("查看 / 导出本地审计日志")
  .option("--dir <path>", "审计目录（默认 ~/.tengence-sanitize/audit）")
  .option("--export <json|csv>", "导出格式")
  .action(async (opts) => {
    const dir = opts.dir || undefined;
    if (opts.export) {
      const csv = opts.export === "csv";
      const content = exportAudit(dir, "json");
      if (csv) {
        process.stdout.write(csvContent(content));
      } else {
        process.stdout.write(content + "\n");
      }
      return;
    }
    process.stdout.write(JSON.stringify(readAuditEntries(dir), null, 2) + "\n");
  });

function defaultOutput(input: string): string {
  const dir = path.dirname(path.resolve(input));
  const base = path.basename(input);
  return path.join(dir, `sanitized-${base}`);
}

function readAuditEntries(dir?: string): unknown[] {
  return JSON.parse(exportAudit(dir, "json")) as unknown[];
}

function csvContent(json: string): string {
  try {
    const records = JSON.parse(json) as Record<string, unknown>[];
    if (records.length === 0) return "";
    const header = Object.keys(records[0]);
    const lines = [header.join(",")];
    for (const r of records) {
      lines.push(header.map((h) => `"${String(r[h] ?? "").replace(/"/g, '""')}"`).join(","));
    }
    return lines.join("\n") + "\n";
  } catch {
    return json;
  }
}

function fail(e: unknown): void {
  if (e instanceof ConfigError) {
    process.stderr.write(`[config] ${e.message}\n`);
  } else if (e instanceof CommanderError) {
    process.stderr.write(e.message + "\n");
  } else {
    process.stderr.write(`[error] ${e instanceof Error ? e.message : String(e)}\n`);
  }
  process.exitCode = 1;
}

program.parseAsync(process.argv).catch((e) => {
  fail(e);
  process.exit(1);
});
