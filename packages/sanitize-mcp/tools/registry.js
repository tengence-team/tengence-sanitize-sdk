'use strict';
/**
 * Tengence sanitize MCP tool registry (@tengence/sanitize-mcp/tools/registry)
 * ============================================================================
 * Each tool = { name, title, description, annotations, inputSchema, run(args) }.
 * inputSchema uses Zod raw shapes (native in @modelcontextprotocol/server 2.x;
 * auto-converted to JSON Schema).
 *
 * TRUST BOUNDARY (this product's core constraint — plaintext stays on the user
 * machine and NEVER enters the AI context):
 *   - keys / salts / api keys are NEVER tool arguments; they are read from env
 *     vars only (TENGENCE_SANITIZE_SALT / TENGENCE_SANITIZE_KEY / TENGENCE_API_KEY
 *     or config.upload.apiKeyEnv). The MCP process stores no secret anywhere.
 *   - tool outputs never echo plaintext: dry_run strips the `before` samples
 *     (only desensitized `after` values are returned), sanitize_file returns
 *     statistics only, audit records hold counts/field names only.
 *   - restore (decrypt back to plaintext) is GATED: registered only when
 *     SANITIZE_MCP_ENABLE_RESTORE=1; gen-key never enters MCP (its output IS a key).
 *
 * Implementation: every tool calls the @tengence/sanitize-sdk domain API directly
 * (same logic as the CLI — zero duplicated orchestration).
 */

const { z } = require('zod');
const fs = require('fs');
const path = require('path');
const sdk = require('@tengence/sanitize-sdk');

/** Wrap a successful structured result as MCP text JSON. */
function okStructured(data) {
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

/** Wrap a failure as MCP isError result. */
function fail(e) {
  const message = e && e.message ? e.message : String(e);
  return {
    content: [{ type: 'text', text: JSON.stringify({ ok: false, error: message }, null, 2) }],
    isError: true,
  };
}

/** Shared enum for explicit input format override (auto-detect when omitted). */
const FORMAT_ENUM = ['csv', 'json', 'jsonl', 'excel'];

const configArg = z
  .string()
  .describe('absolute path to sanitize.config.json (fields are user-defined; secrets come from env vars, never from arguments)');
const inputArg = z.string().describe('absolute path to the input data file (CSV / JSON / JSONL / XLSX)');
const outputArg = z.string().describe('absolute path of the desensitized output file to write');
const formatArg = z
  .enum(FORMAT_ENUM)
  .optional()
  .describe('explicit input format; omit to auto-detect from extension/content');

/**
 * Tool group matchers — aggregated into Implementation.instructions by server.js
 * against the LIVE tool list, so instructions can never drift from the registry.
 */
const TOOL_GROUPS = [
  { group: '配置 (Config)', match: /^sanitize_config_info$/ },
  { group: '预览 (Dry-run)', match: /^sanitize_dry_run$/ },
  { group: '执行 (Sanitize)', match: /^sanitize_file$/ },
  { group: '上传 (Upload)', match: /^sanitize_upload$/ },
  { group: '审计 (Audit)', match: /^sanitize_audit_/ },
  { group: '还原 (Restore, 可选)', match: /^sanitize_restore$/ },
];

const tools = [
  {
    name: 'sanitize_config_info',
    title: '校验脱敏配置',
    annotations: { readOnlyHint: true },
    description:
      'Load and validate a sanitize.config.json. Returns the rule summary (field → method, per rule), configFingerprint and masking_meta (used to declare masking on upload). Never accepts secrets — keys/salts/api keys are read from env vars only.',
    inputSchema: z.object({ config: configArg }),
    async run(args) {
      try {
        const config = sdk.loadConfig(args.config);
        const engine = sdk.createEngine(config);
        return okStructured({
          ok: true,
          configPath: args.config,
          version: config.version,
          rules: config.rules.map((r) => ({
            fields: r.fields,
            method: r.method,
          })),
          configFingerprint: sdk.computeConfigFingerprint(config),
          maskingMeta: engine.maskingMeta(),
        });
      } catch (e) {
        return fail(e);
      }
    },
  },
  {
    name: 'sanitize_dry_run',
    title: '脱敏预览（不写文件）',
    annotations: { readOnlyHint: true },
    description:
      'Preview desensitization on an input file without writing output: per-field hit counts, up to 3 desensitized AFTER samples per field (plaintext BEFORE samples are intentionally stripped — plaintext never enters the AI context), plus unmatchedFields (top-level fields present in data but not declared in config — a miss-config guard).',
    inputSchema: z.object({
      config: configArg,
      input: inputArg,
      format: formatArg,
    }),
    async run(args) {
      try {
        const sanitizer = sdk.createSanitizer({ config: args.config });
        const report = await sanitizer.dryRun(args.input, { format: args.format });
        return okStructured({
          ok: true,
          dryRun: true,
          inputRows: report.inputRows,
          fieldStats: report.fieldStats.map((s) => ({
            field: s.field,
            method: s.method,
            hits: s.hits,
            afterSamples: s.samples.map((x) => x.after), // no `before` — by design
          })),
          unmatchedFields: report.unmatchedFields,
        });
      } catch (e) {
        return fail(e);
      }
    },
  },
  {
    name: 'sanitize_file',
    title: '执行文件脱敏',
    description:
      'Run streaming desensitization from an input file to an output file (CSV/JSON/JSONL/XLSX in → CSV/JSON/JSONL/XLSX out; Excel out is CSV unless format=excel). Returns statistics only — batchId, input/output/error row counts, warnings (e.g. mask-fallback), auditFile path. No row content is returned, so plaintext never enters the AI context; inspect output file locally if needed.',
    inputSchema: z.object({
      config: configArg,
      input: inputArg,
      output: outputArg,
      format: formatArg,
    }),
    async run(args) {
      try {
        const sanitizer = sdk.createSanitizer({ config: args.config });
        const result = await sanitizer.sanitizeFile(args.input, args.output, { format: args.format });
        return okStructured({ ok: true, ...result });
      } catch (e) {
        return fail(e);
      }
    },
  },
  {
    name: 'sanitize_upload',
    title: '上传已脱敏数据',
    description:
      'Upload an ALREADY desensitized file to the batch push endpoint (POST /v1/push/data, Bearer apiKey from env TENGENCE_API_KEY or config.upload.apiKeyEnv). Returns batchId, accepted count and rejection details. Only pass desensitized output files — the server-side plaintext-rejection check (collect-service, separately scheduled) is the enforcement backstop.',
    inputSchema: z.object({
      config: configArg,
      input: inputArg,
      push_url: z.string().optional().describe(`push endpoint override (default ${sdk.DEFAULT_PUSH_URL})`),
      format: formatArg,
    }),
    async run(args) {
      try {
        const sanitizer = sdk.createSanitizer({ config: args.config, pushUrl: args.push_url });
        const format = args.format ?? sdk.detectInputFormat(args.input);
        const rows = [];
        for await (const row of sdk.readRowsIter(args.input, format)) rows.push(row);
        const result = await sanitizer.upload(rows);
        return okStructured({ ok: true, ...result });
      } catch (e) {
        return fail(e);
      }
    },
  },
  {
    name: 'sanitize_audit_list',
    title: '列出本地审计记录',
    annotations: { readOnlyHint: true },
    description:
      'List local audit records: batchId, configFingerprint, input/output rows, field hits, unmatchedFields, timestamp, exitCode and upload result. Audit records contain counts and field names only — no plaintext values.',
    inputSchema: z.object({
      dir: z.string().optional().describe('audit directory; omit to use the default (~/.tengence/sanitize/audits)'),
    }),
    async run(args) {
      try {
        const dir = args.dir ?? sdk.resolveAuditDir();
        return okStructured({ ok: true, dir, records: sdk.readAudit(dir) });
      } catch (e) {
        return fail(e);
      }
    },
  },
  {
    name: 'sanitize_audit_export',
    title: '导出审计记录',
    annotations: { readOnlyHint: true },
    description:
      'Export all local audit records to a JSON or CSV file and return its path (for compliance evidence). No plaintext is ever included.',
    inputSchema: z.object({
      dir: z.string().optional().describe('audit directory; omit to use the default'),
      format: z.enum(['json', 'csv']).optional().describe('export format (default json)'),
    }),
    async run(args) {
      try {
        const dir = args.dir ?? sdk.resolveAuditDir();
        const content = sdk.exportAudit(dir, args.format ?? 'json');
        fs.mkdirSync(dir, { recursive: true });
        const file = path.join(dir, `audit-export-${Date.now()}.${args.format ?? 'json'}`);
        fs.writeFileSync(file, content, 'utf8');
        return okStructured({ ok: true, file, records: JSON.parse(sdk.exportAudit(dir, 'json')).length });
      } catch (e) {
        return fail(e);
      }
    },
  },
  {
    name: 'sanitize_restore',
    title: '本地还原 enc 密文（明文！）',
    annotations: { readOnlyHint: false },
    gated: 'SANITIZE_MCP_ENABLE_RESTORE', // registered only when this env var = "1"
    description:
      'GATED tool (only registered when SANITIZE_MCP_ENABLE_RESTORE=1): decrypt an AES-SIV encrypted value back to PLAINTEXT locally, using the key from env TENGENCE_SANITIZE_KEY. The returned value IS plaintext and therefore enters the AI context — enable deliberately, only for users who understand the trust boundary. Default recommendation: do restore in the CLI (tengence-sanitize restore) instead.',
    inputSchema: z.object({
      config: configArg,
      field: z.string().describe('field path the value was encrypted under (e.g. phone)'),
      value: z.string().describe('enc hex value to decrypt (54 hex for an 11-digit phone)'),
    }),
    async run(args) {
      try {
        const sanitizer = sdk.createSanitizer({ config: args.config });
        const restored = sanitizer.restore(args.field, args.value);
        return okStructured({ ok: true, field: args.field, restored });
      } catch (e) {
        return fail(e);
      }
    },
  },
];

module.exports = { tools, TOOL_GROUPS };
