'use strict';
/**
 * Tengence sanitize MCP Resources (@tengence/sanitize-mcp/tools/resources)
 * ============================================================================
 * Reference data the AI reads (not actions) through the MCP Resources primitive.
 * Fixed resources + one parameterized template. Deep usage rules live HERE, loaded
 * on demand — not in Implementation.instructions — so instructions stay lean and
 * context stays small.
 *
 * Safety: resources never contain secrets (no keys/salts/api keys) and never
 * contain plaintext values. The audit template exposes counts/field names only.
 *
 * This module is SDK-agnostic: it exports plain descriptors + callbacks; server.js
 * wraps them with registerResource / ResourceTemplate.
 *
 * Resource URI map:
 *   sanitize://methods        fixed — desensitization algorithms & output formats
 *   sanitize://config-schema  fixed — sanitize.config.json schema + field paths
 *   sanitize://workflows      fixed — canonical workflows & when-not-to-call
 *   sanitize://audit/{batchId} template — one local audit record (no plaintext)
 */

const sdk = require('@tengence/sanitize-sdk');

/** 审计目录：优先 SANITIZE_MCP_AUDIT_DIR，否则 SDK 默认（与工具层一致）。 */
function auditDir() {
  return process.env.SANITIZE_MCP_AUDIT_DIR || sdk.resolveAuditDir();
}

const fixedResources = [
  {
    name: 'methods',
    uri: 'sanitize://methods',
    config: {
      title: '脱敏算法参考',
      description: 'Desensitization methods: hash / mask / encrypt / preserve — deterministic semantics, output length table, joinability.',
      mimeType: 'text/markdown',
    },
    read() {
      return {
        contents: [
          {
            uri: 'sanitize://methods',
            mimeType: 'text/markdown',
            text: [
              '# 脱敏算法（sanitize://methods）',
              '',
              '所有输出为**纯 hex 或原文子串**，不含任何特殊字符（后端可安全用于关联/去重）。',
              '',
              '## hash（不可逆，确定性，可 join）',
              '- `SHA-256`：32 hex（默认）或 64 hex（hashLength: 64）。盐必填：`TENGENCE_SANITIZE_SALT`（用户自持，服务端不可复算）。',
              '- `HMAC-SHA-256`：32 hex，密钥必填：`TENGENCE_SANITIZE_KEY`（32B）。',
              '- 同明文 + 同盐/密钥 → 同哈希：可用于跨批 join / 去重 / 后台标识（如手机号）。',
              '',
              '## mask（不可逆，保格式局部显示）',
              '- `keepFirst` / `keepLast`（各默认 0）：如手机号 keepFirst:3,keepLast:4 → `138****1234`。',
              '- **边界（重要）**：需 `keepFirst + keepLast < 字段长度` 才真正打码；`0/0` 输出为「* + 原文」（如 `**张三`），**仍含明文**；字段过短（如 2 字姓名 keep 1/1）时按告警不脱敏、值原样透传。**姓名/短字段请用 hash 或 encrypt，不要用 mask**。',
              '',
              '## encrypt（可逆，确定性单值 AES-SIV，RFC 5297）',
              '- 输出 = `hex(V 16B ‖ CTR 密文)`，纯 hex；同明文 → 同密文 → 可 join/去重/标识。',
              '- 长度 = `2 × (16 + 明文字节数)`：手机号（11B）→ **54 hex**；订单号（15B）→ 62 hex。',
              '- 密钥：`TENGENCE_SANITIZE_KEY`（32B，用户自持）。还原 = `tengence-sanitize restore`（CLI，本地）；MCP 默认不提供 restore（明文不进 AI 上下文，除非 SANITIZE_MCP_ENABLE_RESTORE=1）。',
              '',
              '## preserve（保留原值）',
              '- 不改动字段（用于声明占位，不产生脱敏）。',
              '',
              '## 确定性语义',
              '- hash / encrypt 均为确定性：同输入 → 同输出 → 后端可直接对该值精确匹配/去重/标识。',
              '- 盐/密钥丢失 ⇒ 历史哈希/密文不可还原/不可复算（文档明示）。',
            ].join('\n'),
          },
        ],
      };
    },
  },
  {
    name: 'config-schema',
    uri: 'sanitize://config-schema',
    config: {
      title: '配置结构',
      description: 'sanitize.config.json schema: version, rules[].fields (user-defined field paths), methods & params, upload & audit sections.',
      mimeType: 'text/markdown',
    },
    read() {
      return {
        contents: [
          {
            uri: 'sanitize://config-schema',
            mimeType: 'text/markdown',
            text: [
              '# sanitize.config.json（sanitize://config-schema）',
              '',
              '```json',
              '{',
              '  "version": 1,',
              '  "rules": [',
              '    { "fields": ["phone"], "method": "hash", "params": { "algorithm": "SHA-256", "saltEnv": "TENGENCE_SANITIZE_SALT" } },',
              '    { "fields": ["id_card"], "method": "mask", "params": { "keepFirst": 3, "keepLast": 4 } },',
              '    { "fields": ["contact.phone", "items[*].price"], "method": "encrypt", "params": { "keyEnv": "TENGENCE_SANITIZE_KEY" } }',
              '  ],',
              '  "upload": { "pushUrl": "https://api.mossego.com/v1/push/data", "apiKeyEnv": "TENGENCE_API_KEY", "batchSize": 1000, "maxBatchPayloadBytes": 4194304, "maxRetries": 3, "timeoutMs": 30000 },',
              '  "audit": { "enabled": true, "dir": "~/.tengence/sanitize/audits" }',
              '}',
              '```',
              '',
              '## 字段路径（完全用户自定义，仅显式声明）',
              '- 顶层：`phone`、`id_card`；',
              '- 嵌套对象：`contact.phone`；',
              '- 数组：`items[*].price`（对数组每个元素生效）；',
              '- ⚠️ **扁平列名含点号**（如 CSV 列名就叫 `contact.phone`）**不会**被嵌套路径 `contact.phone` 匹配——嵌套路径访问的是对象 `contact` 下的 `phone`。列名含点号时请改列名（如 `contact_phone`）或调整数据为嵌套结构，并用 dry-run 的 `unmatchedFields` 确认无漏配；',
              '- 配置未声明的顶层字段不会脱敏，dry-run 的 `unmatchedFields` 会列出（防漏配兜底）。',
              '',
              '## 规则参数',
              '- `hash`：`algorithm`（SHA-256 | HMAC-SHA-256）、`saltEnv`（哈希盐环境变量名）、`keyEnv`（HMAC 密钥环境变量名）、`hashLength`（32 | 64）。',
              '- `mask`：`keepFirst`、`keepLast`。',
              '- `encrypt`：`keyEnv`（32B 密钥环境变量名）。',
              '- `preserve`：无参数。',
              '',
              '## 环境变量（密钥只在环境里，不进配置文件/参数）',
              '- `TENGENCE_SANITIZE_SALT`：SHA-256 盐；`TENGENCE_SANITIZE_KEY`：encrypt/HMAC 密钥（32B）；`TENGENCE_API_KEY`：上传 Bearer。',
            ].join('\n'),
          },
        ],
      };
    },
  },
  {
    name: 'workflows',
    uri: 'sanitize://workflows',
    config: {
      title: '规范工作流',
      description: 'Canonical desensitization workflow, restore guidance and when-not-to-call rules.',
      mimeType: 'text/markdown',
    },
    read() {
      return {
        contents: [
          {
            uri: 'sanitize://workflows',
            mimeType: 'text/markdown',
            text: [
              '# 规范工作流（sanitize://workflows）',
              '',
              '## CANONICAL PIPELINE（一条业务数据上线）',
              '1. `sanitize_config_info(config)` —— 校验配置，拿到 configFingerprint / masking_meta；',
              '2. `sanitize_dry_run(config, input)` —— 预览：确认每个声明字段的命中（hits>0）与 `unmatchedFields`（漏配先补配，不要直接脱敏）；',
              '3. `sanitize_file(config, input, output)` —— 流式脱敏出文件；',
              '4. `sanitize_upload(config, output)` —— 上传**脱敏后**文件（Bearer apiKey 来自环境变量）。',
              '',
              '## 还原（恢复原文）',
              '- **默认在 CLI 做**：`tengence-sanitize restore --field phone --value <hex>`（密钥仅本地环境变量）。',
              '- MCP 仅在 `SANITIZE_MCP_ENABLE_RESTORE=1` 时注册 `sanitize_restore`；其返回值为明文，会进入 AI 上下文，仅知情用户使用。',
              '',
              '## 真实网关契约（2026-10-19 实测确认）',
              '- 推送地址：`https://api.mossego.com/v1/push/data`（旧 `api.tengence.com` 已废弃，会返回 `INVALID_API_KEY`）；',
              '- 成功判定：HTTP 2xx 且业务 `code` 为 `0` / `200` / `SUCCESS` / `OK`（网关实际返回 `code:"SUCCESS"`）；',
              '- 行必需包含数据集主键字段（默认 `id`），缺失返回 `ID_FIELD_MISSING`——上传前确认输入含主键列；',
              '- `UNAUTHORIZED` 偶发为瞬时状态：可重试一次；连续失败需用户核对数据集成应用 apiKey；',
              '- `INVALID_API_KEY`：key 无效（域名错误或 key 非数据集成应用），需用户核对，SDK 不轰炸重试。',
              '',
              '## WHEN NOT TO CALL',
              '- 任何密钥/盐/apiKey 禁止作为工具参数传入——只用环境变量；',
              '- 不要请求/回显原文：工具输出不含明文，需要看原文请让用户打开本地文件；',
              '- 生成输出文件 / 上传属写操作，执行前先与用户确认；',
              '- dry-run 出现 unmatchedFields 时先补配再执行。',
            ].join('\n'),
          },
        ],
      };
    },
  },
];

/**
 * Resource template: one audit record by batchId (no plaintext — counts/names only).
 */
const resourceTemplates = [
  {
    name: 'audit-record',
    uriTemplate: 'sanitize://audit/{batchId}',
    config: {
      title: '审计记录',
      description: 'One local audit record by batchId: rows, field hits, unmatched fields, exitCode, upload result. No plaintext.',
      mimeType: 'application/json',
    },
    async list() {
      return {
        resources: sdk.readAudit(auditDir()).map((r) => ({
          uri: `sanitize://audit/${r.batchId}`,
          name: r.batchId,
          description: `audit ${r.batchId} @ ${r.ts}`,
          mimeType: 'application/json',
        })),
      };
    },
    async read(uri, variables) {
      const batchId = String(variables && variables.batchId || '');
      const record = sdk.readAudit(auditDir()).find((r) => r.batchId === batchId);
      if (!record) {
        throw new Error(`Unknown audit batchId "${batchId}". List available ids via sanitize://audit/{batchId} template list or sanitize_audit_list.`);
      }
      return {
        contents: [
          {
            uri: `sanitize://audit/${batchId}`,
            mimeType: 'application/json',
            text: JSON.stringify(record, null, 2),
          },
        ],
      };
    },
  },
];

module.exports = { fixedResources, resourceTemplates };
