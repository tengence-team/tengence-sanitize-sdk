# tengence-sanitize-sdk

tengence 数据导入服务的**本地脱敏前置工具**：用户在本地（自有环境）完成字段级脱敏后再调用现有批量推送接口上传，**明文不出用户环境**。

- SDK：`@tengence/sanitize-sdk`（Node/TypeScript 编程集成）
- CLI：`tengence-sanitize`（命令行 / 脚本）
- MCP：`@tengence/sanitize-mcp`（AI 客户端接入，`com.tengence/sanitize`）
- 独立 git 仓库，与 `tengence-track-sdk-web` 分离

## 为什么做本地脱敏

业界数据同步工具（DataX、Fivetran、Airbyte、AWS DMS、Snowflake、神策等）的脱敏几乎都发生在「数据已进入工具/平台之后」，无法打消「明文传给服务商」的顾虑。支付行业 P2PE、GA4 client-side redaction、Amplitude 发送前哈希等源头侧做法是唯一能保证明文不出域的模式——本工具即采用该模式。调研结论与方案见 `tengence-track-sdk-web/数据导入脱敏-详细实施方案.md`。

## 信任边界

```
用户本机（明文仅在此）                   服务端
原始数据 ──> SDK/CLI/MCP 本地脱敏 ──> 纯 hex/掩码值 ──HTTP(Bearer apiKey)──> POST /v1/push/data
            · 盐/密钥用户自持（env，MCP 内部零保存）
            · 本地审计日志
            · 可逆字段凭用户自持 key 本地还原
```

## 三种形态怎么选

| 形态 | 适用场景 | 入口 |
| --- | --- | --- |
| **SDK** | 把脱敏嵌入自有程序/流水线（Node），精细控制 | `import { createSanitizer } from '@tengence/sanitize-sdk'` |
| **CLI** | 命令行/脚本批处理，人类直接操作，dry-run/审计最直观 | `tengence-sanitize` |
| **MCP** | AI 客户端（豆包工作台等）代理用户完成配置→预览→脱敏→上传 | `@tengence/sanitize-mcp`（stdio / HTTP） |

三者共享同一套核心逻辑（零重复实现），行为一致。

## 快速开始（CLI）

```bash
cd packages/sanitize-cli && npm link   # 或 npx @tengence/sanitize-cli

# 1. 生成密钥（可逆加密用，32B / 64 hex）
tengence-sanitize gen-key --out ~/.tengence/sanitize-key

# 2. 配置环境变量（密钥只走环境，不进配置文件/参数）
export TENGENCE_SANITIZE_SALT="$(openssl rand -hex 16)"   # SHA-256 哈希盐
export TENGENCE_SANITIZE_KEY="$(cat ~/.tengence/sanitize-key)"  # encrypt/HMAC 密钥
export TENGENCE_API_KEY="sk-你的数据集成应用apiKey"        # 上传 Bearer

# 3. 编写 sanitize.config.json（字段完全用户自定义，见「配置示例」）

# 4. dry-run 预览（命中统计 + 样例 + 未命中字段清单，不写文件）
tengence-sanitize run --config sanitize.config.json --input data.csv --dry-run

# 5. 正式脱敏
tengence-sanitize run --config sanitize.config.json --input data.csv --output data.sanitized.csv

# 6. 上传到批量推送接口（POST https://api.mossego.com/v1/push/data）
tengence-sanitize run --config sanitize.config.json --input data.csv --output data.sanitized.csv --upload

# 7. 还原可逆字段（本地，凭自持 key；明文只在本机输出）
tengence-sanitize restore --field order_no --value <enc值>

# 8. 审计
tengence-sanitize audit
tengence-sanitize audit --export csv
```

退出码：`0` 成功；`1` 配置/参数错误；`2` 上传被拒；`3` 部分行失败。

## 端到端示例（完整可复制）

```bash
# 输入：data.csv（含 id 主键列，服务端必需）
# id,phone,name,id_card,order_no,remark
# 1,13800138000,张三,110101199001011234,ORD202610180001,普通订单

# 配置：sanitize.config.json（见「配置示例」）
# 1) 预览
tengence-sanitize run --config sanitize.config.json --input data.csv --dry-run
# 输出（节选）：
# { "dryRun": true, "inputRows": 1,
#   "fieldStats": [ { "field": "phone", "method": "hash", "hits": 1,
#     "samples": [ { "before": "13800138000", "after": "1c797a078e4a6693c968d02270aefd66" } ] }, ... ],
#   "unmatchedFields": [] }
# → 确认每个声明字段 hits>0、unmatchedFields 为空后再继续；有漏配先补配。

# 2) 脱敏 + 上传（Bearer apiKey 来自 TENGENCE_API_KEY）
tengence-sanitize run --config sanitize.config.json --input data.csv --output data.sanitized.csv --upload
# 输出（节选）：
# { "batchId": "...", "inputRows": 1, "outputRows": 1, "errorRows": 0, "auditFile": "..." }
# { "batchId": "...", "accepted": 1 }   ← 服务端按业务 code（SUCCESS/OK/0/200）判定成功
```

## SDK 编程用法

```ts
import { createSanitizer } from "@tengence/sanitize-sdk";

const s = createSanitizer({
  config: "./sanitize.config.json", // 或配置对象
  // apiKey / pushUrl 可选，缺省走环境变量与默认地址
});

// 内存批量脱敏（小数据量；大文件用 sanitizeFile 流式）
const rows = s.sanitizeRows([{ phone: "13800138000", id: "1" }]);
// [{ phone: "1c797a078e4a6693c968d02270aefd66", id: "1" }]

// dry-run 预览：命中统计 + 脱敏后样例 + 未命中字段清单
const report = await s.dryRun("./data.csv");

// 文件流式脱敏（CSV/JSON/JSONL/Excel）
const result = await s.sanitizeFile("./data.csv", "./data.sanitized.csv");

// 上传脱敏后行数据（自动分片/重试；成功判定见「上传」）
const up = await s.upload(s.sanitizeRows(rows));
// up = { batchId, accepted, rejected? }

// 还原可逆字段（凭自持 key，本地）
const plain = s.restore("order_no", "ab12cd…"); // 解密失败抛错

// 审计
const audit = s.auditLog();          // AuditRecord[]
const json = s.exportAudit();        // JSON 字符串
```

## 使用 MCP（AI 接入）

`@tengence/sanitize-mcp` 让 AI 客户端（豆包工作台 / 支持 MCP 的客户端）通过 Model Context Protocol 直接使用上述脱敏能力——**配置校验、dry-run 预览、文件脱敏、上传、审计**。AI 连接后**自动**获得 6+1 个工具、3 个提示词模板、4 类参考资源与每会话 instructions，无需额外 skill。详见 [`packages/sanitize-mcp/README.md`](packages/sanitize-mcp/README.md)。

**stdio 客户端配置**（MCP 2026-07-28，客户端需 pin 协议版本）：

```jsonc
{
  "mcpServers": {
    "tengence-sanitize": {
      "command": "npx",
      "args": ["-y", "-p", "@tengence/sanitize-mcp", "tengence-sanitize-mcp"],
      "env": {
        "TENGENCE_SANITIZE_SALT": "…",
        "TENGENCE_SANITIZE_KEY": "…",
        "TENGENCE_API_KEY": "…"
        // "SANITIZE_MCP_ENABLE_RESTORE": "1"  // 明确知情才开启还原
      }
    }
  }
}
```

**HTTP 自托管**：

```bash
SANITIZE_MCP_PORT=8788 SANITIZE_MCP_TOKEN=sk-xxx \
  npx -y @tengence/sanitize-mcp tengence-sanitize-mcp-http
# Base URL = http://127.0.0.1:8788/   Auth = Bearer <SANITIZE_MCP_TOKEN>
```

典型用法：对 AI 说「帮我脱敏这份 CSV 并上传」——AI 会依次校验配置 → dry-run → 脱敏 → 经你确认后上传。

## 配置示例

```jsonc
{
  "version": 1,
  "rules": [
    { "fields": ["phone"], "method": "hash", "params": { "algorithm": "SHA-256", "saltEnv": "TENGENCE_SANITIZE_SALT" } },
    { "fields": ["user_id"], "method": "hash", "params": { "algorithm": "HMAC-SHA-256", "keyEnv": "TENGENCE_SANITIZE_KEY", "hashLength": 64 } },
    { "fields": ["name"], "method": "mask", "params": { "keepFirst": 1, "keepLast": 1 } },
    { "fields": ["id_card"], "method": "mask", "params": { "keepFirst": 4, "keepLast": 4 } },
    { "fields": ["order_no"], "method": "encrypt", "params": { "keyEnv": "TENGENCE_SANITIZE_KEY" } },
    { "fields": ["remark"], "method": "preserve" }
  ],
  "upload": { "pushUrl": "https://api.mossego.com/v1/push/data", "apiKeyEnv": "TENGENCE_API_KEY", "batchSize": 1000, "maxRetries": 3, "timeoutMs": 30000 },
  "audit": { "enabled": true, "dir": "~/.tengence/sanitize/audits" }
}
```

> 字段选择：**仅 `rules[].fields` 显式字段路径**（顶层 `phone`、嵌套 `contact.phone`、数组 `items[*].price`），字段完全由用户自定义，不限于内置 PII 名单；正则匹配 / PII 自动识别本轮不做。dry-run 的 `unmatchedFields` 提示漏配。

## 算法与输出

| 方法 | 语义 | 输出 |
| --- | --- | --- |
| `hash` | 不可逆确定性伪名化（可 join/去重/后台标识） | 纯 hex，默认 32 位（128-bit），可配 64 |
| `mask` | 展示类掩码（不用于 join） | 保留片段 + `*`（如 `1101**********1234`） |
| `encrypt` | 可逆确定性加密（RFC 5297 AES-SIV），平台可直接 join，用户持 key 本地还原 | 纯 hex，`2×(16+len)`（手机号 54 位） |
| `preserve` | 显式原样 | 原样 |

- 输出**纯十六进制、无特殊字符**（去掉 `$` 等），后端可直接做关联/去重。
- 同明文 → 同输出（确定性）：跨批稳定，增量导入可 join。
- **mask 边界**：需 `keepFirst + keepLast < 字段长度` 才真正打码；`0/0` 输出为「*+原文」（`**张三`）**仍含明文**；字段过短（如 2 字姓名 keep 1/1）告警不脱敏、值透传。**姓名/短字段建议 hash 或 encrypt，不要用 mask**。

## 上传

复用现有批量推送接口（不新建）：

- `POST {pushUrl}`，默认 `https://api.mossego.com/v1/push/data`
- `Authorization: Bearer {应用 apiKey}`
- 请求体：`{ data: [...], batch_id, config_fingerprint, masking_meta }`
- 分片：按 `batchSize`（默认 1000）与字节上限双条件切片
- 重试：指数退避 + 抖动 + 429 Retry-After；4xx/业务错误码不轰炸
- `masking_meta` 声明「字段 → 方法」，供服务端后续做明文拒收格式机检（独立排期）

**真实网关契约（2026-10-19 实测确认）**：

- 行**必需**含数据集主键字段（默认 `id`），缺失返回 `ID_FIELD_MISSING`——输入务必带主键列；
- 成功判定：HTTP 2xx 且业务 `code` 为 `0` / `200` / `SUCCESS` / `OK` / 缺省（网关实际返回 `code:"SUCCESS"`）；
- `UNAUTHORIZED` 偶发为瞬时状态，可重试一次；连续失败请用户核对数据集成应用 apiKey；
- `INVALID_API_KEY`：key 无效或域名错误（旧 `api.tengence.com` 已废弃），需用户核对，不轰炸重试；
- 数据集需处于 RUNNING；POST 批量默认 UPSERT 幂等。

## 常见坑（实测踩坑记录）

1. **扁平列名含点号**：CSV 列名就叫 `contact.phone` 时，**不会**被嵌套路径 `contact.phone` 匹配（嵌套路径访问的是对象 `contact` 下的 `phone`）→ 该列漏配、明文随包上传。改列名（如 `contact_phone`）或改嵌套结构，dry-run 兜底发现。
2. **2 字姓名 mask 泄漏**：`mask(1/1)` 不脱敏、`mask(0/0)` 输出「*+原文」——姓名/短字段请用 hash。
3. **`.xls` 老格式不支持**：需先转 `.xlsx`（exceljs 解析，日期归一化为 `yyyy-MM-dd HH:mm:ss`）。
4. **盐/密钥丢失不可恢复**：hash 不可复算、enc 不可还原；密钥是用户的，务必离线备份。
5. **上传前务必 dry-run**：hits=0 或 unmatchedFields 非空时先补配，否则会带着明文上传。

## 开发

```bash
npm install
npm run build      # 构建全部包
npm test           # vitest 单测（全仓 78 项）
npm run typecheck
```

## 里程碑状态

- 阶段一 MVP：✅ 已实施（仓库骨架、SDK、CLI、MCP、真实网关契约实测）
- 阶段二（后续）：正则/PII 自动识别评估、服务端明文拒收改造（collect-service，独立排期）、断点续传、KMS 接口
- 阶段三（后续）：FPE / AES-SIV 替代、紧凑输出、压测

## License

MIT
