# @tengence/sanitize-mcp

Tengence 数据脱敏的 **MCP 服务**：让 AI（MCP 客户端）通过 Model Context Protocol 调用 `@tengence/sanitize-sdk` 的本地脱敏能力——配置校验、dry-run 预览、文件脱敏、上传与审计。支持 **stdio**（本地客户端）与 **Streamable HTTP**（远程/自托管）两种传输，基于 **MCP 2026-07-28** 规范（无状态协议核心）。

> 命名空间：`com.tengence/sanitize` · 这是 `@tengence/sanitize-sdk` 的 MCP 桥接层（与 CLI 共享同一套核心逻辑，零重复实现）。

## 信任边界（最重要的约束）

脱敏产品的立身之本：**明文不离开用户本机，也绝不进入 AI 上下文**。MCP 化之后延伸为三条硬规则：

1. **密钥/盐/apiKey 一律只走环境变量**（`TENGENCE_SANITIZE_SALT` / `TENGENCE_SANITIZE_KEY` / `TENGENCE_API_KEY`），工具参数拒绝接受任何密钥——MCP 进程不落盘、不缓存、不打印密钥。
2. **工具输出不回显明文**：dry-run 只返回**脱敏后**样例（剥离 `before`）；`sanitize_file` 只返回统计；审计记录只有字段名与计数。
3. **还原明文默认不开放**：`sanitize_restore`（解密回原文）仅在 `SANITIZE_MCP_ENABLE_RESTORE=1` 时注册；`gen-key` 永不进 MCP。默认还原请用 CLI `tengence-sanitize restore`。

## 环境要求

- **Node.js ≥ 22.13.0**

## 安装与运行

### 方式一：npx 直装（推荐）
```bash
npx -y -p @tengence/sanitize-mcp tengence-sanitize-mcp        # stdio 模式，无需本地仓库
# HTTP 版：npx -y -p @tengence/sanitize-mcp tengence-sanitize-mcp-http
```

### 方式二：作为客户端 MCP server 配置（stdio）
```jsonc
{
  "mcpServers": {
    "tengence-sanitize": {
      "command": "npx",
      "args": ["-y", "-p", "@tengence/sanitize-mcp", "tengence-sanitize-mcp"],
      "env": {
        "TENGENCE_SANITIZE_SALT": "…",   // SHA-256 盐（用户自持）
        "TENGENCE_SANITIZE_KEY": "…",    // encrypt/HMAC 密钥 32B（用户自持）
        "TENGENCE_API_KEY": "…"          // 上传 Bearer（上传时才需要）
        // "SANITIZE_MCP_ENABLE_RESTORE": "1"  // 明确知情才开启还原
        // "SANITIZE_MCP_AUDIT_DIR": "~/…"     // 审计目录覆盖
      }
    }
  }
}
```

### 方式三：Streamable HTTP（自托管）
```bash
SANITIZE_MCP_PORT=8788 SANITIZE_MCP_TOKEN=sk-xxx \
  npx -y @tengence/sanitize-mcp-http
# Base URL = http://127.0.0.1:8788/    Auth = Bearer <SANITIZE_MCP_TOKEN>
```
> 远程模式为静态 Bearer 鉴权（无 OAuth 2.1 / 动态客户端注册），适合单用户自托管；多租户公开托管需网关层（TLS/ACL/CORS）补齐。

## 环境变量

| 变量 | 用途 | 必填 |
| --- | --- | --- |
| `TENGENCE_SANITIZE_SALT` | SHA-256 哈希盐（用户自持） | hash 规则且非 HMAC 时必填 |
| `TENGENCE_SANITIZE_KEY` | encrypt/HMAC 密钥（32B，用户自持） | encrypt/HMAC 规则时必填 |
| `TENGENCE_API_KEY` | 上传 Bearer（或 config `upload.apiKeyEnv` 指定其他变量名） | 上传时必填 |
| `SANITIZE_MCP_ENABLE_RESTORE` | `1` 时注册 `sanitize_restore`（默认不注册） | 否 |
| `SANITIZE_MCP_AUDIT_DIR` | 审计目录覆盖（默认 SDK 默认目录） | 否 |
| `SANITIZE_MCP_PORT` / `SANITIZE_MCP_TOKEN` / `SANITIZE_MCP_CORS_ORIGIN` | HTTP 模式端口（默认 8788）/ Bearer 令牌 / 可选 CORS | 否 |

## 工具（Tools，6 个 + 1 个可选）

| 工具 | 作用 | 输出（无明文） |
| --- | --- | --- |
| `sanitize_config_info` | 校验配置 | 规则摘要 / configFingerprint / masking_meta |
| `sanitize_dry_run` | 脱敏预览（不写文件） | 命中统计 + 脱敏后样例 + unmatchedFields |
| `sanitize_file` | 执行流式脱敏 | batchId / 行数 / 告警 / 审计路径 |
| `sanitize_upload` | 上传已脱敏文件 | accepted / rejected |
| `sanitize_audit_list` | 列出本地审计 | 批次统计（无明文） |
| `sanitize_audit_export` | 导出审计为文件 | 导出文件路径 |
| `sanitize_restore` * | 本地还原 enc 密文（明文！） | 仅 `SANITIZE_MCP_ENABLE_RESTORE=1` 时注册 |

### 参数速查（每个工具怎么调）

| 工具 | 参数 | 必填 | 说明 |
| --- | --- | --- | --- |
| `sanitize_config_info` | `config` | ✅ | `sanitize.config.json` 绝对路径；返回规则摘要 / configFingerprint / masking_meta |
| `sanitize_dry_run` | `config`、`input` | ✅ | 输入文件（CSV/JSON/JSONL/XLSX）；返回命中统计 + **脱敏后**样例 + unmatchedFields |
| | `input_format` | — | 显式指定格式（`csv`/`json`/`jsonl`/`xlsx`），缺省自动探测 |
| `sanitize_file` | `config`、`input`、`output` | ✅ | 流式脱敏，返回 batchId/行数/告警/审计路径 |
| | `input_format` | — | 同上 |
| `sanitize_upload` | `config`、`input` | ✅ | `input` 为**已脱敏**文件路径；返回 accepted/rejected |
| | `push_url` | — | 覆盖上传端点（默认 `https://api.mossego.com/v1/push/data`） |
| `sanitize_audit_list` | `dir` | — | 审计目录（默认 `~/.tengence/sanitize/audits`） |
| `sanitize_audit_export` | `dir`、`format` | — | `format`: `json`\|`csv`（默认 json），导出到本地文件 |
| `sanitize_restore` * | `field`、`value` | ✅ | 仅在 `SANITIZE_MCP_ENABLE_RESTORE=1` 时可用；`field` 为加密时字段路径，`value` 为 enc hex |

> ⚠️ 任何工具都**不接受密钥/盐/apiKey 参数**——一律来自环境变量；工具参数里出现密钥会被视为错误用法。

## AI 客户端接入引导（让 AI 自己会用）

连接本服务后，客户端**自动**获得下面的能力，无需额外 skill：

- **tools/list** → 6+1 个工具（上文）；**resources/list** → 4 类参考数据；**prompts/list** → 3 个提示词模板；每会话自动注入 `Implementation.instructions`（TOOL GROUPS + 规范流水线 + 安全红线）。

典型任务路径（AI 可直接按此执行）：

1. **生成/审阅配置**：用户说「帮我配脱敏」→ 触发 `sanitize_setup_config` prompt（先读 `sanitize://config-schema`，产出配置，用 `sanitize_config_info` 校验）。
2. **脱敏一份文件（+ 上传）**：`sanitize_config_info(config)` → `sanitize_dry_run(config, input)`（确认 hits>0、unmatchedFields 为空，有漏配先补配）→ `sanitize_file(config, input, output)` → 用户确认后 `sanitize_upload(config, output)`。可触发 `sanitize_desensitize_file` prompt 一步到位。
3. **审计核对**：`sanitize_audit_list` / 读 `sanitize://audit/{batchId}` → 汇总批次数/行数/命中/未命中/上传结果；可触发 `sanitize_verify_audit` prompt。

「什么时候该用什么」的完整规则沉淀在：instructions（每会话）→ `sanitize://workflows`（按需）→ 三个 prompts（显式触发）。

## Prompts（提示词模板，3 个，用户显式触发）

- `sanitize_setup_config` —— 为指定业务字段生成/审阅 `sanitize.config.json`；
- `sanitize_desensitize_file` —— 完整脱敏流程（校验 → 预览 → 脱敏 → 可选上传）；
- `sanitize_verify_audit` —— 审计核对与合规小结。

## Resources（资源，按需读取，不占上下文）

- `sanitize://methods` —— 算法与输出长度（hash 32/64 hex、enc 2×(16+len) 手机号 54 hex、mask）；
- `sanitize://config-schema` —— 配置结构与字段路径规则（嵌套/数组）；
- `sanitize://workflows` —— 规范流水线与安全红线；
- `sanitize://audit/{batchId}` —— 单条审计记录（模板资源）。

## 常见错误与处理（AI/运维排查速查）

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 连接被拒（`legacy: reject`） | 客户端用 2025 世代 initialize 握手 | 客户端需支持 MCP 2026-07-28 并 pin 协议版本（如 SDK v2 `versionNegotiation.mode.pin = '2026-07-28'`） |
| HTTP 请求 400/422「缺 `_meta`」 | 2026-07-28 每请求需 `_meta` 信封（protocolVersion/clientInfo/clientCapabilities） | 按协议补 `params._meta` 三键 |
| HTTP 401 | 缺/错 `SANITIZE_MCP_TOKEN` | 请求头带 `Authorization: Bearer <token>` |
| dry-run 出现 `unmatchedFields` | 数据里有配置未声明的字段 | 先补配再脱敏；⚠️ 扁平列名含点号（如列名 `contact.phone`）不会被嵌套路径匹配，改列名或改数据 |
| 某字段 `hits: 0` 但数据里有值 | 字段路径不匹配，或字段过短（如 2 字姓名 mask 1/1 不脱敏） | 核对路径；姓名/短字段改用 hash 或 encrypt |
| 上传返回 `ID_FIELD_MISSING` | 行缺少数据集主键字段（默认 `id`） | 数据补 `id` 列后重试 |
| 上传返回 `UNAUTHORIZED` | 偶发瞬时状态，或 key 失效 | **先重试一次**；连续失败请用户核对数据集成应用 apiKey |
| 上传返回 `INVALID_API_KEY` | key 无效 / 域名错误 | 确认用的是 `api.mossego.com` 且 key 为数据集成应用 apiKey，请用户核对 |
| 读取 `.xls` 报错 | 老格式不支持 | 提示用户转 `.xlsx` |

## 协议

- **MCP 2026-07-28**（无状态核心）：每请求独立、无 Session；`Mcp-Method` / `Mcp-Name` 路由头由 SDK 输出，网关可路由。
- strict modern-only：2025 世代（initialize 握手）客户端会被拒绝（`legacy: 'reject'`）；客户端需声明协议版本（如 SDK v2 客户端 `versionNegotiation: { mode: { pin: '2026-07-28' } }`）。

## 测试

```bash
npm run test -w @tengence/sanitize-mcp   # 25 项：单测（无明文断言/门控断言）+ 真实客户端端到端（stdio）
```

## 许可

MIT © Tengence Team
