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

## Prompts（提示词模板，3 个，用户显式触发）

- `sanitize_setup_config` —— 为指定业务字段生成/审阅 `sanitize.config.json`；
- `sanitize_desensitize_file` —— 完整脱敏流程（校验 → 预览 → 脱敏 → 可选上传）；
- `sanitize_verify_audit` —— 审计核对与合规小结。

## Resources（资源，按需读取，不占上下文）

- `sanitize://methods` —— 算法与输出长度（hash 32/64 hex、enc 2×(16+len) 手机号 54 hex、mask）；
- `sanitize://config-schema` —— 配置结构与字段路径规则（嵌套/数组）；
- `sanitize://workflows` —— 规范流水线与安全红线；
- `sanitize://audit/{batchId}` —— 单条审计记录（模板资源）。

## 协议

- **MCP 2026-07-28**（无状态核心）：每请求独立、无 Session；`Mcp-Method` / `Mcp-Name` 路由头由 SDK 输出，网关可路由。
- strict modern-only：2025 世代（initialize 握手）客户端会被拒绝（`legacy: 'reject'`）；客户端需声明协议版本（如 SDK v2 客户端 `versionNegotiation: { mode: { pin: '2026-07-28' } }`）。

## 测试

```bash
npm run test -w @tengence/sanitize-mcp   # 25 项：单测（无明文断言/门控断言）+ 真实客户端端到端（stdio）
```

## 许可

MIT © Tengence Team
