# sanitize-mcp 实施方案（已确认）

> 让 AI（MCP 客户端）通过 Model Context Protocol 调用 `@tengence/sanitize-sdk` 的本地脱敏能力。
> 参考 `tengence-geo-agent/packages/geo-mcp` 的实施方式；按 **MCP 2026-07-28** 规范（当前最新修订，无状态核心）实现。
> 核心约束：**明文不离开用户本机，也绝不进入 AI 上下文**。

---

## 1. 调研结论（已核实）

### 1.1 MCP 规范现状

- 当前最新修订为 **2026-07-28**（上一版 2025-11-25；再往前 2025-06-18 / 2025-03-26）。2026-07-28 是协议史上最大修订，核心变化：
  - **无状态协议核心**：取消 `initialize/initialized` 握手与 `Mcp-Session-Id`；每个请求自带 `_meta`（协议版本/客户端身份/能力）；新增可选 `server/discover`；任何请求可落到负载均衡后的任意实例。
  - **头路由**：`Mcp-Method` / `Mcp-Name` HTTP 头承载方法名与工具名，网关可据此路由与鉴权。
  - **列表结果可缓存**：`tools/list` / `prompts/list` / `resources/list` 带 `ttlMs` / `cacheScope`。
  - **MRTR（Multi Round-Trip Requests）**：服务端返回 `resultType:"input_required"` 请求补充输入。
  - **Tasks 扩展**：`io.modelcontextprotocol/tasks`（长任务，轮询 `tasks/get` + `tasks/update`）。
  - 鉴权加固（RFC 9207 issuer 校验、CIMD 取代 DCR）；Roots/Sampling/Logging 与 HTTP+SSE 传输进入 12 个月弃用期。
- TypeScript SDK v2（分体式）：`@modelcontextprotocol/server@2.3.1`（ESM-only）、`@modelcontextprotocol/node@2.1.1`（Node HTTP 适配）、`@modelcontextprotocol/client@^2.3.1`——与 geo-mcp 锁定版本一致。

### 1.2 geo-mcp 实施要点（参考蓝本）

| 层 | geo-mcp 做法 | 我们沿用 |
| --- | --- | --- |
| 协议 | MCP 2026-07-28，`serveStdio(factory, { legacy:'reject' })` / `createMcpHandler(factory, { legacy:'reject' })`，strict modern-only | 同 |
| 服务工厂 | `buildServer()`：每请求/每连接新建无状态实例；`McpServer({name,version},{instructions, capabilities})` | 同 |
| instructions | `Implementation.instructions`：聚合 TOOL_GROUPS（由注册表实时聚合，防漂移）+ 规范流水线 + 何时不调用 | 同 |
| 工具 | `tools/registry.js`：描述符 `{name,title,description,inputSchema(zod),run(args)}`，输出 JSON 文本，错误 `isError:true` | 同 |
| 资源 | 固定资源 + `ResourceTemplate`；仅暴露非敏感白名单数据 | 同（增加「无明文」约束） |
| 提示词 | `{name,title,description,argsSchema,run(args)→{description,messages}}`，用户显式触发 | 同 |
| 桥接 | 直接调用 `@tengence/geo-sdk` 域 API（同一逻辑，零重复）；编排类动作委托 CLI | sanitize-sdk 已是纯函数库，**全部直接桥接，无需 CLI 委托** |
| 传输 | stdio + Streamable HTTP（Bearer 鉴权、GET / 健康检查、CORS 可选） | 同 |
| 包 | `@tengence/geo-mcp`，`mcpName: com.tengence/geo`，双 bin，Node ≥22.13，CJS 主体 + 动态 import ESM SDK | 同（`com.tengence/sanitize`） |

---

## 2. 信任边界设计（本方案最重要的一条）

脱敏产品的立身之本 = **明文不出本地**。MCP 化之后必须守住延伸边界：**明文也不进入 AI 上下文**（对话记录、模型提示词、日志都可能留存）。三条硬规则：

1. **密钥/盐/apiKey 一律只走环境变量，MCP 内部零保存**：`TENGENCE_SANITIZE_SALT`、`TENGENCE_SANITIZE_KEY`、`TENGENCE_API_KEY`（或 config 的 `upload.apiKeyEnv`）。工具参数**拒绝接受**任何密钥/盐/token——防止密钥被模型读进上下文；MCP 进程不落盘、不缓存、不打印任何密钥（启动 banner 只显示已配置/未配置，不显示值）。
2. **工具输出不回显明文**：
   - `dry-run`：剥离 SDK 返回的 `before` 样例，只返回**脱敏后**样例（hash/enc 为 hex、mask 为部分打码，均非原文）+ 命中统计。
   - `sanitize_file`：只返回统计（batchId/行数/告警/审计路径），不返回任何行数据。
   - 审计资源：审计记录本就不含明文（仅字段名与计数）。
3. **还原明文默认不暴露（已确认：开关方案）**：`restore`（解密回原文）默认**不注册**，保留在 CLI（`tengence-sanitize restore`）。设置 `SANITIZE_MCP_ENABLE_RESTORE=1` 时注册为可选第 7 个工具 `sanitize_restore(field, value)`——参数仅字段名与密文，**密钥仍只从环境变量读取**，MCP 内部不保存。`gen-key` 永不进 MCP（生成结果即密钥本身）。

---

## 3. 工具集（tools，6 个）

按「配置 → 预览 → 执行 → 上传 → 审计」流水线组织，参数全部用 zod shape + `describe()`（AI 无需查文档即可正确调用）：

| # | 工具 | 作用 | 关键输出（均无明文） |
| --- | --- | --- | --- |
| 1 | `sanitize_config_info(config)` | 加载并校验配置文件 | 规则摘要（字段→方法）、`configFingerprint`、`masking_meta`、错误信息 |
| 2 | `sanitize_dry_run(config, input[, format])` | 脱敏预览（不写文件） | `inputRows`、每字段 `{field,method,hits,after样例≤3}`、`unmatchedFields`（防漏配兜底） |
| 3 | `sanitize_file(config, input, output[, format])` | 执行流式脱敏 | `{batchId,inputRows,outputRows,errorRows,warnings,auditFile}` |
| 4 | `sanitize_upload(config, input[, push_url])` | 上传已脱敏文件 → POST /v1/push/data（Bearer） | `{batchId,accepted,rejected?}` |
| 5 | `sanitize_audit_list([dir])` | 列出本地审计记录 | 每批 `{batchId,fingerprint,行数,hits,unmatched,ts,exitCode,uploadResult}` |
| 6 | `sanitize_audit_export(dir, format json\|csv)` | 导出审计为文件 | 输出文件路径 |
| 7* | `sanitize_restore(field, value)` | **仅当 `SANITIZE_MCP_ENABLE_RESTORE=1` 时注册**：本地解密 enc 密文回原文 | `{field, restored: true}`（输出即明文，仅开关开启后可用；key 仍走环境变量） |

设计要点：
- `config` 参数是**配置文件路径**（AI 不拼 JSON，路径由客户端提供）；`input/output` 均为本机文件路径，**服务端不猜测路径**。
- 上传只接受已脱敏文件（`push_url` 默认 `DEFAULT_PUSH_URL`；apiKey 仅环境变量；服务端明文拒收校验兜底——collect-service 独立排期不变）。
- 每个工具 `annotations` 标注 `readOnlyHint`（dry_run/audit_list/audit_export/config_info = 只读；sanitize_file/upload/restore = 写）。

---

## 4. 资源（resources，参考数据放资源，不占 instructions）

深度规则与参考数据通过 `resources/read` 按需加载，避免烧上下文：

| URI | 类型 | 内容 |
| --- | --- | --- |
| `sanitize://methods` | 固定 | 脱敏算法参考：hash（SHA-256 32hex / 64hex；HMAC 需密钥）、mask（keepFirst/keepLast）、encrypt（AES-SIV，2×(16+len)，手机号 54 hex）、preserve；确定性语义（可 join/去重） |
| `sanitize://config-schema` | 固定 | `sanitize.config.json` 完整结构 + 字段路径规则（支持嵌套 `contact.phone`、数组 `items[*].price`）+ 最小示例 |
| `sanitize://workflows` | 固定 | 规范流程：config → dry-run 预览 → sanitize_file → upload；restore 走 CLI；何时不调用 |
| `sanitize://audit/{batchId}` | 模板 | 单条审计记录详情（读本地审计 JSON，无明文） |

可选加分项（阶段二）：`sanitize://config-example` 完整示例配置（固定资源）。

---

## 5. 提示词模板（prompts，3 个）

用户显式触发（如斜杠命令），编码经过验证的调用序列，让 AI 不必每次重新发明流程：

| name | 用途 | 参数 |
| --- | --- | --- |
| `sanitize_setup_config` | 为指定字段生成/审阅 `sanitize.config.json`（引导读 `sanitize://config-schema`，产出配置路径） | `fields`（字段与脱敏方式描述）、`output`（配置落盘路径） |
| `sanitize_desensitize_file` | 完整脱敏流程：校验配置 → dry-run 预览（确认命中与未命中）→ 执行脱敏 →（可选）上传 | `config`、`input`、`output`、`upload`（bool）、`push_url?` |
| `sanitize_verify_audit` | 审计核对：列出/读取审计，检查未命中字段与上传结果，输出小结 | `dir?`、`batch_id?` |

---

## 6. instructions（`Implementation.instructions`）

- 一句话身份 + 声明：**文件路径由客户端显式提供，不做任何猜测**。
- **TOOL GROUPS**（由注册表实时聚合，防漂移）：配置 / 预览 / 执行 / 上传 / 审计。
- **CANONICAL PIPELINE**：`sanitize_config_info` → `sanitize_dry_run`（确认命中与未命中字段）→ `sanitize_file` → `sanitize_upload`。
- **WHEN NOT TO CALL / 安全红线**（核心引导，防模型误用）：
  1. 任何密钥/盐/apiKey **禁止**作为工具参数传入——只用环境变量；
  2. 工具输出不含原文；需要看原文时请用户直接打开本地文件；
  3. 还原明文一律使用 CLI `tengence-sanitize restore`，MCP 不提供（除非开启 `SANITIZE_MCP_ENABLE_RESTORE`）；
  4. 生成输出文件 / 上传属写操作，执行前先与用户确认；
  5. dry-run 出现 `unmatchedFields` 时先补配再执行，不要直接脱敏。

---

## 7. 传输与鉴权（对齐 geo-mcp）

- **stdio**（`bin/tengence-sanitize-mcp.js`）：`serveStdio(() => buildServer(), { legacy:'reject' })`——本地客户端首选，明文天然不出本机。
- **Streamable HTTP**（`bin/tengence-sanitize-mcp-http.js`）：`createMcpHandler(() => buildServer(), { legacy:'reject' })` + `toNodeHandler`；环境变量 `SANITIZE_MCP_PORT`（默认 8788）、`SANITIZE_MCP_TOKEN`（Bearer；未设置告警 + 无鉴权仅限本地调试）、`SANITIZE_MCP_CORS_ORIGIN`（可选，网关负责 TLS/ACL）。`GET /` 健康检查。2026-07-28 头路由（`Mcp-Method`/`Mcp-Name`）由 SDK 输出，网关可路由。
- 列表结果缓存头（`ttlMs`/`cacheScope`）由 SDK 处理，服务端不手写。
- **不做 Tasks 扩展（已确认）**：`io.modelcontextprotocol/tasks` 用于「一次调用跑几分钟/几小时」的长任务（工具立即返回 `taskId`，客户端 `tasks/get` 轮询、`tasks/update` 补充输入、`tasks/cancel` 取消）。本场景为**本地秒级操作**（sanitize_file 流式几秒、upload 分片上传），客户端同步等待即可；引入 Tasks 需额外做任务状态存储、轮询与通知订阅，得不偿失。将来若出现 GB 级超大文件或长时间上传，再按需加入。

### 7.1 环境变量（密钥全部外部注入，MCP 内部零保存）

| 变量 | 用途 | 必填 |
| --- | --- | --- |
| `TENGENCE_SANITIZE_SALT` | SHA-256 哈希盐（用户自持） | hash 规则且非 HMAC 时必填 |
| `TENGENCE_SANITIZE_KEY` | encrypt/HMAC 密钥（32B，用户自持） | encrypt/HMAC 规则时必填 |
| `TENGENCE_API_KEY` | 上传 Bearer（或 config `upload.apiKeyEnv` 指定其他变量名） | 上传时必填 |
| `SANITIZE_MCP_ENABLE_RESTORE` | `1` 时注册 `sanitize_restore`（默认不注册） | 否 |
| `SANITIZE_MCP_AUDIT_DIR` | 审计目录覆盖（默认 SDK 默认目录；资源与工具读取一致） | 否 |
| `SANITIZE_MCP_PORT` / `SANITIZE_MCP_TOKEN` / `SANITIZE_MCP_CORS_ORIGIN` | HTTP 模式端口（默认 8788）/ Bearer 令牌 / 可选 CORS | 否 |

---

## 8. 文件组织（对齐 geo-mcp 结构）

```
tengence-sanitize-sdk/
└── packages/sanitize-mcp/
    ├── package.json          # @tengence/sanitize-mcp，双 bin，mcpName: com.tengence/sanitize
    ├── server.js             # buildServer() 工厂 + buildInstructions()
    ├── tools/
    │   ├── registry.js       # 6 个工具描述符（zod schema + run，直连 sanitize-sdk API）
    │   ├── resources.js      # 固定资源 + audit/{batchId} 模板
    │   └── prompts.js        # 3 个提示词模板
    ├── bin/
    │   ├── sanitize-mcp.js      # stdio 入口
    │   └── sanitize-mcp-http.js # HTTP 入口（Bearer/健康检查/CORS）
    ├── test/                 # vitest 单测
    └── README.md             # 安装/客户端配置（stdio+HTTP）/工具清单/安全红线
```

桥接方式：`server.js`/`tools/*` 直接 `require('@tengence/sanitize-sdk')`（CJS 入口 `dist/index.cjs`，已确认导出 `loadConfig/validateConfig/createSanitizer/readAudit/exportAudit/…` 齐全）；SDK v2 通过动态 import 引入——与 geo-mcp 同构。

---

## 9. 测试与验证

1. **单测（vitest）**：
   - 工具层：config_info 校验失败报错清晰；dry_run 输出**不含 before 明文**（断言样例只含脱敏后值）；sanitize_file 只返回统计；upload 复用现有 mock-fetch 模式（分片/拒收/重试）；audit_list/export 正确。
   - 注册层：6 工具 + 3 prompts + 4 资源全部注册；instructions 不包含密钥字样；`SANITIZE_MCP_ENABLE_RESTORE` 未设置时 `sanitize_restore` 不注册、设置后注册且 schema 无密钥参数。
   - 安全层：任何工具 schema 均无 key/salt/token 参数；gen-key 未注册。
2. **集成实测（真实客户端）**：本地起 stdio，用最小 MCP 客户端（参考 `geo .local/geo_mcp_client.mjs` 模式）跑通：discover → config_info → dry_run（CSV 样例）→ sanitize_file → upload（mock）→ audit_list；全程断言输出无明文。
3. **手动冒烟**：按 README 接入 Doubao 工作台/Claude 类客户端的 `mcpServers` 配置（stdio + HTTP 两条示例）。

---

## 10. 与既有产物衔接

- 复用 sanitize-sdk 的 config/engine/io/audit/upload 全部逻辑，零重复实现；CLI 不动。
- 加密算法 AES-SIV（§5.4）与纯 hex 输出约定不变。
- 服务端明文拒收（collect-service 另一仓库）独立排期，不影响本包。
- 发布：npm `publishConfig.access=public`（对齐 geo-mcp）；GitHub 推送同仓库 main。

---

## 11. 决策点结论（已确认 + 待确认）

| # | 决策点 | 结论 |
| --- | --- | --- |
| 1 | restore 是否暴露 | **已确认：默认不暴露 + `SANITIZE_MCP_ENABLE_RESTORE=1` 开关**；`gen-key` 永不进 MCP；**密钥/盐/apiKey 全部只走外部环境变量，MCP 内部零保存**（不落盘/不缓存/不打印） |
| 2 | 工具划分 | **已确认：6 个 + 1 个开关控制的 `sanitize_restore`（共 7 个工具定义，默认注册 6 个）** |
| 3 | 包位置 | **已确认：`packages/sanitize-mcp`（`@tengence/sanitize-mcp`，与 SDK/CLI 同仓库）** |
| 4 | 传输 | **已确认：stdio + Streamable HTTP 双入口都做**（对齐 geo-mcp） |
| 5 | Tasks 扩展 | **已确认：不做**（本地秒级操作，无长任务；理由见 §7） |
