# tengence-sanitize-sdk

tengence 数据导入服务的**本地脱敏前置工具**：用户在本地（自有环境）完成字段级脱敏后再调用现有批量推送接口上传，**明文不出用户环境**。

- SDK：`@tengence/sanitize-sdk`（Node/TypeScript）
- CLI：`tengence-sanitize`（薄壳封装）
- 独立 git 仓库，与 `tengence-track-sdk-web` 分离

## 为什么做本地脱敏

业界数据同步工具（DataX、Fivetran、Airbyte、AWS DMS、Snowflake、神策等）的脱敏几乎都发生在「数据已进入工具/平台之后」，无法打消「明文传给服务商」的顾虑。支付行业 P2PE、GA4 client-side redaction、Amplitude 发送前哈希等源头侧做法是唯一能保证明文不出域的模式——本工具即采用该模式。调研结论与方案见 `tengence-track-sdk-web/数据导入脱敏-详细实施方案.md`。

## 信任边界

```
用户本机（明文仅在此）                   服务端
原始数据 ──> SDK/CLI 本地脱敏 ──> 纯 hex/掩码值 ──HTTP(Bearer apiKey)──> POST /v1/push/data
            · 盐/密钥用户自持（env）
            · 本地审计日志
```

## 快速开始

```bash
cd packages/sanitize-cli
npm link   # 或使用 npx @tengence/sanitize-cli

# 1. 生成密钥（可逆加密用）
tengence-sanitize gen-key --out ~/.tengence/sanitize-key

# 2. 配置环境变量
export TENGENCE_SANITIZE_SALT="$(openssl rand -hex 16)"
export TENGENCE_SANITIZE_KEY="$(cat ~/.tengence/sanitize-key)"
export TENGENCE_API_KEY="sk-你的应用apiKey"

# 3. 编写 sanitize.config.json（字段完全用户自定义，见 examples/）
# 4. dry-run 预览（命中统计 + 样例 + 未命中字段清单）
tengence-sanitize run --config sanitize.config.json --input data.csv --dry-run

# 5. 正式脱敏
tengence-sanitize run --config sanitize.config.json --input data.csv --output data.sanitized.csv

# 6. 上传到现有批量推送接口（POST /v1/push/data）
tengence-sanitize run --config sanitize.config.json --input data.csv --output data.sanitized.csv --upload

# 7. 还原可逆字段（本地，凭自持 key）
tengence-sanitize restore --field order_no --value <enc值>

# 8. 审计
tengence-sanitize audit
tengence-sanitize audit --export csv
```

## 配置示例

```jsonc
{
  "version": 1,
  "rules": [
    { "fields": ["phone", "contact.phone"], "method": "hash", "params": { "algorithm": "SHA-256", "saltEnv": "TENGENCE_SANITIZE_SALT" } },
    { "fields": ["user_id"], "method": "hash", "params": { "algorithm": "HMAC-SHA-256", "keyEnv": "TENGENCE_SANITIZE_KEY", "hashLength": 64 } },
    { "fields": ["name"], "method": "mask", "params": { "keepFirst": 1, "keepLast": 1 } },
    { "fields": ["order_no"], "method": "encrypt", "params": { "keyEnv": "TENGENCE_SANITIZE_KEY" } },
    { "fields": ["remark"], "method": "preserve" }
  ],
  "upload": { "pushUrl": "https://api.tengence.com/v1/push/data" },
  "audit": { "dir": "./.tengence-sanitize-audit" }
}
```

> 字段选择：**仅 `rules[].fields` 显式字段路径**（`a.b`、`items[*].c`），字段完全由用户自定义，不限于内置 PII 名单；正则匹配 / PII 自动识别本轮不做。dry-run 会输出「未命中字段清单」提示漏配。

## 算法与输出

| 方法 | 语义 | 输出 |
| --- | --- | --- |
| `hash` | 不可逆确定性伪名化（可 join/去重） | 纯 hex，默认 32 位（128-bit），可配 64 |
| `mask` | 展示类掩码（不用于 join） | 保留片段 + `*`（如 `1********0`） |
| `encrypt` | 可逆确定性加密（RFC 5297 AES-SIV），平台可直接 join，用户持 key 本地还原 | 纯 hex，`2×(16+len)`（手机号 54 位） |
| `preserve` | 显式原样 | 原样 |

- 输出**纯十六进制、无特殊字符**（去掉 `$` 等），后端可直接做关联/去重。
- 同明文 → 同输出（确定性）：跨批稳定，增量导入可 join。

## 上传

复用现有批量推送接口（不新建）：

- `POST {pushUrl}`，默认 `https://api.tengence.com/v1/push/data`
- `Authorization: Bearer {应用 apiKey}`
- 请求体：`{ data: [...], batch_id, config_fingerprint, masking_meta }`
- 分片：按 `batchSize`（默认 1000）与字节上限双条件切片
- 重试：指数退避 + 抖动 + 429 Retry-After；4xx/业务错误码不轰炸
- `masking_meta` 声明「字段 → 方法」，供服务端后续做明文拒收格式机检（独立排期）

> 数据集需处于 RUNNING；行需含 ID 字段（服务端配置的 `idFieldName`）；POST 批量默认 UPSERT 幂等。
> 成功判定按业务 `code`（0/200/缺省=成功），实施时以网关实际行为为准。

## 开发

```bash
npm install
npm run build      # 构建两个包
npm test           # vitest 单测
npm run typecheck
```

## 里程碑状态

- 阶段一 MVP：✅ 已实施（T1 仓库骨架 → T9 CLI，见方案 §13）
- 阶段二（后续）：正则/PII 自动识别评估、服务端明文拒收改造（collect-service，独立排期）、断点续传、KMS 接口
- 阶段三（后续）：FPE / AES-SIV 替代、紧凑输出、压测

## License

MIT
