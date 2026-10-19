/**
 * tengence-sanitize-sdk 公共类型定义
 */

export type SanitizeMethod = "hash" | "mask" | "encrypt" | "preserve";

export interface HashParams {
  /** 默认 "SHA-256"（加盐确定性哈希）；"HMAC-SHA-256" 用于高敏感字段（抗字典攻击） */
  algorithm?: "SHA-256" | "HMAC-SHA-256";
  /** 盐环境变量名，默认 "TENGENCE_SANITIZE_SALT"（SHA-256 模式必填） */
  saltEnv?: string;
  /** 密钥环境变量名（HMAC 模式必填） */
  keyEnv?: string;
  /** 输出 hex 长度，默认 32（128-bit）；64 为全量 SHA-256 */
  hashLength?: 32 | 64;
}

export interface MaskParams {
  /** 保留前 N 字符，默认 1 */
  keepFirst?: number;
  /** 保留后 N 字符，默认 1 */
  keepLast?: number;
}

export interface EncryptParams {
  /** 加密密钥环境变量名，默认 "TENGENCE_SANITIZE_KEY"（32 字节） */
  keyEnv?: string;
}

export interface SanitizeRule {
  /** 显式字段路径（唯一指定方式）：a.b、items[*].c；字段完全由用户自定义 */
  fields: string[];
  method: SanitizeMethod;
  params?: HashParams | MaskParams | EncryptParams;
}

export interface UploadOptions {
  /** 批量推送接口地址，默认 {tengence.api.domain}/v1/push/data */
  pushUrl?: string;
  /** apiKey 环境变量名，默认 "TENGENCE_API_KEY" */
  apiKeyEnv?: string;
  /** 每批行数，默认 1000 */
  batchSize?: number;
  /** 单批负载字节上限，默认 4MB（对齐服务端 max-batch-payload-size，实施时按配置调整） */
  maxBatchPayloadBytes?: number;
  /** 最大重试次数，默认 10（对齐现有 SDK） */
  maxRetries?: number;
  /** 单请求超时 ms，默认 30000 */
  timeoutMs?: number;
}

export interface AuditOptions {
  enabled?: boolean;
  /** 审计日志目录，默认 ~/.tengence-sanitize/audit */
  dir?: string;
}

export interface SanitizeConfig {
  version: 1;
  rules: SanitizeRule[];
  dryRun?: boolean;
  upload?: UploadOptions;
  audit?: AuditOptions;
}

export interface DryRunFieldStat {
  field: string;
  method: SanitizeMethod;
  /** 命中（被脱敏处理）的非空值个数 */
  hits: number;
  /** 每个字段最多 3 条前后对照样例 */
  samples: { before: unknown; after: unknown }[];
}

export interface DryRunReport {
  dryRun: true;
  inputRows: number;
  fieldStats: DryRunFieldStat[];
  /** 输入数据中出现但配置未声明的顶层字段（防漏配兜底） */
  unmatchedFields: string[];
}

export interface RejectDetail {
  index?: number;
  code?: string;
  field?: string;
  message?: string;
}

export interface UploadResult {
  batchId: string;
  accepted: number;
  rejected?: RejectDetail[];
}

export interface AuditRecord {
  batchId: string;
  configFingerprint: string;
  ruleVersion: number;
  inputRows: number;
  outputRows: number;
  fieldHits: Record<string, number>;
  unmatchedFields: string[];
  dryRun: boolean;
  uploadResult?: UploadResult | { error: string };
  ts: string;
  exitCode: number;
}

export interface SanitizeFileResult {
  batchId: string;
  inputRows: number;
  outputRows: number;
  errorRows: number;
  auditFile?: string;
  /** 掩码失效等告警明细（字段 → 告警数） */
  warnings: Record<string, number>;
}

export interface Sanitizer {
  /** 内存批量脱敏（小数据量；大文件请用 sanitizeFile 流式） */
  sanitizeRows(rows: Row[]): Row[];
  /** 文件流式脱敏（CSV/JSON/JSONL/Excel） */
  sanitizeFile(input: string, output: string, opts?: { format?: "csv" | "json" | "jsonl" | "excel" }): Promise<SanitizeFileResult>;
  /** dry-run 预览：命中统计 + 前后样例 + 未命中字段清单（不输出文件） */
  dryRun(input: string | Row[], opts?: { format?: "csv" | "json" | "jsonl" | "excel" }): Promise<DryRunReport>;
  /** 本地还原可逆字段（凭自持 key 解密，失败抛错） */
  restore(field: string, value: string): string;
  /** 上传脱敏后行数据（复用批量推送接口，自动分片/重试） */
  upload(rows: Row[]): Promise<UploadResult>;
  /** 读取本地审计记录（最新在前） */
  auditLog(): AuditRecord[];
  /** 导出审计 JSON */
  exportAudit(dir?: string): string;
}

export type Row = Record<string, unknown>;
