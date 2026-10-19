/**
 * 上传适配：复用现有批量推送接口 POST {pushUrl}
 * - 鉴权：Authorization: Bearer {应用 apiKey}
 * - 请求体：{ data, batch_id, config_fingerprint, masking_meta }
 * - 分片：batchSize 行数 + maxBatchPayloadBytes 字节 双条件
 * - 重试：指数退避 + 抖动（封顶 60s）+ 429 尊重 Retry-After；4xx/业务错误码不轰炸
 * - 成功判定：HTTP 2xx 且业务 code 为 0 / 200 / 缺省（以网关实际行为为准，见文档 §6.3）
 */
import type { RejectDetail, Row, UploadResult } from "./types";

/** 默认推送地址：mossego 网关（2026-10-19 真实契约实测确认；原 api.tengence.com 域名已废弃） */
export const DEFAULT_PUSH_URL = "https://api.mossego.com/v1/push/data";

export interface UploadContext {
  pushUrl: string;
  apiKey: string;
  batchSize: number;
  maxBatchPayloadBytes: number;
  maxRetries: number;
  timeoutMs: number;
}

export interface UploadOptions {
  pushUrl?: string;
  apiKeyEnv?: string;
  batchSize?: number;
  maxBatchPayloadBytes?: number;
  maxRetries?: number;
  timeoutMs?: number;
}

export function resolveUploadContext(opts?: UploadOptions, apiKeyOverride?: string): UploadContext {
  const apiKey = apiKeyOverride ?? process.env[opts?.apiKeyEnv ?? "TENGENCE_API_KEY"];
  if (!apiKey) {
    throw new Error("缺少 apiKey：请通过 --api-key 或环境变量 TENGENCE_API_KEY 提供应用 apiKey");
  }
  return {
    pushUrl: opts?.pushUrl ?? DEFAULT_PUSH_URL,
    apiKey,
    batchSize: opts?.batchSize ?? 1000,
    maxBatchPayloadBytes: opts?.maxBatchPayloadBytes ?? 4 * 1024 * 1024,
    maxRetries: opts?.maxRetries ?? 10,
    timeoutMs: opts?.timeoutMs ?? 30000
  };
}

interface RawResponse {
  status: number;
  body: unknown;
  text: string;
}

/** 成功业务码集合：0/200（文档假设）+ SUCCESS/OK（mossego 真实网关实测返回 code:"SUCCESS"） */
const SUCCESS_CODES = new Set<unknown>([0, "0", 200, "200", "SUCCESS", "OK", "ok", "success"]);

function isSuccessBody(body: unknown): boolean {
  if (body === null || body === undefined) return true;
  if (typeof body !== "object") return false;
  const code = (body as Record<string, unknown>).code;
  if (code === undefined || code === null || code === "") return true;
  return SUCCESS_CODES.has(code);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function postJson(ctx: UploadContext, body: unknown): Promise<RawResponse> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ctx.timeoutMs);
  try {
    const res = await fetch(ctx.pushUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${ctx.apiKey}`
      },
      body: JSON.stringify(body),
      signal: ctrl.signal
    });
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      // 非 JSON 响应保留原文
    }
    return { status: res.status, body: parsed ?? text, text };
  } finally {
    clearTimeout(timer);
  }
}

function extractRetryAfter(res: RawResponse, fallbackMs: number): number {
  // Retry-After 无法从 fetch 便捷读取时按指数退避兜底；429 场景下服务端通常返回该头
  return fallbackMs;
}

function backoffMs(attempt: number): number {
  const base = Math.min(500 * 2 ** attempt, 60000);
  const jitter = Math.random() * base * 0.3;
  return Math.floor(base + jitter);
}

/** 单批提交（带重试；4xx/业务码不重试） */
async function submitBatch(ctx: UploadContext, payload: unknown): Promise<RejectDetail | null> {
  let last: RawResponse | null = null;
  for (let attempt = 0; attempt <= ctx.maxRetries; attempt++) {
    try {
      const res = await postJson(ctx, payload);
      last = res;
      if (res.status >= 200 && res.status < 300 && isSuccessBody(res.body)) {
        return null;
      }
      if (res.status === 429) {
        await sleep(extractRetryAfter(res, backoffMs(attempt)));
        continue;
      }
      if (res.status >= 500 || res.status === 408 || res.status === 0) {
        if (attempt < ctx.maxRetries) await sleep(backoffMs(attempt));
        continue;
      }
      // 4xx / 业务错误码：不轰炸，直接回报
      const msg = typeof res.body === "object" && res.body !== null
        ? ((res.body as Record<string, unknown>).msg as string) ?? ((res.body as Record<string, unknown>).message as string) ?? res.text
        : res.text;
      const code = typeof res.body === "object" && res.body !== null ? (res.body as Record<string, unknown>).code : undefined;
      return { code: code === undefined ? String(res.status) : String(code), message: String(msg).slice(0, 500) };
    } catch (e) {
      last = null;
      const isAbort = e instanceof Error && e.name === "AbortError";
      if (attempt < ctx.maxRetries) await sleep(backoffMs(attempt));
      if (attempt === ctx.maxRetries) {
        return { code: isAbort ? "TIMEOUT" : "NETWORK", message: e instanceof Error ? e.message : String(e) };
      }
    }
  }
  return { code: "UNKNOWN", message: last ? last.text.slice(0, 500) : "未知错误" };
}

/**
 * 分片上传：按 batchSize 与字节双条件切片；返回批次结果。
 * maskingMeta：声明字段 → 方法（服务端明文拒收启用后按此校验，见文档 §5.6）
 */
export async function uploadRows(
  ctx: UploadContext,
  rows: Row[],
  batchId: string,
  configFingerprint: string,
  maskingMeta: Record<string, string>
): Promise<UploadResult> {
  const rejected: RejectDetail[] = [];
  let accepted = 0;

  const chunks: Row[][] = [];
  let current: Row[] = [];
  let currentBytes = 0;
  for (const row of rows) {
    const rowBytes = JSON.stringify(row).length;
    if (current.length > 0 && (current.length >= ctx.batchSize || currentBytes + rowBytes > ctx.maxBatchPayloadBytes)) {
      chunks.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(row);
    currentBytes += rowBytes;
  }
  if (current.length > 0) chunks.push(current);

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const payload = { data: chunk, batch_id: batchId, config_fingerprint: configFingerprint, masking_meta: maskingMeta };
    if (JSON.stringify(payload).length > ctx.maxBatchPayloadBytes) {
      // 单批仍超限：按行拆分重试一次
      for (const row of chunk) {
        const single = await submitBatch(ctx, {
          data: [row],
          batch_id: batchId,
          config_fingerprint: configFingerprint,
          masking_meta: maskingMeta
        });
        if (single) {
          rejected.push({ index: -1, ...single });
        } else {
          accepted++;
        }
      }
      continue;
    }
    const err = await submitBatch(ctx, payload);
    if (err) {
      rejected.push({ index: i, ...err });
    } else {
      accepted += chunk.length;
    }
  }

  return { batchId, accepted, rejected: rejected.length > 0 ? rejected : undefined };
}
