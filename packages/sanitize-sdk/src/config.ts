/**
 * 配置加载/校验/指纹
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import type { HashParams, MaskParams, EncryptParams, SanitizeConfig, SanitizeRule, SanitizeMethod } from "./types";

export class ConfigError extends Error {
  public readonly field?: string;
  constructor(message: string, field?: string) {
    super(message);
    this.name = "ConfigError";
    this.field = field;
  }
}

const HASH_ALGORITHMS = new Set(["SHA-256", "HMAC-SHA-256"]);
const METHODS = new Set<SanitizeMethod>(["hash", "mask", "encrypt", "preserve"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asNonEmptyString(v: unknown, field: string): string {
  if (typeof v !== "string" || v.trim() === "") {
    throw new ConfigError(`字段 ${field} 必须为非空字符串`, field);
  }
  return v;
}

/** 校验并归一化配置（填充默认值） */
export function validateConfig(input: unknown): SanitizeConfig {
  if (!isPlainObject(input)) throw new ConfigError("配置必须为对象");
  if (input.version !== 1) throw new ConfigError("配置 version 必须为 1（当前仅支持 version: 1）", "version");

  const rulesRaw = input.rules;
  if (!Array.isArray(rulesRaw) || rulesRaw.length === 0) {
    throw new ConfigError("rules 必须为非空数组（至少声明一条脱敏规则）", "rules");
  }

  const rules: SanitizeRule[] = rulesRaw.map((r, i) => {
    const path = `rules[${i}]`;
    if (!isPlainObject(r)) throw new ConfigError(`${path} 必须为对象`, path);

    const fieldsRaw = r.fields;
    if (!Array.isArray(fieldsRaw) || fieldsRaw.length === 0) {
      throw new ConfigError(`${path}.fields 必须为非空数组（显式字段路径，如 "phone"、"contact.phone"、"items[*].price"）`, `${path}.fields`);
    }
    for (const f of fieldsRaw) {
      if (typeof f !== "string" || f.trim() === "") {
        throw new ConfigError(`${path}.fields 中的字段路径必须为非空字符串`, `${path}.fields`);
      }
    }
    const fields = fieldsRaw.map((f) => f.trim());

    const method = r.method;
    if (typeof method !== "string" || !METHODS.has(method as SanitizeMethod)) {
      throw new ConfigError(`${path}.method 必须为 hash | mask | encrypt | preserve 之一`, `${path}.method`);
    }

    const paramsRaw = r.params === undefined ? {} : r.params;
    if (!isPlainObject(paramsRaw)) throw new ConfigError(`${path}.params 必须为对象`, `${path}.params`);

    let params: HashParams | MaskParams | EncryptParams = {};
    if (method === "hash") {
      const p = paramsRaw as HashParams;
      const algorithm = p.algorithm === undefined ? "SHA-256" : p.algorithm;
      if (!HASH_ALGORITHMS.has(algorithm)) {
        throw new ConfigError(`${path}.params.algorithm 必须为 "SHA-256" | "HMAC-SHA-256"`, `${path}.params.algorithm`);
      }
      const hashLength = p.hashLength === undefined ? 32 : p.hashLength;
      if (hashLength !== 32 && hashLength !== 64) {
        throw new ConfigError(`${path}.params.hashLength 必须为 32 | 64`, `${path}.params.hashLength`);
      }
      params = {
        algorithm,
        saltEnv: p.saltEnv === undefined ? "TENGENCE_SANITIZE_SALT" : asNonEmptyString(p.saltEnv, `${path}.params.saltEnv`),
        keyEnv: p.keyEnv === undefined ? "TENGENCE_SANITIZE_KEY" : asNonEmptyString(p.keyEnv, `${path}.params.keyEnv`),
        hashLength
      };
    } else if (method === "mask") {
      const p = paramsRaw as MaskParams;
      const keepFirst = p.keepFirst === undefined ? 1 : p.keepFirst;
      const keepLast = p.keepLast === undefined ? 1 : p.keepLast;
      if (!Number.isInteger(keepFirst) || keepFirst < 0) throw new ConfigError(`${path}.params.keepFirst 必须为非负整数`, `${path}.params.keepFirst`);
      if (!Number.isInteger(keepLast) || keepLast < 0) throw new ConfigError(`${path}.params.keepLast 必须为非负整数`, `${path}.params.keepLast`);
      params = { keepFirst, keepLast };
    } else if (method === "encrypt") {
      const p = paramsRaw as EncryptParams;
      params = { keyEnv: p.keyEnv === undefined ? "TENGENCE_SANITIZE_KEY" : asNonEmptyString(p.keyEnv, `${path}.params.keyEnv`) };
    }
    // preserve：无参数

    return { fields, method: method as SanitizeMethod, params };
  });

  return {
    version: 1,
    rules,
    dryRun: input.dryRun === true,
    upload: isPlainObject(input.upload)
      ? {
          pushUrl: typeof input.upload.pushUrl === "string" ? input.upload.pushUrl : undefined,
          apiKeyEnv: typeof input.upload.apiKeyEnv === "string" ? input.upload.apiKeyEnv : undefined,
          batchSize: typeof input.upload.batchSize === "number" && input.upload.batchSize > 0 ? Math.floor(input.upload.batchSize) : undefined,
          maxBatchPayloadBytes:
            typeof input.upload.maxBatchPayloadBytes === "number" && input.upload.maxBatchPayloadBytes > 0
              ? Math.floor(input.upload.maxBatchPayloadBytes)
              : undefined,
          maxRetries: typeof input.upload.maxRetries === "number" && input.upload.maxRetries >= 0 ? Math.floor(input.upload.maxRetries) : undefined,
          timeoutMs: typeof input.upload.timeoutMs === "number" && input.upload.timeoutMs > 0 ? Math.floor(input.upload.timeoutMs) : undefined
        }
      : undefined,
    audit: isPlainObject(input.audit)
      ? {
          enabled: typeof input.audit.enabled === "boolean" ? input.audit.enabled : undefined,
          dir: typeof input.audit.dir === "string" && input.audit.dir.trim() !== "" ? input.audit.dir.trim() : undefined
        }
      : undefined
  };
}

/** 从文件或对象加载配置 */
export function loadConfig(input: string | SanitizeConfig): SanitizeConfig {
  if (typeof input === "string") {
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(input, "utf8"));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new ConfigError(`读取配置文件失败（${input}）：${msg}`);
    }
    return validateConfig(raw);
  }
  return validateConfig(input);
}

function canonicalRules(rules: SanitizeRule[]): string {
  const sorted = [...rules]
    .map((r) => ({
      fields: [...r.fields].sort(),
      method: r.method,
      params: r.params ?? {}
    }))
    .sort((a, b) => a.fields.join("|") < b.fields.join("|") ? -1 : 1);
  return JSON.stringify({ version: 1, rules: sorted });
}

/** 配置指纹：sha256(规范化后的 rules + version)。v7：仅本地审计元信息，服务端不做备案校验。 */
export function computeConfigFingerprint(config: SanitizeConfig): string {
  return createHash("sha256").update(canonicalRules(config.rules), "utf8").digest("hex");
}

/** 从环境变量读取值；缺失即报错（拒绝运行，避免产生部分脱敏的脏数据） */
export function requireEnv(name: string, purpose: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") {
    throw new ConfigError(`环境变量 ${name} 未设置（${purpose}），拒绝运行`, name);
  }
  return v;
}
