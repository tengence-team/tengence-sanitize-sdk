/**
 * 脱敏引擎：按规则逐行处理
 */
import { ConfigError, requireEnv } from "../config";
import { tokenizePath, mapPath, getPathValues } from "../field";
import type { SanitizeConfig, SanitizeRule } from "../types";
import { createHasher, type HashFn } from "./hash";
import { createMasker, type MaskFn } from "./mask";
import { parseKey, encryptValue, decryptValue } from "./encrypt";

export interface CompiledRule {
  rule: SanitizeRule;
  tokens: string[][];
  apply: (plain: string) => { value: string; alerted: boolean };
  /** 方法是否可逆（用于 masking_meta 声明与 restore） */
  reversible: boolean;
}

export interface Engine {
  compile: () => CompiledRule[];
  sanitizeRow: (row: Record<string, unknown>) => { row: Record<string, unknown>; fieldHits: Record<string, number>; warnings: Record<string, number> };
  restoreValue: (field: string, value: string) => string;
  maskingMeta: () => Record<string, string>;
  declaredTopLevel: () => Set<string>;
}

export function createEngine(config: SanitizeConfig): Engine {
  const compiled: CompiledRule[] = config.rules.map((rule) => {
    const tokens = rule.fields.map((f) => tokenizePath(f));
    let apply: (plain: string) => { value: string; alerted: boolean };
    let reversible = false;

    if (rule.method === "hash") {
      const p = rule.params as { algorithm?: "SHA-256" | "HMAC-SHA-256"; saltEnv?: string; keyEnv?: string; hashLength?: 32 | 64 };
      const hasher: HashFn = createHasher({
        algorithm: p.algorithm ?? "SHA-256",
        salt: p.algorithm !== "HMAC-SHA-256" ? requireEnv(p.saltEnv ?? "TENGENCE_SANITIZE_SALT", `规则 ${rule.fields.join(",")} 的哈希盐`) : undefined,
        key: p.algorithm === "HMAC-SHA-256" ? requireEnv(p.keyEnv ?? "TENGENCE_SANITIZE_KEY", `规则 ${rule.fields.join(",")} 的 HMAC 密钥`) : undefined,
        hashLength: p.hashLength ?? 32
      });
      apply = (plain) => ({ value: hasher(plain), alerted: false });
    } else if (rule.method === "mask") {
      const p = rule.params as { keepFirst?: number; keepLast?: number };
      const masker: MaskFn = createMasker({ keepFirst: p.keepFirst ?? 1, keepLast: p.keepLast ?? 1 });
      apply = (plain) => masker(plain);
    } else if (rule.method === "encrypt") {
      const p = rule.params as { keyEnv?: string };
      const key = parseKey(requireEnv(p.keyEnv ?? "TENGENCE_SANITIZE_KEY", `规则 ${rule.fields.join(",")} 的加密密钥`));
      apply = (plain) => ({ value: encryptValue(key, plain), alerted: false });
      reversible = true;
    } else {
      apply = (plain) => ({ value: plain, alerted: false });
    }

    return { rule, tokens, apply, reversible };
  });

  const declaredTop: Set<string> = new Set();
  for (const c of compiled) {
    for (const t of c.tokens) {
      if (t.length > 0 && t[0] !== "*") declaredTop.add(t[0]);
    }
  }

  const transformValue = (fn: (plain: string) => { value: string; alerted: boolean }, v: unknown): { value: unknown; alerted: boolean } => {
    // null/undefined/空串/非字符串原样保留（不破坏数据完整性）
    if (v === null || v === undefined) return { value: v, alerted: false };
    if (typeof v !== "string" || v === "") return { value: v, alerted: false };
    return fn(v);
  };

  return {
    compile: () => compiled,

    sanitizeRow(row: Record<string, unknown>): { row: Record<string, unknown>; fieldHits: Record<string, number>; warnings: Record<string, number> } {
      const fieldHits: Record<string, number> = {};
      const warnings: Record<string, number> = {};
      for (const c of compiled) {
        for (const field of c.rule.fields) {
          let hits = 0;
          let warned = 0;
          mapPath(row, tokenizePath(field), (v) => {
            const r = transformValue(c.apply, v);
            if (typeof v === "string" && v !== "" && r.value !== v) hits++;
            if (r.alerted) warned++;
            return r.value;
          });
          if (hits > 0) fieldHits[field] = hits;
          if (warned > 0) warnings[field] = warned;
        }
      }
      return { row, fieldHits, warnings };
    },

    restoreValue(field: string, value: string): string {
      const rule = compiled.find((c) => c.reversible && c.rule.fields.includes(field));
      if (!rule) throw new ConfigError(`字段 ${field} 未配置可逆脱敏（encrypt），无法还原`, field);
      const p = rule.rule.params as { keyEnv?: string };
      const key = parseKey(requireEnv(p.keyEnv ?? "TENGENCE_SANITIZE_KEY", `字段 ${field} 的加密密钥`));
      return decryptValue(key, value);
    },

    maskingMeta(): Record<string, string> {
      const meta: Record<string, string> = {};
      for (const c of compiled) {
        for (const field of c.rule.fields) {
          meta[field] = c.rule.method;
        }
      }
      return meta;
    },

    declaredTopLevel: () => declaredTop
  };
}

export { getPathValues };
