/**
 * hash：不可逆确定性伪名化
 * - SHA-256 + 盐（默认）：hex(SHA256(salt + plaintext))，默认取前 16 字节输出 32 hex
 * - HMAC-SHA-256（可选，高敏感字段）：hex(HMAC-SHA256(key, plaintext))，同样默认 32 hex
 */
import { createHash, createHmac } from "node:crypto";

export interface HashContext {
  algorithm: "SHA-256" | "HMAC-SHA-256";
  salt?: string;
  key?: string;
  hashLength: 32 | 64;
}

export type HashFn = (plain: string) => string;

export function createHasher(ctx: HashContext): HashFn {
  const bytes = ctx.hashLength / 2;
  return (plain: string): string => {
    let digest: Buffer;
    if (ctx.algorithm === "HMAC-SHA-256") {
      if (!ctx.key) throw new Error("HMAC-SHA-256 需要密钥（keyEnv 指定的环境变量）");
      digest = createHmac("sha256", ctx.key).update(plain, "utf8").digest();
    } else {
      if (ctx.salt === undefined) throw new Error("SHA-256+盐需要盐（saltEnv 指定的环境变量）");
      digest = createHash("sha256").update(ctx.salt, "utf8").update(plain, "utf8").digest();
    }
    return digest.subarray(0, bytes).toString("hex");
  };
}
