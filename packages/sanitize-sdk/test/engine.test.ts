import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHasher } from "../src/engine/hash";
import { createMasker } from "../src/engine/mask";
import { encryptValue, decryptValue, parseKey } from "../src/engine/encrypt";
import { createEngine } from "../src/engine";
import type { SanitizeConfig } from "../src/types";

const SALT = "unit-test-salt-2026";
const KEY = "a".repeat(64); // 32 字节 hex

describe("hash", () => {
  it("同明文同输出（确定性）", () => {
    const h = createHasher({ algorithm: "SHA-256", salt: SALT, hashLength: 32 });
    expect(h("13800138000")).toBe(h("13800138000"));
  });

  it("默认输出 32 位纯 hex；hashLength=64 输出 64 位", () => {
    const h32 = createHasher({ algorithm: "SHA-256", salt: SALT, hashLength: 32 });
    const h64 = createHasher({ algorithm: "SHA-256", salt: SALT, hashLength: 64 });
    const v32 = h32("13800138000");
    const v64 = h64("13800138000");
    expect(v32).toMatch(/^[0-9a-f]{32}$/);
    expect(v64).toMatch(/^[0-9a-f]{64}$/);
  });

  it("不同明文不同输出；HMAC 需要 key", () => {
    const h = createHasher({ algorithm: "SHA-256", salt: SALT, hashLength: 32 });
    expect(h("13800138000")).not.toBe(h("13900139000"));
    const hmac = createHasher({ algorithm: "HMAC-SHA-256", key: KEY, hashLength: 32 });
    expect(hmac("13800138000")).toMatch(/^[0-9a-f]{32}$/);
    expect(() => createHasher({ algorithm: "SHA-256", salt: undefined, hashLength: 32 })("x")).toThrow();
  });
});

describe("mask", () => {
  it("默认 1/1 掩码", () => {
    const m = createMasker({ keepFirst: 1, keepLast: 1 });
    expect(m("张小明").value).toBe("张*明");
    expect(m("13800138000").value).toBe("1*********0"); // 11 位 → 9 个 *
  });

  it("keepFirst+keepLast >= 原长时不脱敏并告警", () => {
    const m = createMasker({ keepFirst: 2, keepLast: 0 });
    const r = m("ab");
    expect(r.value).toBe("ab");
    expect(r.alerted).toBe(true);
  });

  it("输出含掩码字符、无特殊符号", () => {
    const m = createMasker({ keepFirst: 4, keepLast: 4 });
    expect(m("110101199001011234").value).toBe("1101**********1234");
  });
});

describe("encrypt（确定性 AES-SIV）", () => {
  it("同明文同输出（确定性，纯 hex，长度 2×(16+len)）", () => {
    const key = parseKey(KEY);
    const v1 = encryptValue(key, "13800138000");
    const v2 = encryptValue(key, "13800138000");
    expect(v1).toBe(v2);
    expect(v1).toMatch(/^[0-9a-f]+$/);
    expect(v1.length).toBe(2 * (16 + Buffer.byteLength("13800138000"))); // 手机号 54 hex
  });

  it("不同明文不同输出", () => {
    const key = parseKey(KEY);
    expect(encryptValue(key, "13800138000")).not.toBe(encryptValue(key, "13900139000"));
  });

  it("可还原（roundtrip）", () => {
    const key = parseKey(KEY);
    const enc = encryptValue(key, "ORD202610180001");
    expect(decryptValue(key, enc)).toBe("ORD202610180001");
  });

  it("篡改/错 key 校验失败抛错", () => {
    const key = parseKey(KEY);
    const other = parseKey("b".repeat(64));
    const enc = encryptValue(key, "13800138000");
    expect(() => decryptValue(other, enc)).toThrow();
    expect(() => decryptValue(key, enc.slice(0, -2) + (enc.endsWith("0") ? "1" : "0"))).toThrow();
  });

  it("key 支持 hex/base64/utf8 三种格式", () => {
    const hex = parseKey("a".repeat(64));
    const b64 = parseKey(Buffer.alloc(32, 1).toString("base64"));
    const utf8 = parseKey("x".repeat(32));
    expect(hex.length).toBe(32);
    expect(b64.length).toBe(32);
    expect(utf8.length).toBe(32);
    expect(() => parseKey("short")).toThrow();
  });
});

describe("engine.sanitizeRow", () => {
  beforeEach(() => {
    process.env.TENGENCE_SANITIZE_SALT = SALT;
    process.env.TENGENCE_SANITIZE_KEY = KEY;
  });
  afterEach(() => {
    delete process.env.TENGENCE_SANITIZE_SALT;
    delete process.env.TENGENCE_SANITIZE_KEY;
  });

  const config: SanitizeConfig = {
    version: 1,
    rules: [
      { fields: ["phone"], method: "hash", params: { algorithm: "SHA-256", saltEnv: "TENGENCE_SANITIZE_SALT", hashLength: 32 } },
      { fields: ["name"], method: "mask", params: { keepFirst: 1, keepLast: 1 } },
      { fields: ["order_no"], method: "encrypt", params: { keyEnv: "TENGENCE_SANITIZE_KEY" } },
      { fields: ["remark"], method: "preserve" }
    ]
  };

  it("按字段脱敏：hash 纯 hex / mask 含 * / encrypt 可还原 / preserve 原样", () => {
    const engine = createEngine(config);
    const { row, fieldHits } = engine.sanitizeRow({ phone: "13800138000", name: "张小明", order_no: "ORD1", remark: "普通", extra: "未声明" });
    expect(String(row.phone)).toMatch(/^[0-9a-f]{32}$/);
    expect(row.name).toBe("张*明");
    expect(String(row.order_no)).toMatch(/^[0-9a-f]{40}$/); // ORD1 = 4B → 2×(16+4)=40
    expect(row.remark).toBe("普通");
    expect(row.extra).toBe("未声明"); // 未声明字段透传
    expect(fieldHits.phone).toBe(1);
  });

  it("空值/非字符串原样保留", () => {
    const engine = createEngine(config);
    const { row } = engine.sanitizeRow({ phone: null, name: 123, order_no: "", remark: undefined });
    expect(row.phone).toBeNull();
    expect(row.name).toBe(123);
    expect(row.order_no).toBe("");
    expect(row.remark).toBeUndefined();
  });

  it("嵌套与数组字段", () => {
    const cfg: SanitizeConfig = {
      version: 1,
      rules: [{ fields: ["contact.phone", "items[*].price"], method: "hash", params: { saltEnv: "TENGENCE_SANITIZE_SALT" } }]
    };
    const engine = createEngine(cfg);
    const row = { contact: { phone: "13800138000" }, items: [{ price: "9.9" }, { price: "19.9" }] };
    const { row: out, fieldHits } = engine.sanitizeRow(row);
    expect(String((out.contact as Record<string, unknown>).phone)).toMatch(/^[0-9a-f]{32}$/);
    expect(String((out.items as { price: string }[])[0].price)).toMatch(/^[0-9a-f]{32}$/);
    expect(String((out.items as { price: string }[])[1].price)).toMatch(/^[0-9a-f]{32}$/);
    expect(fieldHits["contact.phone"]).toBe(1);
    expect(fieldHits["items[*].price"]).toBe(2);
  });

  it("restore 还原可逆字段", () => {
    const engine = createEngine(config);
    const { row } = engine.sanitizeRow({ order_no: "ORD1" });
    expect(engine.restoreValue("order_no", String(row.order_no))).toBe("ORD1");
  });

  it("缺盐时启动即报错（拒绝产生部分脱敏脏数据）", () => {
    delete process.env.TENGENCE_SANITIZE_SALT;
    expect(() => createEngine(config)).toThrow(/TENGENCE_SANITIZE_SALT/);
  });
});
