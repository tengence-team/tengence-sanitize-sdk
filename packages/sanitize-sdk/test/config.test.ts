import { describe, it, expect } from "vitest";
import { validateConfig, loadConfig, computeConfigFingerprint, ConfigError } from "../src/config";
import type { SanitizeConfig } from "../src/types";

const good: SanitizeConfig = {
  version: 1,
  rules: [
    { fields: ["phone"], method: "hash", params: { saltEnv: "TENGENCE_SANITIZE_SALT" } },
    { fields: ["name"], method: "mask" }
  ]
};

describe("config 校验", () => {
  it("合法配置通过并填充默认值", () => {
    const c = validateConfig(good);
    expect(c.version).toBe(1);
    expect(c.rules[0].params).toMatchObject({ algorithm: "SHA-256", saltEnv: "TENGENCE_SANITIZE_SALT", hashLength: 32 });
    expect(c.rules[1].params).toMatchObject({ keepFirst: 1, keepLast: 1 });
    expect(c.dryRun).toBe(false);
  });

  it("version 非法报错", () => {
    expect(() => validateConfig({ version: 2, rules: [] })).toThrow(ConfigError);
  });

  it("rules 为空报错", () => {
    expect(() => validateConfig({ version: 1, rules: [] })).toThrow(/rules 必须为非空数组/);
  });

  it("字段路径必须为非空字符串", () => {
    expect(() => validateConfig({ version: 1, rules: [{ fields: [""], method: "hash" }] })).toThrow(ConfigError);
  });

  it("method 非法报错", () => {
    expect(() => validateConfig({ version: 1, rules: [{ fields: ["phone"], method: "encrypt2" }] })).toThrow(/method 必须为/);
  });

  it("hashLength 非法报错", () => {
    expect(() => validateConfig({ version: 1, rules: [{ fields: ["phone"], method: "hash", params: { hashLength: 16 } }] })).toThrow(/hashLength/);
  });

  it("keepFirst/keepLast 非负整数", () => {
    expect(() => validateConfig({ version: 1, rules: [{ fields: ["name"], method: "mask", params: { keepFirst: -1 } }] })).toThrow(/keepFirst/);
  });

  it("配置文件不存在报错", () => {
    expect(() => loadConfig("/nonexistent/path.json")).toThrow(ConfigError);
  });
});

describe("config 指纹", () => {
  it("字段顺序不同但指纹稳定", () => {
    const a = computeConfigFingerprint(good);
    const b = computeConfigFingerprint({
      version: 1,
      rules: [
        { fields: ["name"], method: "mask" },
        { fields: ["phone"], method: "hash", params: { saltEnv: "TENGENCE_SANITIZE_SALT" } }
      ]
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("规则变化指纹变化", () => {
    const a = computeConfigFingerprint(good);
    const b = computeConfigFingerprint({ version: 1, rules: [{ fields: ["phone"], method: "hash" }] });
    expect(a).not.toBe(b);
  });
});
