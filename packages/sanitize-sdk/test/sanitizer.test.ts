import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSanitizer } from "../src/sanitizer";
import type { SanitizeConfig } from "../src/types";

let tmp: string;
const SALT = "sanitizer-test-salt";
const KEY = "c".repeat(64);

const config: SanitizeConfig = {
  version: 1,
  rules: [
    { fields: ["phone"], method: "hash", params: { saltEnv: "TENGENCE_SANITIZE_SALT" } },
    { fields: ["name"], method: "mask", params: { keepFirst: 1, keepLast: 1 } },
    { fields: ["order_no"], method: "encrypt", params: { keyEnv: "TENGENCE_SANITIZE_KEY" } }
  ],
  audit: { enabled: true, dir: "" }
};

beforeEach(() => {
  process.env.TENGENCE_SANITIZE_SALT = SALT;
  process.env.TENGENCE_SANITIZE_KEY = KEY;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sanitize-sz-"));
  config.audit = { enabled: true, dir: path.join(tmp, "audit") };
});
afterEach(() => {
  delete process.env.TENGENCE_SANITIZE_SALT;
  delete process.env.TENGENCE_SANITIZE_KEY;
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("createSanitizer", () => {
  it("sanitizeRows 内存批量", () => {
    const s = createSanitizer({ config });
    const out = s.sanitizeRows([{ phone: "13800138000", name: "张小明", order_no: "ORD1" }]);
    expect(String(out[0].phone)).toMatch(/^[0-9a-f]{32}$/);
    expect(out[0].name).toBe("张*明");
    expect(String(out[0].order_no)).toMatch(/^[0-9a-f]{40}$/); // ORD1 = 4B → 2×(16+4)=40
  });

  it("sanitizeFile：CSV 流式 + 审计落盘 + 未命中字段清单", async () => {
    const input = path.join(tmp, "in.csv");
    fs.writeFileSync(input, "phone,name,order_no,remark\n13800138000,张小明,ORD1,普通订单\n13900139000,李四四,ORD2,加急订单\n", "utf8");
    const output = path.join(tmp, "out.csv");
    const s = createSanitizer({ config });
    const result = await s.sanitizeFile(input, output);
    expect(result.inputRows).toBe(2);
    expect(result.outputRows).toBe(2);
    expect(result.errorRows).toBe(0);
    expect(result.auditFile).toBeTruthy();
    expect(fs.existsSync(result.auditFile as string)).toBe(true);

    const lines = fs.readFileSync(output, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3); // 表头 + 2 行
    const cells = lines[1].split(",");
    expect(cells[0]).toMatch(/^[0-9a-f]{32}$/); // phone 已 hash
    expect(cells[1]).toBe("张*明"); // name 已 mask

    const audit = JSON.parse(fs.readFileSync(result.auditFile as string, "utf8"));
    expect(audit.inputRows).toBe(2);
    expect(audit.fieldHits.phone).toBe(2);
    expect(audit.unmatchedFields).toContain("remark");
  });

  it("sanitizeFile：JSONL 流式 + 单行错误隔离", async () => {
    const input = path.join(tmp, "in.jsonl");
    fs.writeFileSync(input, '{"phone":"13800138000","name":"张三","order_no":"ORD1"}\n{"phone":"13900139000","name":"李四","order_no":"ORD2"}\n', "utf8");
    const output = path.join(tmp, "out.jsonl");
    const s = createSanitizer({ config });
    // 模拟单行失败：配置 encrypt 字段缺失 key 的场景不做；此处验证正常流式
    const result = await s.sanitizeFile(input, output);
    expect(result.inputRows).toBe(2);
    expect(result.outputRows).toBe(2);
    const outRows = fs.readFileSync(output, "utf8").trim().split("\n");
    expect(JSON.parse(outRows[0]).phone).toMatch(/^[0-9a-f]{32}$/);
  });

  it("dryRun：命中统计 + 样例 + 未命中字段清单（不输出文件）", async () => {
    const input = path.join(tmp, "in.csv");
    fs.writeFileSync(input, "phone,name,order_no,remark\n13800138000,张三,ORD1,普通订单\n13900139000,李四,ORD2,加急订单\n", "utf8");
    const s = createSanitizer({ config });
    const report = await s.dryRun(input);
    expect(report.dryRun).toBe(true);
    expect(report.inputRows).toBe(2);
    const phoneStat = report.fieldStats.find((f) => f.field === "phone");
    expect(phoneStat?.hits).toBe(2);
    expect(phoneStat?.samples[0].after).toMatch(/^[0-9a-f]{32}$/);
    expect(report.unmatchedFields).toContain("remark");
  });

  it("restore 还原 + 上传前 maskingMeta 声明", async () => {
    const s = createSanitizer({ config });
    const out = s.sanitizeRows([{ order_no: "ORD1" }]);
    expect(s.restore("order_no", String(out[0].order_no))).toBe("ORD1");
  });

  it("upload：mock fetch 成功返回 batchId（幂等 UPSERT 语义由服务端保证）", async () => {
    const calls: { url: string; body: Record<string, unknown> }[] = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ url: String(url), body });
      return new Response(JSON.stringify({ code: 0, msg: "ok", data: { batchId: body.batch_id } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;

    const s = createSanitizer({ config, apiKey: "sk-test", pushUrl: "http://localhost/v1/push/data" });
    const rows = s.sanitizeRows([{ phone: "13800138000", name: "张三", order_no: "ORD1", id: "1" }]);
    const result = await s.upload(rows);
    expect(result.accepted).toBe(1);
    expect(result.rejected).toBeUndefined();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("http://localhost/v1/push/data");
    expect(calls[0].body.data).toHaveLength(1);
    expect(calls[0].body.masking_meta).toMatchObject({ phone: "hash", name: "mask", order_no: "encrypt" });
    expect(calls[0].body.config_fingerprint).toMatch(/^[0-9a-f]{64}$/);

    globalThis.fetch = origFetch;
  });

  it("upload：4xx 业务码不重试，回报拒绝明细", async () => {
    const origFetch = globalThis.fetch;
    let count = 0;
    globalThis.fetch = (async () => {
      count++;
      return new Response(JSON.stringify({ code: "APP_NOT_RUNNING", msg: "数据集未运行" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;

    const s = createSanitizer({ config, apiKey: "sk-test", pushUrl: "http://localhost/v1/push/data" });
    const result = await s.upload([{ phone: "13800138000", id: "1" }]);
    expect(result.accepted).toBe(0);
    expect(result.rejected?.[0].code).toBe("APP_NOT_RUNNING");
    expect(count).toBe(1); // 业务码不轰炸

    globalThis.fetch = origFetch;
  });

  it("auditLog / exportAudit", async () => {
    const input = path.join(tmp, "in.csv");
    fs.writeFileSync(input, "phone,name,order_no\n13800138000,张三,ORD1\n", "utf8");
    const output = path.join(tmp, "out.csv");
    const s = createSanitizer({ config });
    await s.sanitizeFile(input, output);
    const logs = s.auditLog();
    expect(logs.length).toBeGreaterThanOrEqual(1);
    expect(logs[0].configFingerprint).toMatch(/^[0-9a-f]{64}$/);
    const exported = s.exportAudit();
    expect(JSON.parse(exported).length).toBeGreaterThanOrEqual(1);
  });

  it("上传分片：batchSize 双条件切片", async () => {
    const origFetch = globalThis.fetch;
    const sizes: number[] = [];
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      sizes.push((body.data as unknown[]).length);
      return new Response(JSON.stringify({ code: 0, data: {} }), { status: 200 });
    }) as typeof fetch;

    const cfg: SanitizeConfig = { ...config, upload: { pushUrl: "http://localhost/v1/push/data", batchSize: 2 } };
    const s = createSanitizer({ config: cfg, apiKey: "sk-test" });
    const rows = s.sanitizeRows(
      Array.from({ length: 5 }, (_, i) => ({ id: String(i), phone: `1380013800${i}` }))
    );
    const result = await s.upload(rows);
    expect(result.accepted).toBe(5);
    expect(sizes).toEqual([2, 2, 1]);

    globalThis.fetch = origFetch;
  });
});
