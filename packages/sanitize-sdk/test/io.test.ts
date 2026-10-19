import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readCsvIter, probeCsvHeader, writeCsv, normalizeHeader } from "../src/io/csv";
import { readJsonlIter, writeJsonl, writeJson } from "../src/io/json";
import { detectInputFormat, detectOutputFormat, probeHeader, readRowsIter, writeRows } from "../src/io";
import { readXlsxIter, writeXlsx, probeXlsxHeader, cellToString, formatDate } from "../src/io/excel";

let tmp: string;

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sanitize-io-"));
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("CSV", () => {
  it("流式读写 roundtrip", async () => {
    const file = path.join(tmp, "t.csv");
    await writeCsv(
      file,
      ["id", "phone", "phone2"],
      [
        { id: "1", phone: "13800138000", phone2: "13900139000" },
        { id: "2", phone: "13700137000", phone2: "13600136000" }
      ]
    );
    const rows: Record<string, unknown>[] = [];
    for await (const r of readCsvIter(file)) rows.push(r);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toEqual({ id: "1", phone: "13800138000", phone2: "13900139000" });
  });

  it("读取时表头去重（重名列 → name_2）", async () => {
    const file = path.join(tmp, "dup.csv");
    fs.writeFileSync(file, "id,phone,phone\n1,13800138000,13900139000\n", "utf8");
    const rows: Record<string, unknown>[] = [];
    for await (const r of readCsvIter(file)) rows.push(r);
    expect(rows[0]).toEqual({ id: "1", phone: "13800138000", phone_2: "13900139000" });
  });

  it("probeCsvHeader 只读首行", async () => {
    const file = path.join(tmp, "h.csv");
    fs.writeFileSync(file, "a,b,c\n1,2,3\n4,5,6\n", "utf8");
    expect(await probeCsvHeader(file)).toEqual(["a", "b", "c"]);
    expect(await probeHeader(file, "csv")).toEqual(["a", "b", "c"]);
  });

  it("空列名生成 col_i", () => {
    expect(normalizeHeader(["a", "", "c"])).toEqual(["a", "col_2", "c"]);
  });
});

describe("JSON / JSONL", () => {
  it("JSONL 流式 roundtrip", async () => {
    const file = path.join(tmp, "t.jsonl");
    await writeJsonl(file, [{ id: 1, phone: "13800138000" }, { id: 2, phone: "13900139000" }]);
    const rows: Record<string, unknown>[] = [];
    for await (const r of readJsonlIter(file)) rows.push(r);
    expect(rows).toHaveLength(2);
    expect(rows[1].phone).toBe("13900139000");
  });

  it("JSON 数组 roundtrip", async () => {
    const file = path.join(tmp, "t.json");
    await writeJson(file, [{ id: 1 }, { id: 2 }]);
    const rows: Record<string, unknown>[] = [];
    for await (const r of readRowsIter(file, "json")) rows.push(r);
    expect(rows).toHaveLength(2);
  });

  it("JSONL 非法行报错含行号", async () => {
    const file = path.join(tmp, "bad.jsonl");
    fs.writeFileSync(file, '{"a":1}\nnot-json\n', "utf8");
    await expect(async () => {
      for await (const _ of readJsonlIter(file)) {
        /* drain */
      }
    }).rejects.toThrow(/第 2 行解析失败/);
  });
});

describe("格式识别", () => {
  it("按扩展名识别", () => {
    expect(detectInputFormat("a.csv")).toBe("csv");
    expect(detectInputFormat("a.json")).toBe("json");
    expect(detectInputFormat("a.jsonl")).toBe("jsonl");
    expect(detectInputFormat("a.xlsx")).toBe("excel");
    expect(() => detectInputFormat("a.xls")).toThrow(/\.xlsx/);
    expect(() => detectInputFormat("a.txt")).toThrow(/无法识别/);
    expect(detectOutputFormat("a.xlsx", "csv")).toBe("excel");
    expect(detectOutputFormat("a.unknown", "csv")).toBe("csv");
  });
});

describe("Excel 单元格归一化", () => {
  it("日期 yyyy-MM-dd HH:mm:ss", () => {
    const d = new Date(2026, 9, 18, 8, 5, 3); // 2026-10-18 08:05:03
    expect(formatDate(d)).toBe("2026-10-18 08:05:03");
    expect(cellToString(d)).toBe("2026-10-18 08:05:03");
  });

  it("数字去尾零 / 布尔 / null", () => {
    expect(cellToString(100.0)).toBe("100");
    expect(cellToString(1.5)).toBe("1.5");
    expect(cellToString(true)).toBe("true");
    expect(cellToString(null)).toBeNull();
    expect(cellToString(undefined)).toBeNull();
  });

  it("XLSX 读写 roundtrip（表头 + 数字归一化）", async () => {
    const file = path.join(tmp, "t.xlsx");
    await writeXlsx(
      file,
      ["id", "phone", "amount"],
      [
        { id: "1", phone: "13800138000", amount: "9.9" },
        { id: "2", phone: "13900139000", amount: "19.9" }
      ]
    );
    expect(await probeXlsxHeader(file)).toEqual(["id", "phone", "amount"]);
    const rows: Record<string, unknown>[] = [];
    for await (const r of readXlsxIter(file)) rows.push(r);
    expect(rows).toHaveLength(2);
    expect(rows[0].id).toBe("1");
    expect(rows[0].phone).toBe("13800138000");
    expect(String(rows[0].amount)).toBe("9.9");
  });

  it("XLSX 流式读：真实日期单元格还原为 Date 并格式化为 yyyy-MM-dd HH:mm:ss", async () => {
    const file = path.join(tmp, "date.xlsx");
    const d = new Date(2026, 9, 18, 8, 5, 3);
    // 用非流式 Workbook 显式构造「日期格式单元格」（Excel/WPS 真实文件的等效形态）
    const ExcelJS = await import("exceljs");
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet("S");
    ws.addRow(["created_at"]);
    const c = ws.getCell(2, 1);
    c.value = d;
    c.numFmt = "yyyy-mm-dd hh:mm:ss";
    await wb.xlsx.writeFile(file);
    const rows: Record<string, unknown>[] = [];
    for await (const r of readXlsxIter(file)) rows.push(r);
    expect(String(rows[0].created_at)).toBe("2026-10-18 08:05:03");
  });
});
