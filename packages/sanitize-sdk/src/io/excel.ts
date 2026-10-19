/**
 * Excel 流式读写（exceljs，MIT）
 * 复刻数据集成仓库（EasyExcel）解析语义：
 *   - sheet 枚举，取首个有数据的 sheet
 *   - 首行为表头（headRowNumber=0 语义），空/重名列名生成
 *   - 单元格归一化：日期 → yyyy-MM-dd HH:mm:ss；数字去尾零；布尔原样；null → null
 * 注意：exceljs 仅支持 .xlsx（.xls 老格式不支持，报清晰错误）。
 */
import fs from "node:fs";
import { finished } from "node:stream/promises";
import ExcelJS from "exceljs";
import type { Row } from "./csv";
import { normalizeHeader } from "./csv";

export function formatDate(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 单元格归一化（对齐 EasyExcel cellToString） */
export function cellToString(v: unknown): unknown {
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return formatDate(v);
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return v;
  if (typeof v === "object" && "text" in (v as object)) return String((v as { text: unknown }).text);
  return String(v);
}

/** Excel 行流（跳过首行表头，仅首个非空 sheet） */
export function readXlsxIter(file: string): AsyncIterable<Row> {
  const reader = new ExcelJS.stream.xlsx.WorkbookReader(fs.createReadStream(file), {
    entries: "emit",
    styles: "cache",
    sharedStrings: "cache"
  });
  return (async function* () {
    let headerSet = false;
    let header: string[] = [];
    for await (const worksheet of reader) {
      for await (const row of worksheet) {
        const values = (row.values as unknown[]).slice(1);
        if (!headerSet) {
          header = normalizeHeader(values.map((v) => (v === null || v === undefined ? "" : String(cellToString(v)))));
          headerSet = true;
          continue;
        }
        const record: Row = {};
        for (let i = 0; i < header.length; i++) {
          const v = cellToString(values[i]);
          record[header[i]] = v === undefined ? null : v;
        }
        yield record;
      }
      if (headerSet) break;
    }
    if (!headerSet) throw new Error("Excel 文件为空或无可读 sheet");
  })();
}

/** 探测首个非空 sheet 的表头（首行） */
export async function probeXlsxHeader(file: string): Promise<string[]> {
  const reader = new ExcelJS.stream.xlsx.WorkbookReader(fs.createReadStream(file), {
    entries: "emit",
    styles: "cache",
    sharedStrings: "cache"
  });
  for await (const worksheet of reader) {
    for await (const row of worksheet) {
      const values = (row.values as unknown[]).slice(1);
      return normalizeHeader(values.map((v) => (v === null || v === undefined ? "" : String(cellToString(v)))));
    }
    break;
  }
  throw new Error("Excel 文件为空或无可读 sheet");
}

export async function writeXlsx(file: string, header: string[], rows: AsyncIterable<Row> | Iterable<Row>): Promise<{ rows: number }> {
  const out = fs.createWriteStream(file);
  const workbook = new ExcelJS.stream.xlsx.WorkbookWriter({ stream: out, useStyles: false, useSharedStrings: false });
  const sheet = workbook.addWorksheet("Sheet1");
  sheet.addRow(header.map((h) => h)).commit();
  let rowsWritten = 0;
  for await (const row of rows) {
    // 单元格归一化（对齐 EasyExcel cellToString）：Date → yyyy-MM-dd HH:mm:ss 文本
    sheet.addRow(header.map((h) => cellToString(row[h]) ?? null)).commit();
    rowsWritten++;
  }
  await workbook.commit();
  await finished(out);
  return { rows: rowsWritten };
}
