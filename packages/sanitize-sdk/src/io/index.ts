/**
 * IO 统一入口：按扩展名分发格式（迭代器 API，内存有界）
 */
import path from "node:path";
import type { Row } from "./csv";
import { readCsvIter, probeCsvHeader, writeCsv } from "./csv";
import { readJsonIter, readJsonlIter, writeJson, writeJsonl } from "./json";
import { readXlsxIter, probeXlsxHeader, writeXlsx } from "./excel";

export type InputFormat = "csv" | "json" | "jsonl" | "excel";
export type OutputFormat = "csv" | "json" | "jsonl" | "excel";

export function detectInputFormat(file: string): InputFormat {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".csv") return "csv";
  if (ext === ".json") return "json";
  if (ext === ".jsonl" || ext === ".ndjson") return "jsonl";
  if (ext === ".xlsx") return "excel";
  if (ext === ".xls") throw new Error("不支持 .xls 老格式：请先另存为 .xlsx（exceljs 仅支持 xlsx）");
  throw new Error(`无法识别输入格式：${ext}（支持 .csv / .json / .jsonl / .xlsx）`);
}

export function detectOutputFormat(file: string, fallback: OutputFormat): OutputFormat {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".csv") return "csv";
  if (ext === ".json") return "json";
  if (ext === ".jsonl" || ext === ".ndjson") return "jsonl";
  if (ext === ".xlsx") return "excel";
  if (ext === ".xls") throw new Error("不支持 .xls 老格式：请使用 .xlsx");
  return fallback;
}

/** 行流读取（按格式） */
export function readRowsIter(file: string, format: InputFormat): AsyncIterable<Row> {
  switch (format) {
    case "csv":
      return readCsvIter(file);
    case "json":
      return readJsonIter(file);
    case "jsonl":
      return readJsonlIter(file);
    case "excel":
      return readXlsxIter(file);
  }
}

/** 表头探测（csv/excel 需要；json/jsonl 按首个记录键） */
export async function probeHeader(file: string, format: InputFormat): Promise<string[]> {
  switch (format) {
    case "csv":
      return probeCsvHeader(file);
    case "excel":
      return probeXlsxHeader(file);
    case "json":
    case "jsonl": {
      for await (const row of readRowsIter(file, format)) {
        return Object.keys(row);
      }
      return [];
    }
  }
}

/** 行流写出（按格式；csv/excel 用 header 固定列） */
export async function writeRows(
  file: string,
  format: OutputFormat,
  header: string[],
  rows: AsyncIterable<Row> | Iterable<Row>
): Promise<{ rows: number }> {
  switch (format) {
    case "csv":
      return writeCsv(file, header, rows);
    case "json":
      return writeJson(file, rows);
    case "jsonl":
      return writeJsonl(file, rows);
    case "excel":
      return writeXlsx(file, header, rows);
  }
}

export { Row };
