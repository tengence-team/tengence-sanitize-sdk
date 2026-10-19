/**
 * JSON / JSONL 读写
 * - .json：整个文件为一个对象数组（用 JSON.parse 全量加载；大文件建议用 .jsonl）
 * - .jsonl：逐行 JSON 对象，流式（内存有界）
 */
import fs from "node:fs";
import { finished } from "node:stream/promises";
import readline from "node:readline";
import type { Row } from "./csv";

export async function* readJsonIter(file: string): AsyncIterable<Row> {
  const text = await fs.promises.readFile(file, "utf8");
  const data = JSON.parse(text);
  if (!Array.isArray(data)) throw new Error(`JSON 文件须为对象数组（或使用 .jsonl 逐行格式）：${file}`);
  for (const item of data) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("JSON 数组元素必须为对象");
    }
    yield item as Row;
  }
}

export function readJsonlIter(file: string): AsyncIterable<Row> {
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  return (async function* () {
    let lineNo = 0;
    for await (const line of rl) {
      const trimmed = line.trim();
      if (trimmed === "") continue;
      lineNo++;
      let item: unknown;
      try {
        item = JSON.parse(trimmed);
      } catch (e) {
        throw new Error(`JSONL 第 ${lineNo} 行解析失败：${(e as Error).message}`);
      }
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new Error(`JSONL 第 ${lineNo} 行必须为对象`);
      }
      yield item as Row;
    }
  })();
}

export async function writeJson(file: string, rows: AsyncIterable<Row> | Iterable<Row>): Promise<{ rows: number }> {
  const all: Row[] = [];
  for await (const row of rows) all.push(row);
  await fs.promises.writeFile(file, JSON.stringify(all, null, 2), "utf8");
  return { rows: all.length };
}

export async function writeJsonl(file: string, rows: AsyncIterable<Row> | Iterable<Row>): Promise<{ rows: number }> {
  const out = fs.createWriteStream(file, { encoding: "utf8" });
  let rowsWritten = 0;
  for await (const row of rows) {
    out.write(JSON.stringify(row) + "\n");
    rowsWritten++;
  }
  out.end();
  await finished(out);
  return { rows: rowsWritten };
}
