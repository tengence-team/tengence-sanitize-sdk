/**
 * CSV 流式读写（RFC 4180，csv-parse / csv-stringify）
 * 首行为表头；表头去重/空列名生成，与 Excel 语义一致。
 */
import fs from "node:fs";
import { finished } from "node:stream/promises";
import readline from "node:readline";
import { parse } from "csv-parse";
import { stringify } from "csv-stringify";

export type Row = Record<string, unknown>;

/** 表头去重：空名 → col_{i}；重名 → {name}_{n}（与 Excel 表头生成规则一致） */
export function normalizeHeader(header: string[]): string[] {
  const seen = new Map<string, number>();
  return header.map((h, i) => {
    const base = h === undefined || h === null || String(h).trim() === "" ? `col_${i + 1}` : String(h).trim();
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return n === 0 ? base : `${base}_${n + 1}`;
  });
}

function headerColumns(rawHeader: string[]): string[] {
  return normalizeHeader(rawHeader);
}

/** CSV 行流（对象键 = 表头列名） */
export function readCsvIter(file: string): AsyncIterable<Row> {
  const parser = fs
    .createReadStream(file, { encoding: "utf8" })
    .pipe(parse({ bom: true, skip_empty_lines: true, relax_column_count: true, columns: headerColumns }));
  return parser as AsyncIterable<Row>;
}

/** 仅读首行表头（不消费整份文件） */
export function probeCsvHeader(file: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
    rl.on("line", (line) => {
      const cells: string[] = [];
      // 简易 RFC 4180 首行切分（表头一般无引号逗号；存在时回退 parse）
      let cur = "";
      let inQ = false;
      for (const ch of line) {
        if (ch === '"') inQ = !inQ;
        else if (ch === "," && !inQ) {
          cells.push(cur);
          cur = "";
        } else cur += ch;
      }
      cells.push(cur);
      resolve(normalizeHeader(cells));
      rl.close();
    });
    rl.on("error", reject);
  });
}

/** 按表头流式写出 CSV（header 固定，缺列补空） */
export async function writeCsv(file: string, header: string[], rows: AsyncIterable<Row> | Iterable<Row>): Promise<{ rows: number }> {
  const out = fs.createWriteStream(file, { encoding: "utf8" });
  const stringifier = stringify({ header: true, columns: header, bom: true });
  stringifier.pipe(out);
  let rowsWritten = 0;
  for await (const row of rows) {
    stringifier.write(row);
    rowsWritten++;
  }
  stringifier.end();
  await finished(out);
  return { rows: rowsWritten };
}
