/**
 * 本地审计日志（JSON，为主）
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import type { AuditRecord, UploadResult } from "./types";

export const DEFAULT_AUDIT_DIR = path.join(os.homedir(), ".tengence-sanitize", "audit");

export function newBatchId(): string {
  return randomUUID();
}

export function resolveAuditDir(dir?: string): string {
  return dir ?? DEFAULT_AUDIT_DIR;
}

export function writeAudit(dir: string, record: AuditRecord): string {
  const auditDir = resolveAuditDir(dir);
  fs.mkdirSync(auditDir, { recursive: true });
  const file = path.join(auditDir, `${record.batchId}.json`);
  fs.writeFileSync(file, JSON.stringify(record, null, 2), "utf8");
  return file;
}

export function appendErrorRow(outputPath: string, rowIndex: number, error: string): void {
  const errFile = `${outputPath}.errors.jsonl`;
  fs.appendFileSync(errFile, JSON.stringify({ rowIndex, error, ts: new Date().toISOString() }) + "\n", "utf8");
}

export function readAudit(dir?: string): AuditRecord[] {
  const auditDir = resolveAuditDir(dir);
  if (!fs.existsSync(auditDir)) return [];
  return fs
    .readdirSync(auditDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      try {
        return JSON.parse(fs.readFileSync(path.join(auditDir, f), "utf8")) as AuditRecord;
      } catch {
        return null;
      }
    })
    .filter((r): r is AuditRecord => r !== null)
    .sort((a, b) => (a.ts < b.ts ? 1 : -1));
}

export function exportAudit(dir: string | undefined, format: "json" | "csv"): string {
  const records = readAudit(dir);
  if (format === "csv") {
    const header = ["batchId", "configFingerprint", "ruleVersion", "inputRows", "outputRows", "dryRun", "uploadResult", "ts", "exitCode"];
    const lines = [header.join(",")];
    for (const r of records) {
      lines.push(
        header
          .map((h) => {
            let v: unknown = r[h as keyof AuditRecord];
            if (h === "uploadResult") v = JSON.stringify(v ?? "");
            if (h === "unmatchedFields") v = JSON.stringify(v);
            return `"${String(v ?? "").replace(/"/g, '""')}"`;
          })
          .join(",")
      );
    }
    return lines.join("\n");
  }
  return JSON.stringify(records, null, 2);
}
