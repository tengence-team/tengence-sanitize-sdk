/**
 * 字段路径解析与变更
 * 支持：a.b、items[*].price、a[*].b[*].c；字段完全由用户自定义（不限于内置 PII 名单）。
 */
export function tokenizePath(p: string): string[] {
  const raw = p.split(".");
  const out: string[] = [];
  for (const seg of raw) {
    if (seg === "[*]") {
      out.push("*");
      continue;
    }
    const m = seg.match(/^([^\[]+)\[(\*)\]$/);
    if (m) {
      out.push(m[1], "*");
    } else {
      out.push(seg);
    }
  }
  return out;
}

/** 对目标路径的值应用变换（数组展开逐元素；对象原位修改） */
export function mapPath(root: unknown, tokens: string[], fn: (v: unknown) => unknown): void {
  apply(root, tokens, 0, fn);
}

function apply(node: unknown, tokens: string[], i: number, fn: (v: unknown) => unknown): void {
  if (i >= tokens.length) return;
  const t = tokens[i];
  if (t === "*") {
    if (Array.isArray(node)) {
      for (const item of node) apply(item, tokens, i + 1, fn);
    }
    return;
  }
  if (node === null || typeof node !== "object" || Array.isArray(node)) return;
  const rec = node as Record<string, unknown>;
  if (i === tokens.length - 1) {
    rec[t] = fn(rec[t]);
    return;
  }
  apply(rec[t], tokens, i + 1, fn);
}

/** 取路径下所有值（数组展开；不存在时为空列表） */
export function getPathValues(root: unknown, tokens: string[]): unknown[] {
  const out: unknown[] = [];
  collect(root, tokens, 0, out);
  return out;
}

function collect(node: unknown, tokens: string[], i: number, out: unknown[]): void {
  if (i >= tokens.length) {
    // 仅收集真实存在的值（缺失路径/值为 undefined 不算命中）
    if (node !== undefined) out.push(node);
    return;
  }
  const t = tokens[i];
  if (t === "*") {
    if (Array.isArray(node)) {
      for (const item of node) collect(item, tokens, i + 1, out);
    }
    return;
  }
  if (node === null || typeof node !== "object" || Array.isArray(node)) return;
  const rec = node as Record<string, unknown>;
  collect(rec[t], tokens, i + 1, out);
}

/** 收集输入行中出现、但任何规则都未声明的顶层字段名（防漏配兜底） */
export function collectUnmatchedFields(row: Record<string, unknown>, declaredTopLevel: Set<string>): string[] {
  const unmatched: string[] = [];
  for (const key of Object.keys(row)) {
    if (!declaredTopLevel.has(key)) unmatched.push(key);
  }
  return unmatched;
}
