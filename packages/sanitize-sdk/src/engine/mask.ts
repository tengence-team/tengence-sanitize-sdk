/**
 * mask：展示类掩码（不可逆，不用于 join/关联）
 * 规则：保留前 keepFirst、后 keepLast 字符，中间以 * 填充；默认 1/1。
 * keepFirst + keepLast >= 原长 → 不脱敏并告警（避免掩码失效）。
 */
export interface MaskContext {
  keepFirst: number;
  keepLast: number;
}

export type MaskResult = { value: string; alerted: boolean };
export type MaskFn = (plain: string) => MaskResult;

export function createMasker(ctx: MaskContext): MaskFn {
  return (plain: string): MaskResult => {
    if (ctx.keepFirst + ctx.keepLast >= plain.length) {
      return { value: plain, alerted: true };
    }
    const prefix = plain.slice(0, ctx.keepFirst);
    const suffix = plain.slice(-ctx.keepLast);
    const stars = "*".repeat(plain.length - ctx.keepFirst - ctx.keepLast);
    return { value: `${prefix}${stars}${suffix}`, alerted: false };
  };
}
