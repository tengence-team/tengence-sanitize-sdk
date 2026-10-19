/**
 * encrypt：可逆确定性加密（RFC 5297 AES-SIV 构造）
 *
 * 为什么用 AES-SIV 而不是「iv=HMAC(key,plaintext) 前 12 字节 + GCM」：
 *   若 iv 由明文派生但未随密文输出，解密时无法重算 iv（依赖明文，循环依赖），
 *   仅凭 key 无法还原。RFC 5297 AES-SIV 将「由明文派生的合成 IV（V，16 字节）」
 *   直接随密文输出（V‖C），V 兼作 MAC tag，满足：
 *     - 确定性：同明文 → 同 V → 同密文 → 同 enc 值（平台可直接 join/去重/标识）
 *     - 可还原：凭 key + enc 值即可解密，解密后校验 V（防篡改/防错 key）
 *     - 长度：2×(16 + 明文字节数)；手机号(11B) → 54 hex（与方案 §5.4 公式一致）
 *
 * 密钥：32 字节（64 hex / 44 base64 / 32 字节 utf8），拆为 K1(CMAC) + K2(CTR)，
 * 即 AES-128-SIV（AES-128 安全等级；确定性加密本就暴露「值相等」关系，属预期语义）。
 */

const ZERO_BLOCK = Buffer.alloc(16);
const RB = 0x87;

/** GF(2^128) 倍乘（RFC 4493 / RFC 5297 dbl） */
function dbl(block: Buffer): Buffer {
  const out = Buffer.alloc(16);
  let carry = 0;
  for (let i = 0; i < 16; i++) {
    const b = block[i];
    out[i] = ((b << 1) & 0xff) | carry;
    carry = (b & 0x80) ? 1 : 0;
  }
  if (carry) out[15] ^= RB;
  return out;
}

function aesEncryptBlock(key: Buffer, block: Buffer): Buffer {
  const c = createCipheriv("aes-128-ecb", key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

/** RFC 4493 CMAC-AES-128 */
function cmac(key: Buffer, message: Buffer): Buffer {
  const k1 = dbl(aesEncryptBlock(key, ZERO_BLOCK));
  const k2 = dbl(k1);
  const n = Math.max(1, Math.ceil(message.length / 16));
  const blocks = Buffer.alloc(n * 16);
  message.copy(blocks, 0);
  for (let i = message.length; i < blocks.length; i++) {
    blocks[i] = i === message.length ? 0x80 : 0x00;
  }
  // 若原始消息长度是 16 的倍数且非空：最后一块 XOR k1（不填充）；否则 XOR k2（已填充）
  const last = blocks.subarray((n - 1) * 16, n * 16);
  const lastKey = message.length > 0 && message.length % 16 === 0 ? k1 : k2;
  for (let i = 0; i < 16; i++) last[i] ^= lastKey[i];

  let x: Buffer = Buffer.alloc(16);
  for (let i = 0; i < n; i++) {
    const block = blocks.subarray(i * 16, (i + 1) * 16);
    const inBlock = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) inBlock[j] = block[j] ^ x[j];
    x = aesEncryptBlock(key, inBlock);
  }
  return x;
}

/** RFC 5297 S2V：单输入 → V = CMAC(K1, message) */
function s2v(k1: Buffer, message: Buffer): Buffer {
  return cmac(k1, message);
}

import { createCipheriv } from "node:crypto";

/** 解析 32 字节密钥：64 hex / 44 base64 / 32 字节 utf8 */
export function parseKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, "hex");
  if (/^[A-Za-z0-9+/]{43}=$/.test(trimmed) || /^[A-Za-z0-9+/]{44}$/.test(trimmed)) {
    const b = Buffer.from(trimmed, "base64");
    if (b.length === 32) return b;
  }
  if (Buffer.byteLength(trimmed, "utf8") === 32) return Buffer.from(trimmed, "utf8");
  throw new Error("密钥格式不正确：须为 32 字节（64 位 hex 或 44 位 base64），可用 tengence-sanitize gen-key 生成");
}

function ctrCrypt(k2: Buffer, v: Buffer, data: Buffer): Buffer {
  const c = createCipheriv("aes-128-ctr", k2, v);
  return Buffer.concat([c.update(data), c.final()]);
}

/** 确定性加密：返回 hex(V 16B ‖ 密文)，纯十六进制无特殊字符 */
export function encryptValue(key: Buffer, plain: string): string {
  const msg = Buffer.from(plain, "utf8");
  const k1 = Buffer.from(key.subarray(0, 16));
  const k2 = Buffer.from(key.subarray(16, 32));
  const v = s2v(k1, msg);
  const ct = ctrCrypt(k2, v, msg);
  return Buffer.concat([v, ct]).toString("hex");
}

/** 解密并校验（V 校验失败 = 篡改或密钥不匹配，抛错） */
export function decryptValue(key: Buffer, hexValue: string): string {
  if (!/^[0-9a-fA-F]+$/.test(hexValue) || hexValue.length % 2 !== 0 || hexValue.length < 32) {
    throw new Error("enc 值须为偶数长度纯 hex 且至少 32 字符");
  }
  const buf = Buffer.from(hexValue, "hex");
  const v = Buffer.from(buf.subarray(0, 16));
  const ct = Buffer.from(buf.subarray(16));
  const k1 = Buffer.from(key.subarray(0, 16));
  const k2 = Buffer.from(key.subarray(16, 32));
  const plain = ctrCrypt(k2, v, ct);
  const expectV = s2v(k1, plain);
  if (!expectV.equals(v)) {
    throw new Error("解密校验失败：值被篡改或密钥不匹配");
  }
  return plain.toString("utf8");
}
