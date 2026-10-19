/**
 * Tool behavior tests: every tool output must never contain plaintext, config
 * validation errors must be actionable, gated restore must honor the env switch,
 * and upload must reuse the SDK's fetch contract.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { tools, TOOL_GROUPS } from '../tools/registry.js';
import { activeTools } from '../server.js';
import * as sdk from '@tengence/sanitize-sdk';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sanitize-mcp-test-'));
const AUDIT_DIR = path.join(tmp, 'audits');
const CONFIG = path.join(tmp, 'sanitize.config.json');
const INPUT = path.join(tmp, 'orders.csv');
const OUTPUT = path.join(tmp, 'orders-out.csv');
const PHONE = '13800138000';
const PLAINTEXT_MARKERS = [PHONE, '张三', '110101199001011234'];

beforeAll(() => {
  process.env.TENGENCE_SANITIZE_SALT = 'mcp-test-salt-001';
  process.env.TENGENCE_SANITIZE_KEY = '0123456789abcdef0123456789abcdef';
  process.env.TENGENCE_API_KEY = 'sk-mcp-test';
  fs.writeFileSync(
    CONFIG,
    JSON.stringify(
      {
        version: 1,
        rules: [
          { fields: ['phone'], method: 'hash', params: { algorithm: 'SHA-256' } },
          { fields: ['id_card'], method: 'mask', params: { keepFirst: 3, keepLast: 4 } },
          { fields: ['order_no'], method: 'encrypt' },
        ],
        audit: { enabled: true, dir: AUDIT_DIR },
      },
      null,
      2
    )
  );
  fs.writeFileSync(INPUT, `phone,id_card,order_no,name\n${PHONE},110101199001011234,ORD202610180001,张三\n13900139000,110101199202022345,ORD202610180002,李四\n`);
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
  delete process.env.TENGENCE_SANITIZE_SALT;
  delete process.env.TENGENCE_SANITIZE_KEY;
  delete process.env.TENGENCE_API_KEY;
});

function tool(name) {
  const t = tools.find((x) => x.name === name);
  expect(t, `tool ${name} exists`).toBeTruthy();
  return t;
}

function collectText(result) {
  return result.content.map((c) => c.text).join('\n');
}

describe('工具注册表', () => {
  it('注册 7 个工具定义，6 个默认激活，restore 被门控', () => {
    expect(tools.map((t) => t.name).sort()).toEqual(
      ['sanitize_audit_export', 'sanitize_audit_list', 'sanitize_config_info', 'sanitize_dry_run', 'sanitize_file', 'sanitize_restore', 'sanitize_upload'].sort()
    );
    delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
    expect(activeTools().map((t) => t.name)).not.toContain('sanitize_restore');
    process.env.SANITIZE_MCP_ENABLE_RESTORE = '1';
    expect(activeTools().map((t) => t.name)).toContain('sanitize_restore');
  });

  it('任何工具 schema 都不接受密钥/盐/token 参数', () => {
    for (const t of tools) {
      for (const key of Object.keys(t.inputSchema.shape || {})) {
        expect(/key|salt|token|secret/i.test(key), `${t.name} 参数 ${key}`).toBe(false);
      }
    }
  });

  it('TOOL_GROUPS 与工具注册表一致（无漂移）', () => {
    const matched = new Set();
    for (const g of TOOL_GROUPS) {
      for (const t of tools) if (g.match.test(t.name)) matched.add(t.name);
    }
    expect(matched.size).toBe(tools.length);
  });
});

describe('sanitize_config_info', () => {
  it('返回规则摘要、指纹与 masking_meta，不含任何环境变量值', async () => {
    const res = await tool('sanitize_config_info').run({ config: CONFIG });
    expect(res.isError).toBeFalsy();
    const data = JSON.parse(collectText(res));
    expect(data.rules).toHaveLength(3);
    expect(data.configFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(data.maskingMeta.phone).toBe('hash');
    expect(collectText(res)).not.toContain('mcp-test-salt-001');
  });

  it('配置不存在/非法时报清晰错误', async () => {
    const res = await tool('sanitize_config_info').run({ config: path.join(tmp, 'nope.json') });
    expect(res.isError).toBe(true);
    expect(collectText(res)).toMatch(/error/i);
  });
});

describe('sanitize_dry_run', () => {
  it('返回命中统计与脱敏后样例，且不含任何原文（before 被剥离）', async () => {
    const res = await tool('sanitize_dry_run').run({ config: CONFIG, input: INPUT });
    expect(res.isError).toBeFalsy();
    const text = collectText(res);
    const data = JSON.parse(text);
    expect(data.inputRows).toBe(2);
    const phone = data.fieldStats.find((s) => s.field === 'phone');
    expect(phone.hits).toBe(2);
    expect(phone.afterSamples[0]).toMatch(/^[0-9a-f]{32}$/);
    // 明文绝不出现
    for (const m of PLAINTEXT_MARKERS) expect(text).not.toContain(m);
    expect(text).not.toContain('before');
    // 未声明字段兜底
    expect(data.unmatchedFields).toContain('name');
  });
});

describe('sanitize_file', () => {
  it('返回统计（batchId/行数/告警/审计路径），不含行内容', async () => {
    const res = await tool('sanitize_file').run({ config: CONFIG, input: INPUT, output: OUTPUT });
    expect(res.isError).toBeFalsy();
    const text = collectText(res);
    const data = JSON.parse(text);
    expect(data.batchId).toBeTruthy();
    expect(data.inputRows).toBe(2);
    expect(data.outputRows).toBe(2);
    expect(data.errorRows).toBe(0);
    expect(data.auditFile).toBeTruthy();
    for (const m of PLAINTEXT_MARKERS) expect(text).not.toContain(m);
    // 输出文件确实是脱敏后的：id_card 掩码（keepFirst 3 + keepLast 4 → 中间 11 个 *），phone 为 32-hex 哈希
    const out = fs.readFileSync(OUTPUT, 'utf8');
    expect(out).toMatch(/110\*{11}1234/);
    expect(out).toMatch(/[0-9a-f]{32}/);
    expect(out).not.toContain(PHONE);
  });
});

describe('sanitize_upload', () => {
  it('上传已脱敏文件（mock fetch），返回 accepted，正文不含明文', async () => {
    const calls = [];
    const fetchMock = vi.fn(async (url, opts) => {
      calls.push({ url, opts });
      return { status: 200, text: async () => JSON.stringify({ code: 0 }) };
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const res = await tool('sanitize_upload').run({ config: CONFIG, input: OUTPUT });
      expect(res.isError).toBeFalsy();
      const data = JSON.parse(collectText(res));
      expect(data.ok).toBe(true);
      expect(data.accepted).toBe(2);
      expect(fetchMock).toHaveBeenCalled();
      const body = JSON.parse(calls[0].opts.body);
      expect(body.config_fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(body.masking_meta.phone).toBe('hash');
      // 请求体是脱敏后的数据：id_card 掩码 + phone 哈希，绝无明文
      const allData = JSON.stringify(body.data);
      expect(allData).not.toContain(PHONE);
      expect(allData).toMatch(/110\*{11}1234/);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('sanitize_audit_*', () => {
  it('audit_list 列出审计记录（无明文）；audit_export 导出文件', async () => {
    const list = await tool('sanitize_audit_list').run({ dir: AUDIT_DIR });
    expect(list.isError).toBeFalsy();
    const ldata = JSON.parse(collectText(list));
    expect(ldata.records.length).toBeGreaterThanOrEqual(2); // sanitize_file + upload 各一条
    expect(collectText(list)).not.toContain(PHONE);

    const exp = await tool('sanitize_audit_export').run({ dir: AUDIT_DIR, format: 'csv' });
    expect(exp.isError).toBeFalsy();
    const edata = JSON.parse(collectText(exp));
    expect(fs.existsSync(edata.file)).toBe(true);
    expect(fs.readFileSync(edata.file, 'utf8')).not.toContain(PHONE);
  });
});

describe('sanitize_restore（门控）', () => {
  it('SANITIZE_MCP_ENABLE_RESTORE=1 时可用并还原成功', async () => {
    process.env.SANITIZE_MCP_ENABLE_RESTORE = '1';
    try {
      // 从脱敏输出文件取 order_no 的 enc 值
      const enc = fs.readFileSync(OUTPUT, 'utf8').split('\n')[1].split(',')[2];
      const res = await tool('sanitize_restore').run({ config: CONFIG, field: 'order_no', value: enc });
      expect(res.isError).toBeFalsy();
      const data = JSON.parse(collectText(res));
      expect(data.restored).toBe('ORD202610180001');
    } finally {
      delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
    }
  });

  it('默认（未设置开关）时 activeTools 不包含 restore', () => {
    delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
    expect(activeTools().map((t) => t.name)).not.toContain('sanitize_restore');
  });
});

describe('SDK 直连校验（测试底座）', () => {
  it('sdk 导出可用（createSanitizer/dryRun/sanitizeFile）', async () => {
    const sanitizer = sdk.createSanitizer({ config: CONFIG });
    const report = await sanitizer.dryRun(INPUT);
    expect(report.inputRows).toBe(2);
  });
});
