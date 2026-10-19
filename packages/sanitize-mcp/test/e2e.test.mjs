/**
 * End-to-end test: a REAL MCP client (SDK v2, @modelcontextprotocol/client 2.3.1)
 * talks to the sanitize-mcp stdio server (2026-07-28 stateless protocol) and runs
 * the canonical pipeline config_info → dry_run → sanitize_file → upload (against a
 * local mock push endpoint) → audit_list, plus resources and prompts discovery.
 *
 * Assertions include the product's core guarantee: NO plaintext ever appears in
 * any tool result / resource / prompt output.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_JS = path.resolve(__dirname, '../bin/sanitize-mcp.js');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sanitize-mcp-e2e-'));
const AUDIT_DIR = path.join(tmp, 'audits');
const CONFIG = path.join(tmp, 'sanitize.config.json');
const INPUT = path.join(tmp, 'orders.csv');
const OUTPUT = path.join(tmp, 'orders-out.csv');
const PHONE = '13800138000';
const PLAINTEXT_MARKERS = [PHONE, '张三', '110101199001011234'];

let pushServer;
let pushUrl;
let pushBodies = [];
let client;
let transport;

function startPushMock() {
  return new Promise((resolve) => {
    pushServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        pushBodies.push(body);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ code: 0 }));
      });
    });
    pushServer.listen(0, '127.0.0.1', () => {
      pushUrl = `http://127.0.0.1:${pushServer.address().port}/v1/push/data`;
      resolve();
    });
  });
}

beforeAll(async () => {
  await startPushMock();
  process.env.TENGENCE_SANITIZE_SALT = 'e2e-salt-999';
  process.env.TENGENCE_SANITIZE_KEY = 'fedcba9876543210fedcba9876543210';
  process.env.TENGENCE_API_KEY = 'sk-e2e';
  delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
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
        upload: { pushUrl, apiKeyEnv: 'TENGENCE_API_KEY', batchSize: 10, maxRetries: 1 },
        audit: { enabled: true, dir: AUDIT_DIR },
      },
      null,
      2
    )
  );
  fs.writeFileSync(INPUT, `phone,id_card,order_no,name\n${PHONE},110101199001011234,ORD202610180001,张三\n13900139000,110101199202022345,ORD202610180002,李四\n`);

  transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_JS],
    env: { ...process.env, SANITIZE_MCP_AUDIT_DIR: AUDIT_DIR },
  });
  client = new Client(
    { name: 'sanitize-mcp-e2e', version: '1.0.0' },
    {
      capabilities: {},
      // 服务端 strict 2026-07-28：客户端必须 pin 到该修订，否则默认 legacy(2025) 会被拒绝
      versionNegotiation: { mode: { pin: '2026-07-28' } },
    }
  );
  await client.connect(transport);
}, 30000);

afterAll(async () => {
  if (client) await client.close();
  if (pushServer) pushServer.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  delete process.env.TENGENCE_SANITIZE_SALT;
  delete process.env.TENGENCE_SANITIZE_KEY;
  delete process.env.TENGENCE_API_KEY;
});

function textOf(result) {
  return result.content.map((c) => c.text).join('\n');
}

describe('MCP 2026-07-28 端到端（真实客户端 + stdio）', () => {
  it('tools/list 暴露 6 个工具，restore 门控关闭', async () => {
    const res = await client.listTools();
    const names = res.tools.map((t) => t.name).sort();
    expect(names).toEqual(
      ['sanitize_audit_export', 'sanitize_audit_list', 'sanitize_config_info', 'sanitize_dry_run', 'sanitize_file', 'sanitize_upload'].sort()
    );
    expect(names).not.toContain('sanitize_restore');
  });

  it('sanitize_config_info 返回指纹与 masking_meta', async () => {
    const res = await client.callTool({ name: 'sanitize_config_info', arguments: { config: CONFIG } });
    const data = JSON.parse(textOf(res));
    expect(data.configFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(data.maskingMeta.phone).toBe('hash');
    expect(textOf(res)).not.toContain('e2e-salt-999');
  });

  it('sanitize_dry_run 只返回脱敏后样例（无 before 明文）', async () => {
    const res = await client.callTool({ name: 'sanitize_dry_run', arguments: { config: CONFIG, input: INPUT } });
    const text = textOf(res);
    const data = JSON.parse(text);
    expect(data.inputRows).toBe(2);
    expect(data.fieldStats.find((s) => s.field === 'phone').afterSamples[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(data.unmatchedFields).toContain('name');
    for (const m of PLAINTEXT_MARKERS) expect(text).not.toContain(m);
    expect(text).not.toContain('before');
  });

  it('sanitize_file 返回统计并写出脱敏文件', async () => {
    const res = await client.callTool({ name: 'sanitize_file', arguments: { config: CONFIG, input: INPUT, output: OUTPUT } });
    const data = JSON.parse(textOf(res));
    expect(data.batchId).toBeTruthy();
    expect(data.inputRows).toBe(2);
    expect(data.outputRows).toBe(2);
    expect(data.errorRows).toBe(0);
    for (const m of PLAINTEXT_MARKERS) expect(textOf(res)).not.toContain(m);
    const out = fs.readFileSync(OUTPUT, 'utf8');
    expect(out).toMatch(/110\*{11}1234/);
    expect(out).not.toContain(PHONE);
  });

  it('sanitize_upload 走真实 HTTP 到本地 mock，accepted=2 且请求体无明文', async () => {
    const res = await client.callTool({ name: 'sanitize_upload', arguments: { config: CONFIG, input: OUTPUT } });
    const data = JSON.parse(textOf(res));
    expect(data.ok).toBe(true);
    expect(data.accepted).toBe(2);
    expect(pushBodies.length).toBeGreaterThan(0);
    const body = JSON.parse(pushBodies[0]);
    expect(body.config_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(body.masking_meta.phone).toBe('hash');
    expect(JSON.stringify(body.data)).not.toContain(PHONE);
  });

  it('resources/list + templates + read：固定资源、模板资源与 workflows 内容', async () => {
    const list = await client.listResources();
    const uris = list.resources.map((r) => r.uri);
    // 固定资源
    expect(uris).toEqual(
      expect.arrayContaining(['sanitize://methods', 'sanitize://config-schema', 'sanitize://workflows'])
    );
    // 模板资源：具体批次出现在 resources/list
    expect(uris.some((u) => /^sanitize:\/\/audit\/[0-9a-f-]{36}$/.test(u))).toBe(true);
    // 模板声明在 resources/templates/list
    const templates = await client.listResourceTemplates();
    expect(templates.resourceTemplates.map((t) => t.uriTemplate)).toContain('sanitize://audit/{batchId}');
    const wf = await client.readResource({ uri: 'sanitize://workflows' });
    const text = wf.contents.map((c) => c.text).join('\n');
    expect(text).toContain('CANONICAL PIPELINE');
    expect(text).toContain('WHEN NOT TO CALL');
    for (const m of PLAINTEXT_MARKERS) expect(text).not.toContain(m);
  });

  it('prompts/list + get：3 个模板，desensitize_file 含完整序列', async () => {
    const list = await client.listPrompts();
    expect(list.prompts.map((p) => p.name).sort()).toEqual(
      ['sanitize_desensitize_file', 'sanitize_setup_config', 'sanitize_verify_audit'].sort()
    );
    const p = await client.getPrompt({ name: 'sanitize_desensitize_file', arguments: { config: CONFIG, input: INPUT, output: OUTPUT, upload: 'false' } });
    expect(p.messages.length).toBeGreaterThan(0);
    expect(p.messages[0].content.text).toContain('sanitize_dry_run');
  });

  it('sanitize_audit_list 返回审计记录且无明文', async () => {
    const res = await client.callTool({ name: 'sanitize_audit_list', arguments: { dir: AUDIT_DIR } });
    const data = JSON.parse(textOf(res));
    expect(data.records.length).toBeGreaterThanOrEqual(2);
    for (const m of PLAINTEXT_MARKERS) expect(textOf(res)).not.toContain(m);
  });
}, 60000);
