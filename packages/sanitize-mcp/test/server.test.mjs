/**
 * Server-layer tests: buildServer builds a stateless McpServer for both gating
 * states; registry carries 3 prompts + 4 resources; instructions aggregate groups
 * from the live registry, name the env-var secret SOURCES (names, never values)
 * and never contain any secret VALUE.
 * Real registration verification (tools/prompts/resources listed over the wire)
 * is covered by the end-to-end client test (test/e2e.mjs).
 */
import { describe, it, expect, afterAll } from 'vitest';
import { buildServer, buildInstructions, activeTools } from '../server.js';
import { tools } from '../tools/registry.js';
import { prompts } from '../tools/prompts.js';
import { fixedResources, resourceTemplates } from '../tools/resources.js';

const SDK_NAMESPACE = 'sanitize';

const DEFAULT_TOOLS = [
  'sanitize_audit_export',
  'sanitize_audit_list',
  'sanitize_config_info',
  'sanitize_dry_run',
  'sanitize_file',
  'sanitize_upload',
];

afterAll(() => {
  delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
});

describe('buildServer 工厂', () => {
  it('默认构建成功，激活 6 个工具（restore 门控关闭）', async () => {
    delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
    await expect(buildServer()).resolves.toBeTruthy();
    expect(activeTools().map((t) => t.name).sort()).toEqual(DEFAULT_TOOLS);
  });

  it('SANITIZE_MCP_ENABLE_RESTORE=1 时构建成功，激活 7 个工具', async () => {
    process.env.SANITIZE_MCP_ENABLE_RESTORE = '1';
    await expect(buildServer()).resolves.toBeTruthy();
    expect(activeTools().map((t) => t.name)).toContain('sanitize_restore');
    expect(activeTools()).toHaveLength(7);
  });

  it('注册表一致性：tools 7 / prompts 3 / resources 4，无漂移', () => {
    expect(tools).toHaveLength(7);
    expect(prompts.map((p) => p.name).sort()).toEqual(
      ['sanitize_desensitize_file', 'sanitize_setup_config', 'sanitize_verify_audit'].sort()
    );
    expect(fixedResources.map((r) => r.uri)).toContain(`${SDK_NAMESPACE}://methods`);
    expect(fixedResources.map((r) => r.uri)).toContain(`${SDK_NAMESPACE}://config-schema`);
    expect(fixedResources.map((r) => r.uri)).toContain(`${SDK_NAMESPACE}://workflows`);
    expect(resourceTemplates.map((r) => r.uriTemplate)).toContain(`${SDK_NAMESPACE}://audit/{batchId}`);
  });
});

describe('instructions', () => {
  it('聚合 TOOL GROUPS、含规范流水线与安全红线', () => {
    delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
    const inst = buildInstructions(activeTools());
    expect(inst).toContain('TOOL GROUPS');
    expect(inst).toContain('CANONICAL PIPELINE');
    expect(inst).toContain('sanitize_dry_run');
    expect(inst).toContain('WHEN NOT TO CALL');
    expect(inst).toContain('TENGENCE_SANITIZE_SALT'); // 变量名（告知密钥来源）
  });

  it('包含密钥变量名（来源），但绝不包含任何密钥值', () => {
    delete process.env.SANITIZE_MCP_ENABLE_RESTORE;
    const inst = buildInstructions(activeTools());
    expect(inst).toContain('TENGENCE_SANITIZE_KEY');
    expect(inst).toContain('TENGENCE_API_KEY');
    expect(inst.toLowerCase()).not.toMatch(/mcp-test-salt|sk-mcp|0123456789abcdef/);
  });
});
