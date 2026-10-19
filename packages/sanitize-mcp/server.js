'use strict';
/**
 * Tengence sanitize MCP Server factory (@tengence/sanitize-mcp/server.js)
 * ============================================================================
 * Built on @modelcontextprotocol/server (SDK v2, ESM-only) — pulled in from the
 * CJS side via dynamic import. Provides buildServer(): registers every tool from
 * tools/registry.js (minus gated tools unless their env switch is on), every
 * Prompt from tools/prompts.js and every Resource from tools/resources.js, and
 * returns an McpServer ready to be served per-request by the transport layer
 * (stdio / HTTP), per MCP protocol revision 2026-07-28 (stateless core).
 *
 * TRUST BOUNDARY: no secret is ever stored, cached or printed by this process;
 * keys/salts/api keys come from env vars only. Tool outputs never contain
 * plaintext (dry_run strips `before` samples; sanitize_file returns stats only;
 * restore is gated behind SANITIZE_MCP_ENABLE_RESTORE=1).
 */

const { tools, TOOL_GROUPS } = require('./tools/registry');
const { prompts } = require('./tools/prompts');
const { fixedResources, resourceTemplates } = require('./tools/resources');

/**
 * Build the server-level instructions (MCP `Implementation.instructions`): the
 * protocol's endorsed mechanism for grouping tools and steering how a client uses
 * them. The TOOL GROUPS listing is aggregated from the registry's TOOL_GROUPS
 * matchers against the LIVE (post-gating) tool list, so it can never drift from
 * what is really registered. Deep rules live in resources (sanitize://workflows
 * etc.) loaded on demand, not here, to avoid burning context.
 */
function buildInstructions(toolsList) {
  const groups = TOOL_GROUPS.map((g) => {
    const names = toolsList.filter((t) => g.match.test(t.name)).map((t) => t.name);
    return names.length ? `- ${g.group}: ${names.join(', ')}` : null;
  })
    .filter(Boolean)
    .join('\n');
  return [
    'You are the Tengence sanitize MCP server — local data desensitization (脱敏) before uploading business data. ' +
      'Plaintext never leaves the user machine and never enters the AI context: tool outputs contain desensitized values and statistics only.',
    '',
    'TOOL GROUPS (read each tool description before calling):',
    groups,
    '- Reference data: read via resources sanitize://methods, sanitize://config-schema, sanitize://workflows, sanitize://audit/{batchId} — load only what a task needs.',
    '',
    'CANONICAL PIPELINE for a data file:',
    'sanitize_config_info(config) -> sanitize_dry_run(config, input) [confirm hits>0 and unmatchedFields, patch config first if any] -> sanitize_file(config, input, output) -> sanitize_upload(config, output) [apiKey from env]',
    '',
    'WHEN NOT TO CALL / SAFETY:',
    '- never pass any key/salt/api key as a tool argument — secrets are env vars only (TENGENCE_SANITIZE_SALT / TENGENCE_SANITIZE_KEY / TENGENCE_API_KEY);',
    '- never echo or request plaintext — tool outputs contain none; for original values have the user open the local file;',
    '- restore (decrypt to plaintext) is gated: only call sanitize_restore when SANITIZE_MCP_ENABLE_RESTORE=1 is set, and its output IS plaintext; otherwise use the CLI `tengence-sanitize restore`;',
    '- writing output files and uploading are write operations — confirm with the user before executing.',
  ].join('\n');
}

/** Environment check: prints key config at startup so misconfiguration is easy to debug. */
function printStartupBanner() {
  const restore = process.env.SANITIZE_MCP_ENABLE_RESTORE === '1';
  console.error(
    `[sanitize-mcp] restore=${restore ? 'ENABLED (plaintext will enter AI context!)' : 'disabled (use CLI: tengence-sanitize restore)'}`
  );
  console.error(
    `[sanitize-mcp] keys: TENGENCE_SANITIZE_SALT=${process.env.TENGENCE_SANITIZE_SALT ? 'set' : 'NOT set'}, ` +
      `TENGENCE_SANITIZE_KEY=${process.env.TENGENCE_SANITIZE_KEY ? 'set' : 'NOT set'}, ` +
      `TENGENCE_API_KEY=${process.env.TENGENCE_API_KEY ? 'set' : 'NOT set'} (values are never printed)`
  );
}

/**
 * Build a fresh MCP server instance with every (non-gated) tool, prompt and
 * resource registered. This is the per-request factory consumed by serveStdio /
 * createMcpHandler — the server is stateless (2026-07-28), so each request (or
 * each stdio connection) gets its own instance built here. File paths are never
 * guessed: the client passes explicit paths as tool arguments.
 * @returns {Promise<import('@modelcontextprotocol/server').McpServer>}
 */
async function buildServer() {
  const { McpServer, ResourceTemplate } = await import('@modelcontextprotocol/server');
  const server = new McpServer(
    { name: 'tengence-sanitize-mcp', version: require('./package.json').version },
    {
      instructions: buildInstructions(activeTools()),
      capabilities: {
        resources: { subscribe: true },
      },
    }
  );

  for (const tool of activeTools()) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      async (args) => tool.run(args || {})
    );
  }

  for (const p of prompts) {
    server.registerPrompt(
      p.name,
      { title: p.title, description: p.description, argsSchema: p.argsSchema },
      (args) => p.run(args || {})
    );
  }

  for (const r of fixedResources) {
    server.registerResource(r.name, r.uri, r.config, () => r.read());
  }

  for (const rt of resourceTemplates) {
    const template = new ResourceTemplate(rt.uriTemplate, { list: () => rt.list() });
    server.registerResource(rt.name, template, rt.config, (uri, variables) => rt.read(uri, variables));
  }

  return server;
}

/** The tool list after gating: a tool with `gated` is registered only when its env switch equals "1". */
function activeTools() {
  return tools.filter((t) => !t.gated || process.env[t.gated] === '1');
}

module.exports = { buildServer, printStartupBanner, buildInstructions, activeTools };
