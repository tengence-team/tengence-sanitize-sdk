#!/usr/bin/env node
/**
 * Tengence sanitize MCP Server — stdio transport (local clients)
 * ============================================================================
 * Usage:
 *   node packages/sanitize-mcp/bin/sanitize-mcp.js
 *
 * Protocol: MCP 2026-07-28 (stateless core), strict modern-only: this entry serves
 * only 2026-07-28 clients via serveStdio with { legacy: 'reject' }; 2025-era
 * initialize-handshake clients are rejected.
 *
 * Trust boundary: plaintext stays on this machine; keys/salts/api keys come from
 * env vars only (TENGENCE_SANITIZE_SALT / TENGENCE_SANITIZE_KEY / TENGENCE_API_KEY)
 * and are never stored or printed by this process.
 *
 * Published distribution: once @tengence/sanitize-mcp is on npm, clients can also
 * launch it without a local checkout via `npx -y @tengence/sanitize-mcp` (the
 * package resolves its own script).
 */

const { buildServer, printStartupBanner } = require('../server');

async function main() {
  const { serveStdio } = await import('@modelcontextprotocol/server/stdio');
  printStartupBanner();
  // Strict 2026-07-28: one factory per connection; legacy 2025-era openings rejected.
  serveStdio(() => buildServer(), { legacy: 'reject' });
}

main().catch((e) => {
  console.error(`[sanitize-mcp] failed to start: ${e.message}`);
  process.exit(1);
});
