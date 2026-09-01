# Examples

- **`embed-sdk.mjs`** — embed the SDK in a Node app and catch a poisoned tool. Run:
  ```bash
  npm install @sentinelreign/guard
  node examples/embed-sdk.mjs
  ```
- **Scan any MCP server** (no install):
  ```bash
  npx @sentinelreign/guard-proxy scan node ./your-mcp-server.mjs
  ```
- **Protect a stdio server** (Cursor / Claude Code):
  ```bash
  npx @sentinelreign/guard-proxy -- node ./your-mcp-server.mjs
  ```
