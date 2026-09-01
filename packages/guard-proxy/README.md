# @sentinelreign/guard-proxy

The **stdio sidecar** for [SentinelAgent Guard](https://guard.sentinelreign.com), and the free
`mcpgrade` scanner.

stdio is the transport no hosted proxy can reach, and it is how Cursor, Claude Code and Copilot
actually load MCP servers: a project-defined server is auto-executed at developer privilege, in the
developer's own environment, with no isolation. The sidecar runs that server as a child process and
sits between it and the client, inspecting every message in both directions with the same engine the
hosted gateway uses — [`@sentinelreign/guard-core`](../guard-core/README.md).

Apache-2.0. Author: Syed Zada Abrar.

## The sidecar

Point your MCP client at `guard-proxy` instead of at the server:

```jsonc
// .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json — same shape
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@sentinelreign/guard-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/repo"]
    }
  }
}
```

A poisoned tool inventory, blocked before the client ever parses it (real output — the fixture server
under `test/fixtures/` advertises a tool whose description carries a hidden instruction):

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | guard-proxy -- node ./mcp-server.mjs
{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"Blocked by SentinelAgent Guard: Instruction payload embedded in a tool description","data":{"findings":[{"check":"L1.TOOL_POISONING","layer":1,"severity":"critical","title":"Instruction payload embedded in a tool description","detail":"Description of \"read_file\" contains a pseudo-tag instruction block.","action":"BLOCK","path":"tools.read_file.description"}]}}}
[guard] blocked tools/list from server: L1.TOOL_POISONING
```

And an argument that never reaches the child at all:

```
$ echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../../etc/passwd"}}}' \
    | guard-proxy -- node ./mcp-server.mjs
{"jsonrpc":"2.0","id":2,"error":{"code":-32004,"message":"Blocked by SentinelAgent Guard: Path traversal in an argument","data":{"findings":[…]}}}
[guard] blocked tools/call from client: L2.PATH_TRAVERSAL, L2.SENSITIVE_FILE_READ
```

### Rules the sidecar keeps

- **Never corrupt the stream.** Newline-delimited JSON-RPC is framed and re-emitted byte for byte.
  Anything not understood — a non-JSON line, a batch array, a notification, a message shape from a
  future spec revision — is forwarded untouched. A firewall that mangles valid traffic is worse than
  no firewall, and the test suite asserts this for each of those cases.
- **Blocking means answering.** The client receives a JSON-RPC error carrying the findings, never
  silence. A swallowed id is indistinguishable from a hung server. (A blocked *notification* has no
  id to answer, so it is dropped and logged instead.)
- **The child's stderr stays the operator's stderr.** It is piped straight through; the sidecar's own
  diagnostics are prefixed `[guard]`.
- **Exit code is the child's exit code.**

### What is checked, in which direction

| Direction | Layer |
| --- | --- |
| client → server | L0 protocol conformance, L2 call-time policy (allowlist, arguments, patterns) |
| server → client, `tools/list` result | L1 tool integrity — rug pulls, poisoning, Unicode concealment |
| server → client, `tools/call` result | L3 response DLP — secrets, indirect prompt injection |

The first inventory a server advertises is pinned, so a mutation later in the same session is caught
as `L1.RUG_PULL`.

stdio carries no `Mcp-Method` / `Mcp-Name` routing headers, so `L0.MISSING_NAME_HEADER` is switched
off for this transport (`STDIO_DISABLED_CHECKS`) rather than being satisfied with headers synthesised
from the body — a check fed its own answer tests nothing. The remaining L0 conformance checks apply.

## `scan` — the free mcpgrade report

```
$ guard-proxy scan node ./mcp-server.mjs

SentinelAgent Guard — mcpgrade scan
  target   node ./mcp-server.mjs
  tools    1
  rubric   mcpgrade-2.0.0

  grade C   60/100

  CRITICAL L1.TOOL_POISONING
           tools.read_file.description
           Description of "read_file" contains a pseudo-tag instruction block.

  1 finding(s): 1 critical
```

A clean server, same command:

```
  grade A+   100/100

  No findings. Tool definitions are clean against L1 tool integrity.
```

`--json` prints the report verbatim, including `rubricVersion`:

```json
{
  "grade": "C",
  "score": 60,
  "rubricVersion": "mcpgrade-2.0.0",
  "findings": [
    {
      "check": "L1.TOOL_POISONING",
      "layer": 1,
      "severity": "critical",
      "title": "Instruction payload embedded in a tool description",
      "detail": "Description of \"read_file\" contains a pseudo-tag instruction block.",
      "action": "BLOCK",
      "path": "tools.read_file.description"
    }
  ],
  "target": "node ./mcp-server.mjs",
  "toolCount": 1
}
```

The score comes from [`mcpgrade`](../guard-core/README.md#mcpgrade--the-published-rubric), the one
published rubric shared with the runtime and the andraxpentester.in scanner: one critical finding is
−40, so 60 = C. The same inventory always produces the same grade, and a change to the arithmetic
requires a `RUBRIC_VERSION` bump.

`scan` grades **L1 only** — it sees an advertised inventory, not live traffic. Claiming L2 or L3
coverage from a `tools/list` would be a claim we cannot demonstrate. A server whose inventory cannot
be retrieved is reported as an error and **not graded**; grading an empty list A+ would be a lie.

Targets: an `http(s)://` URL (JSON or SSE response bodies) or a command to run over stdio. The stdio
client sends `initialize` and `notifications/initialized` first, because servers written against the
2025 revisions refuse everything until they have been initialised.

### Exit codes

| Code | |
| --- | --- |
| `0` | clean, or no finding at or above `--fail-on` |
| `1` | a finding at or above `--fail-on` (default `high`; `--fail-on none` disables) |
| `2` | usage error, or the target could not be scanned |

For the sidecar, the exit code is the child's own.

```
guard-proxy scan --fail-on critical --json https://mcp.example.com/rpc
```

## Options

```
  guard-proxy -- <command> [args...]     run an MCP server behind the firewall
  guard-proxy scan <url>                 grade a remote MCP server
  guard-proxy scan <command> [args...]   grade a stdio MCP server

Scan options
  --json                 machine-readable report on stdout
  --fail-on <severity>   exit 1 when a finding is at or above this severity
                         (critical|high|medium|low|info|none, default: high)
  --timeout <ms>         give up on the server after this long (default: 15000)

Colour follows NO_COLOR and is off when stdout is not a terminal.
```

Colour is a handful of ANSI escapes, not a dependency.

## Status

- **Runtime packaging.** `dist/` compiles to ESM with real `.d.ts` files and the CLI runs under bare
  `node` — the `bin` is a plain `#!/usr/bin/env node` script, no TypeScript loader required. It imports
  the engine as `@guard/core`; in this repository that is a local link, and at publish time the
  dependency is rewritten to the npm alias `npm:@sentinelreign/guard-core`, so the emitted import
  specifier is identical either way and `npm install -g @sentinelreign/guard-proxy` pulls the engine
  from the registry.
- **Not implemented:** a policy file for the sidecar (allowlists and custom rules are accepted through
  the `runProxy()` API but have no CLI flag yet), and persistent baselines across sessions — the pin
  currently lives for the life of the process. Neither is advertised in `--help`.
