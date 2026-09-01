# Usage

Three packages, one engine. Pick the surface that fits how your agent talks to
MCP. Everything here runs locally and free — no key, no network.

- [CLI — scan & sidecar (`@sentinelreign/guard-proxy`)](#cli)
- [SDK — embed in your server (`@sentinelreign/guard`)](#sdk)
- [Engine — call the detector directly (`@sentinelreign/guard-core`)](#engine)

---

## CLI

The fastest way in. No install needed with `npx`.

```bash
# Grade a remote MCP server (A–F, with findings)
npx @sentinelreign/guard-proxy scan https://your-server.example/mcp

# Grade a local stdio MCP server
npx @sentinelreign/guard-proxy scan node ./your-mcp-server.mjs

# Run a stdio server BEHIND the firewall (protects Cursor, Claude Code, etc.)
npx @sentinelreign/guard-proxy -- node ./your-mcp-server.mjs
```

**Options**

| Flag | Meaning |
| --- | --- |
| `--json` | Machine-readable report on stdout |
| `--fail-on <severity>` | Exit `1` when a finding is at or above this severity (`info`\|`medium`\|`high`\|`critical`) |
| `--timeout <ms>` | Give up on the server after this long (default `15000`) |
| `--version`, `--help` | Version / usage |

**Exit codes:** `0` clean (scan) or the child's own code (sidecar) · `1`
findings at/above `--fail-on` · `2` usage error or the target could not be reached.

Use it in CI to fail a build when an MCP dependency regresses:

```bash
npx @sentinelreign/guard-proxy scan node ./server.mjs --fail-on high
```

---

## SDK

Embed detection in your own MCP server. Runs in-process; the verdict is
identical to what the hosted gateway would return.

```bash
npm install @sentinelreign/guard
```

```ts
import { Guard } from '@sentinelreign/guard';

// No licenseKey = full local detection, zero network. That's the whole SDK, free.
const guard = new Guard();

// 1) Pin the tool inventory the first time you list tools (trust on first use):
const listVerdict = guard.verify({ kind: 'tools_list', tools });
// A later listing whose hashes differ is a rug pull -> decision: 'block'.

// 2) Check each call before you forward it:
const callVerdict = guard.verify({
  kind: 'request',
  headers: { 'mcp-method': 'tools/call', 'mcp-name': 'read_file' },
  body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'README.md' } } },
});

// 3) Inspect what a tool returns (secret egress, injected instructions):
const respVerdict = guard.verify({ kind: 'response', toolName: 'read_file', body: result });

if (callVerdict.decision === 'block') {
  return guard.errorFor(callVerdict, 1); // ready-made JSON-RPC error
}
```

**A verdict** is `{ decision: 'allow' | 'warn' | 'block', findings: Finding[] }`.

### `GuardOptions`

| Option | Default | What it does |
| --- | --- | --- |
| `licenseKey` | — | **Optional.** Set it only to connect to the hosted SaaS (central rules, usage, dashboard). Without it: full local detection, no network. |
| `serverId` | `'local'` | Identifier used only when connected to the control plane. |
| `policy` | — | Local policy: `allowedTools`, `customRules`, `disabledChecks`, `baseline`. |
| `transport` | `'http'` | `'stdio'` disables the header-agreement checks that stdio can't carry. |
| `brand` | — | White-label the block message for OEM embedding. |
| `controlPlaneUrl` | hosted | Point at a self-hosted control plane. |
| `failOpenOnNetworkError` | `true` | A control plane that can't be reached must not take your server down. |
| `failOpenOnInvalidLicense` | `false` | Turning this on disables the entitlement gate. |
| `offlineLicense` / `offlineLicensePublicKey` | — | Air-gapped: verify a signed licence locally, zero network. |
| `onDiagnostic` | `console.error` | Sink for licence/control-plane diagnostics. |

### Middleware

```ts
import { wrap, expressGuard } from '@sentinelreign/guard';

// Wrap any MCP handler:
const guarded = wrap(myHandler, { guard });

// Or Express:
app.post('/mcp', expressGuard({ guard }), myHandler);
```

### Handy methods

- `Guard.create(options)` — construct **and** await rule load in one step.
- `guard.pinBaseline(tools)` — freeze an approved inventory for rug-pull detection.
- `guard.errorFor(verdict, id)` — render a block as a JSON-RPC error (respects `brand`).
- `guard.close()` — stop the heartbeat timer (only relevant when licensed).
- Getters: `licenseState`, `planTier`, `counters`, `policy`.

---

## Engine

The pure, zero-dependency detector. Use it when you want the verdict with no SDK
lifecycle at all.

```bash
npm install @sentinelreign/guard-core
```

```ts
import { evaluate, buildBaseline, grade, checkCount, CHECKS } from '@sentinelreign/guard-core';

console.log(checkCount()); // 22

// Deterministic verdict for one event + policy:
const verdict = evaluate(
  { kind: 'tools_list', tools },
  { baseline: buildBaseline(approvedTools) },
);

// Turn findings into an A–F mcpgrade report (the same rubric the scanner uses):
const report = grade(verdict.findings);
console.log(report.grade); // 'A+' … 'F'
```

`evaluate(event, policy)` is a pure function — same inputs, same verdict, every
time. `CHECKS` is the registry the whole system agrees on; see
[CHECKS.md](./CHECKS.md).

---

## Where the paid line is

Everything above is free and self-hosted forever. The hosted SaaS at
**[guard.sentinelreign.com](https://guard.sentinelreign.com)** adds the layer a
team can't self-host easily: a managed, scaled gateway, a dashboard across many
servers, centralized rules, tamper-evident + actor-attributed audit, SIEM/OTel
export, SSO, and an approvals queue. The SDK's `licenseKey` opt-in-connects to
it. Detection is always free; the key unlocks the managed layer, never the
detection.
