# @sentinelreign/guard-core

The deterministic detection engine behind [SentinelAgent Guard](https://guard.sentinelreign.com) — a
protocol-native security firewall for MCP servers and AI agents.

**Zero runtime dependencies. Pure functions. No LLM in the request path.** The same engine runs in the
hosted gateway, in the embedded SDK inside a vendor's own process, and in the stdio sidecar CLI. If two
of those disagree about a verdict, that is a bug in this package, not a configuration difference.

Apache-2.0. Author: Syed Zada Abrar.

```ts
import { evaluate, buildBaseline, toJsonRpcError } from '@sentinelreign/guard-core';

const policy = { baseline: buildBaseline(toolsFromServer), toolAllowlist: ['read_file'] };

const verdict = evaluate({ kind: 'request', headers, body }, policy);
if (verdict.decision === 'block') return toJsonRpcError(verdict, body.id);
```

## Design constraints

- **No I/O, no network, no database, no clock.** `evaluate(event, policy)` is a pure function of its
  arguments, which is what makes the audit log replayable and the three deployment shapes agree.
- **No dependencies, not even a schema validator.** A security control's hot path is the worst place
  for a supply-chain surface, so the JSON-RPC envelope and the JSON Schema subset are hand-written.
- **Rules run on string leaf values at known argument paths**, never on `JSON.stringify(body)`.
  Flattening the request makes the payload and the envelope indistinguishable; it is exactly what made
  the previous prototype block ordinary markdown and shell snippets.
- **Findings never contain secret values.** A DLP alert that quotes the credential has moved the
  credential, not stopped it.

## The five layers

| Layer | Scope | Event kind |
| --- | --- | --- |
| **L0** Protocol conformance | JSON-RPC 2.0 envelope, `Mcp-Method` / `Mcp-Name` header agreement, method surface for MCP 2026-07-28 | `request` |
| **L1** Tool integrity | SHA-256 pinning of tool definitions, rug pulls, poisoning, Unicode concealment, cross-server shadowing | `tools_list` |
| **L2** Call-time policy | Deny-by-default allowlist, argument validation against the server's own `inputSchema`, built-in and tenant pattern rules | `request` |
| **L3** Response DLP | Secrets and injection markers in tool output, with optional redaction | `response` |
| **L4** Tamper-evident audit | Hash-chained log — lives outside this package, since it requires storage | — |

## Checks

`checkCount()` returns the real number. The registry in `src/checks.ts` is the single source of truth:
every `Finding.check` emitted anywhere must resolve to an entry here, enforced at construction time by
`finding()` and asserted by the test suite. **There are currently 22 checks.**

The table below is generated from the registry's own `description` fields.

| Check id | Layer | Severity | Default action | What it detects |
| --- | --- | --- | --- | --- |
| `L0.INVALID_ENVELOPE` | L0 | high | BLOCK | Body is not a JSON-RPC 2.0 request: missing or wrong `jsonrpc`, absent/empty `method`, or `params` that is not an object. |
| `L0.HEADER_MISMATCH` | L0 | critical | BLOCK | The routing header disagrees with the JSON-RPC method. This is how a call is smuggled past a header-routing gateway, so it is treated as an attack signal rather than a spec nit. |
| `L0.NAME_MISMATCH` | L0 | critical | BLOCK | Declared target name disagrees with `params.name` (or `params.uri` for resources/read) — the same smuggling class as a method mismatch, one level down. |
| `L0.MISSING_NAME_HEADER` | L0 | high | BLOCK | tools/call, resources/read and prompts/get MUST declare their target in Mcp-Name so a gateway can authorise it without parsing the body. |
| `L0.UNKNOWN_METHOD` | L0 | medium | WARN | Method is outside the known-method allowlist for this spec revision. Unknown surface cannot be policy-checked. |
| `L0.DEPRECATED_METHOD` | L0 | medium | WARN | initialize, ping, logging/setLevel, resources/subscribe and resources/unsubscribe no longer exist. Their use indicates a stale or spoofed client. |
| `L1.RUG_PULL` | L1 | critical | BLOCK | A previously approved tool now hashes differently — its name, description or inputSchema was mutated post-approval (CVE-2025-54136 class rug pull). |
| `L1.TOOL_ADDED` | L1 | info | ALLOW | The server advertised a tool that was not in the frozen inventory. |
| `L1.TOOL_REMOVED` | L1 | medium | WARN | A tool in the baseline has disappeared. Benign on a deploy, but also how an attacker frees a name for a shadowing tool. |
| `L1.TOOL_POISONING` | L1 | critical | BLOCK | The description carries text aimed at the agent rather than at the operator: pseudo-tags, secrecy directives, instruction overrides, or a long embedded base64 blob. |
| `L1.UNICODE_CONCEALMENT` | L1 | critical | BLOCK | Unicode TAG block (U+E0000–U+E007F), zero-width, bidi override or private-use characters hide text from the human approval dialog while the model still reads it. |
| `L1.TOOL_SHADOWING` | L1 | high | BLOCK | A description naming tools from a different server is the cross-server shadowing precondition: it redirects calls intended for a trusted server. |
| `L2.TOOL_NOT_ALLOWED` | L2 | high | BLOCK | Deny-by-default: when an allowlist is configured, unlisted tools cannot be called. |
| `L2.SCHEMA_VIOLATION` | L2 | medium | WARN | Arguments are validated against the schema the server itself published, so the server is held to its own contract instead of a guessed one. |
| `L2.PATH_TRAVERSAL` | L2 | high | BLOCK | A string argument contains a `..` path segment, raw or percent-encoded. |
| `L2.SENSITIVE_FILE_READ` | L2 | critical | BLOCK | A string argument references /etc/passwd, /etc/shadow, an SSH private key, or cloud credential files. |
| `L2.SHELL_INJECTION` | L2 | critical | BLOCK | A string argument pipes into a shell/interpreter or chains a fetch-and-execute. Ordinary backticks and `$(...)` are NOT flagged — only interpreter and network-fetch targets. |
| `L2.SQL_INJECTION` | L2 | high | BLOCK | A string argument contains a tautology, a UNION SELECT graft, or a stacked destructive statement. SQL-shaped prose alone is not flagged. |
| `L2.SSRF_METADATA` | L2 | critical | BLOCK | A string argument references 169.254.169.254, 169.254.170.2 or metadata.google.internal — the standard credential-theft SSRF target. |
| `L2.CUSTOM_RULE` | L2 | medium | WARN | A custom pattern rule matched a string leaf at a configured argument path. Severity and action come from the rule. |
| `L3.SECRET_IN_RESPONSE` | L3 | critical | BLOCK | A tool result carries an AWS key, PEM private key, JWT, GitHub/Slack/Google token, or a high-entropy string. The finding names the detector, never the value. |
| `L3.RESPONSE_INJECTION` | L3 | high | BLOCK | Tool OUTPUT containing directives aimed at the agent — OWASP's primary indirect prompt-injection technique, since results are rarely reviewed by a human. |

Default action is a function of severity: `critical`/`high` → BLOCK, `medium` → WARN, `low`/`info` →
ALLOW. Decision precedence: any BLOCK finding ⇒ `block`, else any WARN ⇒ `warn`, else `allow`.
Tenants switch individual checks off with `policy.disabledChecks`.

## mcpgrade — the published rubric

`RUBRIC_VERSION = 'mcpgrade-2.0.0'`. One rubric, shared by the runtime, the sidecar CLI and the
andraxpentester.in scanner. The full derivation is documented in `src/mcpgrade.ts`.

Every server starts at **100** and loses points for findings:

| Severity | Points deducted |
| --- | --- |
| critical | 40 |
| high | 20 |
| medium | 8 |
| low | 3 |
| info | 0 |

**Per-check saturation:** any single check id contributes at most **2×** its weight. A server
advertising forty poisoned tools has one defect at scale, not forty defects; without the cap a large
inventory would out-weigh a small malicious server. Breadth of failure — how many *distinct* checks
failed — stays the dominant term.

`score = clamp(100 − total deduction, 0, 100)`, then:

| Grade | Score |
| --- | --- |
| A+ | 100 (clean sheet only) |
| A | 85–99 |
| B | 70–84 |
| C | 55–69 |
| D | 40–54 |
| F | 0–39 |

One critical finding lands at 60 (C). Two distinct criticals land at 20 (F). Any change to weights,
caps or bands requires a `RUBRIC_VERSION` bump, because published grades must stay reproducible.

## ReDoS safety

Tenants author pattern rules from a dashboard, so an unvalidated `(a+)+$` is a self-service denial of
service against the gateway that runs it. `validateRulePattern(pattern)` rejects, **before**
compilation:

- nested quantifiers — a group containing `*`, `+` or `{n,}` that is itself repeated
- alternation under a quantifier whose branches can match the same input (`(ab|ac)+`)
- patterns over 200 characters, repetition bounds over 1000, unbalanced groups, uncompilable sources

The same gate is applied to `pattern` keywords inside a server's own `inputSchema` — a malicious MCP
server is squarely in the threat model. Inspected values are additionally capped at
`MAX_INSPECTED_LENGTH` (4096 characters), so match cost is bounded even for accepted patterns.

## Tests and the attack corpus

`src/corpus/` is the regression suite and the evidence base for every detection claim. Each entry
declares its expected decision and check ids; one table-driven test runs the whole table, and a
separate test asserts that every check in the registry is exercised by at least one entry.

The corpus is deliberately two-sided. The benign half — markdown with fenced shell blocks, `$(...)`
substitution and backticks, pipelines through text utilities, SQL queries and SQL-shaped prose,
CLI-style quoted arguments, ordinary file paths, git SHAs and UUIDs in responses, and user text that
merely *discusses* prompt injection — must produce **zero findings**, not merely `allow`. False
positives are how a security product gets switched to monitor-only, and a monitor-only firewall is a
log shipper.

```
npm test                                       # vitest
npx tsx packages/guard-core/src/benchmark.ts   # measured latency
```

## Benchmark

`src/benchmark.ts` prints measured p50/p95/p99 over a realistic event mix drawn from the corpus.
**There are no hardcoded latency numbers in this repository** — every published figure must cite a run
of this harness on named hardware, and adding a literal is a bug.

## Not implemented here

- **L4 tamper-evident audit** — the hash-chained log requires storage, so it lives in the control
  plane rather than in this pure package.
- **Rate limiting** — stateful by definition; it belongs to the deployment shape holding the counters.
- **JSON Schema `$ref`, `allOf`/`anyOf`/`oneOf`, `$defs`** — deliberately out of the L2 subset. A
  firewall that resolves references is a firewall with a fetch in its hot path.
