# Detection checks

SentinelAgent Guard ships **22 deterministic checks across 5 layers**. Every
check is a pure function over the request/response — no model, no network, no
per-call cost. The count in code is authoritative: `checkCount()` returns `22`,
and this table is generated from the same registry (`CHECKS`), so the docs can
never over-claim.

Severities: `critical` · `high` · `medium` · `info`.

## Layer 0 — Protocol conformance
Is this even a valid MCP request? A header that disagrees with the body is how an
attack sneaks a call past a header-routing gateway, so a mismatch is treated as
an attack, not a typo.

| ID | Severity | Catches |
| --- | --- | --- |
| `L0.INVALID_ENVELOPE` | high | Malformed JSON-RPC envelope |
| `L0.HEADER_MISMATCH` | critical | `Mcp-Method` header ≠ body method |
| `L0.NAME_MISMATCH` | critical | `Mcp-Name` header ≠ the target in params |
| `L0.MISSING_NAME_HEADER` | high | `Mcp-Name` absent on a targeted method |
| `L0.UNKNOWN_METHOD` | medium | Method not in the 2026-07-28 method set |
| `L0.DEPRECATED_METHOD` | medium | Method removed in the 2026-07-28 revision |

## Layer 1 — Tool integrity (the headline)
SHA-256 every tool definition and diff it on every listing.

| ID | Severity | Catches |
| --- | --- | --- |
| `L1.RUG_PULL` | critical | Tool definition changed after you approved it |
| `L1.TOOL_POISONING` | critical | Instruction payload embedded in a tool description |
| `L1.UNICODE_CONCEALMENT` | critical | Invisible characters concealing a payload |
| `L1.TOOL_SHADOWING` | high | A description referencing another server's tools |
| `L1.TOOL_REMOVED` | medium | An approved tool no longer advertised |
| `L1.TOOL_ADDED` | info | A tool not present in the approved baseline |

## Layer 2 — Call-time policy
Deny-by-default allowlist; arguments validated against the server's own schema;
pattern rules run only on the real string values at known argument paths.

| ID | Severity | Catches |
| --- | --- | --- |
| `L2.SENSITIVE_FILE_READ` | critical | Argument targets a credential/identity file (e.g. `~/.ssh/id_rsa`) |
| `L2.SHELL_INJECTION` | critical | Command chaining / pipe-to-interpreter in an argument |
| `L2.SSRF_METADATA` | critical | Cloud instance-metadata endpoint in an argument |
| `L2.TOOL_NOT_ALLOWED` | high | Tool is not on the allowlist |
| `L2.PATH_TRAVERSAL` | high | Path traversal in an argument |
| `L2.SQL_INJECTION` | high | SQL-injection shape in an argument |
| `L2.SCHEMA_VIOLATION` | medium | Arguments violate the server's declared `inputSchema` |
| `L2.CUSTOM_RULE` | medium | A rule you authored matched |

## Layer 3 — Response inspection
Scan what a tool returns, before it reaches the agent.

| ID | Severity | Catches |
| --- | --- | --- |
| `L3.SECRET_IN_RESPONSE` | critical | Credential material (AWS keys, tokens, private keys) in a result |
| `L3.RESPONSE_INJECTION` | high | Injected instruction text in a tool result |

## Layer 4 — Tamper-evident audit
Not a "check" that blocks — the runtime records every request as one row whose
hash chains to the previous row, so the log is verifiable, not just asserted.
Available in the hosted SaaS ([guard.sentinelreign.com](https://guard.sentinelreign.com)).

---

The same registry powers the **mcpgrade** rubric (`RUBRIC_VERSION`) used by the
free scanner at [andraxpentester.in](https://andraxpentester.in) and by
`guard-proxy scan`, so a server graded there and a server protected here are held
to one standard.
