/**
 * The check registry — the single source of truth for what this engine detects.
 *
 * Every `Finding.check` emitted anywhere in guard-core MUST appear here, and the
 * UI reads `checkCount()` rather than a literal. The prototype advertised "39
 * checks" while shipping 9 rules; a registry that both the detectors and the
 * marketing surface read from makes that drift impossible to reproduce.
 */

import type { CheckDescriptor, Finding, RuleAction, Severity } from './types.js';

export const CHECKS: CheckDescriptor[] = [
  /* ---------------------------------------------------------------- L0 --- */
  {
    id: 'L0.INVALID_ENVELOPE',
    layer: 0,
    severity: 'high',
    title: 'Malformed JSON-RPC envelope',
    description:
      'Body is not a JSON-RPC 2.0 request: missing or wrong `jsonrpc`, absent/empty `method`, or `params` that is not an object.',
  },
  {
    id: 'L0.HEADER_MISMATCH',
    layer: 0,
    severity: 'critical',
    title: 'Mcp-Method header does not match body method',
    description:
      'The routing header disagrees with the JSON-RPC method. This is how a call is smuggled past a header-routing gateway, so it is treated as an attack signal rather than a spec nit.',
  },
  {
    id: 'L0.NAME_MISMATCH',
    layer: 0,
    severity: 'critical',
    title: 'Mcp-Name header does not match the target in params',
    description:
      'Declared target name disagrees with `params.name` (or `params.uri` for resources/read) — the same smuggling class as a method mismatch, one level down.',
  },
  {
    id: 'L0.MISSING_NAME_HEADER',
    layer: 0,
    severity: 'high',
    title: 'Mcp-Name header absent on a targeted method',
    description:
      'tools/call, resources/read and prompts/get MUST declare their target in Mcp-Name so a gateway can authorise it without parsing the body.',
  },
  {
    id: 'L0.UNKNOWN_METHOD',
    layer: 0,
    severity: 'medium',
    title: 'Method is not in the 2026-07-28 method set',
    description:
      'Method is outside the known-method allowlist for this spec revision. Unknown surface cannot be policy-checked.',
  },
  {
    id: 'L0.DEPRECATED_METHOD',
    layer: 0,
    severity: 'medium',
    title: 'Method was removed in the 2026-07-28 revision',
    description:
      'initialize, ping, logging/setLevel, resources/subscribe and resources/unsubscribe no longer exist. Their use indicates a stale or spoofed client.',
  },

  /* ---------------------------------------------------------------- L1 --- */
  {
    id: 'L1.RUG_PULL',
    layer: 1,
    severity: 'critical',
    title: 'Tool definition changed after approval',
    description:
      'A previously approved tool now hashes differently — its name, description or inputSchema was mutated post-approval (CVE-2025-54136 class rug pull).',
  },
  {
    id: 'L1.TOOL_ADDED',
    layer: 1,
    severity: 'info',
    title: 'Tool not present in the approved baseline',
    description: 'The server advertised a tool that was not in the frozen inventory.',
  },
  {
    id: 'L1.TOOL_REMOVED',
    layer: 1,
    severity: 'medium',
    title: 'Approved tool no longer advertised',
    description:
      'A tool in the baseline has disappeared. Benign on a deploy, but also how an attacker frees a name for a shadowing tool.',
  },
  {
    id: 'L1.TOOL_POISONING',
    layer: 1,
    severity: 'critical',
    title: 'Instruction payload embedded in a tool description',
    description:
      'The description carries text aimed at the agent rather than at the operator: pseudo-tags, secrecy directives, instruction overrides, or a long embedded base64 blob.',
  },
  {
    id: 'L1.UNICODE_CONCEALMENT',
    layer: 1,
    severity: 'critical',
    title: 'Invisible characters concealing payload in a tool definition',
    description:
      'Unicode TAG block (U+E0000–U+E007F), zero-width, bidi override or private-use characters hide text from the human approval dialog while the model still reads it.',
  },
  {
    id: 'L1.TOOL_SHADOWING',
    layer: 1,
    severity: 'high',
    title: 'Tool description references another server’s tools',
    description:
      'A description naming tools from a different server is the cross-server shadowing precondition: it redirects calls intended for a trusted server.',
  },

  /* ---------------------------------------------------------------- L2 --- */
  {
    id: 'L2.TOOL_NOT_ALLOWED',
    layer: 2,
    severity: 'high',
    title: 'Tool is not on the allowlist',
    description: 'Deny-by-default: when an allowlist is configured, unlisted tools cannot be called.',
  },
  {
    id: 'L2.SCHEMA_VIOLATION',
    layer: 2,
    severity: 'medium',
    title: 'Arguments violate the server’s declared inputSchema',
    description:
      'Arguments are validated against the schema the server itself published, so the server is held to its own contract instead of a guessed one.',
  },
  {
    id: 'L2.PATH_TRAVERSAL',
    layer: 2,
    severity: 'high',
    title: 'Path traversal in an argument',
    description: 'A string argument contains a `..` path segment, raw or percent-encoded.',
  },
  {
    id: 'L2.SENSITIVE_FILE_READ',
    layer: 2,
    severity: 'critical',
    title: 'Argument targets a credential or identity file',
    description: 'A string argument references /etc/passwd, /etc/shadow, an SSH private key, or cloud credential files.',
  },
  {
    id: 'L2.SHELL_INJECTION',
    layer: 2,
    severity: 'critical',
    title: 'Command chaining or pipe-to-interpreter in an argument',
    description:
      'A string argument pipes into a shell/interpreter or chains a fetch-and-execute. Ordinary backticks and `$(...)` are NOT flagged — only interpreter and network-fetch targets.',
  },
  {
    id: 'L2.SQL_INJECTION',
    layer: 2,
    severity: 'high',
    title: 'SQL injection shape in an argument',
    description:
      'A string argument contains a tautology, a UNION SELECT graft, or a stacked destructive statement. SQL-shaped prose alone is not flagged.',
  },
  {
    id: 'L2.SSRF_METADATA',
    layer: 2,
    severity: 'critical',
    title: 'Cloud instance-metadata endpoint in an argument',
    description:
      'A string argument references 169.254.169.254, 169.254.170.2 or metadata.google.internal — the standard credential-theft SSRF target.',
  },
  {
    id: 'L2.CUSTOM_RULE',
    layer: 2,
    severity: 'medium',
    title: 'Tenant-authored rule matched',
    description:
      'A custom pattern rule matched a string leaf at a configured argument path. Severity and action come from the rule.',
  },

  /* ---------------------------------------------------------------- L3 --- */
  {
    id: 'L3.SECRET_IN_RESPONSE',
    layer: 3,
    severity: 'critical',
    title: 'Credential material in a tool result',
    description:
      'A tool result carries an AWS key, PEM private key, JWT, GitHub/Slack/Google token, or a high-entropy string. The finding names the detector, never the value.',
  },
  {
    id: 'L3.RESPONSE_INJECTION',
    layer: 3,
    severity: 'high',
    title: 'Instruction text in a tool result',
    description:
      'Tool OUTPUT containing directives aimed at the agent — OWASP’s primary indirect prompt-injection technique, since results are rarely reviewed by a human.',
  },
];

const BY_ID = new Map(CHECKS.map((c) => [c.id, c]));

/** The real number of implemented checks. The UI must call this, never a literal. */
export function checkCount(): number {
  return CHECKS.length;
}

export function getCheck(id: string): CheckDescriptor | undefined {
  return BY_ID.get(id);
}

/**
 * Default enforcement per severity. Kept as a function of severity rather than a
 * per-check column so a check can never claim a severity its action contradicts.
 */
export function actionForSeverity(severity: Severity): RuleAction {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'BLOCK';
    case 'medium':
      return 'WARN';
    default:
      return 'ALLOW';
  }
}

/**
 * Build a Finding from a registered check id. Throws on an unregistered id so an
 * unregistered check cannot reach production — the registry stays honest by
 * construction rather than by review.
 */
export function finding(
  id: string,
  detail: string,
  extra?: { path?: string; severity?: Severity; action?: RuleAction },
): Finding {
  const descriptor = BY_ID.get(id);
  if (!descriptor) throw new Error(`guard-core: finding references unregistered check "${id}"`);
  const severity = extra?.severity ?? descriptor.severity;
  return {
    check: descriptor.id,
    layer: descriptor.layer,
    severity,
    title: descriptor.title,
    detail,
    action: extra?.action ?? actionForSeverity(severity),
    ...(extra?.path === undefined ? {} : { path: extra.path }),
  };
}
