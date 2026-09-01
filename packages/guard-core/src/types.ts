/**
 * SentinelAgent Guard — public engine contract.
 *
 * Every deployment shape (hosted gateway, embedded SDK, sidecar CLI, scanner)
 * evaluates traffic through this one interface. Detection logic lives ONLY in
 * guard-core; if two shapes disagree about a verdict, that is a bug.
 *
 * The engine is pure: no I/O, no network, no clock beyond what is passed in.
 */

/* -------------------------------------------------------------------------- */
/* MCP protocol shapes (2026-07-28 revision)                                   */
/* -------------------------------------------------------------------------- */

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

/** A tool exactly as a server advertises it in `tools/list`. */
export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  [k: string]: unknown;
}

/* -------------------------------------------------------------------------- */
/* Engine input                                                                */
/* -------------------------------------------------------------------------- */

/** Layer 0/2: an inbound JSON-RPC call, with the transport headers that framed it. */
export interface RequestEvent {
  kind: 'request';
  /** Lowercased header names. `mcp-method` / `mcp-name` drive L0 conformance. */
  headers: Record<string, string>;
  body: unknown;
}

/** Layer 1: the tool inventory a server just advertised. */
export interface ToolsListEvent {
  kind: 'tools_list';
  tools: ToolDefinition[];
}

/** Layer 3: a tool result travelling back toward the agent. */
export interface ResponseEvent {
  kind: 'response';
  /** The tool whose result this is, when known. */
  toolName?: string;
  body: unknown;
}

export type GuardEvent = RequestEvent | ToolsListEvent | ResponseEvent;

/* -------------------------------------------------------------------------- */
/* Policy — what a tenant configures from the dashboard                        */
/* -------------------------------------------------------------------------- */

export type RuleAction = 'BLOCK' | 'WARN' | 'ALLOW';

/** A tenant-authored pattern rule. Patterns are validated before compilation. */
export interface CustomRule {
  id: string;
  name: string;
  /** JavaScript regular expression source. */
  pattern: string;
  action: RuleAction;
  enabled: boolean;
  /**
   * Restrict the rule to specific argument paths (e.g. `path`, `query.q`).
   * Empty means: apply to every string leaf. Rules are NEVER run against a
   * blind JSON.stringify of the body — that is what produced false positives
   * on ordinary markdown and shell snippets in the prototype.
   */
  argumentPaths?: string[];
}

/** The frozen tool inventory a server was approved with, keyed by tool name. */
export type ToolBaseline = Record<string, { hash: string; description?: string }>;

export interface GuardPolicy {
  /** Deny-by-default: when non-empty, only these tools may be called. */
  toolAllowlist?: string[];
  /** Built-in checks the tenant has switched off, by check id. */
  disabledChecks?: string[];
  customRules?: CustomRule[];
  /** Baseline for rug-pull detection. Absent means "first sighting". */
  baseline?: ToolBaseline;
  /** Names of tools belonging to OTHER servers, for shadowing detection. */
  foreignToolNames?: string[];
  /** Block, or only report, on response-side secret detection. */
  redactSecrets?: boolean;
}

/**
 * ADDITIVE (does not alter any shape above): the `inputSchema` each tool
 * declared, keyed by tool name. L2 validates arguments against the server's own
 * published contract, so this is carried alongside the policy rather than being
 * re-derived. Callers may pass this anywhere a `GuardPolicy` is accepted.
 */
export interface GuardPolicyWithSchemas extends GuardPolicy {
  toolSchemas?: Record<string, Record<string, unknown>>;
}

/* -------------------------------------------------------------------------- */
/* Engine output                                                               */
/* -------------------------------------------------------------------------- */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Decision = 'allow' | 'warn' | 'block';

export interface Finding {
  /** Stable identifier, e.g. `L1.RUG_PULL`. Referenced by docs and the rubric. */
  check: string;
  layer: 0 | 1 | 2 | 3;
  severity: Severity;
  title: string;
  /** Human-readable specifics. Must never contain a raw secret value. */
  detail: string;
  action: RuleAction;
  /** Where in the payload the finding sits, e.g. `params.arguments.path`. */
  path?: string;
}

export interface Verdict {
  decision: Decision;
  findings: Finding[];
  /** Populated by L3 when redaction is enabled. */
  redactedBody?: unknown;
}

/* -------------------------------------------------------------------------- */
/* Check registry — the single source of truth for "how many checks"           */
/* -------------------------------------------------------------------------- */

export interface CheckDescriptor {
  id: string;
  layer: 0 | 1 | 2 | 3;
  severity: Severity;
  title: string;
  /** One-line description published in the docs and the mcpgrade rubric. */
  description: string;
}

/* -------------------------------------------------------------------------- */
/* mcpgrade — the published rubric                                             */
/* -------------------------------------------------------------------------- */

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface GradeReport {
  grade: Grade;
  /** 0-100. Deterministic function of the findings below. */
  score: number;
  rubricVersion: string;
  findings: Finding[];
}
