/**
 * L2 — call-time policy.
 *
 * The load-bearing design decision: pattern rules are evaluated against STRING
 * LEAF VALUES at known argument paths, never against `JSON.stringify(body)`.
 * Regexing a serialized blob is what made the prototype block ordinary markdown,
 * shell snippets and SQL-shaped prose — the payload and the envelope were
 * indistinguishable once flattened. Walking to the leaves keeps a `rm -rf` in a
 * code sample (a `content` argument the user typed) distinguishable from a
 * `rm -rf` in a `command` argument, and lets every finding name its path.
 */

import { finding } from './checks.js';
import type { CustomRule, Finding, GuardPolicy, GuardPolicyWithSchemas, Severity } from './types.js';

/** Values longer than this are truncated before any regex touches them. */
export const MAX_INSPECTED_LENGTH = 4096;
const MAX_LEAVES = 512;
const MAX_WALK_DEPTH = 12;
const MAX_SCHEMA_DEPTH = 8;
const MAX_PATTERN_LENGTH = 200;
const MAX_REPETITION_BOUND = 1000;

/* ------------------------------------------------------ ReDoS-safe patterns */

export type PatternValidation = { ok: true } | { ok: false; reason: string };

function quantifierAt(pattern: string, index: number): boolean {
  const c = pattern[index];
  if (c === '*' || c === '+') return true;
  if (c === '{') return /^\{\d+(?:,\d*)?\}/.test(pattern.slice(index));
  return false;
}

/** Unbounded or repeated quantifiers inside a body that is itself repeated. */
function containsQuantifier(body: string): boolean {
  let inClass = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') {
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      continue;
    }
    if (quantifierAt(body, i)) return true;
  }
  return false;
}

/** Split on top-level `|`, ignoring alternation nested in groups or classes. */
function topLevelBranches(body: string): string[] {
  const branches: string[] = [];
  let depth = 0;
  let inClass = false;
  let current = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') {
      current += c + (body[i + 1] ?? '');
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      current += c;
      continue;
    }
    if (c === '[') {
      inClass = true;
      current += c;
      continue;
    }
    if (c === '(') depth++;
    if (c === ')') depth--;
    if (c === '|' && depth === 0) {
      branches.push(current);
      current = '';
      continue;
    }
    current += c;
  }
  branches.push(current);
  return branches;
}

/**
 * Branches that can match the same input make a repeated group ambiguous, which
 * is the exponential case: `(ab|ac)+` against a long non-matching tail.
 * First-character equality is a cheap, conservative proxy for that overlap.
 */
function hasOverlappingAlternation(body: string): boolean {
  const branches = topLevelBranches(body);
  if (branches.length < 2) return false;
  const firsts = branches.map((b) => (b.startsWith('?:') ? b.slice(2) : b).replace(/^\^/, '')[0]);
  const seen = new Set<string>();
  for (const f of firsts) {
    if (f === undefined) return true; // an empty branch matches everything
    if (seen.has(f)) return true;
    seen.add(f);
  }
  return false;
}

/**
 * Reject catastrophic-backtracking shapes BEFORE compilation. Tenants author
 * these regexes from a dashboard; an unvalidated `(a+)+$` there is a
 * self-service denial of service against the gateway that runs it.
 */
export function validateRulePattern(pattern: string): PatternValidation {
  if (pattern.length === 0) return { ok: false, reason: 'pattern is empty' };
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return { ok: false, reason: `pattern exceeds ${MAX_PATTERN_LENGTH} characters` };
  }

  for (const m of pattern.matchAll(/\{(\d+)(?:,(\d*))?\}/g)) {
    const upper = m[2] === undefined || m[2] === '' ? Number(m[1]) : Number(m[2]);
    if (upper > MAX_REPETITION_BOUND) {
      return { ok: false, reason: `repetition bound ${upper} exceeds ${MAX_REPETITION_BOUND}` };
    }
  }

  const openStack: number[] = [];
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') {
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      continue;
    }
    if (c === '(') {
      openStack.push(i);
      continue;
    }
    if (c === ')') {
      const start = openStack.pop();
      if (start === undefined) return { ok: false, reason: 'unbalanced parenthesis' };
      if (!quantifierAt(pattern, i + 1)) continue;
      const body = pattern.slice(start + 1, i);
      if (containsQuantifier(body)) {
        return { ok: false, reason: `nested quantifier: group (${body}) is itself repeated` };
      }
      if (hasOverlappingAlternation(body)) {
        return { ok: false, reason: `overlapping alternation under a quantifier: (${body})` };
      }
    }
  }
  if (openStack.length > 0) return { ok: false, reason: 'unbalanced parenthesis' };
  if (inClass) return { ok: false, reason: 'unterminated character class' };

  try {
    new RegExp(pattern);
  } catch (e) {
    return { ok: false, reason: `not a valid regular expression: ${(e as Error).message}` };
  }
  return { ok: true };
}

// Small cache: the same tenant patterns recur on every request in a session.
const compiled = new Map<string, RegExp | null>();

function compileRule(pattern: string): RegExp | null {
  const cached = compiled.get(pattern);
  if (cached !== undefined) return cached;
  const verdict = validateRulePattern(pattern);
  const re = verdict.ok ? new RegExp(pattern) : null;
  if (compiled.size > 500) compiled.clear();
  compiled.set(pattern, re);
  return re;
}

/* ------------------------------------------------------------- schema subset */

export interface SchemaViolation {
  path: string;
  message: string;
}

function typeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function typeMatches(declared: string, value: unknown): boolean {
  const actual = typeOf(value);
  if (declared === 'number') return actual === 'number' || actual === 'integer';
  if (declared === 'integer') return actual === 'integer';
  return declared === actual;
}

/**
 * A deliberately small JSON Schema 2020-12 subset: type, required, properties,
 * enum, items, minimum/maximum, minLength/maxLength, pattern,
 * additionalProperties. No `$ref`, no composition keywords — a firewall that
 * resolves references is a firewall with a fetch in its hot path.
 */
export function validateAgainstSchema(
  value: unknown,
  schema: Record<string, unknown>,
  path: string,
  depth = 0,
): SchemaViolation[] {
  if (depth > MAX_SCHEMA_DEPTH) return [];
  const out: SchemaViolation[] = [];

  const declared = schema.type;
  if (typeof declared === 'string' && !typeMatches(declared, value)) {
    out.push({ path, message: `expected ${declared}, got ${typeOf(value)}` });
    return out; // Further keywords are meaningless against the wrong type.
  }
  if (Array.isArray(declared) && !declared.some((t) => typeof t === 'string' && typeMatches(t, value))) {
    out.push({ path, message: `expected one of ${declared.join('|')}, got ${typeOf(value)}` });
    return out;
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((allowed) => allowed === value)) {
    out.push({ path, message: `value is not one of the ${schema.enum.length} permitted enum values` });
  }

  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) {
      out.push({ path, message: `${value} is below minimum ${schema.minimum}` });
    }
    if (typeof schema.maximum === 'number' && value > schema.maximum) {
      out.push({ path, message: `${value} is above maximum ${schema.maximum}` });
    }
  }

  if (typeof value === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) {
      out.push({ path, message: `length ${value.length} is below minLength ${schema.minLength}` });
    }
    if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) {
      out.push({ path, message: `length ${value.length} exceeds maxLength ${schema.maxLength}` });
    }
    if (typeof schema.pattern === 'string') {
      // The server authored this pattern; it gets the same ReDoS gate a tenant
      // rule does, because a malicious server is exactly our threat model.
      const re = compileRule(schema.pattern);
      if (re && !re.test(value.slice(0, MAX_INSPECTED_LENGTH))) {
        out.push({ path, message: 'value does not match the declared pattern' });
      }
    }
  }

  if (Array.isArray(value) && schema.items && typeof schema.items === 'object') {
    const items = schema.items as Record<string, unknown>;
    value.forEach((item, i) => out.push(...validateAgainstSchema(item, items, `${path}[${i}]`, depth + 1)));
  }

  if (typeOf(value) === 'object') {
    const obj = value as Record<string, unknown>;
    const properties = (schema.properties ?? {}) as Record<string, unknown>;
    if (Array.isArray(schema.required)) {
      for (const key of schema.required) {
        if (typeof key === 'string' && !(key in obj)) {
          out.push({ path: `${path}.${key}`, message: 'required property is missing' });
        }
      }
    }
    for (const [key, child] of Object.entries(obj)) {
      const sub = properties[key];
      if (sub && typeof sub === 'object') {
        out.push(...validateAgainstSchema(child, sub as Record<string, unknown>, `${path}.${key}`, depth + 1));
      } else if (schema.additionalProperties === false) {
        out.push({ path: `${path}.${key}`, message: 'property is not declared and additionalProperties is false' });
      }
    }
  }

  return out;
}

/* ------------------------------------------------------------- leaf walking */

export interface StringLeaf {
  /** Full dotted path for reporting, e.g. `params.arguments.path`. */
  path: string;
  /** Path relative to the arguments object, for CustomRule.argumentPaths. */
  relative: string;
  value: string;
}

export function collectStringLeaves(root: unknown, prefix: string): StringLeaf[] {
  const leaves: StringLeaf[] = [];
  const walk = (node: unknown, path: string, relative: string, depth: number): void => {
    if (leaves.length >= MAX_LEAVES || depth > MAX_WALK_DEPTH) return;
    if (typeof node === 'string') {
      leaves.push({ path, relative, value: node.slice(0, MAX_INSPECTED_LENGTH) });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`, relative, depth + 1));
      return;
    }
    if (node !== null && typeof node === 'object') {
      for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
        walk(child, `${path}.${key}`, relative ? `${relative}.${key}` : key, depth + 1);
      }
    }
  };
  walk(root, prefix, '', 0);
  return leaves;
}

/* ----------------------------------------------------- built-in argument rules */

/**
 * Each pattern is deliberately narrow. `$(date)` in a markdown sample and
 * `SELECT * FROM users` in prose must pass; only interpreter targets, network
 * fetch-and-execute, and genuine injection shapes are flagged.
 */
const ARGUMENT_RULES: { check: string; re: RegExp; what: string }[] = [
  { check: 'L2.PATH_TRAVERSAL', re: /(?:^|[/\\])\.\.(?:[/\\]|$)/, what: 'a `..` path segment' },
  { check: 'L2.PATH_TRAVERSAL', re: /%2e%2e(?:%2f|%5c|\/)/i, what: 'a percent-encoded `..` path segment' },

  { check: 'L2.SENSITIVE_FILE_READ', re: /\/etc\/(?:passwd|shadow|sudoers)\b/i, what: 'a system identity file' },
  { check: 'L2.SENSITIVE_FILE_READ', re: /\bid_(?:rsa|dsa|ecdsa|ed25519)\b/, what: 'an SSH private key' },
  { check: 'L2.SENSITIVE_FILE_READ', re: /(?:^|[/\\])\.ssh[/\\]/, what: 'the SSH configuration directory' },
  { check: 'L2.SENSITIVE_FILE_READ', re: /(?:^|[/\\])\.aws[/\\]credentials\b/, what: 'AWS credentials' },

  { check: 'L2.SHELL_INJECTION', re: /\|\s*(?:sudo\s+)?(?:ba|z|k|a|c)?sh\b/, what: 'a pipe into a shell' },
  { check: 'L2.SHELL_INJECTION', re: /\|\s*(?:python3?|perl|ruby|node|php)\b/, what: 'a pipe into an interpreter' },
  { check: 'L2.SHELL_INJECTION', re: /[;&]{1,2}\s*rm\s+-[a-z]*[rf]/, what: 'a chained recursive delete' },
  {
    check: 'L2.SHELL_INJECTION',
    re: /[;&]{1,2}\s*(?:curl|wget|nc|ncat)\s+\S/i,
    what: 'a chained network fetch',
  },
  {
    check: 'L2.SHELL_INJECTION',
    re: /[$`]\(?\s*(?:curl|wget|nc|ncat)\s+\S/i,
    what: 'command substitution invoking a network fetch',
  },

  { check: 'L2.SQL_INJECTION', re: /'\s*(?:or|and)\s+(?:'?[\w]+'?\s*=\s*'?[\w]+'?)/i, what: 'a quoted tautology' },
  { check: 'L2.SQL_INJECTION', re: /\bunion\s+(?:all\s+)?select\b/i, what: 'a UNION SELECT graft' },
  {
    check: 'L2.SQL_INJECTION',
    re: /;\s*(?:drop|truncate)\s+table\b|;\s*delete\s+from\b/i,
    what: 'a stacked destructive statement',
  },
  // Deliberately requires the comment to abut the quote (`admin'--`) or follow a
  // statement terminator (`admin'; --`). A bare `' --` would flag ordinary CLI
  // argument strings such as `--name='x' --verbose`.
  { check: 'L2.SQL_INJECTION', re: /'--|'\s*;\s*--/, what: 'a quote-terminated comment' },

  {
    check: 'L2.SSRF_METADATA',
    re: /\b169\.254\.(?:169\.254|170\.2)\b/,
    what: 'the cloud instance-metadata address',
  },
  { check: 'L2.SSRF_METADATA', re: /\bmetadata\.google\.internal\b/i, what: 'the GCP metadata host' },
  { check: 'L2.SSRF_METADATA', re: /\[fd00:ec2::254\]|\bfd00:ec2::254\b/i, what: 'the EC2 IMDSv6 metadata address' },
];

/* ---------------------------------------------------------------- evaluation */

function severityFor(action: CustomRule['action']): Severity {
  return action === 'BLOCK' ? 'high' : action === 'WARN' ? 'medium' : 'info';
}

function ruleApplies(rule: CustomRule, leaf: StringLeaf): boolean {
  if (!rule.argumentPaths || rule.argumentPaths.length === 0) return true;
  return rule.argumentPaths.some((p) => leaf.relative === p || leaf.relative.startsWith(`${p}.`));
}

/**
 * @param method    the JSON-RPC method being invoked
 * @param params    the request params (already known to be an object)
 * @param policy    tenant policy; `toolSchemas` is read when present
 */
export function checkPolicy(method: string, params: Record<string, unknown>, policy: GuardPolicy): Finding[] {
  const findings: Finding[] = [];
  const toolName = typeof params.name === 'string' ? params.name : undefined;

  // --- deny-by-default allowlist --------------------------------------------
  if (method === 'tools/call' && policy.toolAllowlist && policy.toolAllowlist.length > 0) {
    if (!toolName || !policy.toolAllowlist.includes(toolName)) {
      findings.push(
        finding('L2.TOOL_NOT_ALLOWED', `"${toolName ?? '(unnamed)'}" is not on the ${policy.toolAllowlist.length}-tool allowlist.`, {
          path: 'params.name',
        }),
      );
    }
  }

  // --- the server's own declared contract ------------------------------------
  const schemas = (policy as GuardPolicyWithSchemas).toolSchemas;
  if (method === 'tools/call' && toolName && schemas?.[toolName]) {
    for (const v of validateAgainstSchema(params.arguments ?? {}, schemas[toolName], 'params.arguments')) {
      findings.push(finding('L2.SCHEMA_VIOLATION', `${v.path}: ${v.message}`, { path: v.path }));
    }
  }

  // --- pattern rules, per string leaf ----------------------------------------
  const [root, prefix] =
    method === 'tools/call' ? [params.arguments, 'params.arguments'] : [params, 'params'];
  const leaves = collectStringLeaves(root, prefix);

  for (const leaf of leaves) {
    const seen = new Set<string>();
    for (const rule of ARGUMENT_RULES) {
      if (seen.has(rule.check)) continue;
      if (rule.re.test(leaf.value)) {
        seen.add(rule.check);
        findings.push(finding(rule.check, `Argument at ${leaf.path} contains ${rule.what}.`, { path: leaf.path }));
      }
    }

    for (const rule of policy.customRules ?? []) {
      if (!rule.enabled || !ruleApplies(rule, leaf)) continue;
      const re = compileRule(rule.pattern);
      if (!re) continue; // Rejected by the ReDoS gate; surfaced at rule-save time.
      if (re.test(leaf.value)) {
        const severity = severityFor(rule.action);
        findings.push(
          finding('L2.CUSTOM_RULE', `Rule "${rule.name}" (${rule.id}) matched at ${leaf.path}.`, {
            path: leaf.path,
            severity,
            action: rule.action,
          }),
        );
      }
    }
  }

  return findings;
}
