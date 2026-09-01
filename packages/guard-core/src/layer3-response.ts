/**
 * L3 — egress DLP on tool results.
 *
 * Two distinct risks travel in the same direction. A tool result can carry
 * credential material out of the customer's environment and into a model
 * context (and from there into a transcript, a log, a training set). And a tool
 * result can carry INSTRUCTIONS: OWASP's primary indirect prompt-injection
 * technique, effective precisely because nobody reads tool output.
 *
 * Invariant: a Finding.detail names the detector and the path. It never contains
 * the matched value — findings are written to the audit log, and a DLP alert
 * that quotes the secret has moved the secret rather than stopped it.
 */

import { finding } from './checks.js';
import type { Finding, GuardPolicy, ResponseEvent, Severity } from './types.js';

const MAX_SCAN_LENGTH = 64 * 1024;
const MAX_DEPTH = 12;

/* -------------------------------------------------------------- detectors */

interface SecretDetector {
  name: string;
  re: RegExp;
}

/** Order matters only for reporting; every detector runs. */
const SECRET_DETECTORS: SecretDetector[] = [
  { name: 'AWS_ACCESS_KEY', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'PRIVATE_KEY', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'GITHUB_TOKEN', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: 'SLACK_TOKEN', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'GOOGLE_API_KEY', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

/** Candidate tokens for the entropy check: secret-shaped runs, nothing else. */
const ENTROPY_CANDIDATE = /[A-Za-z0-9+/=_-]{32,}/g;
const ENTROPY_MIN_LENGTH = 32;
/**
 * Shannon entropy in bits per character. A uniformly random hex string tops out
 * at log2(16) = 4.0, so 4.5 deliberately excludes hashes and IDs (not secrets,
 * and the dominant false-positive source) while random base64/base62 key
 * material lands near 5.5–6.0.
 */
const ENTROPY_THRESHOLD = 4.5;

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

interface SecretHit {
  detector: string;
  start: number;
  end: number;
}

function scanSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  for (const det of SECRET_DETECTORS) {
    det.re.lastIndex = 0;
    for (const m of text.matchAll(det.re)) {
      if (m.index === undefined) continue;
      hits.push({ detector: det.name, start: m.index, end: m.index + m[0].length });
    }
  }
  ENTROPY_CANDIDATE.lastIndex = 0;
  for (const m of text.matchAll(ENTROPY_CANDIDATE)) {
    const start = m.index;
    if (start === undefined) continue;
    const token = m[0];
    if (token.length < ENTROPY_MIN_LENGTH) continue;
    const end = start + token.length;
    // Skip spans a named detector already claimed — one finding per secret.
    if (hits.some((h) => start < h.end && end > h.start)) continue;
    if (shannonEntropy(token) >= ENTROPY_THRESHOLD) {
      hits.push({ detector: 'HIGH_ENTROPY_STRING', start, end });
    }
  }
  return hits.sort((a, b) => a.start - b.start);
}

function redact(text: string, hits: SecretHit[]): string {
  // Right to left so earlier offsets stay valid.
  let out = text;
  for (const h of [...hits].sort((a, b) => b.start - a.start)) {
    out = `${out.slice(0, h.start)}[REDACTED:${h.detector}]${out.slice(h.end)}`;
  }
  return out;
}

/* ------------------------------------------------------- response injection */

const INJECTION_PATTERNS: { re: RegExp; what: string }[] = [
  {
    re: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|rules?)/i,
    what: 'an instruction override',
  },
  {
    re: /\bdisregard\s+(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|policy)/i,
    what: 'a system-prompt override',
  },
  { re: /<\s*\/?\s*(?:important|system|instructions?|admin)\s*>/i, what: 'a pseudo-tag instruction block' },
  { re: /\b(?:new|updated|additional)\s+(?:system\s+)?instructions?\s*:/i, what: 'an injected instruction preamble' },
  {
    re: /\bdo\s*n[o']?t\s+(?:tell|inform|mention|reveal|disclose)\b[^.]{0,40}\b(?:the\s+)?user\b/i,
    what: 'a secrecy directive',
  },
  {
    re: /\b(?:ai\s+)?(?:assistant|agent|model|llm|claude|chatgpt)\s*[,:]\s*(?:you|please|now|immediately)\b/i,
    what: 'text addressed to the assistant',
  },
];

/* ---------------------------------------------------------------- traversal */

interface Located {
  path: string;
  value: string;
}

function collectStrings(node: unknown, path: string, depth: number, out: Located[]): void {
  if (out.length >= 512 || depth > MAX_DEPTH) return;
  if (typeof node === 'string') {
    out.push({ path, value: node.slice(0, MAX_SCAN_LENGTH) });
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((item, i) => collectStrings(item, `${path}[${i}]`, depth + 1, out));
    return;
  }
  if (node !== null && typeof node === 'object') {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      collectStrings(v, `${path}.${k}`, depth + 1, out);
    }
  }
}

function mapStrings(node: unknown, fn: (s: string) => string, depth = 0): unknown {
  if (depth > MAX_DEPTH) return node;
  if (typeof node === 'string') return fn(node);
  if (Array.isArray(node)) return node.map((item) => mapStrings(item, fn, depth + 1));
  if (node !== null && typeof node === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) out[k] = mapStrings(v, fn, depth + 1);
    return out;
  }
  return node;
}

/* ---------------------------------------------------------------- evaluation */

export interface ResponseResult {
  findings: Finding[];
  /** Present only when redaction was requested AND something was redacted. */
  redactedBody?: unknown;
}

export function checkResponse(event: ResponseEvent, policy: GuardPolicy): ResponseResult {
  const findings: Finding[] = [];
  const strings: Located[] = [];
  collectStrings(event.body, 'body', 0, strings);

  const where = event.toolName ? ` returned by "${event.toolName}"` : '';
  let sawSecret = false;

  for (const { path, value } of strings) {
    const hits = scanSecrets(value);
    if (hits.length > 0) {
      sawSecret = true;
      const byDetector = [...new Set(hits.map((h) => h.detector))].join(', ');
      findings.push(
        finding(
          'L3.SECRET_IN_RESPONSE',
          // Detector names and a count only — never the matched text.
          `${hits.length} credential match(es) at ${path}${where}: ${byDetector}.`,
          {
            path,
            // Redaction removes the material, so the call need not be dropped;
            // without it the only safe move is to stop the response.
            ...(policy.redactSecrets ? { severity: 'medium' as Severity, action: 'WARN' as const } : {}),
          },
        ),
      );
    }

    for (const { re, what } of INJECTION_PATTERNS) {
      if (re.test(value)) {
        findings.push(
          finding('L3.RESPONSE_INJECTION', `Tool output at ${path}${where} contains ${what}.`, { path }),
        );
        break;
      }
    }
  }

  if (policy.redactSecrets && sawSecret) {
    return { findings, redactedBody: mapStrings(event.body, (s) => redact(s, scanSecrets(s))) };
  }
  return { findings };
}
