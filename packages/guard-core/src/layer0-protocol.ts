/**
 * L0 — JSON-RPC / MCP protocol conformance for the 2026-07-28 revision.
 *
 * This revision is stateless: there is no `initialize` handshake and no
 * `Mcp-Session-Id`. Routing information that used to live in session state now
 * travels in the `Mcp-Method` / `Mcp-Name` headers, which is precisely why a
 * header/body disagreement is an attack signal and not a nit — a gateway that
 * authorises on the header and forwards the body is bypassed by exactly that
 * disagreement.
 *
 * The envelope is validated by hand. guard-core takes no dependencies, and a
 * schema library is a supply-chain surface in a security control's hot path.
 */

import { finding } from './checks.js';
import type { Finding, RequestEvent, Verdict } from './types.js';

/** Methods this spec revision defines. Anything else is unknown surface. */
export const KNOWN_METHODS: readonly string[] = [
  'tools/list',
  'tools/call',
  'resources/list',
  'resources/read',
  'resources/templates/list',
  'prompts/list',
  'prompts/get',
  'server/discover',
  'subscriptions/listen',
  'completion/complete',
];

/** Methods the 2026-07-28 revision REMOVED. Their use means a stale or spoofed client. */
export const REMOVED_METHODS: readonly string[] = [
  'initialize',
  'ping',
  'logging/setLevel',
  'resources/subscribe',
  'resources/unsubscribe',
];

/** Methods that must declare their target in `Mcp-Name`. */
const TARGETED_METHODS: Record<string, 'name' | 'uri'> = {
  'tools/call': 'name',
  'resources/read': 'uri',
  'prompts/get': 'name',
};

/**
 * Firewall block codes. JSON-RPC reserves -32768..-32000 for the protocol and
 * leaves -32099..-32000 implementation-defined; MCP further reserves -32020 and
 * below for itself, so Guard confines itself to -32000..-32019 and never emits
 * anything outside that window.
 */
export const GUARD_ERROR_CODES = {
  /** L0: envelope or conformance failure. */
  PROTOCOL_VIOLATION: -32000,
  /** L0: header/body disagreement — gateway bypass attempt. */
  GATEWAY_BYPASS: -32001,
  /** L1: tool inventory integrity failure (rug pull, poisoning, concealment). */
  TOOL_INTEGRITY: -32002,
  /** L2: tool not permitted by policy. */
  TOOL_NOT_ALLOWED: -32003,
  /** L2: argument rejected by schema or pattern policy. */
  POLICY_VIOLATION: -32004,
  /** L3: egress blocked by data-loss prevention. */
  DLP_BLOCK: -32005,
} as const;

const CODE_MIN = -32019;
const CODE_MAX = -32000;

export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data: { findings: Finding[] } };
}

function codeFor(f: Finding | undefined): number {
  if (!f) return GUARD_ERROR_CODES.PROTOCOL_VIOLATION;
  if (f.check === 'L0.HEADER_MISMATCH' || f.check === 'L0.NAME_MISMATCH') {
    return GUARD_ERROR_CODES.GATEWAY_BYPASS;
  }
  if (f.check === 'L2.TOOL_NOT_ALLOWED') return GUARD_ERROR_CODES.TOOL_NOT_ALLOWED;
  switch (f.layer) {
    case 0:
      return GUARD_ERROR_CODES.PROTOCOL_VIOLATION;
    case 1:
      return GUARD_ERROR_CODES.TOOL_INTEGRITY;
    case 2:
      return GUARD_ERROR_CODES.POLICY_VIOLATION;
    default:
      return GUARD_ERROR_CODES.DLP_BLOCK;
  }
}

/** Render a blocking verdict as a spec-shaped JSON-RPC error response. */
export function toJsonRpcError(verdict: Verdict, id: string | number | null): JsonRpcErrorResponse {
  const blocking = verdict.findings.find((f) => f.action === 'BLOCK') ?? verdict.findings[0];
  const code = codeFor(blocking);
  // Defence in depth: a future code added out of range must not reach the wire.
  const safeCode = code >= CODE_MIN && code <= CODE_MAX ? code : GUARD_ERROR_CODES.PROTOCOL_VIOLATION;
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: safeCode,
      message: blocking ? `Blocked by SentinelAgent Guard: ${blocking.title}` : 'Blocked by SentinelAgent Guard',
      data: { findings: verdict.findings },
    },
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Parsed view of a request, for layers that run after L0. */
export interface ParsedRequest {
  method: string;
  params: Record<string, unknown>;
  id: string | number | null;
}

/** Returns the parsed request when the envelope is well-formed enough to keep inspecting. */
export function parseRequest(body: unknown): ParsedRequest | undefined {
  if (!isPlainObject(body)) return undefined;
  if (typeof body.method !== 'string' || body.method.length === 0) return undefined;
  const id = body.id;
  return {
    method: body.method,
    params: isPlainObject(body.params) ? body.params : {},
    id: typeof id === 'string' || typeof id === 'number' ? id : null,
  };
}

export function checkProtocol(event: RequestEvent): Finding[] {
  const findings: Finding[] = [];
  const body = event.body;

  if (!isPlainObject(body)) {
    findings.push(finding('L0.INVALID_ENVELOPE', 'Request body is not a JSON object.'));
    return findings;
  }
  if (body.jsonrpc !== '2.0') {
    findings.push(
      finding('L0.INVALID_ENVELOPE', `jsonrpc must be the string "2.0" (saw ${JSON.stringify(body.jsonrpc)}).`, {
        path: 'jsonrpc',
      }),
    );
  }
  if (typeof body.method !== 'string' || body.method.length === 0) {
    findings.push(finding('L0.INVALID_ENVELOPE', 'method must be a non-empty string.', { path: 'method' }));
    return findings; // Nothing downstream can be judged without a method.
  }
  if (body.params !== undefined && !isPlainObject(body.params)) {
    findings.push(finding('L0.INVALID_ENVELOPE', 'params, when present, must be an object.', { path: 'params' }));
  }

  const method = body.method;
  const params = isPlainObject(body.params) ? body.params : {};

  // --- Header/body agreement -------------------------------------------------
  // Headers arrive lowercased per the RequestEvent contract.
  const headerMethod = event.headers['mcp-method'];
  if (headerMethod !== undefined && headerMethod !== method) {
    findings.push(
      finding(
        'L0.HEADER_MISMATCH',
        `Mcp-Method header declares "${headerMethod}" but the body invokes "${method}". A header-routing gateway would authorise the former and forward the latter.`,
        { path: 'headers.mcp-method' },
      ),
    );
  }

  const targetKey = TARGETED_METHODS[method];
  if (targetKey) {
    const headerName = event.headers['mcp-name'];
    const target = params[targetKey];
    if (headerName === undefined) {
      findings.push(
        finding('L0.MISSING_NAME_HEADER', `${method} requires an Mcp-Name header declaring params.${targetKey}.`, {
          path: 'headers.mcp-name',
        }),
      );
    } else if (typeof target === 'string' && headerName !== target) {
      findings.push(
        finding(
          'L0.NAME_MISMATCH',
          `Mcp-Name header declares "${headerName}" but params.${targetKey} is "${target}".`,
          { path: 'headers.mcp-name' },
        ),
      );
    }
  }

  // --- Method surface --------------------------------------------------------
  if (REMOVED_METHODS.includes(method)) {
    findings.push(
      finding('L0.DEPRECATED_METHOD', `"${method}" was removed in the 2026-07-28 revision.`, { path: 'method' }),
    );
  } else if (!KNOWN_METHODS.includes(method) && !method.startsWith('notifications/')) {
    findings.push(
      finding('L0.UNKNOWN_METHOD', `"${method}" is not defined by the 2026-07-28 revision.`, { path: 'method' }),
    );
  }

  return findings;
}
