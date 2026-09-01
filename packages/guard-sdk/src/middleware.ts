/**
 * Integration adapters. The point of these is that embedding Guard is a few
 * lines, not a refactor.
 *
 * Both adapters check BOTH directions. Checking only inbound requests leaves the
 * headline attack — a server mutating its own tool definitions after approval —
 * completely undetected, because a rug pull travels in a `tools/list` RESULT.
 */

import type { GuardEvent, JsonRpcErrorResponse, ToolDefinition, Verdict } from '@guard/core';
import { idOf } from './guard.js';
import type { Guard } from './guard.js';

/* --------------------------------------------------------- Express / Connect */

/** Structural subset of `express.Request`; no @types/express dependency. */
export interface ConnectRequest {
  headers: Record<string, string | string[] | undefined>;
  /** Parsed JSON body — mount `express.json()` before this middleware. */
  body?: unknown;
}

/** Structural subset of `express.Response`. */
export interface ConnectResponse {
  status(code: number): ConnectResponse;
  json(body: unknown): unknown;
}

function lowercaseHeaders(headers: ConnectRequest['headers']): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(',') : v;
  }
  return out;
}

/**
 * Express/Connect middleware for an MCP server exposed over HTTP.
 *
 * ```ts
 * app.post('/mcp', express.json(), expressGuard(guard), handler);
 * ```
 *
 * A blocked call is answered with HTTP 200 and a JSON-RPC error object: the
 * transport succeeded, the application-level call was refused. That is what an
 * MCP client is built to parse.
 */
export function expressGuard(guard: Guard) {
  return function guardMiddleware(req: ConnectRequest, res: ConnectResponse, next: () => void): void {
    const verdict = guard.verify({
      kind: 'request',
      headers: lowercaseHeaders(req.headers),
      body: req.body,
    });
    if (verdict.decision === 'block') {
      res.status(200).json(guard.errorFor(verdict, idOf(req.body)));
      return;
    }
    next();
  };
}

/* ------------------------------------------------------------------- wrap() */

/** A plain MCP request handler: takes a JSON-RPC request, returns its `result`. */
export type McpHandler = (request: Record<string, unknown>) => Promise<unknown> | unknown;

export interface WrapOptions {
  /**
   * Transport headers, when the host has them. Omit for stdio and in-process
   * servers — construct the Guard with `transport: 'stdio'` in that case, so the
   * header-agreement checks are switched off explicitly rather than faked.
   */
  headers?: Record<string, string>;
  /** Called for every non-`allow` verdict; useful for the host's own logging. */
  onVerdict?: (verdict: Verdict, event: GuardEvent) => void;
}

function toolsOf(result: unknown): ToolDefinition[] | undefined {
  if (typeof result !== 'object' || result === null) return undefined;
  const tools = (result as { tools?: unknown }).tools;
  return Array.isArray(tools) ? (tools as ToolDefinition[]) : undefined;
}

/**
 * Wrap a plain MCP handler. Inbound requests are checked (L0/L2), and so is what
 * the handler returns: a `tools/list` result goes through L1 tool integrity —
 * catching a rug pull — and every other result through L3 response DLP.
 *
 * Returns either the handler's result or a JSON-RPC error object.
 */
export function wrap(guard: Guard, handler: McpHandler, options: WrapOptions = {}) {
  const report = (verdict: Verdict, event: GuardEvent) => {
    if (verdict.decision !== 'allow') options.onVerdict?.(verdict, event);
  };

  return async function guardedHandler(request: Record<string, unknown>): Promise<unknown | JsonRpcErrorResponse> {
    const id = idOf(request);

    const requestEvent: GuardEvent = { kind: 'request', headers: options.headers ?? {}, body: request };
    const inbound = guard.verify(requestEvent);
    report(inbound, requestEvent);
    if (inbound.decision === 'block') return guard.errorFor(inbound, id);

    const result = await handler(request);

    const tools = request.method === 'tools/list' ? toolsOf(result) : undefined;
    const outboundEvent: GuardEvent = tools
      ? { kind: 'tools_list', tools }
      : {
          kind: 'response',
          ...(typeof (request.params as { name?: unknown } | undefined)?.name === 'string'
            ? { toolName: (request.params as { name: string }).name }
            : {}),
          body: result,
        };

    const outbound = guard.verify(outboundEvent);
    report(outbound, outboundEvent);
    if (outbound.decision === 'block') return guard.errorFor(outbound, id);
    // L3 redaction, when the policy asked for it, rewrites rather than drops.
    return outbound.redactedBody ?? result;
  };
}
