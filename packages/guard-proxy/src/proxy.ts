/**
 * The stdio sidecar.
 *
 * `guard-proxy -- node ./my-server.js` spawns the MCP server as a child and sits
 * transparently between the client and that child. stdio is the transport no
 * hosted proxy can reach, and it is how Cursor, Claude Code and Copilot actually
 * load MCP servers — auto-executed at developer privilege, with no isolation.
 *
 * Two rules govern everything here:
 *
 *   1. NEVER corrupt the stream. Anything the proxy does not understand — a
 *      non-JSON line, a notification, a batch, a message shape from a future
 *      spec revision — is forwarded byte-for-byte. A firewall that mangles
 *      valid traffic is worse than no firewall.
 *   2. Blocking means answering the CLIENT with a JSON-RPC error, not dropping
 *      the message silently. A client waiting forever on a swallowed id is
 *      indistinguishable from a hung server.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import {
  buildBaseline,
  evaluate,
  toJsonRpcError,
  type GuardPolicyWithSchemas,
  type ToolDefinition,
  type Verdict,
} from '@guard/core';

/**
 * stdio carries no `Mcp-Method` / `Mcp-Name` routing headers, so the
 * header-agreement checks have nothing to compare against. They are switched off
 * explicitly rather than satisfied with headers synthesised from the body, which
 * would make the check pass without testing anything.
 */
export const STDIO_DISABLED_CHECKS = ['L0.MISSING_NAME_HEADER'];

export type Direction = 'client->server' | 'server->client';

export interface ProxyEvent {
  direction: Direction;
  verdict: Verdict;
  method?: string;
  id?: string | number | null;
}

export interface ProxyOptions {
  command: string;
  args?: string[];
  policy?: GuardPolicyWithSchemas;
  /** Client -> proxy. Defaults to `process.stdin`. */
  stdin?: Readable;
  /** Proxy -> client. Defaults to `process.stdout`. */
  stdout?: Writable;
  /** Diagnostics and the child's own stderr. Defaults to `process.stderr`. */
  stderr?: Writable;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  /** Called for every non-`allow` verdict. */
  onEvent?: (event: ProxyEvent) => void;
}

export interface ProxyHandle {
  child: ChildProcessWithoutNullStreams;
  /** Resolves with the child's exit code once it has exited. */
  exited: Promise<number>;
}

/* ------------------------------------------------------------------ framing */

/** Newline-delimited framing. The line is handed on verbatim, `\r` included. */
export function lineReader(onLine: (line: string) => void): {
  push: (chunk: Buffer | string) => void;
  flush: () => void;
} {
  let buffer = '';
  return {
    push(chunk) {
      buffer += chunk.toString();
      let nl = buffer.indexOf('\n');
      while (nl !== -1) {
        onLine(buffer.slice(0, nl));
        buffer = buffer.slice(nl + 1);
        nl = buffer.indexOf('\n');
      }
    },
    flush() {
      // A final line without its terminator is still a message worth delivering.
      if (buffer.length > 0) {
        const rest = buffer;
        buffer = '';
        onLine(rest);
      }
    },
  };
}

function parseMessage(line: string): Record<string, unknown> | undefined {
  const trimmed = line.trim();
  if (trimmed.length === 0 || (trimmed[0] !== '{' && trimmed[0] !== '[')) return undefined;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined; // Batches (arrays) are forwarded untouched.
  } catch {
    return undefined;
  }
}

function idOf(message: Record<string, unknown>): string | number | null {
  const id = message.id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

function toolsOf(result: unknown): ToolDefinition[] | undefined {
  if (typeof result !== 'object' || result === null) return undefined;
  const tools = (result as { tools?: unknown }).tools;
  return Array.isArray(tools) ? (tools as ToolDefinition[]) : undefined;
}

/* -------------------------------------------------------------------- proxy */

export function runProxy(options: ProxyOptions): ProxyHandle {
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;

  const disabled = new Set([...(options.policy?.disabledChecks ?? []), ...STDIO_DISABLED_CHECKS]);
  const policy: GuardPolicyWithSchemas = {
    ...options.policy,
    disabledChecks: [...disabled],
  };

  const child = spawn(options.command, options.args ?? [], {
    stdio: ['pipe', 'pipe', 'pipe'],
    ...(options.env ? { env: options.env } : {}),
    ...(options.cwd ? { cwd: options.cwd } : {}),
  }) as ChildProcessWithoutNullStreams;

  // The child's diagnostics are the operator's diagnostics. Never swallow them.
  child.stderr.pipe(stderr, { end: false });

  const pending = new Map<string | number, { method: string; toolName?: string }>();
  const note = (line: string) => stderr.write(`[guard] ${line}\n`);

  const report = (event: ProxyEvent) => {
    if (event.verdict.decision !== 'allow') options.onEvent?.(event);
  };

  const refuse = (verdict: Verdict, id: string | number | null, why: string) => {
    if (id === null) {
      // JSON-RPC forbids answering a notification, so record it and drop it.
      note(`blocked ${why} (notification, no reply possible)`);
      return;
    }
    stdout.write(`${JSON.stringify(toJsonRpcError(verdict, id))}\n`);
    note(`blocked ${why}: ${verdict.findings.map((f) => f.check).join(', ') || 'policy'}`);
  };

  /* ----------------------------------------------------- client -> server */

  const fromClient = lineReader((line) => {
    const message = parseMessage(line);
    const method = message && typeof message.method === 'string' ? message.method : undefined;

    if (!message || method === undefined) {
      child.stdin.write(`${line}\n`); // Not a request we understand — pass through.
      return;
    }

    const verdict = evaluate({ kind: 'request', headers: {}, body: message }, policy);
    report({ direction: 'client->server', verdict, method, id: idOf(message) });

    if (verdict.decision === 'block') {
      refuse(verdict, idOf(message), `${method} from client`);
      return;
    }

    const id = message.id;
    if (typeof id === 'string' || typeof id === 'number') {
      const params = message.params as { name?: unknown } | undefined;
      pending.set(id, {
        method,
        ...(typeof params?.name === 'string' ? { toolName: params.name } : {}),
      });
    }
    child.stdin.write(`${line}\n`);
  });

  /* ----------------------------------------------------- server -> client */

  const fromServer = lineReader((line) => {
    const message = parseMessage(line);
    if (!message || !('result' in message)) {
      if (message) pending.delete(idOf(message) as string | number); // an error reply closes the id
      stdout.write(`${line}\n`);
      return;
    }

    const id = idOf(message);
    const request = id === null ? undefined : pending.get(id);
    if (id !== null) pending.delete(id);

    const tools = request?.method === 'tools/list' ? toolsOf(message.result) : undefined;
    const verdict = tools
      ? evaluate({ kind: 'tools_list', tools }, policy)
      : evaluate(
          {
            kind: 'response',
            ...(request?.toolName ? { toolName: request.toolName } : {}),
            body: message.result,
          },
          policy,
        );
    report({ direction: 'server->client', verdict, ...(request ? { method: request.method } : {}), id });

    if (verdict.decision === 'block') {
      refuse(verdict, id, `${request?.method ?? 'response'} from server`);
      return;
    }

    // Trust on first use: the first inventory the server advertises becomes the
    // pin, so a mutation later in the session is a rug pull.
    if (tools && !policy.baseline) policy.baseline = buildBaseline(tools);

    if (verdict.redactedBody !== undefined) {
      stdout.write(`${JSON.stringify({ ...message, result: verdict.redactedBody })}\n`);
      return;
    }
    stdout.write(`${line}\n`);
  });

  stdin.on('data', fromClient.push);
  stdin.on('end', () => {
    fromClient.flush();
    child.stdin.end();
  });
  child.stdout.on('data', fromServer.push);
  child.stdout.on('end', fromServer.flush);

  child.on('error', (err) => note(`failed to start "${options.command}": ${err.message}`));

  const exited = new Promise<number>((resolve) => {
    child.on('close', (code, signal) => resolve(code ?? (signal ? 1 : 0)));
    child.on('error', () => resolve(127));
  });

  return { child, exited };
}
