/**
 * The sidecar is driven end to end: a real node child process speaking real
 * JSON-RPC over real pipes. Anything less would not exercise the framing, which
 * is where a transparent proxy actually breaks.
 */

import { PassThrough } from 'node:stream';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { lineReader, runProxy, type ProxyHandle } from '../src/proxy.js';

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures/mcp-server.mjs');

interface Session {
  send: (message: unknown) => void;
  sendRaw: (line: string) => void;
  /** Wait for a message from the proxy matching `match`. */
  next: (match: (m: Record<string, unknown>) => boolean, ms?: number) => Promise<Record<string, unknown>>;
  /** Every line the client received, verbatim. */
  lines: string[];
  stderr: () => string;
  handle: ProxyHandle;
  end: () => Promise<void>;
}

const live: Session[] = [];
afterEach(async () => {
  while (live.length) await live.pop()!.end();
});

function session(env: Record<string, string> = {}): Session {
  const toProxy = new PassThrough();
  const fromProxy = new PassThrough();
  const errStream = new PassThrough();

  const lines: string[] = [];
  const messages: Record<string, unknown>[] = [];
  const waiters: { match: (m: Record<string, unknown>) => boolean; resolve: (m: Record<string, unknown>) => void }[] = [];

  const reader = lineReader((line) => {
    lines.push(line);
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      messages.push(parsed);
      for (let i = waiters.length - 1; i >= 0; i--) {
        if (waiters[i].match(parsed)) waiters.splice(i, 1)[0].resolve(parsed);
      }
    } catch {
      /* non-JSON lines are still recorded in `lines` */
    }
  });
  fromProxy.on('data', reader.push);

  let errText = '';
  errStream.on('data', (c: Buffer) => (errText += c.toString()));

  const handle = runProxy({
    command: process.execPath,
    args: [FIXTURE],
    stdin: toProxy,
    stdout: fromProxy,
    stderr: errStream,
    env: { ...process.env, ...env },
  });

  const s: Session = {
    send: (message) => toProxy.write(`${JSON.stringify(message)}\n`),
    sendRaw: (line) => toProxy.write(`${line}\n`),
    lines,
    stderr: () => errText,
    handle,
    next(match, ms = 5_000) {
      const found = messages.find(match);
      if (found) return Promise.resolve(found);
      return new Promise((ok, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for a message')), ms);
        waiters.push({
          match,
          resolve: (m) => {
            clearTimeout(timer);
            ok(m);
          },
        });
      });
    },
    async end() {
      toProxy.end();
      handle.child.kill('SIGTERM');
      await handle.exited;
    },
  };
  live.push(s);
  return s;
}

const settle = () => new Promise((ok) => setTimeout(ok, 250));

describe('stdio sidecar', () => {
  it('passes a clean tools/call through to the child and the result back', async () => {
    const s = session();
    s.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
    s.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: 'README.md' } },
    });

    const reply = (await s.next((m) => m.id === 2)) as { result: { content: { text: string }[] } };
    expect(reply.result.content[0].text).toBe('contents of README.md');
    // stderr is a separate pipe and can lag the stdout reply.
    await settle();
    expect(s.stderr()).toContain('RECV {"jsonrpc":"2.0","id":2');
  });

  it('blocks a poisoned tools/list — the client never sees the inventory', async () => {
    const s = session({ FIXTURE_POISON: '1' });
    s.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });

    const reply = (await s.next((m) => m.id === 1)) as {
      error: { code: number; data: { findings: { check: string }[] } };
    };

    expect(reply.error.code).toBe(-32002);
    expect(reply.error.data.findings.map((f) => f.check)).toContain('L1.TOOL_POISONING');
    // The tool definition itself never crossed to the client.
    expect(s.lines.join('\n')).not.toContain('id_rsa');
    // ...but it did reach the proxy, which is what the child answered.
    await settle();
    expect(s.stderr()).toContain('RECV {"jsonrpc":"2.0","id":1,"method":"tools/list"');
  });

  it('catches a rug pull between two tools/list calls in one session', async () => {
    const s = session({ FIXTURE_RUGPULL: '1' });
    s.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
    const first = (await s.next((m) => m.id === 1)) as { result: { tools: unknown[] } };
    expect(first.result.tools).toHaveLength(1);

    s.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    const second = (await s.next((m) => m.id === 2)) as { error: { data: { findings: { check: string }[] } } };
    expect(second.error.data.findings.map((f) => f.check)).toContain('L1.RUG_PULL');
  });

  it('blocks a path-traversal call before it reaches the child', async () => {
    const s = session();
    s.send({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '../../../../etc/passwd' } },
    });

    const reply = (await s.next((m) => m.id === 5)) as { error: { code: number } };
    expect(reply.error.code).toBe(-32004);
    await settle();
    expect(s.stderr()).not.toContain('etc/passwd');
  });

  it('blocks a tool result carrying credential material', async () => {
    const s = session();
    s.send({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'leak_secret', arguments: {} } });

    const reply = (await s.next((m) => m.id === 6)) as {
      error: { code: number; data: { findings: { check: string; detail: string }[] } };
    };
    expect(reply.error.code).toBe(-32005);
    expect(reply.error.data.findings[0].check).toBe('L3.SECRET_IN_RESPONSE');
    // The finding names the detector, never the credential.
    expect(JSON.stringify(reply)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});

describe('stream integrity', () => {
  it('forwards a line it cannot parse without altering it', async () => {
    const s = session();
    s.sendRaw('this is not json at all');
    await settle();
    expect(s.stderr()).toContain('RECV this is not json at all');
  });

  it('forwards a JSON-RPC batch untouched', async () => {
    const s = session();
    s.sendRaw('[{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}]');
    await settle();
    expect(s.stderr()).toContain('RECV [{"jsonrpc":"2.0","id":9');
  });

  it('forwards an unsolicited server notification to the client verbatim', async () => {
    const s = session();
    s.send({ jsonrpc: '2.0', id: 10, method: 'notify_me', params: {} });

    const note = await s.next((m) => m.method === 'notifications/message');
    expect(note).toEqual({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'hello' } });
  });

  it("keeps the child's stderr flowing to the parent's stderr", async () => {
    const s = session();
    await settle();
    expect(s.stderr()).toContain('mcp-fixture: ready');
  });

  it('exits with the child exit code', async () => {
    const s = session();
    s.handle.child.kill('SIGKILL');
    expect(await s.handle.exited).toBeGreaterThan(0);
  });
});

describe('lineReader', () => {
  it('reassembles messages split across chunks and keeps CRLF bytes', () => {
    const seen: string[] = [];
    const reader = lineReader((line) => seen.push(line));
    reader.push('{"a":1}\r\n{"b":');
    reader.push('2}\n');
    reader.push('tail-without-newline');
    reader.flush();
    expect(seen).toEqual(['{"a":1}\r', '{"b":2}', 'tail-without-newline']);
  });
});
