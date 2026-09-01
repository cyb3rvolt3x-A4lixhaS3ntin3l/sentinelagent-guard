/**
 * `guard-proxy scan <url|command...>` — the free scan.
 *
 * It connects to an MCP server, pulls `tools/list`, runs L1 tool integrity, and
 * prints an mcpgrade report. This is the top of the funnel, and it shares one
 * rubric with the hosted product, so the output has to be honest and
 * reproducible: the same inventory always yields the same score, and a server
 * whose inventory could not be retrieved is reported as an error rather than
 * graded A+ on an empty list.
 */

import { spawn } from 'node:child_process';
import {
  evaluate,
  grade,
  RUBRIC_VERSION,
  type Finding,
  type GradeReport,
  type Severity,
  type ToolDefinition,
} from '@guard/core';
import { lineReader } from './proxy.js';

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export type Target = { kind: 'http'; url: string } | { kind: 'stdio'; command: string; args: string[] };

export interface ScanReport extends GradeReport {
  target: string;
  toolCount: number;
}

export class ScanError extends Error {}

export function parseTarget(argv: string[]): Target {
  if (argv.length === 0) throw new ScanError('scan needs a target: a URL, or a command to run.');
  const first = argv[0];
  if (/^https?:\/\//i.test(first)) {
    if (argv.length > 1) throw new ScanError('a URL target takes no extra arguments.');
    return { kind: 'http', url: first };
  }
  return { kind: 'stdio', command: first, args: argv.slice(1) };
}

export function describeTarget(target: Target): string {
  return target.kind === 'http' ? target.url : [target.command, ...target.args].join(' ');
}

const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };

/* --------------------------------------------------------------------- HTTP */

/** Streamable-HTTP servers may answer a POST with SSE; the JSON is in `data:`. */
function fromSse(text: string): unknown {
  for (const line of text.split('\n')) {
    if (!line.startsWith('data:')) continue;
    try {
      return JSON.parse(line.slice(5).trim());
    } catch {
      /* keep looking */
    }
  }
  return undefined;
}

async function listOverHttp(url: string, timeoutMs: number): Promise<ToolDefinition[]> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        // The gateway-routing headers this spec revision expects.
        'mcp-method': 'tools/list',
      },
      body: JSON.stringify(LIST),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new ScanError(`could not reach ${url}: ${(err as Error).message}`);
  }
  if (!res.ok) throw new ScanError(`${url} responded ${res.status} ${res.statusText}`);

  const text = await res.text();
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = fromSse(text);
  }
  const tools = (payload as { result?: { tools?: unknown } } | undefined)?.result?.tools;
  if (!Array.isArray(tools)) {
    const error = (payload as { error?: { message?: string } } | undefined)?.error;
    throw new ScanError(error?.message ? `server refused tools/list: ${error.message}` : `no tool inventory in the response from ${url}`);
  }
  return tools as ToolDefinition[];
}

/* -------------------------------------------------------------------- stdio */

async function listOverStdio(command: string, args: string[], timeoutMs: number): Promise<ToolDefinition[]> {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const stderr: string[] = [];
  child.stderr.on('data', (c: Buffer) => stderr.push(c.toString()));

  return await new Promise<ToolDefinition[]>((resolve, reject) => {
    const done = (fn: () => void) => {
      clearTimeout(timer);
      child.kill('SIGTERM');
      fn();
    };
    const timer = setTimeout(
      () =>
        done(() =>
          reject(
            new ScanError(
              `no tools/list response within ${timeoutMs}ms from "${command}"${stderr.length ? `\n  child stderr: ${stderr.join('').trim()}` : ''}`,
            ),
          ),
        ),
      timeoutMs,
    );

    const reader = lineReader((line) => {
      let msg: { id?: unknown; result?: { tools?: unknown }; error?: { message?: string } };
      try {
        msg = JSON.parse(line) as typeof msg;
      } catch {
        return; // Servers print banners on stdout; ignore what is not JSON.
      }
      if (msg.id !== 2) return;
      if (Array.isArray(msg.result?.tools)) {
        done(() => resolve(msg.result!.tools as ToolDefinition[]));
      } else {
        done(() => reject(new ScanError(`server refused tools/list: ${msg.error?.message ?? 'no tools in result'}`)));
      }
    });
    child.stdout.on('data', reader.push);
    child.on('error', (err) => done(() => reject(new ScanError(`could not start "${command}": ${err.message}`))));
    child.on('exit', (code) =>
      done(() => reject(new ScanError(`"${command}" exited with code ${code} before answering tools/list`))),
    );

    // Servers written against the 2025 revisions refuse everything until they
    // have been initialised; servers written against 2026-07-28 ignore this.
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'sentinelagent-guard-scan', version: '0.1.0' },
        },
      })}\n`,
    );
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    child.stdin.write(`${JSON.stringify(LIST)}\n`);
  });
}

/* --------------------------------------------------------------------- scan */

export async function scan(target: Target, timeoutMs = 15_000): Promise<ScanReport> {
  const tools =
    target.kind === 'http'
      ? await listOverHttp(target.url, timeoutMs)
      : await listOverStdio(target.command, target.args, timeoutMs);

  // L1 only: a scan sees the advertised inventory, not live traffic. Claiming
  // L2/L3 coverage from a tools/list would be a claim we cannot demonstrate.
  const verdict = evaluate({ kind: 'tools_list', tools }, {});
  return { ...grade(verdict.findings), target: describeTarget(target), toolCount: tools.length };
}

/* ------------------------------------------------------------------ output */

const ANSI = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  cyan: '\u001b[36m',
};

export function colorEnabled(stream: { isTTY?: boolean } = process.stdout): boolean {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  return stream.isTTY === true;
}

const severityColor: Record<Severity, keyof typeof ANSI> = {
  critical: 'red',
  high: 'red',
  medium: 'yellow',
  low: 'cyan',
  info: 'dim',
};

/** Highest severity present, or undefined for a clean sheet. */
export function worstSeverity(findings: Finding[]): Severity | undefined {
  let worst: Severity | undefined;
  for (const f of findings) {
    if (worst === undefined || SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(worst)) worst = f.severity;
  }
  return worst;
}

/** True when any finding is at or above `threshold`. */
export function atOrAbove(findings: Finding[], threshold: Severity): boolean {
  const bar = SEVERITY_ORDER.indexOf(threshold);
  return findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) >= bar);
}

export function renderReport(report: ScanReport, color: boolean): string {
  const paint = (text: string, style: keyof typeof ANSI) => (color ? `${ANSI[style]}${text}${ANSI.reset}` : text);
  const gradeStyle: keyof typeof ANSI =
    report.score >= 85 ? 'green' : report.score >= 55 ? 'yellow' : 'red';

  const out: string[] = [
    '',
    paint('SentinelAgent Guard — mcpgrade scan', 'bold'),
    `  target   ${report.target}`,
    `  tools    ${report.toolCount}`,
    `  rubric   ${report.rubricVersion}`,
    '',
    `  ${paint(`grade ${report.grade}`, gradeStyle)}   ${report.score}/100`,
    '',
  ];

  if (report.findings.length === 0) {
    out.push('  No findings. Tool definitions are clean against L1 tool integrity.', '');
    return out.join('\n');
  }

  for (const f of report.findings) {
    out.push(`  ${paint(f.severity.toUpperCase().padEnd(8), severityColor[f.severity])} ${paint(f.check, 'bold')}`);
    if (f.path) out.push(`           ${paint(f.path, 'dim')}`);
    out.push(`           ${f.detail}`);
    out.push('');
  }

  const counts = new Map<Severity, number>();
  for (const f of report.findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const summary = [...SEVERITY_ORDER]
    .reverse()
    .filter((s) => counts.has(s))
    .map((s) => `${counts.get(s)} ${s}`)
    .join(', ');
  out.push(`  ${report.findings.length} finding(s): ${summary}`, '');
  return out.join('\n');
}

export function renderJson(report: ScanReport): string {
  return JSON.stringify({ ...report, rubricVersion: RUBRIC_VERSION }, null, 2);
}
