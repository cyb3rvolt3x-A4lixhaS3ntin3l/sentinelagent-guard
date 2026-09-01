#!/usr/bin/env node
/**
 * guard-proxy — the stdio sidecar and the free mcpgrade scanner.
 *
 * Exit codes are chosen for CI:
 *   0  clean (scan), or the child's own code (sidecar)
 *   1  findings at or above --fail-on
 *   2  usage error, or the target could not be scanned
 */

import { runProxy } from './proxy.js';
import {
  ScanError,
  SEVERITY_ORDER,
  atOrAbove,
  colorEnabled,
  parseTarget,
  renderJson,
  renderReport,
  scan,
} from './scan.js';
import type { Severity } from '@guard/core';

const VERSION = '0.1.1';

const USAGE = `sentinelagent guard-proxy ${VERSION}

  guard-proxy -- <command> [args...]     run an MCP server behind the firewall
  guard-proxy scan <url>                 grade a remote MCP server
  guard-proxy scan <command> [args...]   grade a stdio MCP server

Scan options
  --json                 machine-readable report on stdout
  --fail-on <severity>   exit 1 when a finding is at or above this severity
                         (critical|high|medium|low|info|none, default: high)
  --timeout <ms>         give up on the server after this long (default: 15000)

Colour follows NO_COLOR and is off when stdout is not a terminal.
`;

function fail(message: string): never {
  process.stderr.write(`guard-proxy: ${message}\n`);
  process.exit(2);
}

async function runScan(argv: string[]): Promise<number> {
  let json = false;
  let failOn: Severity | 'none' = 'high';
  let timeout = 15_000;
  const rest: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') json = true;
    else if (arg === '--fail-on') {
      const value = argv[++i];
      if (value !== 'none' && !SEVERITY_ORDER.includes(value as Severity)) fail(`unknown severity "${value}"`);
      failOn = value as Severity | 'none';
    } else if (arg === '--timeout') {
      timeout = Number(argv[++i]);
      if (!Number.isFinite(timeout) || timeout <= 0) fail('--timeout needs a positive number of milliseconds');
    } else if (arg.startsWith('--')) fail(`unknown option "${arg}"`);
    else rest.push(arg);
  }

  const report = await scan(parseTarget(rest), timeout);
  process.stdout.write(json ? `${renderJson(report)}\n` : renderReport(report, colorEnabled(process.stdout)));

  if (failOn === 'none') return 0;
  return atOrAbove(report.findings, failOn) ? 1 : 0;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(USAGE);
    return argv.length === 0 ? 2 : 0;
  }
  if (argv[0] === '--version' || argv[0] === '-v') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  if (argv[0] === 'scan') {
    try {
      return await runScan(argv.slice(1));
    } catch (err) {
      if (err instanceof ScanError) fail(err.message);
      throw err;
    }
  }

  // Sidecar: everything after `--` is the server command.
  const sep = argv.indexOf('--');
  const command = sep === -1 ? argv : argv.slice(sep + 1);
  if (command.length === 0) fail('nothing to run. Use: guard-proxy -- <command> [args...]');

  const { exited } = runProxy({ command: command[0], args: command.slice(1) });
  return await exited;
}

main().then(
  (code) => process.exit(code),
  (err: Error) => fail(err.message),
);
