/**
 * The scan is published output. A grade that moves for the same inventory is a
 * broken promise, so the fixed-input grade is asserted literally.
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { atOrAbove, parseTarget, renderReport, scan, ScanError, worstSeverity } from '../src/scan.js';

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures/mcp-server.mjs');

describe('scan', () => {
  it('grades a clean stdio server A+ with no findings', async () => {
    const report = await scan({ kind: 'stdio', command: process.execPath, args: [FIXTURE] }, 10_000);

    expect(report.toolCount).toBe(1);
    expect(report.findings).toEqual([]);
    expect(report.score).toBe(100);
    expect(report.grade).toBe('A+');
    expect(report.rubricVersion).toBe('mcpgrade-2.0.0');
  }, 20_000);

  it('produces a stable grade for a fixed poisoned inventory', async () => {
    const report = await scan({ kind: 'stdio', command: process.execPath, args: [FIXTURE] }, 10_000);
    expect(report.grade).toBe('A+');

    process.env.FIXTURE_POISON = '1';
    try {
      const poisoned = await scan({ kind: 'stdio', command: process.execPath, args: [FIXTURE] }, 10_000);
      // One critical finding: 100 - 40 = 60 = C, per mcpgrade-2.0.0.
      expect(poisoned.findings.map((f) => f.check)).toEqual(['L1.TOOL_POISONING']);
      expect(poisoned.score).toBe(60);
      expect(poisoned.grade).toBe('C');
    } finally {
      delete process.env.FIXTURE_POISON;
    }
  }, 20_000);

  it('reports an unreachable target as an error rather than grading it', async () => {
    await expect(scan({ kind: 'http', url: 'http://127.0.0.1:1/mcp' }, 2_000)).rejects.toBeInstanceOf(ScanError);
  });

  it('reports a server that never answers rather than grading an empty inventory', async () => {
    await expect(
      scan({ kind: 'stdio', command: process.execPath, args: ['-e', 'setTimeout(()=>{},5000)'] }, 700),
    ).rejects.toBeInstanceOf(ScanError);
  }, 20_000);
});

describe('targets', () => {
  it('recognises URLs and commands', () => {
    expect(parseTarget(['https://mcp.example.com/rpc'])).toEqual({ kind: 'http', url: 'https://mcp.example.com/rpc' });
    expect(parseTarget(['node', 'server.js'])).toEqual({ kind: 'stdio', command: 'node', args: ['server.js'] });
    expect(() => parseTarget([])).toThrow(ScanError);
  });
});

describe('report output', () => {
  const report = {
    grade: 'C' as const,
    score: 60,
    rubricVersion: 'mcpgrade-2.0.0',
    target: 'node server.js',
    toolCount: 1,
    findings: [
      {
        check: 'L1.TOOL_POISONING',
        layer: 1 as const,
        severity: 'critical' as const,
        title: 'Tool poisoning',
        detail: 'Description of "read_file" contains a pseudo-tag instruction block.',
        action: 'BLOCK' as const,
        path: 'tools.read_file.description',
      },
    ],
  };

  it('emits no escape codes when colour is off', () => {
    const text = renderReport(report, false);
    expect(text).not.toContain('\u001b[');
    expect(text).toContain('grade C');
    expect(text).toContain('L1.TOOL_POISONING');
    expect(text).toContain('tools.read_file.description');
  });

  it('emits escape codes when colour is on', () => {
    expect(renderReport(report, true)).toContain('\u001b[');
  });

  it('applies the --fail-on threshold by severity rank', () => {
    expect(worstSeverity(report.findings)).toBe('critical');
    expect(atOrAbove(report.findings, 'high')).toBe(true);
    expect(atOrAbove(report.findings, 'critical')).toBe(true);
    expect(atOrAbove([], 'info')).toBe(false);
  });
});
