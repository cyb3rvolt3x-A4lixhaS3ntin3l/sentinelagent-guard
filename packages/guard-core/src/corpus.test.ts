import { describe, expect, it } from 'vitest';
import { CHECKS } from './checks.js';
import { CORPUS } from './corpus/index.js';
import { evaluate } from './engine.js';

const REGISTERED = new Set(CHECKS.map((c) => c.id));

describe('attack corpus', () => {
  it.each(CORPUS.map((entry) => [entry.name, entry] as const))('%s', (_name, entry) => {
    const verdict = evaluate(entry.event, entry.policy);
    const ids = verdict.findings.map((f) => f.check);

    if (entry.benign) {
      // Not merely "allow" — legitimate traffic must produce no noise at all.
      expect(verdict.findings, `unexpected findings: ${JSON.stringify(verdict.findings, null, 2)}`).toEqual([]);
    }

    for (const expected of entry.expect.checks) expect(ids).toContain(expected);
    expect(verdict.decision).toBe(entry.expect.decision);

    // Nothing may emit a check id the published registry does not declare.
    for (const id of ids) expect(REGISTERED).toContain(id);
  });

  it('covers both directions', () => {
    const benign = CORPUS.filter((e) => e.benign).length;
    expect(benign).toBeGreaterThan(10);
    expect(CORPUS.length - benign).toBeGreaterThan(30);
  });

  it('exercises every check in the registry except the ones only reachable by configuration', () => {
    const exercised = new Set(CORPUS.flatMap((e) => e.expect.checks));
    const missing = CHECKS.map((c) => c.id).filter((id) => !exercised.has(id));
    expect(missing).toEqual([]);
  });

  it('never leaks a secret value into a finding detail', () => {
    const secrets = ['AKIAIOSFODNN7EXAMPLE', 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8', 'xoxb-2183746512-abcdefGHIJKL'];
    for (const entry of CORPUS) {
      const verdict = evaluate(entry.event, entry.policy);
      for (const f of verdict.findings) {
        for (const s of secrets) expect(f.detail).not.toContain(s);
      }
    }
  });
});
