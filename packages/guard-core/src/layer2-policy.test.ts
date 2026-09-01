import { describe, expect, it } from 'vitest';
import { evaluate } from './engine.js';
import { collectStringLeaves, validateAgainstSchema, validateRulePattern } from './layer2-policy.js';
import type { GuardEvent, GuardPolicy } from './types.js';

const call = (name: string, args: Record<string, unknown>): GuardEvent => ({
  kind: 'request',
  headers: { 'mcp-method': 'tools/call', 'mcp-name': name },
  body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
});

/* -------------------------------------------------------------------- ReDoS */

describe('validateRulePattern', () => {
  const catastrophic = [
    '(a+)+$',
    '(a*)*$',
    '(a+)*b',
    '([a-zA-Z]+)*$',
    '(\\d+)+$',
    '(x|x)+y',
    '(ab|ac)+z',
    '((a+))+',
    '(a{1,10})+',
    '(.*)*',
  ];

  it.each(catastrophic)('rejects the catastrophic shape %s', (pattern) => {
    const result = validateRulePattern(pattern);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason.length).toBeGreaterThan(0);
  });

  it('rejects over-long patterns before compilation', () => {
    expect(validateRulePattern('a'.repeat(500)).ok).toBe(false);
  });

  it('rejects an absurd repetition bound', () => {
    expect(validateRulePattern('a{1,999999}').ok).toBe(false);
  });

  it('rejects an empty or uncompilable pattern', () => {
    expect(validateRulePattern('').ok).toBe(false);
    expect(validateRulePattern('(unclosed').ok).toBe(false);
    expect(validateRulePattern('[unterminated').ok).toBe(false);
    expect(validateRulePattern('a{2,1}').ok).toBe(false);
  });

  const safe = [
    'ACME-INTERNAL-\\d{4}',
    '^[a-z0-9_]+$',
    '(?:alpha|beta|gamma)',
    'secret[-_]?key',
    '\\bconfidential\\b',
    '(foo)?bar+',
    '[A-Z]{2,6}-\\d{1,5}',
  ];

  it.each(safe)('accepts the ordinary tenant pattern %s', (pattern) => {
    expect(validateRulePattern(pattern)).toEqual({ ok: true });
  });

  it('a tenant cannot hang the gateway with a catastrophic rule', () => {
    const policy: GuardPolicy = {
      customRules: [
        { id: 'evil', name: 'ReDoS', pattern: '(a+)+$', action: 'BLOCK', enabled: true },
        { id: 'evil2', name: 'ReDoS 2', pattern: '^(a|a)+$', action: 'BLOCK', enabled: true },
      ],
    };
    // The classic exponential trigger: many `a`s and one character that fails.
    const event = call('write_file', { content: `${'a'.repeat(4000)}!` });
    const started = process.hrtime.bigint();
    const verdict = evaluate(event, policy);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(verdict.decision).toBe('allow'); // rejected rules never compile
    expect(elapsedMs).toBeLessThan(100);
  });

  it('caps the length of the value a compiled rule is run against', () => {
    const policy: GuardPolicy = {
      customRules: [{ id: 'tail', name: 'Tail marker', pattern: 'NEEDLE', action: 'BLOCK', enabled: true }],
    };
    // Beyond MAX_INSPECTED_LENGTH, so it is deliberately not inspected.
    const event = call('write_file', { content: `${'x'.repeat(5000)}NEEDLE` });
    expect(evaluate(event, policy).decision).toBe('allow');
    expect(evaluate(call('write_file', { content: 'NEEDLE' }), policy).decision).toBe('block');
  });
});

/* ------------------------------------------------------------ schema subset */

describe('inputSchema validation', () => {
  const schema = {
    type: 'object',
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[\\w./-]+$' },
      mode: { enum: ['read', 'write'] },
      depth: { type: 'integer', minimum: 0, maximum: 5 },
      tags: { type: 'array', items: { type: 'string' } },
    },
    required: ['path'],
    additionalProperties: false,
  };

  const violations = (value: unknown) => validateAgainstSchema(value, schema, 'args').map((v) => v.message);

  it('accepts a conforming object', () => {
    expect(violations({ path: 'a/b.txt', mode: 'read', depth: 2, tags: ['x'] })).toEqual([]);
  });

  it('reports missing required properties', () => {
    expect(violations({}).join()).toContain('required property is missing');
  });

  it('reports type, enum, range, length and pattern failures', () => {
    expect(violations({ path: 123 }).join()).toContain('expected string');
    expect(violations({ path: 'a', mode: 'delete' }).join()).toContain('enum');
    expect(violations({ path: 'a', depth: 9 }).join()).toContain('above maximum');
    expect(violations({ path: 'a', depth: 1.5 }).join()).toContain('expected integer');
    expect(violations({ path: '' }).join()).toContain('below minLength');
    expect(violations({ path: 'x'.repeat(40) }).join()).toContain('maxLength');
    expect(violations({ path: 'has spaces!' }).join()).toContain('declared pattern');
  });

  it('rejects undeclared properties when additionalProperties is false', () => {
    expect(violations({ path: 'a', exfil: 'y' }).join()).toContain('additionalProperties');
  });

  it('descends into array items', () => {
    expect(violations({ path: 'a', tags: ['ok', 7] }).join()).toContain('expected string');
  });

  it('terminates on a pathologically deep schema', () => {
    let schemaDeep: Record<string, unknown> = { type: 'string' };
    let value: unknown = 'leaf';
    for (let i = 0; i < 200; i++) {
      schemaDeep = { type: 'object', properties: { n: schemaDeep } };
      value = { n: value };
    }
    expect(() => validateAgainstSchema(value, schemaDeep, 'args')).not.toThrow();
  });
});

/* ------------------------------------------------------------ leaf walking */

describe('string leaf walking', () => {
  it('reports the dotted path of every string leaf, including array indices', () => {
    const leaves = collectStringLeaves({ a: 'x', b: { c: ['y', 'z'] }, n: 4 }, 'params.arguments');
    expect(leaves.map((l) => l.path)).toEqual([
      'params.arguments.a',
      'params.arguments.b.c[0]',
      'params.arguments.b.c[1]',
    ]);
    expect(leaves[1].relative).toBe('b.c');
  });

  it('does not evaluate rules against a serialized blob', () => {
    // `rm -rf /` sitting in a documentation string must not be treated the same
    // as `rm -rf /` in a command argument reached via a chain operator.
    const doc = 'Never run `rm -rf /` on production.';
    expect(evaluate(call('write_file', { path: 'runbook.md', content: doc }), {}).decision).toBe('allow');
  });

  it('terminates on deeply nested arguments', () => {
    let value: unknown = 'leaf';
    for (let i = 0; i < 500; i++) value = { n: value };
    expect(() => evaluate(call('t', { value }), {})).not.toThrow();
  });
});
