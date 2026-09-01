/**
 * Measured latency harness. `npx tsx packages/guard-core/src/benchmark.ts`
 *
 * Every latency figure published anywhere — site, docs, sales deck — must trace
 * back to a run of this file on named hardware. There are no hardcoded latency
 * numbers in this repository, and adding one is a bug.
 *
 * The mix is drawn from the corpus so it reflects real traffic shapes: mostly
 * clean calls, a minority of attacks, one tools/list, one response scan.
 */

import { CORPUS } from './corpus/index.js';
import { evaluate } from './engine.js';
import { checkCount } from './checks.js';

const ITERATIONS = Number(process.env.GUARD_BENCH_ITERATIONS ?? 20_000);
const WARMUP = 2_000;

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, index)];
}

function run(label: string, samples: (() => void)[], iterations: number): void {
  for (let i = 0; i < WARMUP; i++) samples[i % samples.length]();

  const timings = new Float64Array(iterations);
  for (let i = 0; i < iterations; i++) {
    const fn = samples[i % samples.length];
    const t0 = process.hrtime.bigint();
    fn();
    timings[i] = Number(process.hrtime.bigint() - t0) / 1000; // microseconds
  }

  const sorted = Array.from(timings).sort((a, b) => a - b);
  const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
  const fmt = (n: number) => `${n.toFixed(2)} µs`;
  console.log(
    `${label.padEnd(28)} n=${iterations}  mean=${fmt(mean).padStart(10)}  p50=${fmt(percentile(sorted, 50)).padStart(10)}  p95=${fmt(percentile(sorted, 95)).padStart(10)}  p99=${fmt(percentile(sorted, 99)).padStart(10)}  max=${fmt(sorted[sorted.length - 1]).padStart(10)}`,
  );
}

const byKind = (kind: string) => CORPUS.filter((e) => e.event.kind === kind);

const mk = (entries: typeof CORPUS) => entries.map((e) => () => void evaluate(e.event, e.policy));

console.log(`SentinelAgent Guard — guard-core benchmark`);
console.log(`node ${process.version} on ${process.platform}/${process.arch}`);
console.log(`${checkCount()} checks, ${CORPUS.length} corpus events\n`);

run('requests (L0+L2)', mk(byKind('request')), ITERATIONS);
run('tools/list (L1)', mk(byKind('tools_list')), ITERATIONS);
run('responses (L3)', mk(byKind('response')), ITERATIONS);
run('full corpus mix', mk(CORPUS), ITERATIONS);

console.log('\nEvery published latency figure must come from a run of this file.');
