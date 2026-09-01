/**
 * mcpgrade — the published grading rubric.
 *
 * ONE rubric, shared by the andraxpentester.in scanner, the sidecar CLI and the
 * runtime. Two surfaces that grade the same server differently destroy the
 * grade's meaning, so the arithmetic lives here and nowhere else.
 *
 * ============================== THE RUBRIC ==============================
 *
 * Every server starts at 100 and loses points for findings.
 *
 *   1. Severity weights (points deducted per finding):
 *
 *        critical  40
 *        high      20
 *        medium     8
 *        low        3
 *        info       0
 *
 *   2. Per-check saturation. The deduction contributed by any single check id is
 *      capped at 2× its severity weight. Rationale: a server advertising forty
 *      poisoned tools is not twenty times worse than one advertising two — it
 *      has one defect, at scale. Without the cap, a large inventory would
 *      dominate the score and a small malicious server would out-grade a large
 *      sloppy one. The cap keeps BREADTH of failure (how many distinct checks
 *      failed) the dominant term, which is what a grade should express.
 *
 *   3. Findings whose severity is `info` never move the score. They are
 *      inventory notes, not defects.
 *
 *   4. score = clamp(100 - total deduction, 0, 100), rounded to an integer.
 *
 *   5. Grade bands:
 *
 *        A+  100        no deductions at all
 *        A    85-99
 *        B    70-84
 *        C    55-69
 *        D    40-54
 *        F     0-39
 *
 *      A+ is reserved for a clean sheet. A single medium finding (-8) lands at
 *      92 = A; a single critical (-40) lands at 60 = C; two distinct criticals
 *      (-80) land at 20 = F. That is the intended shape: one critical failure is
 *      not a passing grade, and two are disqualifying.
 *
 * The rubric is versioned. Any change to weights, caps or bands REQUIRES a
 * RUBRIC_VERSION bump, because published grades must remain reproducible.
 * ========================================================================
 */

import type { Finding, Grade, GradeReport, Severity } from './types.js';

export const RUBRIC_VERSION = 'mcpgrade-2.0.0';

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

/** A single check id may contribute at most this multiple of its weight. */
export const PER_CHECK_SATURATION = 2;

const BANDS: { min: number; grade: Grade }[] = [
  { min: 100, grade: 'A+' },
  { min: 85, grade: 'A' },
  { min: 70, grade: 'B' },
  { min: 55, grade: 'C' },
  { min: 40, grade: 'D' },
  { min: 0, grade: 'F' },
];

export function scoreFindings(findings: Finding[]): number {
  const perCheck = new Map<string, number>();
  for (const f of findings) {
    const weight = SEVERITY_WEIGHTS[f.severity];
    if (weight === 0) continue;
    const cap = weight * PER_CHECK_SATURATION;
    const current = perCheck.get(f.check) ?? 0;
    perCheck.set(f.check, Math.min(cap, current + weight));
  }
  let deduction = 0;
  for (const d of perCheck.values()) deduction += d;
  return Math.max(0, Math.min(100, Math.round(100 - deduction)));
}

export function gradeForScore(score: number): Grade {
  for (const band of BANDS) if (score >= band.min) return band.grade;
  return 'F';
}

export function grade(findings: Finding[]): GradeReport {
  const score = scoreFindings(findings);
  return { grade: gradeForScore(score), score, rubricVersion: RUBRIC_VERSION, findings };
}
