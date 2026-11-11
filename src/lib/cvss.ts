// CVSS v3.1 base score, per the FIRST specification (https://www.first.org/cvss/v3.1/specification-document)

export const CVSS31_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 0, C: 0 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
} as const;

export type MetricId = keyof typeof CVSS31_WEIGHTS;
export type BaseMetrics = Record<MetricId, string>;
export const METRIC_ORDER = Object.keys(CVSS31_WEIGHTS) as MetricId[];

// PR weights when Scope is Changed
const PR_SCOPE_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

// Spec Appendix A: integer arithmetic avoids float errors such as ceil(4.000000000000001) giving 4.1
export function roundup(value: number): number {
  const int = Math.round(value * 100000);
  return int % 10000 === 0 ? int / 100000 : (Math.floor(int / 10000) + 1) / 10;
}

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export function severityOf(score: number): Severity {
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

export function scoreCvss31(m: BaseMetrics) {
  const w = CVSS31_WEIGHTS;
  const changed = m.S === 'C';
  const iss = 1 - (1 - w.C[m.C as 'H']) * (1 - w.I[m.I as 'H']) * (1 - w.A[m.A as 'H']);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const pr = changed ? PR_SCOPE_CHANGED[m.PR] : w.PR[m.PR as 'N'];
  const exploitability = 8.22 * w.AV[m.AV as 'N'] * w.AC[m.AC as 'L'] * pr * w.UI[m.UI as 'N'];

  let baseScore = 0;
  if (impact > 0) {
    baseScore = changed
      ? roundup(Math.min(1.08 * (impact + exploitability), 10))
      : roundup(Math.min(impact + exploitability, 10));
  }

  return {
    baseScore,
    impact,
    exploitability,
    severity: severityOf(baseScore),
    vector: 'CVSS:3.1/' + METRIC_ORDER.map(k => `${k}:${m[k]}`).join('/'),
  };
}

// Accepts a full CVSS 3.0 or 3.1 base vector; temporal/environmental metrics are reported but not scored
export function parseCvss3Vector(input: string): { metrics: BaseMetrics; ignored: string[] } | { error: string } {
  const parts = input.trim().split('/');
  const prefix = parts.shift();
  if (prefix !== 'CVSS:3.1' && prefix !== 'CVSS:3.0') {
    if (prefix === 'CVSS:4.0') return { error: 'This is a CVSS v4.0 vector. This calculator scores v3.1 only.' };
    return { error: 'The vector must start with CVSS:3.1/ (or CVSS:3.0/).' };
  }
  const metrics: Partial<BaseMetrics> = {};
  const ignored: string[] = [];
  for (const part of parts) {
    const [key, value, extra] = part.split(':');
    if (!key || value === undefined || extra !== undefined) return { error: `"${part}" is not a valid metric.` };
    if (key in CVSS31_WEIGHTS) {
      const id = key as MetricId;
      if (metrics[id]) return { error: `${key} appears more than once.` };
      if (!(value in CVSS31_WEIGHTS[id])) return { error: `${key}:${value} is not a valid value for ${key}.` };
      metrics[id] = value;
    } else {
      ignored.push(part);
    }
  }
  const missing = METRIC_ORDER.filter(k => !metrics[k]);
  if (missing.length) return { error: `Missing base metric${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}.` };
  return { metrics: metrics as BaseMetrics, ignored };
}
