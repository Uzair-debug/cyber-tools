import { describe, expect, it } from 'vitest';
import { parseCvss3Vector, roundup, scoreCvss31, severityOf, type BaseMetrics } from '@/lib/cvss';

const score = (vector: string) => {
  const parsed = parseCvss3Vector(vector);
  if ('error' in parsed) throw new Error(parsed.error);
  return scoreCvss31(parsed.metrics);
};

// Reference scores from the FIRST CVSS v3.1 calculator / NVD
describe('scoreCvss31 matches FIRST reference scores', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'CRITICAL'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'CRITICAL'],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', 9.0, 'CRITICAL'],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8, 'HIGH'],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, 'HIGH'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5, 'HIGH'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'MEDIUM'], // reflected XSS
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9, 'MEDIUM'],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4, 'MEDIUM'], // stored XSS
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 5.5, 'MEDIUM'],
    ['CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 6.8, 'MEDIUM'],
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N', 2.7, 'LOW'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0, 'NONE'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N', 0, 'NONE'],
  ])('%s = %s', (vector, expected, severity) => {
    const result = score(vector);
    expect(result.baseScore).toBe(expected);
    expect(result.severity).toBe(severity);
  });

  it('uses the Scope:Changed privilege weights', () => {
    // PR:L is 0.62 unchanged but 0.68 changed, PR:H is 0.27 vs 0.5
    expect(score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H').baseScore).toBe(9.9);
    expect(score('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H').baseScore).toBe(9.1);
  });

  it('rebuilds a canonical vector in metric order', () => {
    expect(score('CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N').vector).toBe(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    );
  });
});

describe('roundup (spec Appendix A)', () => {
  it('avoids floating-point overshoot', () => {
    expect(roundup(4.000000000000001)).toBe(4.0);
  });
  it.each([
    [4.02, 4.1],
    [4.0, 4.0],
    [4.1, 4.1],
    [0.01, 0.1],
    [9.99, 10.0],
  ])('roundup(%s) = %s', (input, expected) => {
    expect(roundup(input)).toBe(expected);
  });
});

describe('severityOf boundaries', () => {
  it.each([
    [0, 'NONE'],
    [0.1, 'LOW'],
    [3.9, 'LOW'],
    [4.0, 'MEDIUM'],
    [6.9, 'MEDIUM'],
    [7.0, 'HIGH'],
    [8.9, 'HIGH'],
    [9.0, 'CRITICAL'],
    [10, 'CRITICAL'],
  ])('%s is %s', (value, expected) => {
    expect(severityOf(value)).toBe(expected);
  });
});

describe('parseCvss3Vector', () => {
  it('accepts CVSS 3.0 vectors', () => {
    expect(score('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').baseScore).toBe(9.8);
  });

  it('reports temporal/environmental metrics as ignored instead of failing', () => {
    const parsed = parseCvss3Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O');
    expect('metrics' in parsed && parsed.ignored).toEqual(['E:P', 'RL:O']);
  });

  it.each([
    ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /must start with CVSS:3\.1/],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', /v4\.0/],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', /Missing base metric: A/],
    ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /AV:X is not a valid value/],
    ['CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /AV appears more than once/],
    ['CVSS:3.1/AV:N:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /not a valid metric/],
    ['CVSS:3.1/AV', /not a valid metric/],
  ])('rejects %s', (vector, message) => {
    const parsed = parseCvss3Vector(vector);
    expect('error' in parsed && parsed.error).toMatch(message);
  });

  it('accepts surrounding whitespace', () => {
    const parsed = parseCvss3Vector('  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n');
    expect('metrics' in parsed && (parsed.metrics as BaseMetrics).AV).toBe('N');
  });
});
