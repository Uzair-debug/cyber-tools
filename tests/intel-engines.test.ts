import { describe, expect, it } from 'vitest';
import { refangText } from '@/lib/defang';
import { classifyIoc, defangIoc, INTEL_ENGINES } from '@/components/intel-pivot/intel-engines';

const url = 'https://evil.example/login?a=1';

describe('VirusTotal URL pivot', () => {
  it('searches for the URL itself as one path segment', () => {
    const link = INTEL_ENGINES.find(e => e.id === 'virustotal')!.buildUrl(url, 'URL');
    const term = link.replace('https://www.virustotal.com/gui/search/', '');
    expect(term).not.toContain('/');
    expect(decodeURIComponent(decodeURIComponent(term))).toBe(url);
  });
});

describe('defangIoc', () => {
  it('round-trips through refangText', () => {
    expect(defangIoc(url)).toBe('hxxps://evil[.]example/login?a=1');
    expect(refangText(defangIoc(url))).toBe(url);
  });

  it('brackets IPv6 colons without a stray space', () => {
    expect(defangIoc('2001:db8::1')).toBe('2001[:]db8[:][:]1');
    expect(refangText(defangIoc('2001:db8::1'))).toBe('2001:db8::1');
  });

  it('accepts already defanged input', () => {
    expect(defangIoc(defangIoc(url))).toBe(defangIoc(url));
  });
});

describe('classifyIoc', () => {
  it.each([
    [url, 'URL'],
    ['evil.example/path', 'URL'],
    ['hxxps://evil[.]example/a', 'URL'],
    ['evil[.]example', 'DOMAIN'],
    ['8[.]8[.]8[.]8', 'IPV4'],
    ['not an ioc/really', 'UNKNOWN'],
  ])('%s is %s', (input, expected) => {
    expect(classifyIoc(input)).toBe(expected);
  });
});
