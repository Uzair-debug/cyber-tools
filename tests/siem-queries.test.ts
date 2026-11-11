import { describe, expect, it } from 'vitest';
import { buildQueries, extractIocs } from '@/lib/siem-queries';

const NOW = new Date('2026-10-31T00:00:00Z');

describe('SIEM extractIocs', () => {
  it('refangs and normalises mixed indicators', () => {
    const iocs = extractIocs(
      'hxxps://Evil[.]com/login?x=1, 8.8.8.8:443; user@phish.net\n' +
        '44D88612FEA8A8F36DE82E1278ABB02F da39a3ee5e6b4b0d3255bfef95601890afd80709 ' +
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "quoted.org" junk!!'
    );
    expect(iocs.ips).toEqual(['8.8.8.8']);
    expect(iocs.domains).toEqual(['evil.com', 'phish.net', 'quoted.org']);
    expect(iocs.md5).toEqual(['44d88612fea8a8f36de82e1278abb02f']);
    expect(iocs.sha1).toEqual(['da39a3ee5e6b4b0d3255bfef95601890afd80709']);
    expect(iocs.sha256).toEqual(['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
    expect(iocs.unrecognised).toEqual(['junk!!']);
  });

  it('deduplicates', () => {
    expect(extractIocs('evil.com EVIL.com hxxp://evil[.]com/').domains).toEqual(['evil.com']);
  });

  it.each(['256.1.1.1', '1.2.3', 'evil.c0m', 'abc', 'a'.repeat(33)])('puts %s in unrecognised', token => {
    const iocs = extractIocs(token);
    expect(iocs.unrecognised).toEqual([token]);
  });
});

describe('buildQueries', () => {
  const iocs = extractIocs('1.2.3.4 evil.com 44d88612fea8a8f36de82e1278abb02f');
  const q = buildQueries(iocs, 'Case 42', NOW);

  it('returns a query for every platform', () => {
    expect(Object.keys(q).sort()).toEqual(['elastic', 'kql', 'qradar', 'sigma', 'spl']);
  });

  it('includes every indicator type in every query (mixed input never drops indicators)', () => {
    for (const [platform, text] of Object.entries(q)) {
      expect(text, platform).toContain('1.2.3.4');
      expect(text, platform).toContain('evil.com');
    }
    for (const platform of ['kql', 'spl', 'elastic', 'sigma', 'qradar'] as const) {
      expect(q[platform], platform).toContain('44d88612fea8a8f36de82e1278abb02f');
    }
  });

  it('KQL declares each list and searches IPs, domains and hashes', () => {
    expect(q.kql).toContain('let threat_ips = dynamic(["1.2.3.4"]);');
    expect(q.kql).toContain('let threat_domains = dynamic(["evil.com"]);');
    expect(q.kql).toMatch(/RemoteIP in \(threat_ips\)/);
    expect(q.kql).toMatch(/has_any \(threat_domains\)/);
    expect(q.kql).toMatch(/MD5 in~ \(threat_md5\)/);
  });

  it('Sigma rules are dated from the supplied clock', () => {
    expect(q.sigma).toContain('date: 2026-10-31');
  });

  it('cannot break out of a query comment through the title', () => {
    const injected = buildQueries(iocs, 'Title\n| take 1000000\n//', NOW);
    // The title is kept on the first comment line; a newline would start a new KQL statement
    expect(injected.kql.split('\n')[0]).toBe('// Title | take 1000000 //');
    expect(injected.kql).not.toMatch(/^\| take 1000000$/m);
  });

  it('produces only IP clauses when only IPs are given', () => {
    const ipOnly = buildQueries(extractIocs('9.9.9.9'), 'T', NOW);
    expect(ipOnly.kql).not.toContain('threat_domains');
    expect(ipOnly.kql).not.toContain('threat_md5');
  });
});
