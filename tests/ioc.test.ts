import { describe, expect, it } from 'vitest';
import { extractIocs } from '@/lib/ioc';

describe('extractIocs', () => {
  it('pulls every IOC type out of defanged text', () => {
    const iocs = extractIocs(
      'hxxps://evil[.]com/login from 198.51.100.7, contact bad[@]phish[.]net, hash 44d88612fea8a8f36de82e1278abb02f ' +
        'and da39a3ee5e6b4b0d3255bfef95601890afd80709 and ' +
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, also see other[.]org, CVE-2024-3400'
    );
    expect(iocs.urls).toEqual(['https://evil.com/login']);
    expect(iocs.ips).toEqual(['198.51.100.7']);
    expect(iocs.emails).toEqual(['bad@phish.net']);
    expect(iocs.domains).toEqual(['other.org']);
    expect(iocs.md5s).toHaveLength(1);
    expect(iocs.sha1s).toHaveLength(1);
    expect(iocs.sha256s).toHaveLength(1);
    expect(iocs.cves).toEqual(['CVE-2024-3400']);
  });

  it('understands the other defang styles', () => {
    const iocs = extractIocs('hxxps[:]//evil[.]example/a bob[at]evil[.]example other(dot)example');
    expect(iocs.urls).toEqual(['https://evil.example/a']);
    expect(iocs.emails).toEqual(['bob@evil.example']);
    expect(iocs.domains).toEqual(['other.example']);
  });

  it('removes trailing punctuation and unmatched brackets from URLs', () => {
    const { urls } = extractIocs('from http://cdn.bad.example/file.exe. See (https://x.example/a), and https://y.example/a_(b)');
    expect(urls).toEqual(['http://cdn.bad.example/file.exe', 'https://x.example/a', 'https://y.example/a_(b)']);
  });

  it.each(['invoice.pdf', 'invoice.docx', 'notes.txt', 'report.xlsx', 'setup.exe', 'script.ps1'])(
    'does not report the file name %s as a domain',
    name => {
      expect(extractIocs(name).domains).toEqual([]);
    }
  );

  it('does not repeat hosts already reported in URLs or emails', () => {
    expect(extractIocs('https://in-url.example/a a@in-mail.example bare.example').domains).toEqual(['bare.example']);
  });

  it('keeps a bare domain even when a URL host contains it', () => {
    expect(extractIocs('https://notevil.example/ and evil.example').domains).toEqual(['evil.example']);
  });

  it('publicIpsOnly drops every non-public range, not only RFC 1918', () => {
    const text = '10.0.0.1 172.16.0.1 192.168.1.1 127.0.0.1 169.254.1.1 100.64.0.1 224.0.0.1 192.0.2.1 8.8.8.8';
    expect(extractIocs(text, { publicIpsOnly: true }).ips).toEqual(['8.8.8.8']);
    expect(extractIocs(text).ips).toHaveLength(9);
  });

  it('ignores IPs inside longer dotted numbers but accepts a sentence-ending IP', () => {
    expect(extractIocs('1.2.3.4.5 and 8.8.4.4.').ips).toEqual(['8.8.4.4']);
  });

  it('does not treat out-of-range octets as IPs', () => {
    expect(extractIocs('999.1.1.1').ips).toEqual([]);
  });

  it('deduplicates repeated indicators across defang styles and letter case', () => {
    expect(extractIocs('1.2.3.4 1.2.3.4 1[.]2[.]3[.]4').ips).toEqual(['1.2.3.4']);
    expect(extractIocs(`${'A'.repeat(32)} ${'a'.repeat(32)}`).md5s).toEqual(['a'.repeat(32)]);
  });

  it('keeps duplicates when dedup is off', () => {
    expect(extractIocs('8.8.8.8 8.8.8.8', { dedup: false }).ips).toHaveLength(2);
  });

  it('does not pull an MD5 out of a longer SHA-256', () => {
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const iocs = extractIocs(sha256);
    expect(iocs.sha256s).toEqual([sha256]);
    expect(iocs.md5s).toEqual([]);
  });

  it('returns nothing for empty input', () => {
    expect(Object.values(extractIocs('  ')).flat()).toEqual([]);
  });
});
