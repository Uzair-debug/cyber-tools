import { describe, expect, it } from 'vitest';
import { csvCell } from '@/lib/utils';
import { defangText, refangText } from '@/lib/defang';
import { calculateCidr, ipToLong, longToIp } from '@/lib/cidr-utils';

describe('csvCell (formula injection guard)', () => {
  it.each([
    ['=HYPERLINK("http://evil","x")', `"'=HYPERLINK(""http://evil"",""x"")"`],
    ['+cmd|/c calc', `"'+cmd|/c calc"`],
    ['-2+3', `"'-2+3"`],
    ['@SUM(A1)', `"'@SUM(A1)"`],
    ['\t=1', `"'\t=1"`],
    ['\r=1', `"'\r=1"`],
  ])('neutralises %j', (input, expected) => {
    expect(csvCell(input)).toBe(expected);
  });

  it('quotes ordinary values and doubles embedded quotes', () => {
    expect(csvCell('evil.com')).toBe('"evil.com"');
    expect(csvCell('say "hi", then go')).toBe('"say ""hi"", then go"');
    expect(csvCell('a=b')).toBe('"a=b"'); // = only matters at the start
  });

  it('handles non-string values', () => {
    expect(csvCell(null)).toBe('""');
    expect(csvCell(undefined)).toBe('""');
    expect(csvCell(42)).toBe('"42"');
    expect(csvCell(-1)).toBe(`"'-1"`);
  });
});

describe('defangText / refangText', () => {
  it('defangs URLs, IPs and domains', () => {
    expect(defangText('visit https://evil.com/login or http://10.0.0.1:8080/')).toBe(
      'visit hxxps://evil[.]com/login or hxxp://10[.]0[.]0[.]1:8080/'
    );
  });

  it('defangs the @ in email addresses', () => {
    expect(defangText('reply to user@evil.com now')).toBe('reply to user[@]evil[.]com now');
  });

  it('leaves sentence punctuation alone', () => {
    expect(defangText('Done. Next step.')).toBe('Done. Next step.');
  });

  it('does not double-defang already defanged text', () => {
    const once = defangText('https://evil.com');
    expect(defangText(once)).toBe(once);
  });

  it('round-trips through refangText', () => {
    const original = 'Phish from bob@evil.co.za via https://login.evil.co.za/a?b=1 hosted on 203.0.113.5';
    expect(refangText(defangText(original))).toBe(original);
  });

  it.each([
    ['hxxps://evil[.]com', 'https://evil.com'],
    ['hxxp://evil(.)com', 'http://evil.com'],
    ['evil[dot]com', 'evil.com'],
    ['evil{.}com', 'evil.com'],
    ['https[://]evil.com', 'https://evil.com'],
    ['hxxps[:]//evil[.]com', 'https://evil.com'],
    ['1.2.3.4[:]443', '1.2.3.4:443'],
    ['user[at]evil.com', 'user@evil.com'],
    ['user(@)evil.com', 'user@evil.com'],
  ])('refangs %s', (input, expected) => {
    expect(refangText(input)).toBe(expected);
  });

  it('returns empty strings for empty input', () => {
    expect(defangText('')).toBe('');
    expect(refangText('')).toBe('');
  });
});

describe('CIDR calculator', () => {
  it('converts between dotted and numeric form', () => {
    expect(ipToLong('255.255.255.255')).toBe(4294967295);
    expect(ipToLong('192.168.1.1')).toBe(3232235777);
    expect(longToIp(3232235777)).toBe('192.168.1.1');
    expect(longToIp(0)).toBe('0.0.0.0');
  });

  it('calculates a /24', () => {
    const c = calculateCidr('192.168.1.77/24');
    expect(c).toMatchObject({
      cidr: '192.168.1.0/24',
      netmask: '255.255.255.0',
      wildcard: '0.0.0.255',
      networkAddress: '192.168.1.0',
      broadcastAddress: '192.168.1.255',
      firstUsableIp: '192.168.1.1',
      lastUsableIp: '192.168.1.254',
      totalHosts: 256,
      usableHosts: 254,
      scope: 'RFC 1918 Private',
      ipClass: 'Class C',
    });
  });

  it.each([
    ['10.20.30.40/8', '10.0.0.0/8', 16777214],
    ['172.16.5.4/12', '172.16.0.0/12', 1048574],
    ['8.8.8.8/30', '8.8.8.8/30', 2],
    ['0.0.0.0/0', '0.0.0.0/0', 4294967294],
  ])('%s -> %s with %s usable hosts', (input, cidr, usable) => {
    const c = calculateCidr(input);
    expect(c.cidr).toBe(cidr);
    expect(c.usableHosts).toBe(usable);
  });

  it('treats /31 as a point-to-point link (RFC 3021) and /32 as one host', () => {
    expect(calculateCidr('10.0.0.0/31')).toMatchObject({ usableHosts: 2, firstUsableIp: '10.0.0.0', lastUsableIp: '10.0.0.1' });
    expect(calculateCidr('10.0.0.9/32')).toMatchObject({ usableHosts: 1, firstUsableIp: '10.0.0.9', lastUsableIp: '10.0.0.9' });
  });

  it('defaults to /24 when no prefix is given', () => {
    expect(calculateCidr('10.1.2.3').cidr).toBe('10.1.2.0/24');
  });

  it('splits into four subnets two bits longer', () => {
    const subnets = (calculateCidr('10.0.0.0/24').subnetsBreakdown ?? []).map(s => s.cidr);
    expect(subnets).toEqual(['10.0.0.0/26', '10.0.0.64/26', '10.0.0.128/26', '10.0.0.192/26']);
  });

  it.each(['10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/2x', '10.0.0.0/', '10.0.0.0/24/8'])(
    'reports invalid prefix %s instead of guessing /24',
    input => {
      expect(() => calculateCidr(input)).toThrow(/Invalid prefix length/);
    }
  );

  it.each(['256.0.0.0/24', '10.0.0/24', 'not-an-ip', '1.2.3./24', '1e1.0.0.1/24', '0x10.0.0.1/24'])('rejects invalid address %s', input => {
    expect(() => calculateCidr(input)).toThrow(/Invalid IPv4 address/);
  });

  it.each([
    ['10.0.0.1', 'RFC 1918 Private'],
    ['127.0.0.1', 'Loopback'],
    ['169.254.1.1', 'Link-local'],
    ['100.64.0.1', 'CGNAT (RFC 6598)'],
    ['224.0.0.1', 'Multicast'],
    ['192.0.2.1', 'Reserved'],
    ['8.8.8.8', 'Public IP'],
  ])('%s has scope %s', (ip, scope) => {
    expect(calculateCidr(ip).scope).toBe(scope);
  });
});
