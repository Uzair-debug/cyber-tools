import { beforeEach, describe, expect, it, vi } from 'vitest';

// assertPublicHost resolves names with dns/promises; mock it so tests never touch the network
const lookup = vi.fn();
vi.mock('dns/promises', () => ({ default: { lookup: (...args: unknown[]) => lookup(...args) } }));

const { classifyIp, isNonPublicIp, validateDomain, assertPublicHost, BlockedHostError, readTextCapped } = await import(
  '@/lib/net-utils'
);

describe('classifyIp: IPv4', () => {
  it.each([
    ['8.8.8.8', 'public'],
    ['1.1.1.1', 'public'],
    ['172.15.255.255', 'public'],
    ['172.32.0.1', 'public'],
    ['100.63.255.255', 'public'],
    ['100.128.0.1', 'public'],
    ['10.0.0.1', 'private'],
    ['127.0.0.1', 'private'],
    ['127.255.255.254', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'private'], // cloud metadata endpoint
    ['0.0.0.0', 'bogon'],
    ['100.64.0.1', 'bogon'], // CGNAT
    ['192.0.0.1', 'bogon'],
    ['192.0.2.1', 'bogon'],
    ['198.18.0.1', 'bogon'],
    ['198.51.100.1', 'bogon'],
    ['203.0.113.1', 'bogon'],
    ['224.0.0.1', 'bogon'],
    ['255.255.255.255', 'bogon'],
  ])('%s is %s', (ip, expected) => {
    expect(classifyIp(ip)).toBe(expected);
  });

  it.each(['256.1.1.1', '1.2.3', '1.2.3.4.5', '2130706433', '0x7f.0.0.1', '017700000001', 'localhost', ''])(
    'rejects non-standard form %j as invalid',
    ip => {
      expect(classifyIp(ip)).toBe('invalid');
    }
  );
});

describe('classifyIp: IPv6', () => {
  it.each([
    ['2606:4700:4700::1111', 'public'],
    ['[2001:4860:4860::8888]', 'public'], // bracketed URL form
    ['2002:0808:0808::1', 'public'], // 6to4 wrapping a public IPv4
    ['::1', 'private'],
    ['[::1]', 'private'],
    ['fc00::1', 'private'],
    ['fd12:3456::1', 'private'],
    ['fe80::1', 'private'],
    ['fe80::1%eth0', 'private'],
    ['fec0::1', 'private'],
    ['::ffff:127.0.0.1', 'private'], // IPv4-mapped loopback
    ['::ffff:7f00:1', 'private'],
    ['::ffff:169.254.169.254', 'private'],
    ['::ffff:0:7f00:1', 'private'], // IPv4-translated
    ['64:ff9b::7f00:1', 'private'], // NAT64 loopback
    ['64:ff9b:1::1', 'private'], // local-use NAT64
    ['2002:7f00:1::', 'private'], // 6to4 loopback
    ['2002:c0a8:0101::1', 'private'], // 6to4 192.168.1.1
    ['::ffff:8.8.8.8', 'public'],
    ['::', 'bogon'],
    ['::127.0.0.1', 'bogon'], // IPv4-compatible (deprecated)
    ['2001::1', 'bogon'], // Teredo
    ['2001:db8::1', 'bogon'],
    ['ff02::1', 'bogon'],
    ['100::1', 'bogon'],
  ])('%s is %s', (ip, expected) => {
    expect(classifyIp(ip)).toBe(expected);
  });

  it('isNonPublicIp is true for private and bogon only', () => {
    expect(isNonPublicIp('10.1.1.1')).toBe(true);
    expect(isNonPublicIp('100.64.0.1')).toBe(true);
    expect(isNonPublicIp('8.8.8.8')).toBe(false);
    expect(isNonPublicIp('not-an-ip')).toBe(false);
  });
});

describe('validateDomain', () => {
  it.each(['example.com', 'sub.example.co.za', 'xn--e1afmkfd.xn--p1ai', 'a-b.io', 'mail.example.com'])(
    'accepts %s',
    domain => {
      expect(validateDomain(domain).isValid).toBe(true);
    }
  );

  it.each([
    ['', 'empty'],
    ['8.8.8.8', 'IPv4'],
    ['::1', 'IPv6'],
    ['exa mple.com', 'space'],
    ['example.com\r\nX-Injected: 1', 'CR/LF'],
    ['example.com/path', 'slash'],
    ['.example.com', 'leading dot'],
    ['example.com.', 'trailing dot'],
    ['example..com', 'double dot'],
    ['-example.com', 'leading hyphen'],
    ['example-.com', 'label ending in hyphen'],
    ['localhost', 'no TLD'],
    ['example.c', 'one-letter TLD'],
    [`${'a'.repeat(64)}.com`, '64-char label'],
    [`${'a.'.repeat(127)}com`, 'over 253 chars'],
  ])('rejects %j (%s)', domain => {
    const result = validateDomain(domain);
    expect(result.isValid).toBe(false);
    expect(result.code).toBe('INVALID_DOMAIN');
  });
});

describe('assertPublicHost (SSRF guard)', () => {
  beforeEach(() => {
    lookup.mockReset();
  });

  it.each(['localhost', 'LOCALHOST', 'localhost.', 'printer.local', 'db.internal', 'nas.home.arpa', 'app.localhost'])(
    'blocks internal name %s without resolving it',
    async host => {
      await expect(assertPublicHost(host)).rejects.toBeInstanceOf(BlockedHostError);
      expect(lookup).not.toHaveBeenCalled();
    }
  );

  it.each(['127.0.0.1', '10.0.0.5', '169.254.169.254', '[::1]', '::ffff:127.0.0.1', '64:ff9b::7f00:1', '0.0.0.0'])(
    'blocks non-public IP literal %s',
    async host => {
      await expect(assertPublicHost(host)).rejects.toBeInstanceOf(BlockedHostError);
    }
  );

  it('allows a public IP literal without a DNS lookup', async () => {
    await expect(assertPublicHost('8.8.8.8')).resolves.toEqual(['8.8.8.8']);
    expect(lookup).not.toHaveBeenCalled();
  });

  it('rejects an empty host', async () => {
    await expect(assertPublicHost('  ')).rejects.toBeInstanceOf(BlockedHostError);
  });

  it('returns every resolved address when all are public', async () => {
    lookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:2800:220:1::1', family: 6 },
    ]);
    await expect(assertPublicHost('Example.COM.')).resolves.toEqual(['93.184.216.34', '2606:2800:220:1::1']);
    expect(lookup).toHaveBeenCalledWith('example.com', { all: true, verbatim: true });
  });

  it('blocks a name if ANY resolved address is non-public (rebinding-style records)', async () => {
    lookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    await expect(assertPublicHost('rebind.example')).rejects.toThrow(/non-public address \(127\.0\.0\.1\)/);
  });

  it('blocks names like localtest.me / nip.io that resolve to loopback', async () => {
    lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    await expect(assertPublicHost('127.0.0.1.nip.io')).rejects.toBeInstanceOf(BlockedHostError);
  });

  it('fails closed outside Workers when resolution fails', async () => {
    lookup.mockRejectedValue(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));
    await expect(assertPublicHost('does-not-exist.example')).rejects.toThrow(/could not be resolved/);
  });

  it('fails closed outside Workers when resolution returns nothing', async () => {
    lookup.mockResolvedValue([]);
    await expect(assertPublicHost('empty.example')).rejects.toBeInstanceOf(BlockedHostError);
  });
});

describe('readTextCapped', () => {
  const streamOf = (...chunks: string[]) =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const c of chunks) controller.enqueue(new TextEncoder().encode(c));
        controller.close();
      },
    });

  it('returns the whole body when it is under the cap', async () => {
    expect(await readTextCapped({ body: streamOf('hello ', 'world') }, 1024)).toBe('hello world');
  });

  it('truncates at exactly maxBytes across chunk boundaries', async () => {
    expect(await readTextCapped({ body: streamOf('abcd', 'efgh', 'ijkl') }, 6)).toBe('abcdef');
  });

  it('stops reading once the cap is reached', async () => {
    let pulls = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++;
        controller.enqueue(new Uint8Array(1024).fill(65));
      },
    });
    const text = await readTextCapped({ body: endless }, 4096);
    expect(text).toHaveLength(4096);
    expect(pulls).toBeLessThan(10);
  });

  it('returns an empty string for a missing body', async () => {
    expect(await readTextCapped({ body: null }, 10)).toBe('');
  });
});
