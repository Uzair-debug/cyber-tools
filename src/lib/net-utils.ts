import net from 'net';
import dns from 'dns/promises';
import { DnsErrorCode } from '@/lib/types';
import { classifyIpv4, IpClass } from '@/lib/ip-class';

// Server-side network helpers shared by the API routes.

export type { IpClass };

export const PORT_SERVICE_NAMES: Record<number, string> = {
  22: 'SSH',
  53: 'DNS (TCP)',
  80: 'HTTP',
  443: 'HTTPS',
  3389: 'RDP',
  8080: 'HTTP-Proxy',
};

/**
 * Expands an IPv6 address into 8 numeric hextets. Embedded IPv4 tails (::ffff:1.2.3.4) are converted.
 */
function expandIpv6(ip: string): number[] | null {
  let addr = ip.split('%')[0]; // drop zone index
  const v4Tail = addr.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4Tail) {
    const o = v4Tail[2].split('.').map(Number);
    addr = `${v4Tail[1]}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (missing < 0) return null;

  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  const nums = groups.map(g => parseInt(g, 16));
  return nums.length === 8 && nums.every(n => !isNaN(n) && n >= 0 && n <= 0xffff) ? nums : null;
}

function classifyIpv6(ip: string): IpClass {
  const h = expandIpv6(ip);
  if (!h) return 'invalid';

  // Ranges that carry an IPv4 address are classified by the embedded address, so
  // e.g. ::ffff:127.0.0.1 or 64:ff9b::7f00:1 can't be used to reach loopback
  const embeddedV4 = (hi: number, lo: number) => classifyIpv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
  const zeros = (from: number, to: number) => h.slice(from, to).every(n => n === 0);

  if (zeros(0, 5) && h[5] === 0xffff) return embeddedV4(h[6], h[7]); // ::ffff:0:0/96 IPv4-mapped
  if (zeros(0, 4) && h[4] === 0xffff && h[5] === 0) return embeddedV4(h[6], h[7]); // ::ffff:0:0:0/96 IPv4-translated
  if (h[0] === 0x0064 && h[1] === 0xff9b && zeros(2, 6)) return embeddedV4(h[6], h[7]); // 64:ff9b::/96 NAT64
  if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0x0001) return 'private'; // 64:ff9b:1::/48 local-use NAT64
  if (h[0] === 0x2002) return embeddedV4(h[1], h[2]); // 2002::/16 6to4

  const isAllZeroPrefix = zeros(0, 7);
  if (isAllZeroPrefix && h[7] === 1) return 'private'; // ::1 loopback
  if ((h[0] & 0xfe00) === 0xfc00) return 'private'; // fc00::/7 unique local
  if ((h[0] & 0xffc0) === 0xfe80) return 'private'; // fe80::/10 link-local
  if ((h[0] & 0xffc0) === 0xfec0) return 'private'; // fec0::/10 site-local (deprecated)

  if (zeros(0, 6) && !isAllZeroPrefix) return 'bogon'; // ::a.b.c.d IPv4-compatible (deprecated)
  if (h[0] === 0x2001 && h[1] === 0x0000) return 'bogon'; // 2001::/32 Teredo

  if (isAllZeroPrefix && h[7] === 0) return 'bogon'; // :: unspecified
  if ((h[0] & 0xff00) === 0xff00) return 'bogon'; // ff00::/8 multicast
  if (h[0] === 0x2001 && h[1] === 0x0db8) return 'bogon'; // 2001:db8::/32 documentation
  if (h[0] === 0x0100 && h[1] === 0 && h[2] === 0 && h[3] === 0) return 'bogon'; // 100::/64 discard

  return 'public';
}

/**
 * Classifies an IP address (IPv4, IPv6 or bracketed IPv6 from a URL hostname).
 * 'private' = RFC 1918, loopback, link-local, unique local; 'bogon' = reserved / non-routable.
 */
export function classifyIp(ip: string): IpClass {
  const clean = ip.trim().replace(/^\[|\]$/g, '');
  const version = net.isIP(clean);
  if (version === 4) return classifyIpv4(clean);
  if (version === 6) return classifyIpv6(clean);
  return 'invalid';
}

/**
 * True for any address that must not be reached from the server (private or bogon).
 */
export function isNonPublicIp(ip: string): boolean {
  const cls = classifyIp(ip);
  return cls === 'private' || cls === 'bogon';
}

/**
 * Validates a domain name (letters, digits, hyphens and dots; a TLD; 1-63 character labels).
 * Rejects IP addresses, whitespace and control characters such as CR/LF.
 */
export function validateDomain(domain: string): {
  isValid: boolean;
  code?: DnsErrorCode;
  error?: string;
  suggestion?: string;
} {
  if (!domain) {
    return {
      isValid: false,
      code: 'INVALID_DOMAIN',
      error: 'Domain parameter is required',
      suggestion: 'Provide a target domain such as "example.com" or "microsoft.com".',
    };
  }

  if (domain.length > 253) {
    return {
      isValid: false,
      code: 'INVALID_DOMAIN',
      error: 'Domain name exceeds maximum permitted length of 253 characters',
      suggestion: 'Check the domain name for typographical errors or accidental repetition.',
    };
  }

  // Check if input is an IP address
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || /^[0-9a-fA-F:]+$/.test(domain)) {
    return {
      isValid: false,
      code: 'INVALID_DOMAIN',
      error: `"${domain}" is an IP address, not a domain name`,
      suggestion: 'Use the IP Threat Intelligence tool for direct IP address reconnaissance.',
    };
  }

  if (domain.includes(' ') || /[^a-z0-9.-]/i.test(domain)) {
    return {
      isValid: false,
      code: 'INVALID_DOMAIN',
      error: 'Domain contains invalid characters or whitespace',
      suggestion: 'Domain names may only contain letters, numbers, hyphens, and dots.',
    };
  }

  if (
    domain.startsWith('.') ||
    domain.endsWith('.') ||
    domain.startsWith('-') ||
    domain.endsWith('-') ||
    domain.includes('..')
  ) {
    return {
      isValid: false,
      code: 'INVALID_DOMAIN',
      error: 'Malformed domain structure (leading/trailing dots, hyphens, or consecutive dots)',
      suggestion: 'Ensure the domain follows standard dot-separated notation (e.g. domain.com).',
    };
  }

  const labels = domain.split('.');
  if (labels.length < 2 || !labels[labels.length - 1] || labels[labels.length - 1].length < 2) {
    return {
      isValid: false,
      code: 'INVALID_DOMAIN',
      error: 'Domain must include a valid Top-Level Domain (TLD)',
      suggestion: 'Ensure the domain includes an authoritative suffix like .com, .org, or .co.za.',
    };
  }

  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return {
        isValid: false,
        code: 'INVALID_DOMAIN',
        error: `Domain label "${label}" is invalid (labels must be 1 to 63 characters)`,
        suggestion: 'Verify the domain name spelling.',
      };
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return {
        isValid: false,
        code: 'INVALID_DOMAIN',
        error: `Domain label "${label}" cannot begin or end with a hyphen`,
        suggestion: 'Remove leading or trailing hyphens from labels.',
      };
    }
  }

  return { isValid: true };
}

const IS_CLOUDFLARE_WORKER = typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';

// Hostnames that only make sense inside a private network
const INTERNAL_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];

/**
 * Thrown when a target is refused by the SSRF guard. Its message is safe to show to the caller.
 */
export class BlockedHostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BlockedHostError';
  }
}

/**
 * SSRF guard for server-side requests to user-supplied hosts. Throws BlockedHostError when the
 * host is localhost / an internal name, a non-public IP literal, or resolves to ANY non-public
 * address. Returns the validated addresses so callers can connect to one of them directly.
 *
 * Fails closed when the name cannot be resolved, except on Cloudflare Workers: there node:dns runs
 * over DoH (which can fail on its own), and the Workers runtime cannot reach private networks, so
 * the request is allowed and an empty list is returned.
 *
 * Residual risk: fetch() resolves the name again, so a DNS-rebinding host with a very short TTL can
 * still swap in a private address between this check and the connection. Raw sockets (TLS, WHOIS)
 * avoid this by connecting to the returned address.
 */
export async function assertPublicHost(hostname: string): Promise<string[]> {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host) throw new BlockedHostError('A target host is required.');

  if (host === 'localhost' || INTERNAL_HOST_SUFFIXES.some(s => host.endsWith(s))) {
    throw new BlockedHostError(`Access to internal host "${host}" is blocked.`);
  }

  if (net.isIP(host)) {
    if (classifyIp(host) !== 'public') {
      throw new BlockedHostError(`Access to non-public IP address ${host} is blocked.`);
    }
    return [host];
  }

  let addresses: string[] = [];
  try {
    const results = await dns.lookup(host, { all: true, verbatim: true });
    addresses = results.map(r => r.address);
  } catch {
    // Resolution failed: handled below
  }
  if (addresses.length === 0) {
    if (IS_CLOUDFLARE_WORKER) return [];
    throw new BlockedHostError(`Host "${host}" could not be resolved.`);
  }

  const blocked = addresses.find(a => classifyIp(a) !== 'public');
  if (blocked) {
    throw new BlockedHostError(`Host "${host}" resolves to a non-public address (${blocked}). Blocked for security.`);
  }
  return addresses;
}

export interface IpGeoInfo {
  country: string;
  countryCode: string;
  region: string;
  city: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  asn: string; // e.g. "AS15169", or '' when unknown
  asnName: string; // ISP / ASN organisation
  org: string;
}

const GEO_CACHE_TTL_MS = 60 * 60 * 1000;
const geoCache = new Map<string, { value: IpGeoInfo | null; expires: number }>();

/**
 * Looks up geolocation / ASN for several IPs in one request.
 * Primary: ip-api.com batch endpoint (free tier is HTTP-only, 15 batch requests/min, 100 IPs each).
 * Fallback: freeipapi.com per IP (first 2) for anything the primary could not resolve.
 * Results are cached in memory for an hour. Missing entries mean the lookup failed.
 */
export async function lookupIpGeo(ips: string[]): Promise<Map<string, IpGeoInfo>> {
  const results = new Map<string, IpGeoInfo>();
  const now = Date.now();
  const pending: string[] = [];

  for (const ip of Array.from(new Set(ips))) {
    if (classifyIp(ip) !== 'public') continue;
    const cached = geoCache.get(ip);
    if (cached && cached.expires > now) {
      if (cached.value) results.set(ip, cached.value);
    } else {
      pending.push(ip);
    }
  }
  if (pending.length === 0) return results;

  const fields = 'status,query,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as';
  try {
    const res = await fetch(`http://ip-api.com/batch?fields=${fields}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pending.slice(0, 100).map(query => ({ query }))),
      signal: AbortSignal.timeout(4000),
    });
    if (res.ok) {
      const rows = await res.json();
      if (Array.isArray(rows)) {
        for (const row of rows) {
          if (row?.status !== 'success' || !row.query) continue;
          const info: IpGeoInfo = {
            country: row.country || '',
            countryCode: row.countryCode || '',
            region: row.regionName || '',
            city: row.city || '',
            latitude: row.lat,
            longitude: row.lon,
            timezone: row.timezone,
            asn: (row.as || '').split(' ')[0] || '',
            asnName: row.isp || row.org || '',
            org: row.org || '',
          };
          results.set(row.query, info);
          geoCache.set(row.query, { value: info, expires: now + GEO_CACHE_TTL_MS });
        }
      }
    }
  } catch {
    // Primary failed, fall back per IP below
  }

  // Per-IP fallback is capped: on Cloudflare Workers each fetch is a subrequest (50 per request on the free plan)
  const unresolved = pending.filter(ip => !results.has(ip)).slice(0, 2);
  await Promise.all(
    unresolved.map(async ip => {
      try {
        const res = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`, {
          signal: AbortSignal.timeout(3000),
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!data?.countryName) return;
        const info: IpGeoInfo = {
          country: data.countryName || '',
          countryCode: data.countryCode || '',
          region: data.regionName || '',
          city: data.cityName || '',
          latitude: data.latitude,
          longitude: data.longitude,
          timezone: data.timeZones?.[0],
          asn: data.asn ? `AS${data.asn}` : '',
          asnName: data.asnOrganization || '',
          org: data.asnOrganization || '',
        };
        results.set(ip, info);
        geoCache.set(ip, { value: info, expires: Date.now() + GEO_CACHE_TTL_MS });
      } catch {
        // Lookup failed; leave unresolved
      }
    })
  );

  // Cache failures briefly so repeated scans don't hammer rate-limited providers
  for (const ip of pending) {
    if (!results.has(ip)) geoCache.set(ip, { value: null, expires: Date.now() + 5 * 60 * 1000 });
  }

  return results;
}

/**
 * Reads a response or request body as text, stopping at maxBytes so a hostile server can't make us buffer
 * an unbounded body. Anything past the cap is dropped.
 */
export async function readTextCapped(res: { body: ReadableStream<Uint8Array> | null }, maxBytes: number): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value.subarray(0, maxBytes - total));
    total += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  return new TextDecoder().decode(Buffer.concat(chunks));
}
