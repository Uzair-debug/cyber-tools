import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit } from '@/lib/rate-limit';
import dns from 'dns/promises';
import net from 'net';
import { IpThreatData } from '@/lib/types';
import { classifyIp, lookupIpGeo, PORT_SERVICE_NAMES } from '@/lib/net-utils';

export const dynamic = 'force-dynamic';

const IS_CLOUDFLARE_WORKER = typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';

const DNSBLS = [
  { name: 'SpamCop', host: 'bl.spamcop.net' },
  { name: 'Barracuda BRBL', host: 'b.barracudacentral.org' },
  { name: 'S5h Security', host: 'all.s5h.net' },
  { name: 'GBUDB Truncate', host: 'truncate.gbudb.net' },
];

const PROBE_PORTS = [80, 443, 22, 53, 3389, 8080];

export async function GET(request: NextRequest) {
  const limited = await enforceRateLimit(request);
  if (limited) return limited;
  // Port probes against a caller-chosen address also count against the stricter limit
  const heavyLimited = await enforceRateLimit(request, 'heavy');
  if (heavyLimited) return heavyLimited;

  const { searchParams } = new URL(request.url);
  const rawIp = searchParams.get('ip') || '';
  const ip = rawIp.trim();

  if (!ip) {
    return NextResponse.json({ error: 'IP address parameter is required' }, { status: 400 });
  }

  // 1. Strict IP format validation (IPv4 or IPv6)
  const ipVersion = net.isIP(ip);
  if (ipVersion === 0) {
    return NextResponse.json(
      { error: `"${ip}" is not a valid IPv4 or IPv6 address. Please provide a valid IP address.` },
      { status: 400 }
    );
  }

  // 2. Check if private / bogon
  const ipClass = classifyIp(ip);
  const isPrivate = ipClass === 'private';
  const isBogon = ipClass === 'bogon';
  const isPublic = ipClass === 'public';

  // 3. Reverse DNS, GeoIP/ASN, live port probes and DNSBL queries are independent, so run them in parallel.
  // Private and bogon addresses are not probed or looked up, so nothing is reported for them.
  const [reverseDns, geoMap, openPorts, dnsblResults] = await Promise.all([
    isPublic ? lookupPtr(ip, ipVersion) : Promise.resolve(undefined),
    isPublic ? lookupIpGeo([ip]) : Promise.resolve(new Map()),
    isPublic ? Promise.all(PROBE_PORTS.map(p => probeTcpPort(ip, p, 1200))) : Promise.resolve([]),
    isPublic && ipVersion === 4
      ? Promise.all(DNSBLS.map(async item => ({ name: item.name, result: await checkDnsbl(ip, item.host) })))
      : Promise.resolve([]),
  ]);

  // 4. GeoIP / ASN
  let geo: IpThreatData['geo'] = undefined;
  let asn: IpThreatData['asn'] = undefined;

  if (isPrivate) {
    geo = {
      country: 'Not geolocatable (non-public address)',
      countryCode: 'N/A',
      city: 'N/A',
      region: 'Private / loopback / link-local range',
    };
    asn = {
      asn: 'N/A',
      name: 'Non-public address (not routed on the internet)',
      route: ip,
    };
  } else {
    const info = geoMap.get(ip);
    if (info) {
      geo = {
        country: info.country || 'Unknown',
        countryCode: info.countryCode || 'N/A',
        city: info.city || 'Unknown',
        region: info.region || 'Unknown',
        latitude: info.latitude,
        longitude: info.longitude,
        timezone: info.timezone,
      };
      asn = {
        asn: info.asn || 'Unknown',
        name: info.asnName || 'Unknown Provider',
        route: ip,
        domain: info.org || undefined,
      };
    }
  }

  // 5. Live Threat Intelligence & Multi-DNSBL verdict (NO RANDOM NUMBERS)
  let threatScore = 0;
  let threatLevel: IpThreatData['threatLevel'] = 'CLEAN';
  let totalReports = 0;
  const categories: string[] = [];

  if (isBogon) {
    threatScore = 80;
    threatLevel = 'SUSPICIOUS';
    totalReports = 0;
    categories.push('Bogon / Unallocated IP Address Space');
  } else if (isPrivate) {
    threatScore = 0;
    threatLevel = 'UNKNOWN';
    totalReports = 0;
    categories.push('Non-public address (private, loopback or link-local) — not checked against blocklists');
  } else if (ipVersion === 4) {
    const detections = dnsblResults.filter(r => r.result === 'listed').map(r => r.name);
    const failedLists = dnsblResults.filter(r => r.result === 'error').map(r => r.name);

    if (failedLists.length > 0) {
      categories.push(`${failedLists.length} of ${DNSBLS.length} blocklists could not be queried: ${failedLists.join(', ')}`);
    }

    if (detections.length === 0 && failedLists.length === DNSBLS.length) {
      threatScore = 0;
      threatLevel = 'UNKNOWN';
      totalReports = 0;
    } else if (detections.length === 0) {
      threatScore = 0;
      threatLevel = 'CLEAN';
      totalReports = 0;
      categories.push(`Not listed on ${DNSBLS.length - failedLists.length} queried blocklists`);
    } else {
      totalReports = detections.length;
      if (detections.length === 1) {
        threatScore = 40;
        threatLevel = 'SUSPICIOUS';
        categories.push(`Flagged on ${detections[0]} Blacklist`);
      } else if (detections.length === 2) {
        threatScore = 75;
        threatLevel = 'MALICIOUS';
        categories.push(`Multi-Listed: ${detections.join(', ')}`);
      } else {
        threatScore = Math.min(100, 70 + detections.length * 10);
        threatLevel = 'MALICIOUS';
        categories.push(`High Risk: Detected on ${detections.join(', ')}`);
      }
    }
  } else {
    // IPv6 addresses are not checked against blocklists, so no reputation verdict is given
    threatScore = 0;
    threatLevel = 'UNKNOWN';
    totalReports = 0;
    categories.push('IPv6 address — blocklist reputation not checked');
  }

  // Workers can't open sockets to Cloudflare's own network, so every probe of a Cloudflare IP
  // times out and would wrongly read as 'filtered'. Report those ports as not probed instead.
  let probedPorts = openPorts;
  let portProbeNote: string | undefined;
  if (IS_CLOUDFLARE_WORKER && asn?.asn === 'AS13335') {
    probedPorts = [];
    portProbeNote = "Cloudflare-hosted address: the portal runs on Cloudflare Workers, which can't open connections to Cloudflare's own network.";
  }

  const result: IpThreatData = {
    ip,
    hostname: reverseDns && reverseDns !== 'No PTR record found' ? reverseDns : undefined,
    asn: asn || {
      asn: 'Unresolved',
      name: 'Unresolved Autonomous System',
      route: `${ip}/32`,
    },
    geo: geo || {
      country: 'Unresolved',
      countryCode: 'N/A',
      city: 'Unresolved',
      region: 'Unresolved',
    },
    isPrivate,
    isBogon,
    reverseDns,
    threatScore,
    threatLevel,
    abuseConfidenceScore: threatScore,
    totalReports,
    openPortsSimulated: probedPorts, // Kept for interface compatibility, contains live TCP probe results
    portProbeNote,
    categories,
  };

  return NextResponse.json(result);
}

// ======================= Helper Functions =======================

/**
 * Reverse DNS. Uses the local resolver first and falls back to DNS-over-HTTPS (the Workers runtime
 * has no reverse lookup). Returns 'No PTR record found' only when DoH confirms there is none;
 * undefined means the lookup itself failed.
 */
async function lookupPtr(ip: string, ipVersion: number): Promise<string | undefined> {
  // Local resolvers often answer ENOTFOUND for PTR queries they can't serve, so any local failure
  // is confirmed over DoH before reporting that no PTR record exists
  try {
    const hostnames = await dns.reverse(ip);
    if (hostnames.length > 0) return hostnames[0];
  } catch {
    // fall through to DoH
  }
  if (ipVersion !== 4) return undefined;

  const ptrName = `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${ptrName}&type=PTR`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return undefined;
    const data = await res.json();
    const ptr = (data?.Answer || []).find((a: any) => a.type === 12)?.data;
    if (ptr) return String(ptr).replace(/\.$/, '');
    return data?.Status === 0 || data?.Status === 3 ? 'No PTR record found' : undefined;
  } catch {
    return undefined;
  }
}

function probeTcpPort(
  host: string,
  port: number,
  timeoutMs = 1200
): Promise<{ port: number; service: string; state: 'open' | 'filtered' | 'closed' }> {
  const service = PORT_SERVICE_NAMES[port] || `Port ${port}`;

  return new Promise(resolve => {
    const socket = new net.Socket();
    let state: 'open' | 'filtered' | 'closed' = 'filtered';
    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      state = 'open';
      socket.destroy();
      resolve({ port, service, state });
    });

    socket.on('timeout', () => {
      state = 'filtered';
      socket.destroy();
      resolve({ port, service, state });
    });

    socket.on('error', err => {
      const code = (err as any)?.code;
      if (code === 'ECONNREFUSED' || code === 'ECONNRESET') {
        state = 'closed';
      } else {
        state = 'filtered';
      }
      socket.destroy();
      resolve({ port, service, state });
    });

    try {
      socket.connect(port, host);
    } catch {
      resolve({ port, service, state: 'filtered' });
    }
  });
}

/**
 * Queries a DNSBL via DoH. Only answers in 127.0.0.2 - 127.0.0.255 mean "listed".
 * DNSBLs answer queries from public resolvers (like Google DNS) with refusal codes such as
 * 127.255.255.254 or 127.0.0.1, which must not be treated as listings.
 */
async function checkDnsbl(ip: string, dnsblHost: string): Promise<'listed' | 'not_listed' | 'error'> {
  const parts = ip.split('.');
  if (parts.length !== 4) return 'error';
  const rev = parts.reverse().join('.');
  const query = `${rev}.${dnsblHost}`;

  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(query)}&type=A`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(2500),
    });

    if (!res.ok) return 'error';
    const data = await res.json();

    // Status 3 = NXDOMAIN: not listed
    if (data.Status === 3) return 'not_listed';
    if (data.Status !== 0) return 'error';

    const answers: string[] = Array.isArray(data.Answer)
      ? data.Answer.filter((a: any) => a.type === 1).map((a: any) => String(a.data))
      : [];
    if (answers.length === 0) return 'not_listed';

    const isListingCode = (a: string) => {
      const octets = a.split('.').map(Number);
      return octets.length === 4 && octets[0] === 127 && octets[1] === 0 && octets[2] === 0 && octets[3] >= 2;
    };

    if (answers.some(isListingCode)) return 'listed';
    // Any other answer (127.255.255.x, 127.0.0.1, ...) is a refusal or error code
    return 'error';
  } catch {
    return 'error';
  }
}
