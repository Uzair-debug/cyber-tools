import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit } from '@/lib/rate-limit';
import net from 'net';
import dns from 'dns/promises';
import { SubdomainResult, WhoisData } from '@/lib/types';
import { assertPublicHost, validateDomain } from '@/lib/net-utils';

export const dynamic = 'force-dynamic';

// Map of common ccTLD and gTLD WHOIS servers
const WHOIS_SERVERS: Record<string, string> = {
  'co.za': 'whois.registry.net.za',
  'net.za': 'whois.registry.net.za',
  'org.za': 'whois.registry.net.za',
  'web.za': 'whois.registry.net.za',
  'za': 'whois.registry.net.za',
  'com': 'whois.verisign-grs.com',
  'net': 'whois.verisign-grs.com',
  'org': 'whois.pir.org',
  'io': 'whois.nic.io',
  'co.uk': 'whois.nic.uk',
  'uk': 'whois.nic.uk',
  'de': 'whois.denic.de',
  'ca': 'whois.cira.ca',
  'au': 'whois.auda.org.au',
  'co': 'whois.nic.co',
  'info': 'whois.afilias.net',
  'biz': 'whois.biz',
  'xyz': 'whois.nic.xyz',
  'tech': 'whois.nic.tech',
  'online': 'whois.nic.online',
  'app': 'whois.nic.google',
  'dev': 'whois.nic.google',
  'ai': 'whois.nic.ai',
};

function getWhoisServer(domain: string): string {
  const parts = domain.split('.');
  if (parts.length >= 3) {
    const sld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (WHOIS_SERVERS[sld]) return WHOIS_SERVERS[sld];
  }
  const tld = parts[parts.length - 1];
  if (WHOIS_SERVERS[tld]) return WHOIS_SERVERS[tld];
  return 'whois.iana.org';
}

const WHOIS_DEADLINE_MS = 8000;
const WHOIS_MAX_RESPONSE_CHARS = 256 * 1024;

function queryWhoisSocket(domain: string, server: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.createConnection(43, server, () => {
      socket.write(`${domain}\r\n`);
    });

    socket.setTimeout(4500);

    // setTimeout only fires on idle, so a server dripping bytes could hold the socket open forever.
    // A hard deadline and size cap bound every query regardless of how the server behaves.
    let buffer = '';
    const deadline = setTimeout(() => socket.destroy(), WHOIS_DEADLINE_MS);
    socket.on('close', () => {
      clearTimeout(deadline);
      resolve(buffer);
    });

    socket.on('data', data => {
      buffer += data.toString('utf-8');
      if (buffer.length > WHOIS_MAX_RESPONSE_CHARS) {
        buffer = buffer.slice(0, WHOIS_MAX_RESPONSE_CHARS);
        socket.destroy();
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(buffer);
    });

    socket.on('end', () => {
      resolve(buffer);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(buffer);
    });
  });
}

/**
 * Queries a WHOIS server named in another server's response. The name comes from remote data, so it
 * must be a well-formed public hostname; the socket connects to the validated address.
 * Returns '' when the server is rejected.
 */
async function queryReferredWhoisServer(domain: string, server: string): Promise<string> {
  const host = server.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/:].*$/, '');
  if (!validateDomain(host).isValid) return '';
  try {
    const addresses = await assertPublicHost(host);
    return await queryWhoisSocket(domain, addresses[0] || host);
  } catch {
    return '';
  }
}

export async function GET(request: NextRequest) {
  const limited = await enforceRateLimit(request);
  if (limited) return limited;

  const { searchParams } = new URL(request.url);
  const rawDomain = searchParams.get('domain') || '';
  const cleanDomain = rawDomain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');

  // Same validation as /api/dns; it also keeps CR/LF out of the raw port 43 query
  const validation = validateDomain(cleanDomain);
  if (!validation.isValid) {
    return NextResponse.json(
      { error: validation.error || 'Invalid domain parameter', suggestion: validation.suggestion },
      { status: 400 }
    );
  }

  try {
    const whoisServer = getWhoisServer(cleanDomain);

    // Run direct WHOIS socket query, RDAP query, and crt.sh Subdomain discovery in parallel
    const [initialSocketText, rdapRes, crtRes] = await Promise.all([
      queryWhoisSocket(cleanDomain, whoisServer),
      fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`, {
        headers: {
          Accept: 'application/rdap+json, application/json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        },
        signal: AbortSignal.timeout(4000),
        next: { revalidate: 3600 },
      })
        .then(r => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${cleanDomain}`)}&output=json`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        signal: AbortSignal.timeout(4000),
        next: { revalidate: 3600 },
      })
        .then(r => (r.ok ? r.json() : []))
        .catch(() => []),
    ]);

    let rawSocketText = initialSocketText;
    let queriedServer = whoisServer;

    // IANA only knows the TLD; follow its "refer:" line to the registry that holds the domain
    if (whoisServer === 'whois.iana.org') {
      const ianaRefer = initialSocketText.match(/^refer:\s*(\S+)/im);
      if (ianaRefer && ianaRefer[1]) {
        queriedServer = ianaRefer[1].trim();
        rawSocketText = await queryReferredWhoisServer(cleanDomain, queriedServer);
      } else {
        // No registry WHOIS exists for this TLD; IANA's TLD record is not domain data
        rawSocketText = '';
      }
    }

    // Check if registry WHOIS referred to a secondary registrar WHOIS server (e.g. Verisign -> MarkMonitor)
    const referralMatch = rawSocketText.match(/Registrar WHOIS Server:\s*([^\s\r\n]+)/i);
    if (referralMatch && referralMatch[1] && referralMatch[1].toLowerCase() !== queriedServer.toLowerCase()) {
      try {
        const secondaryText = await queryReferredWhoisServer(cleanDomain, referralMatch[1].trim());
        if (secondaryText && secondaryText.trim().length > 50) {
          rawSocketText = `${rawSocketText}\n\n--- SECONDARY REGISTRAR WHOIS (${referralMatch[1].trim()}) ---\n${secondaryText}`;
        }
      } catch {
        // Fall back to initial response
      }
    }

    // Parse Port 43 Raw WHOIS Text
    let registrar = '';
    let creationDate = '';
    let expirationDate = '';
    let updatedDate = '';
    let registrantOrg = '';
    let country = '';
    let abuseEmail = '';
    let abusePhone = '';
    const nameservers: string[] = [];
    const status: string[] = [];
    let dnssec = false;

    if (rawSocketText) {
      const lines = rawSocketText.split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        const lower = trimmed.toLowerCase();

        // Registrar
        if (!registrar && (lower.startsWith('registrar:') || lower.startsWith('registrar name:') || lower.startsWith('sponsoring registrar:'))) {
          registrar = trimmed.split(/:(.+)/)[1]?.trim();
        }

        // Creation Date
        if (!creationDate && (lower.startsWith('creation date:') || lower.startsWith('created:') || lower.startsWith('registered:'))) {
          creationDate = trimmed.split(/:(.+)/)[1]?.trim();
        }

        // Expiry Date
        if (
          !expirationDate &&
          (lower.startsWith('registry expiry date:') ||
            lower.startsWith('expiry date:') ||
            lower.startsWith('registrar registration expiration date:') ||
            lower.startsWith('expires:'))
        ) {
          expirationDate = trimmed.split(/:(.+)/)[1]?.trim();
        }

        // Updated Date
        if (!updatedDate && (lower.startsWith('updated date:') || lower.startsWith('last-modified:') || lower.startsWith('changed:'))) {
          updatedDate = trimmed.split(/:(.+)/)[1]?.trim();
        }

        // Registrant Organization
        if (!registrantOrg && (lower.startsWith('registrant organization:') || lower.startsWith('registrant:') || lower.startsWith('org:'))) {
          registrantOrg = trimmed.split(/:(.+)/)[1]?.trim();
        }

        // Country
        if (!country && (lower.startsWith('registrant country:') || lower.startsWith('country:'))) {
          country = trimmed.split(':')[1]?.trim();
        }

        // Abuse Contacts
        if (!abuseEmail && lower.startsWith('registrar abuse contact email:')) {
          abuseEmail = trimmed.split(':')[1]?.trim();
        }
        if (!abusePhone && lower.startsWith('registrar abuse contact phone:')) {
          abusePhone = trimmed.split(':')[1]?.trim();
        }

        // Nameservers
        if (lower.startsWith('name server:') || lower.startsWith('nserver:')) {
          const ns = trimmed.split(':')[1]?.trim().toLowerCase().replace(/\.$/, '');
          if (ns && !nameservers.includes(ns)) {
            nameservers.push(ns);
          }
        }

        // Status
        if (lower.startsWith('domain status:') || lower.startsWith('status:')) {
          const st = trimmed.split(':')[1]?.trim().split(' ')[0];
          if (st && !status.includes(st)) {
            status.push(st);
          }
        }

        // DNSSEC
        if (lower.startsWith('dnssec:')) {
          const dVal = trimmed.split(':')[1]?.trim().toLowerCase();
          if (dVal.includes('signed') && !dVal.includes('unsigned')) {
            dnssec = true;
          }
        }
      }
    }

    // RDAP Fallback if Port 43 values are missing
    const rdapData = rdapRes;
    if (rdapData) {
      if (!registrar) {
        const registrarEntity = (rdapData.entities || []).find((e: any) =>
          e.roles?.includes('registrar') || e.roles?.includes('sponsor')
        );
        if (registrarEntity?.vcardArray?.[1]) {
          const fn = registrarEntity.vcardArray[1].find((item: any) => item[0] === 'fn');
          if (fn) registrar = fn[3];
        } else if (registrarEntity?.handle) {
          registrar = registrarEntity.handle;
        }
      }

      if (!creationDate || !expirationDate) {
        (rdapData.events || []).forEach((ev: any) => {
          if (!creationDate && ev.eventAction === 'registration') creationDate = ev.eventDate;
          if (!expirationDate && ev.eventAction === 'expiration') expirationDate = ev.eventDate;
          if (!updatedDate && (ev.eventAction === 'last changed' || ev.eventAction === 'last update')) updatedDate = ev.eventDate;
        });
      }

      if (nameservers.length === 0 && rdapData.nameservers) {
        rdapData.nameservers.forEach((ns: any) => {
          if (ns.ldhName) {
            const cleanNs = ns.ldhName.toLowerCase().replace(/\.$/, '');
            if (!nameservers.includes(cleanNs)) nameservers.push(cleanNs);
          }
        });
      }

      if (status.length === 0 && Array.isArray(rdapData.status)) {
        status.push(...rdapData.status);
      }

      if (!registrantOrg) {
        const registrantEntity = (rdapData.entities || []).find((e: any) =>
          e.roles?.includes('registrant')
        );
        if (registrantEntity?.vcardArray?.[1]) {
          const fn = registrantEntity.vcardArray[1].find((item: any) => item[0] === 'fn' || item[0] === 'org');
          if (fn && typeof fn[3] === 'string' && fn[3].trim()) registrantOrg = fn[3].trim();
        }
      }

      if (!country) {
        const anyEntity = (rdapData.entities || []).find((e: any) =>
          e.roles?.includes('registrant') || e.roles?.includes('administrative')
        );
        if (anyEntity?.vcardArray?.[1]) {
          const adr = anyEntity.vcardArray[1].find((item: any) => item[0] === 'adr');
          if (adr && Array.isArray(adr[3]) && adr[3][6]) country = adr[3][6];
        }
      }

      if (rdapData.secureDNS?.delegationSigned) {
        dnssec = true;
      }
    }

    // If nameservers were still not found in WHOIS or RDAP, query genuine authoritative DNS NS records
    if (nameservers.length === 0) {
      try {
        const liveNs = await dns.resolveNs(cleanDomain);
        if (Array.isArray(liveNs)) {
          liveNs.forEach(ns => {
            const cleanNs = ns.toLowerCase().replace(/\.$/, '');
            if (cleanNs && !nameservers.includes(cleanNs)) {
              nameservers.push(cleanNs);
            }
          });
        }
      } catch {
        // Domain has no active nameservers
      }
    }

    // Parse crt.sh Subdomains
    const rawCrt = Array.isArray(crtRes) ? crtRes : [];
    const subMap = new Map<string, SubdomainResult>();

    rawCrt.forEach((entry: any) => {
      const nameValue = entry.name_value || entry.common_name;
      if (nameValue) {
        const names = nameValue.split('\n');
        names.forEach((name: string) => {
          const cleanName = name.trim().toLowerCase().replace(/^\*\./, '');
          const belongsToDomain = cleanName === cleanDomain || cleanName.endsWith(`.${cleanDomain}`);
          if (belongsToDomain && !subMap.has(cleanName)) {
            subMap.set(cleanName, {
              subdomain: cleanName,
              issuer: entry.issuer_name ? entry.issuer_name.split(',')[0].replace('O=', '').trim() : 'Unknown CA',
              loggedAt: entry.entry_timestamp || entry.not_before || undefined,
            });
          }
        });
      }
    });

    const subdomains = Array.from(subMap.values()).slice(0, 100);

    // ZERO FAKE OR FALLBACK REGISTRAR / NAMESERVER DATA
    const whois: WhoisData = {
      domain: cleanDomain,
      registrar: registrar || undefined,
      creationDate: creationDate || undefined,
      expirationDate: expirationDate || undefined,
      updatedDate: updatedDate || undefined,
      registrantOrg: registrantOrg || undefined,
      country: country || undefined,
      abuseEmail: abuseEmail || undefined,
      abusePhone: abusePhone || undefined,
      nameservers: nameservers, // Genuine nameservers or empty list if none exist
      status,
      dnssec,
      rawWhois: rawSocketText || undefined,
    };

    return NextResponse.json({
      whois,
      subdomains,
      queriedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    return NextResponse.json(
      { error: 'Failed to retrieve WHOIS / Subdomain intel' },
      { status: 500 }
    );
  }
}
