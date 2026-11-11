import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit } from '@/lib/rate-limit';
import dns from 'dns/promises';
import crypto from 'crypto';
import { assertPublicHost, BlockedHostError, lookupIpGeo, readTextCapped, validateDomain } from '@/lib/net-utils';
import { DkimSelectorResult, DnsErrorCode, DnsErrorResponse, DnsRecordResult, DomainReconData, PolicyEvaluation } from '@/lib/types';

interface DohQueryResult {
  records: any[];
  status?: number; // 0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN, 5 = REFUSED
  ad?: boolean; // Authenticated Data: resolver validated the answer with DNSSEC
  cnames?: Array<{ name: string; target: string }>; // CNAME chain the resolver followed
  error?: string;
  isTimeout?: boolean;
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

  // 1. Rigorous Domain Validation
  const validation = validateDomain(cleanDomain);
  if (!validation.isValid) {
    const errPayload: DnsErrorResponse = {
      error: validation.error || 'Invalid domain parameter',
      code: validation.code || 'INVALID_DOMAIN',
      domain: cleanDomain,
      suggestion: validation.suggestion || 'Provide a fully qualified domain name (e.g. example.com).',
    };
    return NextResponse.json(errPayload, { status: 400 });
  }

  try {
    const records: Record<string, DnsRecordResult> = {};
    const recordErrors: Record<string, string> = {};

    // 2. Resolve standard record types in parallel with local resolver
    const [
      aRes,
      aaaaRes,
      mxRes,
      txtRes,
      cnameRes,
      nsRes,
      soaRes,
      caaRes,
      dmarcTxt,
      bimiTxt,
      mtaStsTxt,
    ] = await Promise.allSettled([
      dns.resolve4(cleanDomain, { ttl: true }).catch(() =>
        dns.resolve4(cleanDomain).then(ips => ips.map(ip => ({ address: ip, ttl: undefined })))
      ),
      dns.resolve6(cleanDomain, { ttl: true }).catch(() =>
        dns.resolve6(cleanDomain).then(ips => ips.map(ip => ({ address: ip, ttl: undefined })))
      ),
      dns.resolveMx(cleanDomain),
      dns.resolveTxt(cleanDomain),
      dns.resolveCname(cleanDomain),
      dns.resolveNs(cleanDomain),
      dns.resolveSoa(cleanDomain),
      dns.resolveCaa(cleanDomain),
      dns.resolveTxt(`_dmarc.${cleanDomain}`),
      dns.resolveTxt(`default._bimi.${cleanDomain}`),
      dns.resolveTxt(`_mta-sts.${cleanDomain}`),
    ]);

    // Track local resolver errors for diagnostics
    const localRejections: Record<string, any> = {};
    const checkRejection = (key: string, res: PromiseSettledResult<any>) => {
      if (res.status === 'rejected') {
        localRejections[key] = res.reason;
      }
    };
    checkRejection('A', aRes);
    checkRejection('AAAA', aaaaRes);
    checkRejection('MX', mxRes);
    checkRejection('TXT', txtRes);
    checkRejection('NS', nsRes);
    checkRejection('SOA', soaRes);

    // 3. Fallback to DoH (Cloudflare DNS-over-HTTPS with 3.5s timeout) for types the local resolver
    // returned nothing for (skipped on Workers, see dohIfLocalFailed). All fallbacks run in parallel.
    const [aDohResult, aaaaDoh, mxDoh, txtDoh, nsDohResult, dmarcDoh, caaDoh] = await Promise.all([
      dohIfLocalFailed(aRes, cleanDomain, 'A'),
      dohIfLocalFailed(aaaaRes, cleanDomain, 'AAAA'),
      dohIfLocalFailed(mxRes, cleanDomain, 'MX'),
      dohIfLocalFailed(txtRes, cleanDomain, 'TXT'),
      dohIfLocalFailed(nsRes, cleanDomain, 'NS'),
      dohIfLocalFailed(dmarcTxt, `_dmarc.${cleanDomain}`, 'TXT'),
      dohIfLocalFailed(caaRes, cleanDomain, 'CAA'),
    ]);
    const aRecords = aDohResult.records;
    const aaaaRecords = aaaaDoh.records;
    const mxRecords = mxDoh.records;
    const txtRecords = txtDoh.records;
    const nsRecords = nsDohResult.records;
    const dmarcRecords = dmarcDoh.records;

    // 4. Evaluate Global Domain Existence / Network Failures
    const hasAnyCoreRecord =
      aRecords.length > 0 ||
      aaaaRecords.length > 0 ||
      mxRecords.length > 0 ||
      nsRecords.length > 0 ||
      txtRecords.length > 0 ||
      soaRes.status === 'fulfilled';

    if (!hasAnyCoreRecord) {
      // Check if Cloudflare DoH reported explicit NXDOMAIN (status 3)
      const isDoHNxdomain = aDohResult.status === 3 || nsDohResult.status === 3;
      // Check if local resolver reported ENOTFOUND / NXDOMAIN
      const isLocalNxdomain = Object.values(localRejections).some(
        err => err?.code === 'ENOTFOUND' || err?.code === 'NXDOMAIN'
      );

      if (isDoHNxdomain || isLocalNxdomain) {
        const errPayload: DnsErrorResponse = {
          error: `Domain "${cleanDomain}" not found (NXDOMAIN)`,
          code: 'NXDOMAIN',
          domain: cleanDomain,
          details:
            'The requested domain does not exist, has expired, or has no active authoritative nameservers registered in the root zone.',
          suggestion:
            'Verify the spelling of the domain or query WHOIS to confirm whether the domain is currently registered.',
        };
        return NextResponse.json(errPayload, { status: 404 });
      }

      // Check for Timeout
      const isDoHTimeout = aDohResult.isTimeout || nsDohResult.isTimeout;
      const isLocalTimeout = Object.values(localRejections).some(
        err => err?.code === 'ETIMEDOUT' || err?.code === 'ETIMEOUT' || err?.name === 'TimeoutError'
      );

      if (isDoHTimeout || isLocalTimeout) {
        const errPayload: DnsErrorResponse = {
          error: `DNS Query Timed Out for "${cleanDomain}"`,
          code: 'DNS_TIMEOUT',
          domain: cleanDomain,
          details: 'Upstream authoritative nameservers did not respond within the 3.5s timeout threshold.',
          suggestion:
            'The domain nameservers may be temporarily unreachable, overloaded, or rate-limiting queries. Please retry in a few seconds.',
        };
        return NextResponse.json(errPayload, { status: 504 });
      }

      // Check for SERVFAIL
      const isDoHServfail = aDohResult.status === 2 || nsDohResult.status === 2;
      const isLocalServfail = Object.values(localRejections).some(err => err?.code === 'ESERVFAIL');

      if (isDoHServfail || isLocalServfail) {
        const errPayload: DnsErrorResponse = {
          error: `DNS Server Failure (SERVFAIL) for "${cleanDomain}"`,
          code: 'SERVFAIL',
          domain: cleanDomain,
          details:
            'The nameserver encountered an internal failure resolving the domain. This frequently occurs when DNSSEC validation fails due to mismatched DS records.',
          suggestion:
            'Inspect DNSSEC delegation or authoritative server configurations for zone configuration errors.',
        };
        return NextResponse.json(errPayload, { status: 502 });
      }
    }

    // 5. Format Records With Proper Status and Error Handling

    // Format A Records
    if (aRecords.length > 0) {
      records['A'] = {
        type: 'A',
        status: 'found',
        records: aRecords.map((r: any) => ({
          value: typeof r === 'string' ? r : r.address || r.data || r.value || String(r),
          ttl: typeof r === 'object' ? r.ttl : undefined,
        })),
      };
    } else if (aRes.status === 'rejected' && aRes.reason?.code !== 'ENODATA' && aRes.reason?.code !== 'ENOTFOUND') {
      records['A'] = {
        type: 'A',
        status: 'error',
        records: [],
        errorMessage: aRes.reason?.message || 'Failed to query A records',
      };
      recordErrors['A'] = aRes.reason?.message || 'A record resolution failed';
    } else {
      records['A'] = { type: 'A', status: 'not_found', records: [] };
    }

    // Format AAAA Records
    if (aaaaRecords.length > 0) {
      records['AAAA'] = {
        type: 'AAAA',
        status: 'found',
        records: aaaaRecords.map((r: any) => ({
          value: typeof r === 'string' ? r : r.address || r.data || r.value || String(r),
          ttl: typeof r === 'object' ? r.ttl : undefined,
        })),
      };
    } else if (aaaaRes.status === 'rejected' && aaaaRes.reason?.code !== 'ENODATA' && aaaaRes.reason?.code !== 'ENOTFOUND') {
      records['AAAA'] = {
        type: 'AAAA',
        status: 'error',
        records: [],
        errorMessage: aaaaRes.reason?.message || 'Failed to query AAAA records',
      };
      recordErrors['AAAA'] = aaaaRes.reason?.message || 'AAAA record resolution failed';
    } else {
      records['AAAA'] = { type: 'AAAA', status: 'not_found', records: [] };
    }

    // Format MX Records
    if (mxRecords.length > 0) {
      records['MX'] = {
        type: 'MX',
        status: 'found',
        records: mxRecords.map(r => {
          if (typeof r === 'string') return { value: r };
          if (r.exchange !== undefined) return { value: r.exchange, priority: r.priority };
          // DoH MX data format: "<priority> <exchange>"
          const [prio, ...host] = String(r.data || '').split(' ');
          const parsedPrio = parseInt(prio, 10);
          return {
            value: host.join(' ') || r.data,
            priority: isNaN(parsedPrio) ? undefined : parsedPrio,
            ttl: r.ttl,
          };
        }),
      };
    } else if (mxRes.status === 'rejected' && mxRes.reason?.code !== 'ENODATA' && mxRes.reason?.code !== 'ENOTFOUND') {
      records['MX'] = {
        type: 'MX',
        status: 'error',
        records: [],
        errorMessage: mxRes.reason?.message || 'Failed to query MX records',
      };
      recordErrors['MX'] = mxRes.reason?.message || 'MX record resolution failed';
    } else {
      records['MX'] = { type: 'MX', status: 'not_found', records: [] };
    }

    // Format TXT Records
    const txtStrings: string[] = [];
    if (txtRecords.length > 0) {
      const txtTtls: Array<number | undefined> = [];
      txtRecords.forEach(entry => {
        if (typeof entry === 'string') txtStrings.push(joinTxtData(entry));
        else if (Array.isArray(entry)) txtStrings.push(entry.join(''));
        else if (entry.data) txtStrings.push(joinTxtData(entry.data));
        else return;
        txtTtls.push(typeof entry === 'object' && !Array.isArray(entry) ? entry.ttl : undefined);
      });
      records['TXT'] = {
        type: 'TXT',
        status: 'found',
        records: txtStrings.map((v, i) => ({ value: v, ttl: txtTtls[i] })),
      };
    } else if (txtRes.status === 'rejected' && txtRes.reason?.code !== 'ENODATA' && txtRes.reason?.code !== 'ENOTFOUND') {
      records['TXT'] = {
        type: 'TXT',
        status: 'error',
        records: [],
        errorMessage: txtRes.reason?.message || 'Failed to query TXT records',
      };
      recordErrors['TXT'] = txtRes.reason?.message || 'TXT record resolution failed';
    } else {
      records['TXT'] = { type: 'TXT', status: 'not_found', records: [] };
    }

    // Format CNAME Records
    if (cnameRes.status === 'fulfilled' && cnameRes.value && cnameRes.value.length > 0) {
      records['CNAME'] = {
        type: 'CNAME',
        status: 'found',
        records: (Array.isArray(cnameRes.value) ? cnameRes.value : [cnameRes.value]).map(v => ({ value: v })),
      };
    } else if (cnameRes.status === 'rejected' && cnameRes.reason?.code !== 'ENODATA' && cnameRes.reason?.code !== 'ENOTFOUND') {
      records['CNAME'] = {
        type: 'CNAME',
        status: 'error',
        records: [],
        errorMessage: cnameRes.reason?.message || 'Failed to query CNAME records',
      };
    } else {
      records['CNAME'] = { type: 'CNAME', status: 'not_found', records: [] };
    }

    // Format NS Records
    if (nsRecords.length > 0) {
      records['NS'] = {
        type: 'NS',
        status: 'found',
        records: nsRecords.map(v => (typeof v === 'string' ? { value: v } : { value: v.data || v, ttl: v.ttl })),
      };
    } else if (nsRes.status === 'rejected' && nsRes.reason?.code !== 'ENODATA' && nsRes.reason?.code !== 'ENOTFOUND') {
      records['NS'] = {
        type: 'NS',
        status: 'error',
        records: [],
        errorMessage: nsRes.reason?.message || 'Failed to query NS records',
      };
      recordErrors['NS'] = nsRes.reason?.message || 'NS record resolution failed';
    } else {
      records['NS'] = { type: 'NS', status: 'not_found', records: [] };
    }

    // Format SOA Records
    if (soaRes.status === 'fulfilled' && soaRes.value) {
      const s = soaRes.value;
      records['SOA'] = {
        type: 'SOA',
        status: 'found',
        records: [
          {
            value: `Primary NS: ${s.nsname}, Hostmaster: ${s.hostmaster}, Serial: ${s.serial}, Refresh: ${s.refresh}, Retry: ${s.retry}, Expire: ${s.expire}, Min TTL: ${s.minttl}`,
          },
        ],
      };
    } else if (soaRes.status === 'rejected' && soaRes.reason?.code !== 'ENODATA' && soaRes.reason?.code !== 'ENOTFOUND') {
      records['SOA'] = {
        type: 'SOA',
        status: 'error',
        records: [],
        errorMessage: soaRes.reason?.message || 'Failed to query SOA records',
      };
    } else {
      records['SOA'] = { type: 'SOA', status: 'not_found', records: [] };
    }

    // Format CAA Records
    if (caaDoh.records.length > 0) {
      records['CAA'] = {
        type: 'CAA',
        status: 'found',
        records: caaDoh.records.map((c: any) => {
          // DoH returns text: '0 issue "letsencrypt.org"'
          if (typeof c.data === 'string') {
            const m = c.data.match(/^(\d+)\s+(\S+)\s+"?(.*?)"?$/);
            if (m) return { value: `${m[2]} "${m[3]}" (flags: ${m[1]})`, tag: m[2] };
            return { value: c.data };
          }
          // Node returns { critical, <tag>: value }, e.g. { critical: 0, issue: 'letsencrypt.org' }
          const tag = Object.keys(c).find(k => k !== 'critical') || '';
          return { value: `${tag} "${tag ? c[tag] : ''}" (flags: ${c.critical ?? 0})`, tag };
        }),
      };
    } else if (caaDoh.error) {
      records['CAA'] = {
        type: 'CAA',
        status: 'error',
        records: [],
        errorMessage: caaDoh.error,
      };
    } else if (caaRes.status === 'rejected' && caaRes.reason?.code !== 'ENODATA' && caaRes.reason?.code !== 'ENOTFOUND' && caaDoh.status === undefined) {
      records['CAA'] = {
        type: 'CAA',
        status: 'error',
        records: [],
        errorMessage: caaRes.reason?.message || 'Failed to query CAA records',
      };
    } else {
      records['CAA'] = { type: 'CAA', status: 'not_found', records: [] };
    }

    // Policy Analysis: DMARC
    let dmarcString = '';
    if (dmarcRecords.length > 0) {
      const entries = dmarcRecords.map(e => {
        if (typeof e === 'string') return joinTxtData(e);
        if (Array.isArray(e)) return e.join('');
        return joinTxtData(e.data || '');
      });
      dmarcString = entries.find(e => e.toLowerCase().startsWith('v=dmarc1')) || entries[0] || '';
    }
    const dmarcPolicy = parseDmarcPolicy(dmarcString);

    const spfRecord = txtStrings.find(t => t.toLowerCase().startsWith('v=spf1'));
    const primaryIp = records['A']?.records[0]?.value || '';
    const nsHosts = (records['NS']?.records || []).map(r => r.value.replace(/\.$/, ''));
    const mxHosts = (records['MX']?.records || []).map(r => r.value.replace(/\.$/, ''));

    // DKIM selectors to probe
    // Selectors are DNS labels (RFC 6376); anything else is ignored rather than queried or echoed
    const rawSelector = searchParams.get('dkimSelector')?.trim().toLowerCase();
    const customSelector = rawSelector && /^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63}){0,3}$/.test(rawSelector) ? rawSelector : undefined;
    const selectorsToProbe = [
      'selector1',
      'selector2',
      'google',
      'k1',
      'default',
      's1',
      's2',
      'sig1',
      'mimecast1',
      'mimecast2',
      'mandrill',
      'sendgrid',
      'smtp',
      'mail',
      'dkim',
    ];
    if (customSelector && !selectorsToProbe.includes(customSelector)) {
      selectorsToProbe.unshift(customSelector);
    }

    const txtWithDohFallback = async (local: PromiseSettledResult<string[][]>, name: string): Promise<string[]> =>
      (await dohIfLocalFailed(local, name, 'TXT')).records.map(r =>
        Array.isArray(r) ? r.join('') : typeof r === 'string' ? r : joinTxtData(r.data || '')
      );

    // 6-10. Everything below depends only on the records above, so it runs in parallel
    const [spfLookups, bimiEntries, mtaStsPolicy, hostIps, dkimResults, dnssec] = await Promise.all([
      spfRecord ? countSpfLookups(spfRecord, 0, new Set([cleanDomain])) : Promise.resolve(undefined),
      txtWithDohFallback(bimiTxt, `default._bimi.${cleanDomain}`),
      txtWithDohFallback(mtaStsTxt, `_mta-sts.${cleanDomain}`).then(entries =>
        evaluateMtaSts(cleanDomain, entries.find(e => e.toLowerCase().startsWith('v=stsv1')) || '')
      ),
      resolveHostIps([...nsHosts.slice(0, 3), ...mxHosts.slice(0, 3)]),
      Promise.all(selectorsToProbe.map(sel => resolveDkimSelector(cleanDomain, sel))),
      checkDnssec(cleanDomain),
    ]);

    const spfPolicy = parseSpfPolicy(spfRecord, spfLookups);
    const bimiPolicy = parseBimiPolicy(bimiEntries.find(e => e.toLowerCase().startsWith('v=bimi1')) || '');

    // One batched geolocation request for the web host, nameservers and mail servers
    const geo = await lookupIpGeo([primaryIp, ...Array.from(hostIps.values())].filter(Boolean));

    // Identify Web Hosting Company via IP ASN/ISP (NO HARDCODED MOCKS)
    const primaryGeo = primaryIp ? geo.get(primaryIp) : undefined;
    const webHost = primaryGeo
      ? {
          company: primaryGeo.org || primaryGeo.asnName || 'Unresolved Hosting Provider',
          asn: primaryGeo.asn,
          org: primaryGeo.org,
          country: primaryGeo.country,
          city: primaryGeo.city,
          ip: primaryIp,
        }
      : {
          company: primaryIp ? 'Unresolved Hosting Provider' : 'Unresolved',
          asn: '',
          org: primaryIp ? 'Unresolved Organization' : 'Unresolved',
          country: '',
          city: '',
          ip: primaryIp || 'N/A',
        };

    // Enrich A Records: geolocation was only looked up for the primary IP
    if (records['A']?.records) {
      records['A'].records = records['A'].records.map(r => {
        const isPrimary = r.value === primaryIp;
        return {
          ...r,
          resolvedIp: r.value,
          countryCode: isPrimary && primaryGeo?.countryCode ? primaryGeo.countryCode : undefined,
          orgProvider: isPrimary && primaryGeo ? webHost.company : undefined,
        };
      });
    }

    // Enrich NS / MX Records with resolved IPs and authentic Orgs
    const enrichHost = (host: string) => {
      const ip = hostIps.get(host) || '';
      const info = ip ? geo.get(ip) : undefined;
      return {
        resolvedIp: ip ? (info?.countryCode ? `${ip} ${info.countryCode}` : ip) : undefined,
        countryCode: info?.countryCode || undefined,
        orgProvider: info?.org || info?.asnName || undefined,
      };
    };

    if (records['NS']?.records) {
      records['NS'].records = records['NS'].records.map(r => ({ ...r, ...enrichHost(r.value.replace(/\.$/, '')) }));
    }

    if (records['MX']?.records) {
      records['MX'].records = records['MX'].records.map(r => {
        const mxHost = r.value.replace(/\.$/, '');
        const enriched = enrichHost(mxHost);
        let mxOrg = enriched.orgProvider;
        if (!mxOrg) {
          if (mxHost.toLowerCase().includes('outlook') || mxHost.toLowerCase().includes('microsoft')) {
            mxOrg = 'Microsoft 365 / Exchange Online';
          } else if (mxHost.toLowerCase().includes('google') || mxHost.toLowerCase().includes('gmail')) {
            mxOrg = 'Google Workspace Mail';
          }
        }
        return { ...r, ...enriched, orgProvider: mxOrg };
      });
    }

    // Identify Mail Hosting Company via MX records
    const primaryMx = records['MX']?.records[0]?.value || '';
    const mailProvider = detectMailHost(primaryMx);

    // Identify DNS Hosting Provider via NS records
    const nsValues = (records['NS']?.records || []).map(r => r.value);
    const dnsProvider = detectDnsHost(nsValues);

    const isDnssecEnabled = dnssec.enabled;
    const dnssecDetails = dnssec.details;

    const responseData = {
      domain: cleanDomain,
      resolvedIp: primaryIp || undefined,
      hosting: {
        webHost,
        mailHost: {
          provider: mailProvider,
          mxHost: primaryMx || undefined,
        },
        dnsHost: {
          provider: dnsProvider,
          nameservers: nsValues,
        },
      },
      dkimSelectors: dkimResults,
      records,
      recordErrors: Object.keys(recordErrors).length > 0 ? recordErrors : undefined,
      policies: {
        spf: spfPolicy,
        dmarc: dmarcPolicy,
        bimi: bimiPolicy,
        mtaSts: mtaStsPolicy,
      },
      dnssec: {
        enabled: isDnssecEnabled,
        details: dnssecDetails,
      },
      queriedAt: new Date().toISOString(),
    };

    return NextResponse.json(responseData);
  } catch (error: any) {
    const isTimeout =
      error.name === 'TimeoutError' ||
      error.code === 'ETIMEDOUT' ||
      error.code === 'ETIMEOUT';
    const isConnRefused = error.code === 'ECONNREFUSED';

    const code: DnsErrorCode = isTimeout
      ? 'DNS_TIMEOUT'
      : isConnRefused
      ? 'NETWORK_ERROR'
      : 'RESOLVER_ERROR';

    const status = isTimeout ? 504 : isConnRefused ? 502 : 500;

    const errPayload: DnsErrorResponse = {
      error: isTimeout ? 'DNS Query Timed Out' : 'DNS Lookup Failed',
      code,
      domain: cleanDomain,
      details: error.code ? `Resolver error code: ${error.code}` : undefined,
      suggestion: isTimeout
        ? 'DNS servers took too long to answer. Verify network routing and retry.'
        : 'An unexpected error occurred during DNS analysis.',
    };

    return NextResponse.json(errPayload, { status });
  }
}

// ======================= Helper Functions =======================

// On Cloudflare Workers, node:dns already resolves over Cloudflare DoH, and each lookup is a
// subrequest (50 per request on the free plan), so empty answers there are not re-queried.
const IS_CLOUDFLARE_WORKER = typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';

/**
 * Uses the local resolver's answer when it has records. Otherwise re-queries over DoH, because
 * local / corporate resolvers can wrongly report "no data" (e.g. for underscore names). On Workers,
 * ENODATA / ENOTFOUND from node:dns are already DoH answers and are treated as definite.
 */
function dohIfLocalFailed(local: PromiseSettledResult<any>, name: string, type: string): Promise<DohQueryResult> {
  if (local.status === 'fulfilled' && Array.isArray(local.value) && local.value.length > 0) {
    return Promise.resolve({ records: local.value });
  }
  if (IS_CLOUDFLARE_WORKER) {
    if (local.status === 'fulfilled') return Promise.resolve({ records: [], status: 0 });
    const code = local.reason?.code;
    if (code === 'ENODATA') return Promise.resolve({ records: [], status: 0 });
    if (code === 'ENOTFOUND') return Promise.resolve({ records: [], status: 3 });
  }
  return queryDoh(name, type);
}

const DNS_TYPE_CODES: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, DNSKEY: 48, CAA: 257,
};

async function queryDoh(name: string, type: string): Promise<DohQueryResult> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(3500),
        next: { revalidate: 300 },
      }
    );

    if (res.ok) {
      const data = await res.json();
      // Answers include the CNAME chain; keep only records of the requested type
      const typeCode = DNS_TYPE_CODES[type];
      const records = (data.Answer || [])
        .filter((ans: any) => typeCode === undefined || ans.type === typeCode)
        .map((ans: any) => ({
        value: ans.data,
        data: ans.data,
        ttl: ans.TTL,
      }));
      const cnames = (data.Answer || [])
        .filter((ans: any) => ans.type === 5)
        .map((ans: any) => ({ name: String(ans.name).replace(/\.$/, ''), target: String(ans.data).replace(/\.$/, '') }));
      return { records, status: data.Status, ad: data.AD === true, cnames };
    }

    return { records: [], error: `DoH HTTP error ${res.status}` };
  } catch (err: any) {
    const isTimeout = err.name === 'TimeoutError' || err.code === 'ETIMEDOUT';
    return {
      records: [],
      isTimeout,
      error: isTimeout ? 'DoH query timed out (threshold 3500ms)' : 'DoH request failed',
    };
  }
}

async function fetchDoh(name: string, type: string): Promise<any[]> {
  const res = await queryDoh(name, type);
  return res.records;
}

/**
 * DoH returns multi-string TXT records as `"part1" "part2"`; RFC 7208 says they are concatenated.
 */
function joinTxtData(data: string): string {
  const segments = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!segments) return data;
  return segments.map(seg => seg.slice(1, -1).replace(/\\(.)/g, '$1')).join('');
}

/**
 * Counts SPF DNS-querying terms (include, a, mx, ptr, exists, redirect) recursively,
 * following include/redirect targets, as RFC 7208 section 4.6.4 requires.
 */
// Enough includes to prove the 10-lookup limit is exceeded; resolving more can't change the verdict
const SPF_MAX_RESOLVED_INCLUDES = 11;

async function countSpfLookups(
  spfText: string,
  depth: number,
  visited: Set<string>
): Promise<{ count: number; unresolved: string[]; truncated: boolean }> {
  let count = 0;
  let truncated = false;
  const unresolved: string[] = [];
  const terms = spfText.split(/\s+/).slice(1);

  for (const rawTerm of terms) {
    const term = rawTerm.replace(/^[+\-~?]/, '').toLowerCase();
    let target: string | undefined;

    if (term.startsWith('include:')) target = term.slice('include:'.length);
    else if (term.startsWith('redirect=')) target = term.slice('redirect='.length);
    else if (term === 'a' || term.startsWith('a:') || term.startsWith('a/')) count++;
    else if (term === 'mx' || term.startsWith('mx:') || term.startsWith('mx/')) count++;
    else if (term === 'ptr' || term.startsWith('ptr:')) count++;
    else if (term.startsWith('exists:')) count++;

    if (target) {
      count++;
      // Stop resolving once the RFC 7208 limit is already exceeded: the verdict can't change, and an
      // attacker-controlled SPF tree with many unique includes would otherwise fan out without bound.
      if (visited.size > SPF_MAX_RESOLVED_INCLUDES) {
        truncated = true;
        continue;
      }
      if (depth >= 10 || visited.has(target) || target.includes('%{')) {
        if (target.includes('%{')) unresolved.push(target);
        continue;
      }
      visited.add(target);
      const res = await queryDoh(target, 'TXT');
      const nestedSpf = res.records
        .map(r => joinTxtData(r.data || ''))
        .find(t => t.toLowerCase().startsWith('v=spf1'));
      if (nestedSpf) {
        const nested = await countSpfLookups(nestedSpf, depth + 1, visited);
        count += nested.count;
        unresolved.push(...nested.unresolved);
        truncated ||= nested.truncated;
      } else {
        unresolved.push(target);
      }
    }
  }

  return { count, unresolved, truncated };
}

function parseSpfPolicy(
  spfText?: string,
  lookups?: { count: number; unresolved: string[]; truncated?: boolean }
): PolicyEvaluation {
  if (!spfText) {
    return {
      protocol: 'SPF',
      status: 'missing',
      policy: 'No SPF (Sender Policy Framework) record published',
      parsedTags: {},
      issues: ['Domain lacks an SPF record. Attackers can forge emails from this domain.'],
      recommendations: ['Publish a TXT record with "v=spf1 include:_spf.google.com ~all" or your mail provider.'],
      strictness: 'Unprotected',
    };
  }

  const tags: Record<string, string> = {};
  const issues: string[] = [];
  const recommendations: string[] = [];

  const parts = spfText.split(/\s+/);
  parts.forEach((p, idx) => {
    if (p.includes(':')) {
      const [key, ...rest] = p.split(':');
      tags[`${key}_${idx}`] = rest.join(':');
    } else {
      tags[`mechanism_${idx}`] = p;
    }
  });

  let strictness: PolicyEvaluation['strictness'] = 'Moderate';
  let status: PolicyEvaluation['status'] = 'valid';

  // Match the "all" mechanism as a whole term; a bare "all" means "+all"
  const allTerm = parts.find(p => /^[+\-~?]?all$/i.test(p));
  const allQualifier = allTerm ? (/^[+\-~?]/.test(allTerm) ? allTerm[0] : '+') : undefined;
  const hasRedirect = parts.some(p => p.toLowerCase().startsWith('redirect='));

  if (allQualifier === '+') {
    issues.push(`CRITICAL: "${allTerm}" allows ANY server in the world to send mail as this domain.`);
    strictness = 'Unprotected';
    status = 'invalid';
  } else if (allQualifier === '-') {
    strictness = 'Strong / Enforcing';
    recommendations.push('Hard fail (-all) is configured for strict mail server enforcement.');
  } else if (allQualifier === '~') {
    strictness = 'Moderate';
    recommendations.push('Soft fail (~all) is in place. Consider upgrading to -all once mail sources are verified.');
  } else if (allQualifier === '?') {
    strictness = 'Permissive / Testing';
    issues.push('Neutral (?all) provides zero sender protection.');
  } else if (hasRedirect) {
    strictness = 'Moderate';
    recommendations.push('Policy is delegated via redirect=; the final "all" qualifier is defined by the redirect target.');
  } else {
    strictness = 'Permissive / Testing';
    issues.push('No "all" mechanism: unmatched senders get a neutral result, providing no spoofing protection.');
    if (status === 'valid') status = 'warning';
  }

  if (lookups) {
    if (lookups.count > 10) {
      const counted = lookups.truncated ? `at least ${lookups.count}` : `${lookups.count}`;
      issues.push(`Exceeds the RFC 7208 limit of 10 DNS lookups (${counted} counted, including nested includes). Receivers will return PermError.`);
      status = 'invalid';
    }
    if (lookups.unresolved.length > 0) {
      issues.push(`Could not resolve SPF for: ${lookups.unresolved.join(', ')} (lookup count may be incomplete).`);
      if (status === 'valid') status = 'warning';
    }
    tags['dns_lookups'] = lookups.truncated ? `${lookups.count}+` : String(lookups.count);
  }

  return {
    protocol: 'SPF',
    status,
    policy: spfText,
    parsedTags: tags,
    issues,
    recommendations,
    strictness,
  };
}

function parseDmarcPolicy(dmarcText?: string): PolicyEvaluation {
  if (!dmarcText) {
    return {
      protocol: 'DMARC',
      status: 'missing',
      policy: 'No DMARC record found at _dmarc host',
      parsedTags: {},
      issues: ['No DMARC record found. Domain has no protection against phishing/spoofing impersonation.'],
      recommendations: ['Create a TXT record at _dmarc with "v=DMARC1; p=reject; rua=mailto:dmarc-reports@domain.com"'],
      strictness: 'Unprotected',
    };
  }

  const tags: Record<string, string> = {};
  const issues: string[] = [];
  const recommendations: string[] = [];

  const parts = dmarcText.split(';').map(p => p.trim()).filter(Boolean);
  parts.forEach(p => {
    const [key, ...rest] = p.split('=');
    if (key && rest.length > 0) {
      tags[key.trim().toLowerCase()] = rest.join('=').trim();
    }
  });

  const p = tags['p']?.toLowerCase();
  let strictness: PolicyEvaluation['strictness'] = 'Unprotected';
  let status: PolicyEvaluation['status'] = 'valid';

  if (p === 'reject') {
    strictness = 'Strong / Enforcing';
    recommendations.push('Enforcing policy (p=reject): Unauthorized emails are rejected outright by recipient MTAs.');
  } else if (p === 'quarantine') {
    strictness = 'Moderate';
    recommendations.push('Quarantine policy (p=quarantine): Suspicious emails are directed to spam folders.');
  } else if (p === 'none') {
    strictness = 'Permissive / Testing';
    issues.push('Policy is in monitor-only mode (p=none). Spoofed emails are still delivered to inboxes.');
    recommendations.push('Upgrade policy to p=quarantine or p=reject for active spoofing protection.');
  } else {
    issues.push('Missing or invalid "p=" policy tag.');
    status = 'invalid';
  }

  if (!tags['rua']) {
    issues.push('No aggregate reporting address (rua=) configured. You will not receive threat intelligence summaries.');
    if (status === 'valid') status = 'warning';
  }

  return {
    protocol: 'DMARC',
    status,
    policy: dmarcText,
    parsedTags: tags,
    issues,
    recommendations,
    strictness,
  };
}

function parseBimiPolicy(bimiText?: string): PolicyEvaluation {
  if (!bimiText) {
    return {
      protocol: 'BIMI',
      status: 'missing',
      policy: 'No BIMI (Brand Indicators for Message Identification) record published',
      parsedTags: {},
      issues: ['No brand logo assertion record configured.'],
      recommendations: ['Optionally configure BIMI (v=BIMI1; l=https://.../logo.svg; a=https://.../cert.pem) for verified avatar icons in inboxes.'],
      strictness: 'Unprotected',
    };
  }

  const tags: Record<string, string> = {};
  const parts = bimiText.split(';').map(p => p.trim()).filter(Boolean);
  parts.forEach(p => {
    const [key, ...rest] = p.split('=');
    if (key && rest.length > 0) tags[key.trim().toLowerCase()] = rest.join('=').trim();
  });

  return {
    protocol: 'BIMI',
    status: tags['l'] ? 'valid' : 'warning',
    policy: bimiText,
    parsedTags: tags,
    issues: tags['l'] ? [] : ['Missing "l=" SVG logo location tag'],
    recommendations: ['BIMI record is recognized.'],
    strictness: 'Moderate',
  };
}

/**
 * MTA-STS needs both the _mta-sts TXT record and the HTTPS policy file (RFC 8461).
 * The policy file's mode decides whether TLS is actually enforced.
 */
async function evaluateMtaSts(domain: string, mtaStsText?: string): Promise<PolicyEvaluation> {
  if (!mtaStsText) {
    return {
      protocol: 'MTA-STS',
      status: 'missing',
      policy: 'No MTA-STS DNS record at _mta-sts host',
      parsedTags: {},
      issues: ['MTA-STS not configured. Inbound mail transport encryption (TLS) is not strictly enforced against MITM.'],
      recommendations: ['Publish _mta-sts TXT record with "v=STSv1; id=..." and host an HTTPS mta-sts.txt policy file.'],
      strictness: 'Unprotected',
    };
  }

  const tags: Record<string, string> = {};
  mtaStsText.split(';').map(p => p.trim()).filter(Boolean).forEach(p => {
    const [key, ...rest] = p.split('=');
    if (key && rest.length > 0) tags[key.trim().toLowerCase()] = rest.join('=').trim();
  });

  const issues: string[] = [];
  const recommendations: string[] = [];

  if (tags['v'] !== 'STSv1' || !tags['id']) {
    issues.push('TXT record is malformed (requires "v=STSv1; id=...").');
  }

  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  let policyFile: string | null = null;
  try {
    // RFC 8461: the policy must not be fetched via redirects. 'manual' instead of 'error' because
    // Cloudflare Workers doesn't support redirect: 'error'.
    // The policy host comes from the user's domain, so it goes through the SSRF guard first.
    await assertPublicHost(`mta-sts.${domain}`);
    const res = await fetch(policyUrl, { redirect: 'manual', signal: AbortSignal.timeout(4000) });
    if (res.status >= 300 && res.status < 400) {
      issues.push(`Policy file at ${policyUrl} redirects (HTTP ${res.status}); RFC 8461 forbids following redirects, so senders will ignore it.`);
    } else if (res.ok) {
      policyFile = await readTextCapped(res, 64 * 1024);
    } else {
      issues.push(`Policy file returned HTTP ${res.status} at ${policyUrl}.`);
    }
  } catch (err: any) {
    const reason = err instanceof BlockedHostError
      ? err.message
      : err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'connection timed out' : 'connection failed';
    issues.push(`Policy file could not be fetched from ${policyUrl} (${reason}).`);
  }

  if (policyFile === null) {
    recommendations.push('Host a valid policy file over HTTPS; without it, sending servers ignore MTA-STS.');
    return {
      protocol: 'MTA-STS',
      status: 'invalid',
      policy: mtaStsText,
      parsedTags: tags,
      issues,
      recommendations,
      strictness: 'Unprotected',
    };
  }

  policyFile.split(/\r?\n/).forEach(line => {
    const idx = line.indexOf(':');
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();
      tags[`policy_${key}`] = tags[`policy_${key}`] ? `${tags[`policy_${key}`]}, ${value}` : value;
    }
  });

  const mode = tags['policy_mode']?.toLowerCase();
  let strictness: PolicyEvaluation['strictness'] = 'Unprotected';
  let status: PolicyEvaluation['status'] = issues.length > 0 ? 'warning' : 'valid';

  if (mode === 'enforce') {
    strictness = 'Strong / Enforcing';
    recommendations.push('Policy mode is "enforce": sending servers must use valid TLS to the listed MX hosts.');
  } else if (mode === 'testing') {
    strictness = 'Permissive / Testing';
    issues.push('Policy mode is "testing": TLS failures are reported but mail is still delivered.');
    recommendations.push('Switch to mode: enforce once TLS-RPT reports are clean.');
    if (status === 'valid') status = 'warning';
  } else if (mode === 'none') {
    issues.push('Policy mode is "none": MTA-STS is disabled.');
    status = 'warning';
  } else {
    issues.push('Policy file has no valid "mode:" field.');
    status = 'invalid';
  }

  if (!tags['policy_mx']) {
    issues.push('Policy file lists no "mx:" hosts.');
    if (status === 'valid') status = 'warning';
  }

  return {
    protocol: 'MTA-STS',
    status,
    policy: mtaStsText,
    parsedTags: tags,
    issues,
    recommendations,
    strictness,
  };
}

async function resolveDkimSelector(domain: string, selector: string): Promise<DkimSelectorResult> {
  const fqdn = `${selector}._domainkey.${domain}`;

  try {
    // One TXT query: the resolver follows any CNAME delegation and returns the whole chain
    const txtRes = await queryDoh(fqdn, 'TXT');
    const cnameTarget = txtRes.cnames?.find(c => c.name.toLowerCase() === fqdn.toLowerCase())?.target;
    const txtValue: string | undefined = txtRes.records.length > 0 ? (txtRes.records[0].value || txtRes.records[0].data || '') : undefined;

    if (!cnameTarget && !txtValue) {
      return {
        selector,
        fqdn,
        status: 'not_found',
      };
    }

    const cleanTxt = (txtValue || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '');

    let publicKey = '';
    let keyLengthBits = 0;

    // k= defaults to rsa (RFC 6376)
    const kMatch = cleanTxt.match(/(?:^|;)\s*k=([^;\s]+)/i);
    const keyType = kMatch ? kMatch[1].toUpperCase() : 'RSA';

    const pMatch = cleanTxt.match(/(?:^|;)\s*p=([^;]*)/i);
    if (pMatch) {
      publicKey = pMatch[1].replace(/\s+/g, '');
      if (publicKey) {
        try {
          const der = Buffer.from(publicKey, 'base64');
          if (keyType === 'ED25519') {
            // RFC 8463: p= is the raw 32-byte Ed25519 key, not SubjectPublicKeyInfo
            if (der.length === 32) keyLengthBits = 256;
          } else {
            const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
            keyLengthBits = key.asymmetricKeyDetails?.modulusLength || 0;
          }
        } catch {
          // Key could not be decoded; size stays unknown
        }
      }
    }

    const isKeySecure = keyType === 'ED25519' ? keyLengthBits === 256 : keyLengthBits >= 2048;

    return {
      selector,
      fqdn,
      status: cleanTxt.includes('p=') ? 'found' : cnameTarget ? 'delegated' : 'found',
      recordType: cnameTarget ? 'CNAME' : 'TXT',
      cnameTarget,
      publicKey: publicKey || undefined,
      keyType,
      keyLengthBits: keyLengthBits > 0 ? keyLengthBits : undefined,
      isKeySecure,
      rawRecord: cleanTxt || cnameTarget || 'Present',
    };
  } catch {
    return {
      selector,
      fqdn,
      status: 'not_found',
    };
  }
}

function detectMailHost(mxValue: string): string {
  if (!mxValue) return 'No MX Records Found';
  const lower = mxValue.toLowerCase();
  if (lower.includes('outlook.com') || lower.includes('office365.com') || lower.includes('microsoft.com')) {
    return 'Microsoft 365 / Exchange Online (Microsoft)';
  }
  if (lower.includes('google.com') || lower.includes('googlemail.com') || lower.includes('l.google.com')) {
    return 'Google Workspace / Gmail (Google Cloud)';
  }
  if (lower.includes('mimecast')) {
    return 'Mimecast Secure Email Gateway';
  }
  if (lower.includes('pphosted') || lower.includes('proofpoint')) {
    return 'Proofpoint Threat Protection';
  }
  if (lower.includes('barracuda')) {
    return 'Barracuda Email Security Gateway';
  }
  if (lower.includes('zoho')) {
    return 'Zoho Mail (Zoho Corp)';
  }
  if (lower.includes('protonmail') || lower.includes('proton.me')) {
    return 'Proton Mail (Encrypted Swiss Mail)';
  }
  if (lower.includes('fastmail')) {
    return 'Fastmail';
  }
  if (lower.includes('amazonses') || lower.includes('aws.')) {
    return 'Amazon SES (AWS)';
  }
  if (
    lower.includes('cpanel') ||
    lower.includes('webmail') ||
    lower.includes('hostgator') ||
    lower.includes('bluehost') ||
    lower.includes('godaddy') ||
    lower.includes('secureserver')
  ) {
    return 'Shared Web/cPanel Hosting Mail';
  }
  return `Custom / Dedicated Mail Server (${mxValue.split(' ')[0] || mxValue})`;
}

function detectDnsHost(nameservers: string[]): string {
  if (!nameservers || nameservers.length === 0) return 'Unknown DNS Host';
  const combined = nameservers.join(' ').toLowerCase();

  if (combined.includes('v-dns.net') || combined.includes('domains.co.za')) {
    return 'Domains.co.za (Anycast DNS Network)';
  }
  if (combined.includes('cloudflare.com')) {
    return 'Cloudflare Managed Anycast DNS';
  }
  if (combined.includes('awsdns')) {
    return 'Amazon Web Services (Route 53)';
  }
  if (combined.includes('azure-dns')) {
    return 'Microsoft Azure DNS';
  }
  if (combined.includes('googledomains') || combined.includes('cloud-dns.google')) {
    return 'Google Cloud DNS';
  }
  if (combined.includes('domaincontrol.com') || combined.includes('godaddy.com')) {
    return 'GoDaddy Premium DNS';
  }
  if (combined.includes('registrar-servers.com') || combined.includes('namecheap')) {
    return 'Namecheap Anycast DNS';
  }
  if (combined.includes('hetzner')) {
    return 'Hetzner Online DNS';
  }
  if (combined.includes('afrihost')) {
    return 'Afrihost Managed DNS';
  }
  return nameservers[0] ? `Authoritative NS (${nameservers[0]})` : 'Custom DNS Host';
}

/**
 * Resolves each hostname's first A record via DoH, in parallel.
 */
async function resolveHostIps(hosts: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  await Promise.all(
    Array.from(new Set(hosts)).map(async host => {
      const res = await fetchDoh(host, 'A');
      const ip = res[0]?.value || res[0]?.data;
      if (ip) map.set(host, ip);
    })
  );
  return map;
}

/**
 * DNSSEC: DS/DNSKEY presence plus the validating resolver's AD (Authenticated Data) flag.
 */
async function checkDnssec(domain: string): Promise<{ enabled: boolean; details: string }> {
  try {
    const [dsDoh, dnskeyDoh] = await Promise.all([queryDoh(domain, 'DS'), queryDoh(domain, 'DNSKEY')]);
    const hasDs = (dsDoh.records || []).length > 0;
    const hasDnskey = (dnskeyDoh.records || []).length > 0;
    const validated = dnskeyDoh.ad === true;

    if (hasDs && hasDnskey && validated) {
      return { enabled: true, details: 'DNSSEC signed and validated (DS at parent, DNSKEY published, resolver returned AD flag)' };
    }
    if (hasDs && hasDnskey) {
      return { enabled: false, details: 'DS and DNSKEY records published, but the validating resolver did not authenticate the answer' };
    }
    if (hasDnskey) {
      return { enabled: false, details: 'DNSKEY published but no DS record at the parent zone — chain of trust is incomplete' };
    }
    if (hasDs) {
      return { enabled: false, details: 'DS record at parent but no DNSKEY published — DNSSEC is misconfigured' };
    }
    if (dsDoh.error || dnskeyDoh.error) {
      return { enabled: false, details: 'DNSSEC status could not be determined (DoH query failed)' };
    }
    return { enabled: false, details: 'No DNSSEC DS or DNSKEY records published' };
  } catch {
    return { enabled: false, details: 'DNSSEC status could not be determined' };
  }
}
