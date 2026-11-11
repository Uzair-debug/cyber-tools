import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit } from '@/lib/rate-limit';
import {
  SingleLinkCheckResult,
  LinkHopInfo,
  UrlRiskFinding,
  ParsedUrlBreakdown,
  BatchLinkItemResult,
  BatchLinkCheckResponse,
} from '@/lib/types';
import { assertPublicHost, BlockedHostError, readTextCapped } from '@/lib/net-utils';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'work', 'click', 'buzz', 'loan', 'surf', 'gq', 'cf', 'ml', 'tk', 'ga',
  'rest', 'country', 'stream', 'win', 'bid', 'kim', 'fit', 'icu', 'cam', 'monster',
  'cyou', 'beauty', 'hair', 'sbs', 'quest', 'cfd', 'mom', 'rodeo', 'lat', 'date', 'download',
]);

const BRAND_KEYWORDS = [
  'paypal', 'microsoft', 'apple', 'google', 'netflix', 'chase', 'bankofamerica',
  'wellsfargo', 'amazon', 'facebook', 'instagram', 'whatsapp', 'binance', 'coinbase',
  'metamask', 'outlook', 'office365', 'onedrive', 'icloud', 'dhl', 'fedex', 'usps',
];

const SECURITY_KEYWORDS = [
  'secure', 'account', 'verify', 'update', 'signin', 'login', 'banking', 'auth',
  'recover', 'billing', 'confirm', 'validation', 'support', 'helpdesk', 'service',
];

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly', 'rb.gy',
  'rebrand.ly', 'goo.gl', 'tiny.cc', 'bl.ink', 'shorturl.at', 'snip.ly', 'trib.al',
]);

// Caller-controlled scan limits are clamped to these bounds
const MIN_HOPS = 1;
const MAX_HOPS = 10;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 10000;
const MAX_USER_AGENT_LENGTH = 256;

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

/**
 * Optional custom User-Agent: a short printable string, otherwise the default is used.
 */
function sanitizeUserAgent(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const ua = value.trim();
  if (!ua || ua.length > MAX_USER_AGENT_LENGTH || /[^\x20-\x7e]/.test(ua)) return undefined;
  return ua;
}

/**
 * Errors whose message is safe to return to the caller (no raw network error text).
 */
class LinkCheckError extends Error {}

function safeErrorMessage(err: unknown, fallback: string): string {
  return err instanceof BlockedHostError || err instanceof LinkCheckError ? err.message : fallback;
}

function defangUrl(url: string): string {
  return url
    .replace(/^https?:\/\//i, (match) => match.replace('http', 'hxxp'))
    .replace(/\./g, '[.]');
}

function parseUrlBreakdown(rawUrl: string): ParsedUrlBreakdown {
  try {
    const parsed = new URL(rawUrl);
    const hostParts = parsed.hostname.split('.');
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1].toLowerCase() : '';
    const subdomain = hostParts.length > 2 ? hostParts.slice(0, -2).join('.') : '';
    const isPunycode = parsed.hostname.includes('xn--');

    let decodedHostname = parsed.hostname;
    if (isPunycode) {
      try {
        decodedHostname = decodeURI(parsed.hostname);
      } catch {
        // keep hostname
      }
    }

    const queryParams: ParsedUrlBreakdown['queryParams'] = [];
    parsed.searchParams.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      const lowerVal = value.toLowerCase();
      let isSuspicious = false;
      let reason: string | undefined;

      if (['redirect', 'url', 'next', 'dest', 'destination', 'return_to', 'r', 'target', 'link', 'goto', 'out'].includes(lowerKey)) {
        if (/^https?:\/\//i.test(value) || value.startsWith('//') || /%2f%2f/i.test(value)) {
          isSuspicious = true;
          reason = 'Potential Open-Redirect vector containing target URL';
        }
      } else if (['token', 'auth', 'key', 'secret', 'password', 'pass', 'api_key', 'bearer'].includes(lowerKey)) {
        isSuspicious = true;
        reason = 'Sensitive authentication token or secret parameter detected in plain URL';
      } else if (lowerVal.includes('<script') || lowerVal.includes('javascript:') || lowerVal.includes('onerror=')) {
        isSuspicious = true;
        reason = 'Possible XSS injection payload in query parameter';
      }

      queryParams.push({ key, value, isSuspicious, reason });
    });

    return {
      original: rawUrl,
      defanged: defangUrl(rawUrl),
      protocol: parsed.protocol.replace(':', '').toUpperCase(),
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      tld,
      subdomain,
      isPunycode,
      decodedHostname,
      queryParams,
    };
  } catch {
    return {
      original: rawUrl,
      defanged: defangUrl(rawUrl),
      protocol: 'UNKNOWN',
      hostname: 'invalid-url',
      port: '80',
      pathname: '/',
      search: '',
      hash: '',
      tld: '',
      subdomain: '',
      isPunycode: false,
      decodedHostname: '',
      queryParams: [],
    };
  }
}

async function analyzeUrlSecurity(
  inputUrl: string,
  finalUrl: string,
  hops: LinkHopInfo[],
  hasProtocolDowngrade: boolean,
  hasRedirectLoop: boolean
): Promise<{ score: number; level: SingleLinkCheckResult['riskLevel']; findings: UrlRiskFinding[] }> {
  const findings: UrlRiskFinding[] = [];
  let score = 0;

  const initialParsed = parseUrlBreakdown(inputUrl);
  const finalParsed = parseUrlBreakdown(finalUrl);

  // 1. Punycode / IDN Homoglyph Spoofing
  if (initialParsed.isPunycode || finalParsed.isPunycode) {
    score += 45;
    findings.push({
      id: 'punycode_homoglyph',
      title: 'Punycode / IDN Homoglyph Spoofing Detected',
      description: `Hostname uses Internationalized Domain Name (xn--) encoding (${initialParsed.decodedHostname || initialParsed.hostname}), commonly weaponized to spoof legitimate brands with lookalike characters.`,
      severity: 'CRITICAL',
      points: 45,
    });
  }

  // 2. Embedded Credentials in URL
  if (inputUrl.includes('@') && !inputUrl.includes('mailto:')) {
    score += 40;
    findings.push({
      id: 'embedded_credentials',
      title: 'Embedded Credentials / Userinfo Trick in URL',
      description: 'URL contains an "@" symbol. Threat actors use "http://trusted-brand.com@evil-site.com" to mislead users into believing they are visiting a trusted domain.',
      severity: 'HIGH',
      points: 40,
    });
  }

  // 3. Raw IP Address in Hostname
  const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(initialParsed.hostname) || initialParsed.hostname.includes(':');
  if (isIpHost) {
    score += 35;
    findings.push({
      id: 'ip_as_hostname',
      title: 'Direct IP Address Used as Hostname',
      description: `Target uses raw IP address (${initialParsed.hostname}) instead of a registered domain name, often indicating unindexed C2 infrastructure or ad-hoc phishing hosts.`,
      severity: 'HIGH',
      points: 35,
    });
  }

  // 4. Suspicious TLD
  if (SUSPICIOUS_TLDS.has(initialParsed.tld) || SUSPICIOUS_TLDS.has(finalParsed.tld)) {
    const tld = initialParsed.tld || finalParsed.tld;
    score += 25;
    findings.push({
      id: 'suspicious_tld',
      title: `High-Risk Top-Level Domain (.${tld})`,
      description: `The .${tld} TLD has high statistical correlation with spam, phishing campaigns, and malware distribution according to threat intel feeds.`,
      severity: 'MEDIUM',
      points: 25,
    });
  }

  // 5. Open Redirect Parameters
  const openRedirectParams = initialParsed.queryParams.filter(q => q.isSuspicious && q.reason?.includes('Open-Redirect'));
  if (openRedirectParams.length > 0) {
    score += 30;
    findings.push({
      id: 'open_redirect_param',
      title: 'Potential Open-Redirect Parameter Detected',
      description: `URL contains parameter(s) [${openRedirectParams.map(p => p.key).join(', ')}] carrying external target URLs, which may be exploited for redirect evasion.`,
      severity: 'HIGH',
      points: 30,
    });
  }

  // 6. Sensitive Credentials in Query Parameters
  const tokenParams = initialParsed.queryParams.filter(q => q.isSuspicious && q.reason?.includes('Sensitive'));
  if (tokenParams.length > 0) {
    score += 20;
    findings.push({
      id: 'sensitive_token_param',
      title: 'Sensitive Credential / Secret in URL Query',
      description: `URL exposes plaintext secrets/tokens in query parameters [${tokenParams.map(p => p.key).join(', ')}], risking exposure in access logs and referrer headers.`,
      severity: 'MEDIUM',
      points: 20,
    });
  }

  // 7. Protocol Downgrade (HTTPS -> HTTP)
  if (hasProtocolDowngrade) {
    score += 35;
    findings.push({
      id: 'protocol_downgrade',
      title: 'Insecure Protocol Downgrade (HTTPS → HTTP)',
      description: 'The redirection chain downgraded from encrypted HTTPS to insecure plaintext HTTP, exposing traffic to Man-in-the-Middle (MitM) inspection or tampering.',
      severity: 'HIGH',
      points: 35,
    });
  }

  // 8. Redirect Loop Detected
  if (hasRedirectLoop) {
    score += 25;
    findings.push({
      id: 'redirect_loop',
      title: 'Circular Redirection Loop Detected',
      description: 'The destination bounces continuously between addresses without reaching a terminal page.',
      severity: 'MEDIUM',
      points: 25,
    });
  }

  // 9. Excessive Redirection Hops
  if (hops.length > 5) {
    score += 20;
    findings.push({
      id: 'excessive_hops',
      title: `Excessive Redirection Chain (${hops.length} hops)`,
      description: 'Multiple redirect hops (>5) are frequently employed by malicious traffic distribution systems (TDS) to bypass automated URL scanners.',
      severity: 'MEDIUM',
      points: 20,
    });
  }

  // 10. URL Shortener Intermediary
  const isShortener = KNOWN_SHORTENERS.has(initialParsed.hostname.toLowerCase());
  if (isShortener) {
    findings.push({
      id: 'url_shortener',
      title: `Known URL Shortener Service (${initialParsed.hostname})`,
      description: `Initial link passes through a shortening proxy service (${initialParsed.hostname}) masking the true destination (${finalParsed.hostname}).`,
      severity: 'INFO',
      points: 5,
    });
    score += 5;
  }

  // 11. Brand Impersonation / Deceptive Subdomains
  const lowerHost = (initialParsed.subdomain + '.' + initialParsed.hostname).toLowerCase();
  const matchedBrand = BRAND_KEYWORDS.find(b => lowerHost.includes(b) && !initialParsed.hostname.endsWith(`${b}.com`));
  const matchedSecKeyword = SECURITY_KEYWORDS.find(s => lowerHost.includes(s));

  if (matchedBrand && matchedSecKeyword) {
    score += 45;
    findings.push({
      id: 'brand_phishing_heuristic',
      title: `Brand Phishing Heuristic: Impersonating ${matchedBrand.toUpperCase()}`,
      description: `Domain contains brand name "${matchedBrand}" paired with security keyword "${matchedSecKeyword}" outside legitimate authority boundaries.`,
      severity: 'CRITICAL',
      points: 45,
    });
  } else if (matchedBrand) {
    score += 20;
    findings.push({
      id: 'brand_keyword_in_host',
      title: `Brand Keyword in Domain Sub-level ("${matchedBrand}")`,
      description: `Domain contains well-known brand token "${matchedBrand}" in subdomain or non-primary host label.`,
      severity: 'LOW',
      points: 20,
    });
  }

  // 12. Security Headers Presence Bonus / Check
  const lastHop = hops[hops.length - 1];
  if (lastHop) {
    const hasHsts = !!lastHop.headers['strict-transport-security'];
    const hasCsp = !!lastHop.headers['content-security-policy'];
    const hasXfo = !!lastHop.headers['x-frame-options'];

    if (hasHsts && hasCsp) {
      findings.push({
        id: 'strong_security_headers',
        title: 'Strong Security Headers Present on Terminal Endpoint',
        description: 'Endpoint enforces Strict-Transport-Security (HSTS) and Content-Security-Policy (CSP) headers.',
        severity: 'SAFE',
        points: -10,
      });
      score = Math.max(0, score - 10);
    } else if (!hasHsts && lastHop.protocol === 'HTTPS') {
      findings.push({
        id: 'missing_hsts',
        title: 'Missing HSTS on Terminal HTTPS Endpoint',
        description: 'Final endpoint does not publish Strict-Transport-Security header.',
        severity: 'LOW',
        points: 5,
      });
    }
  }

  // Cap score at 100
  score = Math.min(100, Math.max(0, score));

  // Determine Level
  let level: SingleLinkCheckResult['riskLevel'] = 'SAFE';
  if (score >= 80) level = 'CRITICAL';
  else if (score >= 60) level = 'HIGH';
  else if (score >= 35) level = 'MEDIUM';
  else if (score >= 15) level = 'LOW';

  return { score, level, findings };
}

async function traceSingleUrl(
  rawTarget: string,
  maxHops: number = 10,
  customUserAgent?: string,
  timeoutMs: number = 7000
): Promise<SingleLinkCheckResult> {
  let target = rawTarget.trim();
  if (!/^https?:\/\//i.test(target)) {
    target = 'https://' + target;
  }

  const hops: LinkHopInfo[] = [];
  const visitedUrls = new Set<string>();
  const dnsResolvedIps: string[] = [];

  let currentUrl = target;
  let hopIndex = 1;
  let hasRedirectLoop = false;
  let hasProtocolDowngrade = false;
  let initialProtocol = currentUrl.startsWith('https:') ? 'HTTPS' : 'HTTP';
  let totalDuration = 0;

  const defaultUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberToolbox/2.0';
  const ua = customUserAgent || defaultUa;

  while (hopIndex <= maxHops) {
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      break;
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new BlockedHostError(`Unsupported protocol "${parsed.protocol}" was blocked.`);
    }

    // SSRF guard: every address the host resolves to must be public (fails closed if it cannot be
    // resolved outside Workers). fetch() re-resolves the name; see assertPublicHost for the
    // remaining DNS-rebinding window.
    const addresses = await assertPublicHost(parsed.hostname);
    for (const address of addresses) {
      if (!dnsResolvedIps.includes(address)) dnsResolvedIps.push(address);
    }

    const normalizedUrl = parsed.toString().toLowerCase();
    if (visitedUrls.has(normalizedUrl)) {
      hasRedirectLoop = true;
      break;
    }
    visitedUrls.add(normalizedUrl);

    const isCurrentHttps = parsed.protocol === 'https:';
    if (hops.length > 0 && hops[hops.length - 1].isTls && !isCurrentHttps) {
      hasProtocolDowngrade = true;
    }

    const hopStartTime = performance.now();
    let response: Response;

    try {
      response = await fetch(currentUrl, {
        method: 'GET',
        headers: {
          'User-Agent': ua,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err: any) {
      // If error on first hop, throw. If after redirects, record last known state.
      if (hops.length === 0) {
        // Raw connection errors can name internal addresses, so they are not passed through
        const isTimeout = err?.name === 'AbortError' || err?.name === 'TimeoutError';
        throw new LinkCheckError(`Failed to connect to ${parsed.hostname}: ${isTimeout ? 'connection timed out' : 'connection failed'}`);
      }
      break;
    }

    const duration = Math.round(performance.now() - hopStartTime);
    totalDuration += duration;

    const rawHeaders: Record<string, string> = {};
    response.headers.forEach((v, k) => {
      rawHeaders[k.toLowerCase()] = v;
    });

    const securityHeadersPresent: string[] = [];
    ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'].forEach(h => {
      if (rawHeaders[h]) securityHeadersPresent.push(h);
    });

    const locationHeader = response.headers.get('location');
    let resolvedNextUrl: string | undefined;

    if (locationHeader && [301, 302, 303, 307, 308].includes(response.status)) {
      try {
        resolvedNextUrl = new URL(locationHeader, currentUrl).toString();
      } catch {
        resolvedNextUrl = locationHeader;
      }
    }

    const hopRecord: LinkHopInfo = {
      hopNumber: hopIndex,
      url: currentUrl,
      statusCode: response.status,
      statusText: response.statusText || `${response.status}`,
      durationMs: duration,
      protocol: isCurrentHttps ? 'HTTPS' : 'HTTP',
      headers: rawHeaders,
      location: resolvedNextUrl,
      isTls: isCurrentHttps,
      securityHeadersPresent,
    };

    hops.push(hopRecord);

    // If redirected, advance to next hop URL
    if (resolvedNextUrl && [301, 302, 303, 307, 308].includes(response.status)) {
      currentUrl = resolvedNextUrl;
      hopIndex++;
    } else {
      // Reached terminal destination (e.g. 200, 404, 403, 500, etc.)
      break;
    }
  }

  const finalHop = hops[hops.length - 1];
  const finalUrl = finalHop ? finalHop.url : currentUrl;
  const isRedirected = hops.length > 1;

  const { score, level, findings } = await analyzeUrlSecurity(
    target,
    finalUrl,
    hops,
    hasProtocolDowngrade,
    hasRedirectLoop
  );

  return {
    inputUrl: target,
    finalUrl,
    finalStatusCode: finalHop ? finalHop.statusCode : 0,
    finalStatusText: finalHop ? finalHop.statusText : 'Unknown',
    totalDurationMs: totalDuration,
    hopCount: hops.length,
    isRedirected,
    hasRedirectLoop,
    hasProtocolDowngrade,
    riskScore: score,
    riskLevel: level,
    findings,
    hops,
    urlBreakdown: parseUrlBreakdown(finalUrl),
    dnsResolvedIps,
    scanTimestamp: new Date().toISOString(),
  };
}

export async function POST(req: NextRequest) {
  const limited = await enforceRateLimit(req);
  if (limited) return limited;

  // 25 URLs plus options fit comfortably in 64 KB; larger bodies are rejected before parsing
  const MAX_BODY_BYTES = 64 * 1024;
  if (Number(req.headers.get('content-length') || 0) > MAX_BODY_BYTES) {
    return NextResponse.json({ error: 'Request body too large' }, { status: 413 });
  }
  let body: any;
  try {
    const raw = await readTextCapped(req, MAX_BODY_BYTES + 1);
    if (raw.length > MAX_BODY_BYTES) {
      return NextResponse.json({ error: 'Request body too large' }, { status: 413 });
    }
    body = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: 'Request body must be valid JSON' }, { status: 400 });
  }
  if (!body || typeof body !== 'object') {
    return NextResponse.json({ error: 'Request body must be a JSON object' }, { status: 400 });
  }

  try {
    const mode = body.mode || 'single';

    if (mode === 'single') {
      const { url, maxHops, userAgent, timeoutMs } = body;
      if (!url || typeof url !== 'string') {
        return NextResponse.json({ error: 'Valid URL is required' }, { status: 400 });
      }

      const result = await traceSingleUrl(
        url,
        clampInt(maxHops, MIN_HOPS, MAX_HOPS, MAX_HOPS),
        sanitizeUserAgent(userAgent),
        clampInt(timeoutMs, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS, 7000)
      );
      return NextResponse.json(result);
    } else if (mode === 'batch') {
      // Batch checks fan out to up to 25 URLs, so they also count against a stricter limit
      const heavyLimited = await enforceRateLimit(req, 'heavy');
      if (heavyLimited) return heavyLimited;

      const { urls, userAgent } = body;
      if (!urls || !Array.isArray(urls) || urls.length === 0) {
        return NextResponse.json({ error: 'Array of URLs is required for batch check' }, { status: 400 });
      }

      // Limit to 25 URLs per batch request
      const targets = urls
        .slice(0, 25)
        .filter((u: unknown): u is string => typeof u === 'string')
        .map(u => u.trim())
        .filter(Boolean);
      const batchUserAgent = sanitizeUserAgent(userAgent);

      const batchResults: BatchLinkItemResult[] = await Promise.all(
        targets.map(async (u, idx): Promise<BatchLinkItemResult> => {
          const id = `item-${idx}-${Date.now()}`;
          try {
            const single = await traceSingleUrl(u, 6, batchUserAgent, 5000);
            let statusGroup: BatchLinkItemResult['statusGroup'] = '2xx';
            if (single.finalStatusCode >= 300 && single.finalStatusCode < 400) statusGroup = '3xx';
            else if (single.finalStatusCode >= 400 && single.finalStatusCode < 500) statusGroup = '4xx';
            else if (single.finalStatusCode >= 500) statusGroup = '5xx';

            return {
              id,
              inputUrl: u,
              finalUrl: single.finalUrl,
              statusCode: single.finalStatusCode,
              statusText: single.finalStatusText,
              durationMs: single.totalDurationMs,
              hopCount: single.hopCount,
              riskLevel: single.riskLevel,
              statusGroup,
              hasRedirect: single.isRedirected,
            };
          } catch (err: any) {
            return {
              id,
              inputUrl: u,
              finalUrl: u,
              statusCode: 0,
              statusText: 'Unreachable / Error',
              durationMs: 0,
              hopCount: 0,
              riskLevel: 'HIGH',
              statusGroup: 'error',
              errorMessage: safeErrorMessage(err, 'Connection failed'),
              hasRedirect: false,
            };
          }
        })
      );

      const summary = {
        successCount: batchResults.filter(r => r.statusCode >= 200 && r.statusCode < 300).length,
        redirectCount: batchResults.filter(r => r.hasRedirect).length,
        clientErrorCount: batchResults.filter(r => r.statusCode >= 400 && r.statusCode < 500).length,
        serverErrorCount: batchResults.filter(r => r.statusCode >= 500).length,
        errorCount: batchResults.filter(r => r.statusGroup === 'error').length,
        highRiskCount: batchResults.filter(r => r.riskLevel === 'HIGH' || r.riskLevel === 'CRITICAL').length,
      };

      const response: BatchLinkCheckResponse = {
        total: batchResults.length,
        summary,
        results: batchResults,
      };

      return NextResponse.json(response);
    } else {
      return NextResponse.json({ error: `Unsupported mode "${mode}". Use "single" or "batch".` }, { status: 400 });
    }
  } catch (err: any) {
    return NextResponse.json(
      { error: safeErrorMessage(err, 'An unexpected error occurred during link analysis.') },
      { status: err instanceof BlockedHostError ? 400 : 500 }
    );
  }
}
