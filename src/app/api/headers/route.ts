import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit } from '@/lib/rate-limit';
import { SecurityHeadersData, SecurityHeaderItem } from '@/lib/types';
import { assertPublicHost, BlockedHostError } from '@/lib/net-utils';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_REDIRECTS = 5;

/**
 * Fetches a URL, following redirects manually so every hop goes through the SSRF guard
 * (http/https only, no localhost / private / reserved addresses). Workers rejects redirect: 'error',
 * so 'manual' is used. All hops share one timeout.
 */
async function fetchFollowingSafeRedirects(
  url: string,
  method: 'HEAD' | 'GET',
  headers: Record<string, string>,
  timeoutMs: number
): Promise<{ response: Response; finalUrl: string }> {
  const signal = AbortSignal.timeout(timeoutMs);
  let currentUrl = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const parsed = new URL(currentUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new BlockedHostError(`Redirect to unsupported protocol "${parsed.protocol}" was blocked.`);
    }
    await assertPublicHost(parsed.hostname);

    const response = await fetch(currentUrl, { method, headers, redirect: 'manual', signal });
    const location = response.headers.get('location');
    if (!location || ![301, 302, 303, 307, 308].includes(response.status)) {
      return { response, finalUrl: currentUrl };
    }
    currentUrl = new URL(location, currentUrl).toString();
  }

  throw new BlockedHostError(`Too many redirects (more than ${MAX_REDIRECTS}).`);
}

export async function GET(req: NextRequest) {
  const limited = await enforceRateLimit(req);
  if (limited) return limited;

  const { searchParams } = new URL(req.url);
  let target = searchParams.get('url')?.trim();

  if (!target) {
    return NextResponse.json({ error: 'Target URL is required' }, { status: 400 });
  }

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
    target = 'https://' + target;
  }

  let parsedTarget: URL;
  try {
    parsedTarget = new URL(target);
  } catch {
    return NextResponse.json({ error: 'Target URL is not a valid URL' }, { status: 400 });
  }
  if (parsedTarget.protocol !== 'http:' && parsedTarget.protocol !== 'https:') {
    return NextResponse.json({ error: 'Only http:// and https:// URLs can be audited' }, { status: 400 });
  }
  target = parsedTarget.toString();

  try {
    const requestHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (SecOps-Security-Auditor)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    };

    let fetched: { response: Response; finalUrl: string };

    // Attempt lightweight HEAD first to avoid downloading heavy website bodies (e.g. WordPress, heavy assets)
    try {
      fetched = await fetchFollowingSafeRedirects(target, 'HEAD', requestHeaders, 6000);

      // If HEAD is explicitly forbidden or unsupported, retry with GET
      if (fetched.response.status === 405 || fetched.response.status === 501 || fetched.response.status === 403) {
        fetched = await fetchFollowingSafeRedirects(target, 'GET', requestHeaders, 15000);
      }
    } catch (err) {
      if (err instanceof BlockedHostError) throw err;
      // If HEAD times out or network connection drops, fallback to GET with a generous 15-second timeout
      fetched = await fetchFollowingSafeRedirects(target, 'GET', requestHeaders, 15000);
    }
    const { response, finalUrl } = fetched;

    const rawHeaders: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      rawHeaders[key.toLowerCase()] = val;
    });

    // Parse Cookies: getSetCookie() keeps each Set-Cookie header separate, so commas inside
    // attributes like "Expires=Wed, 21 Oct 2026" don't split one cookie into two
    const cookies: SecurityHeadersData['cookies'] = [];
    const cookieEntries: string[] =
      typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
    if (cookieEntries.length > 0) {
      cookieEntries.forEach(c => {
        const parts = c.split(';').map(p => p.trim());
        const nameVal = parts[0].split('=');
        const name = nameVal[0];
        const lowerParts = parts.map(p => p.toLowerCase());
        const hasSecure = lowerParts.includes('secure');
        const hasHttpOnly = lowerParts.includes('httponly');
        const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));
        let sameSite: 'Strict' | 'Lax' | 'None' | 'Missing' = 'Missing';
        if (sameSitePart) {
          const val = sameSitePart.split('=')[1]?.trim();
          if (/^strict$/i.test(val)) sameSite = 'Strict';
          else if (/^lax$/i.test(val)) sameSite = 'Lax';
          else if (/^none$/i.test(val)) sameSite = 'None';
        }

        let status: 'SECURE' | 'WARNING' | 'INSECURE' = 'SECURE';
        if (!hasSecure || !hasHttpOnly) status = 'INSECURE';
        else if (sameSite === 'Missing' || sameSite === 'None') status = 'WARNING';

        cookies.push({ name, hasSecure, hasHttpOnly, sameSite, status });
      });
    }

    // Evaluate Security Headers
    const headersEvaluated: SecurityHeaderItem[] = [];
    let score = 0;

    // 1. Strict-Transport-Security (HSTS)
    const hsts = rawHeaders['strict-transport-security'];
    if (hsts) {
      const hasSubdomains = /includesubdomains/i.test(hsts);
      const hasPreload = /preload/i.test(hsts);
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

      if (maxAge >= 31536000) {
        score += 25;
        headersEvaluated.push({
          name: 'Strict-Transport-Security',
          value: hsts,
          status: 'PASS',
          scoreImpact: 25,
          summary: `Enforces TLS with max-age=${maxAge}s (${Math.round(maxAge / 86400)} days)${hasSubdomains ? ', includeSubDomains' : ''}${hasPreload ? ', preload' : ''}.`,
        });
      } else {
        score += 15;
        headersEvaluated.push({
          name: 'Strict-Transport-Security',
          value: hsts,
          status: 'WARN',
          scoreImpact: 15,
          summary: `HSTS present but max-age (${maxAge}s) is shorter than recommended 1 year (31536000s).`,
          recommendation: 'Increase max-age to 31536000 and consider includeSubDomains.',
        });
      }
    } else {
      headersEvaluated.push({
        name: 'Strict-Transport-Security',
        value: null,
        status: 'FAIL',
        scoreImpact: 0,
        summary: 'Missing HSTS header. Vulnerable to SSL stripping and downgrade attacks.',
        recommendation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      });
    }

    // 2. Content-Security-Policy (CSP)
    const csp = rawHeaders['content-security-policy'];
    if (csp) {
      const hasUnsafeInline = /'unsafe-inline'/i.test(csp);
      const hasUnsafeEval = /'unsafe-eval'/i.test(csp);
      if (!hasUnsafeInline && !hasUnsafeEval) {
        score += 25;
        headersEvaluated.push({
          name: 'Content-Security-Policy',
          value: csp,
          status: 'PASS',
          scoreImpact: 25,
          summary: 'Robust CSP configured without unsafe script execution directives.',
        });
      } else {
        score += 15;
        headersEvaluated.push({
          name: 'Content-Security-Policy',
          value: csp,
          status: 'WARN',
          scoreImpact: 15,
          summary: `CSP is active but permits ${hasUnsafeInline ? "'unsafe-inline'" : ''} ${hasUnsafeEval ? "'unsafe-eval'" : ''}, weakening XSS defenses.`,
          recommendation: 'Refactor inline scripts to use nonces or cryptographic hashes.',
        });
      }
    } else {
      headersEvaluated.push({
        name: 'Content-Security-Policy',
        value: null,
        status: 'FAIL',
        scoreImpact: 0,
        summary: 'Missing CSP header. High risk of Cross-Site Scripting (XSS) and data injection.',
        recommendation: "default-src 'self'; script-src 'self' https:; object-src 'none';",
      });
    }

    // 3. X-Frame-Options (superseded by CSP frame-ancestors when present)
    const xfo = rawHeaders['x-frame-options'];
    const frameAncestors = csp?.match(/(?:^|;)\s*frame-ancestors\s+([^;]+)/i)?.[1]?.trim();
    if (frameAncestors && !/(^|\s)\*(\s|$)/.test(frameAncestors)) {
      score += 20;
      headersEvaluated.push({
        name: 'X-Frame-Options',
        value: xfo || null,
        status: 'PASS',
        scoreImpact: 20,
        summary: `Clickjacking protection provided by CSP frame-ancestors (${frameAncestors}), which supersedes X-Frame-Options in modern browsers.`,
      });
    } else if (xfo && (xfo.trim().toUpperCase() === 'DENY' || xfo.trim().toUpperCase() === 'SAMEORIGIN')) {
      score += 20;
      headersEvaluated.push({
        name: 'X-Frame-Options',
        value: xfo,
        status: 'PASS',
        scoreImpact: 20,
        summary: `Prevents clickjacking UI redressing by restricting framing (${xfo.toUpperCase()}).`,
      });
    } else {
      headersEvaluated.push({
        name: 'X-Frame-Options',
        value: xfo || null,
        status: 'FAIL',
        scoreImpact: 0,
        summary: 'Missing or invalid X-Frame-Options header. Vulnerable to Clickjacking.',
        recommendation: 'X-Frame-Options: DENY or SAMEORIGIN',
      });
    }

    // 4. X-Content-Type-Options
    const xcto = rawHeaders['x-content-type-options'];
    if (xcto && xcto.toLowerCase() === 'nosniff') {
      score += 15;
      headersEvaluated.push({
        name: 'X-Content-Type-Options',
        value: xcto,
        status: 'PASS',
        scoreImpact: 15,
        summary: "Enforces MIME type checking with 'nosniff', preventing drive-by executable confusion.",
      });
    } else {
      headersEvaluated.push({
        name: 'X-Content-Type-Options',
        value: xcto || null,
        status: 'FAIL',
        scoreImpact: 0,
        summary: "Missing 'X-Content-Type-Options: nosniff'. Vulnerable to MIME-type sniffing.",
        recommendation: 'X-Content-Type-Options: nosniff',
      });
    }

    // 5. Referrer-Policy
    const refPol = rawHeaders['referrer-policy'];
    if (refPol) {
      score += 10;
      headersEvaluated.push({
        name: 'Referrer-Policy',
        value: refPol,
        status: 'PASS',
        scoreImpact: 10,
        summary: `Controls referrer data leakage across origins (${refPol}).`,
      });
    } else {
      headersEvaluated.push({
        name: 'Referrer-Policy',
        value: null,
        status: 'WARN',
        scoreImpact: 0,
        summary: 'Missing Referrer-Policy header. Sensitive URLs may leak in HTTP Referer headers.',
        recommendation: 'Referrer-Policy: strict-origin-when-cross-origin',
      });
    }

    // 6. Permissions-Policy
    const permPol = rawHeaders['permissions-policy'] || rawHeaders['feature-policy'];
    if (permPol) {
      score += 5;
      headersEvaluated.push({
        name: 'Permissions-Policy',
        value: permPol,
        status: 'PASS',
        scoreImpact: 5,
        summary: 'Restricts sensitive browser hardware features (camera, microphone, geolocation, payment).',
      });
    } else {
      headersEvaluated.push({
        name: 'Permissions-Policy',
        value: null,
        status: 'OPTIONAL',
        scoreImpact: 0,
        summary: 'Permissions-Policy is recommended to disable unused browser device APIs.',
        recommendation: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
      });
    }

    // Determine Letter Grade
    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'F';
    if (score >= 90) grade = 'A+';
    else if (score >= 75) grade = 'A';
    else if (score >= 60) grade = 'B';
    else if (score >= 45) grade = 'C';
    else if (score >= 25) grade = 'D';

    const result: SecurityHeadersData = {
      targetUrl: target,
      finalUrl,
      statusCode: response.status,
      grade,
      score,
      headersEvaluated,
      cookies,
      rawHeaders,
      remediationSnippets: {
        nginx: `# Nginx Security Headers Configuration
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';" always;`,
        apache: `# Apache .htaccess Security Headers
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self';"
</IfModule>`,
        cloudflare: `// Cloudflare Workers / Transform Rules
response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
response.headers.set('X-Frame-Options', 'SAMEORIGIN');
response.headers.set('X-Content-Type-Options', 'nosniff');
response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');`,
        nextjs: `// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};`,
      },
    };

    return NextResponse.json(result);
  } catch (err: any) {
    if (err instanceof BlockedHostError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    const isTimeout = err?.name === 'AbortError' || err?.name === 'TimeoutError' || /abort|timeout/i.test(err?.message || '');
    // Raw connection errors can name internal addresses, so only a generic message is returned
    const errorMessage = isTimeout
      ? `The connection to "${target}" timed out. The remote web server is taking longer than 15 seconds to respond, or may be blocking automated requests.`
      : 'Failed to connect to target URL or retrieve HTTP headers.';

    return NextResponse.json(
      { error: errorMessage },
      { status: 504 }
    );
  }
}
