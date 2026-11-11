import { NextRequest, NextResponse } from 'next/server';
import { getCloudflareContext } from '@opennextjs/cloudflare';

// Per-IP rate limiting for the API routes, backed by Cloudflare's Workers rate limit bindings
// (configured in wrangler.toml). Limits are approximate and counted per Cloudflare location.

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

declare global {
  interface CloudflareEnv {
    API_RATE_LIMITER?: RateLimitBinding;
    HEAVY_RATE_LIMITER?: RateLimitBinding;
  }
}

// 'api' = every API request; 'heavy' = requests that fan out to many targets or probe a
// caller-chosen host (batch link checks, /api/ip port probes, /api/ssl)
export type RateLimitBucket = 'api' | 'heavy';

const IS_CLOUDFLARE_WORKER = typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';

const BINDINGS: Record<RateLimitBucket, keyof CloudflareEnv> = {
  api: 'API_RATE_LIMITER',
  heavy: 'HEAVY_RATE_LIMITER',
};

/**
 * Returns a 429 response when the caller's IP is over the limit, otherwise null.
 * Outside Cloudflare (next dev / next start) there is no binding and requests are not limited.
 */
export async function enforceRateLimit(req: NextRequest, bucket: RateLimitBucket = 'api'): Promise<NextResponse | null> {
  let limiter: RateLimitBinding | undefined;
  try {
    const { env } = await getCloudflareContext({ async: true });
    limiter = env[BINDINGS[bucket]] as RateLimitBinding | undefined;
  } catch {
    return null;
  }
  if (!limiter) {
    // On Workers a missing binding means wrangler.toml is out of sync; log it so it gets noticed
    if (IS_CLOUDFLARE_WORKER) console.error(`[rate-limit] ${BINDINGS[bucket]} binding is missing; requests are not limited`);
    return null;
  }

  const ip = req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';

  try {
    const { success } = await limiter.limit({ key: `${bucket}:${ip}` });
    if (success) return null;
  } catch (err) {
    console.error(`[rate-limit] ${BINDINGS[bucket]} failed:`, err);
    // Fail open for the general bucket so a limiter outage doesn't take every tool down, but fail
    // closed for 'heavy': those routes probe caller-chosen hosts and are the ones worth abusing.
    if (bucket === 'api') return null;
    return NextResponse.json(
      {
        error: 'This tool is temporarily unavailable. Please try again shortly.',
        code: 'RATE_LIMITER_UNAVAILABLE',
      },
      { status: 503, headers: { 'Retry-After': '60' } }
    );
  }

  return NextResponse.json(
    {
      error: 'Too many requests. Please wait a minute and try again.',
      code: 'RATE_LIMITED',
    },
    { status: 429, headers: { 'Retry-After': '60' } }
  );
}
