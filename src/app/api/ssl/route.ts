import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit } from '@/lib/rate-limit';
import tls from 'tls';
import net from 'net';
import crypto from 'crypto';
import { SslCertificateData } from '@/lib/types';
import { assertPublicHost, BlockedHostError, validateDomain } from '@/lib/net-utils';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Grade = SslCertificateData['grade'];
type Strength = 'STRONG' | 'MODERATE' | 'WEAK';

export async function GET(req: NextRequest) {
  const limited = await enforceRateLimit(req);
  if (limited) return limited;
  // Each request opens a connection to a caller-chosen host, so it also counts against the stricter limit
  const heavyLimited = await enforceRateLimit(req, 'heavy');
  if (heavyLimited) return heavyLimited;

  const { searchParams } = new URL(req.url);
  const target = searchParams.get('target')?.trim();
  const portStr = searchParams.get('port')?.trim() || '443';
  const port = /^\d{1,5}$/.test(portStr) ? parseInt(portStr, 10) : NaN;

  if (!target) {
    return NextResponse.json({ error: 'Target host is required' }, { status: 400 });
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return NextResponse.json({ error: 'Port must be an integer between 1 and 65535' }, { status: 400 });
  }

  // Clean domain / hostname. The URL parser normalises odd IPv4 forms (e.g. 2130706433 -> 127.0.0.1).
  const rawHost = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim().toLowerCase();
  let host: string;
  try {
    host = net.isIP(rawHost) === 6 ? rawHost : new URL(`https://${rawHost}`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return NextResponse.json({ error: 'Target host is not a valid hostname or IP address' }, { status: 400 });
  }
  if (!net.isIP(host) && !validateDomain(host).isValid) {
    return NextResponse.json({ error: 'Target host is not a valid hostname or IP address' }, { status: 400 });
  }

  // SSRF guard: no localhost / private / reserved targets, including names that resolve to them
  let validatedAddresses: string[];
  try {
    validatedAddresses = await assertPublicHost(host);
  } catch (err: any) {
    const message = err instanceof BlockedHostError ? err.message : 'Target host could not be validated';
    return NextResponse.json({ error: message }, { status: 400 });
  }

  try {
    let certData: SslCertificateData;
    try {
      // 1. Attempt direct socket TLS inspection (works in standard Node.js environments).
      // Connects to the address that was just validated so the name cannot be re-resolved elsewhere.
      certData = await inspectTlsCertificate(host, port, validatedAddresses[0]);
    } catch {
      // 2. Cloudflare Workers compatibility fallback:
      // In workerd isolates, tlsSocket.getPeerCertificate() and rejectUnauthorized are not implemented.
      // Certificate Transparency logs only describe the certificate itself, so handshake properties
      // (protocol, cipher, OCSP stapling, served chain) are reported as unknown rather than guessed.
      certData = await inspectViaCertificateTransparency(host, port);
    }
    return NextResponse.json(certData);
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || 'Failed to establish TLS connection or extract certificate' },
      { status: 500 }
    );
  }
}

function formatFingerprint(hex: string): string {
  return hex.match(/.{2}/g)?.join(':').toUpperCase() || '';
}

function firstString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0];
  return undefined;
}

/**
 * Reads the public key type and size from the DER certificate itself.
 */
function describePublicKey(rawDer: Buffer): SslCertificateData['publicKey'] {
  try {
    const x509 = new crypto.X509Certificate(rawDer);
    const keyType = x509.publicKey.asymmetricKeyType;
    const details = x509.publicKey.asymmetricKeyDetails || {};

    if (keyType === 'rsa' || keyType === 'rsa-pss') {
      const bits = details.modulusLength;
      if (!bits) return null;
      const strength: Strength = bits < 2048 ? 'WEAK' : bits === 2048 ? 'MODERATE' : 'STRONG';
      return { type: 'RSA', bits, strength };
    }
    if (keyType === 'ec') {
      const curveBits: Record<string, number> = {
        prime256v1: 256,
        'P-256': 256,
        secp384r1: 384,
        'P-384': 384,
        secp521r1: 521,
        'P-521': 521,
      };
      const curve = details.namedCurve || 'unknown curve';
      const bits = curveBits[curve];
      if (!bits) return { type: `EC (${curve})`, bits: null, strength: null };
      return { type: `ECDSA (${curve})`, bits, strength: bits >= 256 ? 'STRONG' : 'WEAK' };
    }
    if (keyType === 'ed25519') return { type: 'Ed25519', bits: 256, strength: 'STRONG' };
    if (keyType === 'ed448') return { type: 'Ed448', bits: 456, strength: 'STRONG' };
    return keyType ? { type: keyType.toUpperCase(), bits: null, strength: null } : null;
  } catch {
    return null;
  }
}

/**
 * Direct TLS Socket Handshake (for Node environments supporting full tls.connect)
 */
function inspectTlsCertificate(host: string, port: number, connectAddress?: string): Promise<SslCertificateData> {
  return new Promise((resolve, reject) => {
    let ocspStapled = false;

    // rejectUnauthorized: false lets the handshake complete for expired, self-signed or mismatched
    // certificates so they can be reported. Trust is evaluated explicitly via socket.authorized.
    // workerd throws on this option, which drops into the Certificate Transparency fallback.
    // requestOCSP is forwarded by tls.connect to the TLSSocket but is missing from ConnectionOptions typings.
    const connectOptions: tls.ConnectionOptions & { requestOCSP: boolean } = {
      host: connectAddress || host,
      port,
      servername: net.isIP(host) ? undefined : host,
      timeout: 5000,
      rejectUnauthorized: false,
      requestOCSP: true,
    };
    const socket = tls.connect(
      connectOptions,
      () => {
        try {
          if (typeof socket.getPeerCertificate !== 'function') {
            socket.destroy();
            return reject(new Error('getPeerCertificate is not supported in this runtime.'));
          }

          const peerCert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol() || null;
          const cipher = socket.getCipher();

          if (!peerCert || !peerCert.raw) {
            socket.destroy();
            return reject(new Error('No peer certificate presented by target host.'));
          }

          // Calculate Fingerprints
          const rawDer = peerCert.raw;
          const sha256Fingerprint = formatFingerprint(crypto.createHash('sha256').update(rawDer).digest('hex'));
          const sha1Fingerprint = formatFingerprint(crypto.createHash('sha1').update(rawDer).digest('hex'));

          // Dates & Expiration
          const validFrom = peerCert.valid_from ? new Date(peerCert.valid_from).toISOString() : '';
          const validTo = peerCert.valid_to ? new Date(peerCert.valid_to).toISOString() : '';
          const now = Date.now();
          const toTime = validTo ? new Date(validTo).getTime() : NaN;
          const fromTime = validFrom ? new Date(validFrom).getTime() : NaN;

          const isExpired = !isNaN(toTime) && now > toTime;
          const isNotYetValid = !isNaN(fromTime) && now < fromTime;
          const daysRemaining = isNaN(toTime) ? 0 : Math.max(0, Math.floor((toTime - now) / (1000 * 60 * 60 * 24)));

          const subjectCn = firstString(peerCert.subject?.CN) || '(no CN in certificate)';
          const issuerOrg = firstString(peerCert.issuer?.O);
          const issuerCn = firstString(peerCert.issuer?.CN) || issuerOrg || '(no issuer CN in certificate)';

          // SAN list (exactly as listed in the certificate)
          const sanList: string[] = [];
          if (peerCert.subjectaltname) {
            peerCert.subjectaltname.split(',').forEach(s => {
              const clean = s.trim().replace(/^DNS:/i, '').replace(/^IP Address:/i, '');
              if (clean && !sanList.includes(clean)) sanList.push(clean);
            });
          }

          // Trust evaluation from the actual verification result
          const authError = socket.authorizationError ? String(socket.authorizationError) : undefined;
          const isSelfSigned =
            authError === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
            authError === 'SELF_SIGNED_CERT_IN_CHAIN';
          const hostnameError = tls.checkServerIdentity(host, peerCert);
          const hostnameMatches = !hostnameError;
          const isTrusted = socket.authorized && hostnameMatches;

          const publicKey = describePublicKey(rawDer);

          // Cipher strength and Perfect Forward Secrecy (PFS)
          let cipherSuite: SslCertificateData['cipherSuite'] = null;
          if (cipher?.name) {
            const cipherName = cipher.name;
            const isTls13 = protocol === 'TLSv1.3';
            const isPfs = isTls13 || cipherName.includes('ECDHE') || cipherName.includes('DHE');
            const isAead = cipherName.includes('GCM') || cipherName.includes('POLY1305') || cipherName.includes('CCM');
            let strength: Strength = 'STRONG';
            if (cipherName.includes('RC4') || cipherName.includes('DES') || cipherName.includes('NULL')) {
              strength = 'WEAK';
            } else if (cipherName.includes('CBC') || !isAead) {
              strength = 'MODERATE';
            }
            cipherSuite = {
              name: cipherName,
              standardName: cipher.standardName || cipherName,
              version: cipher.version || protocol || undefined,
              isPfs,
              isAead,
              strength,
            };
          }

          // Certificate chain as returned by the TLS stack
          const certChain: SslCertificateData['certificateChain'] = [];
          let current: any = peerCert;
          let depth = 0;
          while (current && depth < 6) {
            certChain.push({
              subject: firstString(current.subject?.CN) || firstString(current.subject?.O) || '(unnamed)',
              issuer: firstString(current.issuer?.CN) || firstString(current.issuer?.O) || '(unnamed)',
              validTo: current.valid_to ? new Date(current.valid_to).toISOString() : '',
            });
            if (!current.issuerCertificate || current.issuerCertificate === current) break;
            current = current.issuerCertificate;
            depth++;
          }

          // Grade calculation
          let grade: Grade = 'A';
          let gradeReason = 'Trusted certificate with modern TLS configuration';

          if (isExpired) {
            grade = 'F';
            gradeReason = `Certificate expired on ${validTo}`;
          } else if (isNotYetValid) {
            grade = 'F';
            gradeReason = 'Certificate is not yet valid';
          } else if (!hostnameMatches) {
            grade = 'F';
            gradeReason = `Certificate does not match hostname "${host}"`;
          } else if (isSelfSigned) {
            grade = 'C';
            gradeReason = 'Self-signed certificate is not trusted by public roots';
          } else if (!socket.authorized) {
            grade = 'F';
            gradeReason = `Certificate chain is not trusted (${authError || 'verification failed'})`;
          } else if (protocol === 'TLSv1' || protocol === 'TLSv1.1' || protocol === 'SSLv3') {
            grade = 'F';
            gradeReason = `Deprecated ${protocol} protocol in use`;
          } else if (cipherSuite?.strength === 'WEAK' || publicKey?.strength === 'WEAK') {
            grade = 'C';
            gradeReason = 'Weak cryptographic cipher or key length detected';
          } else if (daysRemaining < 7) {
            grade = 'B';
            gradeReason = `Certificate expires soon (${daysRemaining} days remaining)`;
          } else if (protocol === 'TLSv1.3' && cipherSuite?.isPfs && cipherSuite?.isAead && daysRemaining > 14) {
            grade = 'A+';
            gradeReason = 'Trusted certificate with TLS 1.3, Perfect Forward Secrecy and AEAD cipher';
          }

          const result: SslCertificateData = {
            host,
            port,
            source: 'live-handshake',
            grade,
            gradeReason,
            isValid: !isExpired && !isNotYetValid,
            isTrusted,
            trustError: authError || (hostnameError ? hostnameError.message : undefined),
            hostnameMatches,
            isExpired,
            isSelfSigned,
            daysRemaining,
            validFrom,
            validTo,
            subject: {
              commonName: subjectCn,
              organization: firstString(peerCert.subject?.O),
              organizationalUnit: firstString(peerCert.subject?.OU),
              country: firstString(peerCert.subject?.C),
              state: firstString(peerCert.subject?.ST),
              locality: firstString(peerCert.subject?.L),
            },
            issuer: {
              commonName: issuerCn,
              organization: issuerOrg,
              country: firstString(peerCert.issuer?.C),
            },
            sanList,
            protocol,
            cipherSuite,
            publicKey,
            fingerprints: {
              sha256: sha256Fingerprint,
              sha1: sha1Fingerprint,
            },
            serialNumber: peerCert.serialNumber || null,
            ocspStapling: ocspStapled,
            certChainCount: certChain.length,
            certificateChain: certChain,
          };

          socket.destroy();
          resolve(result);
        } catch (e) {
          socket.destroy();
          reject(e);
        }
      }
    );

    socket.on('OCSPResponse', (response: Buffer) => {
      if (response && response.length > 0) ocspStapled = true;
    });

    socket.on('error', err => {
      socket.destroy();
      reject(err);
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Connection to ${host}:${port} timed out after 5000ms.`));
    });
  });
}

/**
 * Certificate Transparency (CT) Logs Inspection
 * Used in serverless environments (Cloudflare Workers, Edge Isolates) where raw TLS
 * inspection is unavailable. CT reports the most recently logged certificate for the host,
 * which is not necessarily the certificate the server is currently presenting.
 */
async function inspectViaCertificateTransparency(host: string, port: number): Promise<SslCertificateData> {
  let certItem: {
    common_name?: string;
    issuer_name?: string;
    name_value?: string;
    not_before?: string;
    not_after?: string;
    serial_number?: string;
    sha256?: string;
    crtShId?: number;
  } | null = null;

  // 1. Query crt.sh Certificate Transparency Logs
  try {
    const crtRes = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecOps-SSL-Auditor' },
      signal: AbortSignal.timeout(6000),
    });
    if (crtRes.ok) {
      const crtList = await crtRes.json();
      if (Array.isArray(crtList) && crtList.length > 0) {
        const now = Date.now();
        const sorted = crtList.sort((a, b) => (b.id || 0) - (a.id || 0));
        // Prefer unexpired cert
        const picked = sorted.find(c => new Date(c.not_after).getTime() > now) || sorted[0];
        certItem = {
          common_name: picked.common_name,
          issuer_name: picked.issuer_name,
          name_value: picked.name_value,
          not_before: picked.not_before,
          not_after: picked.not_after,
          serial_number: picked.serial_number,
          crtShId: picked.id,
        };
      }
    }
  } catch {
    // crt.sh may be rate limited or slow; proceed to fallback
  }

  // 2. Fallback to CertSpotter CT API
  if (!certItem) {
    try {
      const csRes = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=true&expand=dns_names&expand=issuer`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecOps-SSL-Auditor' },
        signal: AbortSignal.timeout(6000),
      });
      if (csRes.ok) {
        const csList = await csRes.json();
        if (Array.isArray(csList) && csList.length > 0) {
          const matching = csList.filter((c: any) => c.dns_names && c.dns_names.some((n: string) => n === host || n === '*.' + host || ('*.' + host.split('.').slice(1).join('.')) === n));
          const now = Date.now();
          const active = matching.filter((c: any) => new Date(c.not_after).getTime() > now);
          const latest = active[active.length - 1] || matching[matching.length - 1];
          if (latest) {
            certItem = {
              common_name: latest.dns_names?.[0],
              issuer_name: latest.issuer?.name || latest.issuer?.friendly_name,
              name_value: latest.dns_names?.join('\n'),
              not_before: latest.not_before,
              not_after: latest.not_after,
              sha256: latest.cert_sha256,
            };
          }
        }
      }
    } catch {
      // CertSpotter failed
    }
  }

  if (!certItem) {
    throw new Error(`Could not retrieve SSL/TLS certificate for "${host}". Target host may not have logged public certificates, or network is unreachable.`);
  }

  // 3. Download the logged certificate itself (crt.sh) to read its real key and fingerprints
  let publicKey: SslCertificateData['publicKey'] = null;
  let sha256Fingerprint = certItem.sha256 ? formatFingerprint(certItem.sha256) : null;
  let sha1Fingerprint: string | null = null;
  if (certItem.crtShId) {
    try {
      const pemRes = await fetch(`https://crt.sh/?d=${certItem.crtShId}`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecOps-SSL-Auditor' },
        signal: AbortSignal.timeout(6000),
      });
      if (pemRes.ok) {
        const pem = await pemRes.text();
        const x509 = new crypto.X509Certificate(pem);
        publicKey = describePublicKey(x509.raw);
        sha256Fingerprint = x509.fingerprint256;
        sha1Fingerprint = x509.fingerprint;
      }
    } catch {
      // Key details and fingerprints stay unknown
    }
  }

  const commonName: string = certItem.common_name || '(no CN in logged certificate)';
  const rawIssuer: string = certItem.issuer_name || '';
  const validFrom: string = certItem.not_before ? new Date(certItem.not_before).toISOString() : '';
  const validTo: string = certItem.not_after ? new Date(certItem.not_after).toISOString() : '';

  const now = Date.now();
  const fromTime = validFrom ? new Date(validFrom).getTime() : NaN;
  const toTime = validTo ? new Date(validTo).getTime() : NaN;
  const isExpired = !isNaN(toTime) && now > toTime;
  const isNotYetValid = !isNaN(fromTime) && now < fromTime;
  const daysRemaining = isNaN(toTime) ? 0 : Math.max(0, Math.floor((toTime - now) / (1000 * 60 * 60 * 24)));

  // Extract SANs
  const sanList: string[] = [];
  if (certItem.name_value) {
    certItem.name_value.split('\n').forEach((s: string) => {
      const clean = s.trim().replace(/^DNS:/i, '');
      if (clean && !sanList.includes(clean)) sanList.push(clean);
    });
  }

  // Parse issuer CN and Org
  const issuerCnMatch = rawIssuer.match(/CN=([^,]+)/i);
  const issuerOrgMatch = rawIssuer.match(/O=([^,]+)/i);
  const issuerCountryMatch = rawIssuer.match(/C=([^,]+)/i);

  const issuerOrg = issuerOrgMatch ? issuerOrgMatch[1].trim() : undefined;
  const issuerCn = issuerCnMatch ? issuerCnMatch[1].trim() : (issuerOrg || rawIssuer || 'Unknown issuer');
  const issuerCountry = issuerCountryMatch ? issuerCountryMatch[1].trim() : undefined;

  // Grade reflects certificate validity only; the handshake was not observed
  let grade: Grade = 'A';
  let gradeReason = 'Logged certificate is within its validity period (protocol and cipher not assessed — no live handshake)';

  if (isExpired) {
    grade = 'F';
    gradeReason = `Most recent logged certificate expired on ${validTo}`;
  } else if (isNotYetValid) {
    grade = 'F';
    gradeReason = 'Most recent logged certificate is not yet valid';
  } else if (publicKey?.strength === 'WEAK') {
    grade = 'C';
    gradeReason = 'Logged certificate uses a weak key';
  } else if (daysRemaining < 7) {
    grade = 'B';
    gradeReason = `Logged certificate expires soon (${daysRemaining} days remaining)`;
  }

  return {
    host,
    port,
    source: 'certificate-transparency',
    grade,
    gradeReason,
    isValid: !isExpired && !isNotYetValid,
    isTrusted: null,
    hostnameMatches: null,
    isExpired,
    // CT logs only accept CA-issued certificates
    isSelfSigned: false,
    daysRemaining,
    validFrom,
    validTo,
    subject: {
      commonName,
    },
    issuer: {
      commonName: issuerCn,
      organization: issuerOrg,
      country: issuerCountry,
    },
    sanList,
    protocol: null,
    cipherSuite: null,
    publicKey,
    fingerprints: {
      sha256: sha256Fingerprint,
      sha1: sha1Fingerprint,
    },
    serialNumber: certItem.serial_number || null,
    ocspStapling: null,
    certChainCount: 0,
    certificateChain: [],
  };
}
