'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Key,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
  Sparkles,
  Lock,
  Unlock,
  Clock,
  Code2,
  FileCode,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Zap,
} from 'lucide-react';
import { JwtAuditData } from '@/lib/types';
import CryptoJS from 'crypto-js';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

const SAMPLE_TOKENS = [
  {
    label: 'Standard Valid Token (HS256)',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNvYyBBbmFseXN0IiwiYWRtaW4iOnRydWUsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.5cO9jE5m3yD-Y8YwS1mR0mJ5-Q4fDkYgWwGZ9xP6L0A',
    secret: 'secret',
  },
  {
    label: 'Expired User Token',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzg5MCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjIwMDAwMDAwfQ.gLwH5Bf9N6pX_w3Y4k5Q0g9m6LwH5Bf9N6pX_w3Y4k4',
    secret: 'supersecretkey123',
  },
  {
    label: '🚨 Critical: "alg: none" Exploit Token',
    token: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZSI6WyJzdXBlcmFkbWluIl0sImlhdCI6MTcwMDAwMDAwMH0.',
    secret: '',
  },
  {
    label: 'Weak HMAC Secret Token ("password123")',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZXZlbG9wZXIiLCJyb2xlcyI6WyJkZXZlbG9wZXIiLCJidWlsZGVyIl0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.k0tC4E2nN3z3dK_K8R1m2J5Q4fDkYgWwGZ9xP6L0Abc',
    secret: 'password123',
  },
];

const COMMON_SECRETS_DICTIONARY = [
  'secret',
  'password',
  '123456',
  '12345678',
  'password123',
  'jwtsecret',
  'admin',
  'qwerty',
  'letmein',
  'supersecret',
  'test',
  'development',
  'production',
  'key',
  'mysecret',
  'secret123',
  'auth0',
  'jsonwebtoken',
  'changeme',
];

function base64UrlDecode(str: string) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  try {
    return decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
  } catch {
    return atob(base64);
  }
}

// Computes the base64url HMAC signature for HS256 / HS384 / HS512; null for other algorithms
function computeHmacSignature(algorithm: string, signingInput: string, secret: string): string | null {
  const hmac =
    algorithm === 'HS256' ? CryptoJS.HmacSHA256 :
    algorithm === 'HS384' ? CryptoJS.HmacSHA384 :
    algorithm === 'HS512' ? CryptoJS.HmacSHA512 :
    null;
  if (!hmac) return null;
  return CryptoJS.enc.Base64.stringify(hmac(signingInput, secret))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export function JwtAuditor() {
  const [tokenInput, setTokenInput] = useState(SAMPLE_TOKENS[0].token);
  const [secretInput, setSecretInput] = useState(SAMPLE_TOKENS[0].secret);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isCracking, setIsCracking] = useState(false);
  const [crackedResult, setCrackedResult] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('jwt', { persist: false }); // tokens are bearer credentials: session-only history

  // Parse and audit JWT reactively
  const auditResult: JwtAuditData | null = useMemo(() => {
    if (!tokenInput.trim()) return null;
    const parts = tokenInput.trim().split('.');
    if (parts.length < 2 || parts.length > 3) {
      return null;
    }

    try {
      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));
      const signatureHex = parts[2] || '';
      const algorithm = header.alg || 'UNKNOWN';

      const nowSec = Math.floor(Date.now() / 1000);
      const isExpired = typeof payload.exp === 'number' ? payload.exp < nowSec : false;
      const isNotYetValid = typeof payload.nbf === 'number' ? payload.nbf > nowSec : false;

      const vulnerabilities: JwtAuditData['vulnerabilities'] = [];

      // Vulnerability 1: alg: none check
      if (!algorithm || algorithm.toLowerCase() === 'none') {
        vulnerabilities.push({
          severity: 'CRITICAL',
          title: 'Unsecured JWT Algorithm (alg: "none")',
          description: 'The token specifies algorithm "none" or lacks signature enforcement, allowing arbitrary payload tampering and privilege escalation.',
          recommendation: 'Enforce strong cryptographic algorithms (RS256, ES256, HS256) on the backend and reject tokens with alg="none".',
        });
      }

      // Vulnerability 2: Expiration check
      if (isExpired) {
        vulnerabilities.push({
          severity: 'HIGH',
          title: 'Token Expired',
          description: `The token expired at ${new Date(payload.exp * 1000).toUTCString()} (exp claim).`,
          recommendation: 'Do not accept expired tokens; request token refresh.',
        });
      } else if (payload.exp === undefined) {
        vulnerabilities.push({
          severity: 'MEDIUM',
          title: 'Missing Expiration Claim (exp)',
          description: 'The token does not define an expiration timestamp, making it valid indefinitely if leaked.',
          recommendation: 'Always set a short-lived exp timestamp claim (e.g. 15-60 minutes).',
        });
      }

      if (isNotYetValid) {
        vulnerabilities.push({
          severity: 'MEDIUM',
          title: 'Token Not Yet Valid',
          description: `The token is not valid before ${new Date(payload.nbf * 1000).toUTCString()} (nbf claim).`,
          recommendation: 'Do not accept tokens before their nbf time.',
        });
      }

      // Vulnerability 3: Symmetric vs Asymmetric Algorithm
      if (algorithm.startsWith('HS')) {
        vulnerabilities.push({
          severity: 'LOW',
          title: 'Symmetric Secret in Use (HMAC)',
          description: `Token uses ${algorithm}. Both the signing authority and verifying microservices share the same secret key, increasing blast radius if a verification service is compromised.`,
          recommendation: 'Consider migrating to asymmetric public/private keys (RS256 or ES256) for zero-trust microservice verification.',
        });
      }

      // Claims Summary
      const roles =
        payload.roles !== undefined ? payload.roles :
        payload.role !== undefined ? [payload.role] :
        payload.admin === true ? ['admin'] :
        [];

      return {
        header,
        payload,
        signatureHex,
        algorithm,
        isValidStructure: true,
        isExpired,
        expirationDate: payload.exp ? new Date(payload.exp * 1000).toLocaleString() : undefined,
        issuedAtDate: payload.iat ? new Date(payload.iat * 1000).toLocaleString() : undefined,
        notBeforeDate: payload.nbf ? new Date(payload.nbf * 1000).toLocaleString() : undefined,
        claimsSummary: {
          issuer: payload.iss,
          subject: payload.sub,
          audience: payload.aud,
          roles: Array.isArray(roles) ? roles.map(String) : [String(roles)],
        },
        vulnerabilities,
      };
    } catch {
      return null;
    }
  }, [tokenInput]);

  // Fast Dictionary Secret Cracker
  const handleCrackSecret = () => {
    if (!tokenInput.trim()) return;
    const parts = tokenInput.trim().split('.');
    if (parts.length !== 3 || !parts[2]) {
      setCrackedResult('Token lacks HMAC signature to crack.');
      return;
    }
    const algorithm = auditResult?.algorithm || '';
    if (!['HS256', 'HS384', 'HS512'].includes(algorithm)) {
      setCrackedResult(`Dictionary cracking only applies to HMAC tokens (HS256/HS384/HS512); this token uses ${algorithm || 'an unknown algorithm'}.`);
      return;
    }

    setIsCracking(true);
    setCrackedResult(null);

    setTimeout(() => {
      const headerAndPayload = `${parts[0]}.${parts[1]}`;
      const targetSig = parts[2];

      let found: string | null = null;
      for (const secret of COMMON_SECRETS_DICTIONARY) {
        if (computeHmacSignature(algorithm, headerAndPayload, secret) === targetSig) {
          found = secret;
          break;
        }
      }

      setIsCracking(false);
      if (found) {
        setCrackedResult(`🚨 CRACKED! Secret Key is: "${found}"`);
        setSecretInput(found);
      } else {
        setCrackedResult(`Checked ${COMMON_SECRETS_DICTIONARY.length} common secrets with ${algorithm}. None matched.`);
      }
    }, 400);
  };

  // Verify the signature against the secret typed by the user (HMAC algorithms only)
  const secretVerification: 'MATCH' | 'MISMATCH' | 'NOT_APPLICABLE' | null = useMemo(() => {
    if (!auditResult || !secretInput) return null;
    const parts = tokenInput.trim().split('.');
    if (parts.length !== 3 || !parts[2]) return null;
    const expected = computeHmacSignature(auditResult.algorithm, `${parts[0]}.${parts[1]}`, secretInput);
    if (expected === null) return 'NOT_APPLICABLE';
    return expected === parts[2] ? 'MATCH' : 'MISMATCH';
  }, [auditResult, secretInput, tokenInput]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-fuchsia-500/20 border border-fuchsia-500/40 text-fuchsia-400">
            <Key className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                JWT Security & Exploit Auditor
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Decode JSON Web Tokens, audit cryptographic signatures (alg: none), verify expiration claims & test weak secrets
            </p>
          </div>
        </div>
      </div>

      {/* Top Presets */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-3">

        {/* Presets */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => {
              setTokenInput(val);
              setCrackedResult(null);
            }}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-fuchsia-400" /> Presets:
          </span>
          {SAMPLE_TOKENS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setTokenInput(p.token);
                setSecretInput(p.secret);
                setCrackedResult(null);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-fuchsia-300 hover:text-fuchsia-200 transition-all"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main JWT Token Input */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-bold text-slate-300 tracking-normal">
            RAW ENCODED JWT TOKEN (HEADER.PAYLOAD.SIGNATURE)
          </label>
          <button
            onClick={() => copyToClipboard(tokenInput, 'raw-jwt')}
            className="text-[11px] font-mono text-fuchsia-400 hover:text-fuchsia-300 flex items-center gap-1"
          >
            {copiedKey === 'raw-jwt' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            Copy Token
          </button>
        </div>
        <textarea
          value={tokenInput}
          onChange={e => setTokenInput(e.target.value)}
          onBlur={() => {
            if (tokenInput.trim() && auditResult) addEntry(tokenInput.trim());
          }}
          placeholder="Paste JWT token (e.g. eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)..."
          rows={3}
          className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-fuchsia-300 placeholder-slate-600 focus:outline-none focus:border-fuchsia-500 select-all"
        />
      </div>

      {/* Audit & Breakdown Dashboard */}
      {auditResult ? (
        <div className="space-y-6 animate-in fade-in duration-300">
          
          {/* Top Status & Claims Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            
            {/* Algorithm Metric */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">ALGORITHM</span>
              <div className="text-lg font-mono font-bold text-slate-100 flex items-center gap-2">
                <span>{auditResult.algorithm}</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                    auditResult.algorithm.toLowerCase() === 'none'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}
                >
                  {auditResult.algorithm.toLowerCase() === 'none'
                    ? 'VULNERABLE'
                    : secretVerification === 'MATCH'
                    ? 'SIGNATURE VERIFIED'
                    : 'SIGNED (NOT VERIFIED)'}
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400">Type: {auditResult.header.typ || 'not set'}</p>
            </div>

            {/* Expiration Status */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">TEMPORAL VALIDITY</span>
              <div className="text-lg font-mono font-bold text-slate-100 flex items-center gap-2">
                <span className={auditResult.isExpired || auditResult.vulnerabilities.some(v => v.title === 'Token Not Yet Valid') ? 'text-rose-400' : 'text-emerald-400'}>
                  {auditResult.isExpired
                    ? 'EXPIRED'
                    : auditResult.vulnerabilities.some(v => v.title === 'Token Not Yet Valid')
                    ? 'NOT YET VALID'
                    : auditResult.expirationDate
                    ? 'NOT EXPIRED'
                    : 'NO EXPIRY'}
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 truncate">
                {auditResult.expirationDate ? `Exp: ${auditResult.expirationDate}` : 'Missing exp claim'}
              </p>
            </div>

            {/* Subject / User */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">SUBJECT (SUB)</span>
              <div className="text-sm font-mono font-bold text-slate-100 truncate" title={auditResult.claimsSummary.subject}>
                {auditResult.claimsSummary.subject || 'None Specified'}
              </div>
              <p className="text-[10px] font-mono text-slate-400">
                Roles: <strong className="text-fuchsia-300">{(auditResult.claimsSummary.roles || []).join(', ') || 'N/A'}</strong>
              </p>
            </div>

            {/* Vulnerability Count */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">SECURITY FINDINGS</span>
              <div className="text-lg font-mono font-bold text-slate-100 flex items-center gap-2">
                <span className={auditResult.vulnerabilities.length > 0 ? 'text-amber-400' : 'text-emerald-400'}>
                  {auditResult.vulnerabilities.length} Finding{auditResult.vulnerabilities.length === 1 ? '' : 's'}
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400">Automated flaw scanner</p>
            </div>

          </div>

          {/* Security Flaws & Vulnerabilities */}
          {auditResult.vulnerabilities.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-bold text-slate-200 tracking-normal flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" /> Security Vulnerabilities & Misconfigurations
              </h3>
              <div className="space-y-2.5">
                {auditResult.vulnerabilities.map((vuln, idx) => (
                  <div
                    key={idx}
                    className={`p-4 rounded-2xl border ${
                      vuln.severity === 'CRITICAL'
                        ? 'bg-rose-950/20 border-rose-800/60'
                        : vuln.severity === 'HIGH'
                        ? 'bg-rose-950/20 border-rose-800/40'
                        : 'bg-amber-950/20 border-amber-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-slate-100">{vuln.title}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold ${
                          vuln.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-700'
                            : 'bg-amber-950 text-amber-300 border border-amber-700'
                        }`}
                      >
                        {vuln.severity}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-300 leading-relaxed mb-2">{vuln.description}</p>
                    <div className="text-[11px] font-mono text-emerald-300">
                      <span className="font-bold text-emerald-400">Remediation: </span>
                      {vuln.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Decoded Header & Payload Side by Side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Decoded Header */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-3 shadow-xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-rose-400 flex items-center gap-2">
                  <Code2 className="w-4 h-4" /> DECODED HEADER (JOSE)
                </h3>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(auditResult.header, null, 2), 'hdr-json')}
                  className="text-[11px] font-mono text-slate-400 hover:text-rose-300 flex items-center gap-1"
                >
                  {copiedKey === 'hdr-json' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  Copy JSON
                </button>
              </div>
              <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-rose-300 select-all overflow-x-auto">
                {JSON.stringify(auditResult.header, null, 2)}
              </pre>
            </div>

            {/* Decoded Payload */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-3 shadow-xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-fuchsia-400 flex items-center gap-2">
                  <Code2 className="w-4 h-4" /> DECODED PAYLOAD (CLAIMS)
                </h3>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(auditResult.payload, null, 2), 'pld-json')}
                  className="text-[11px] font-mono text-slate-400 hover:text-fuchsia-300 flex items-center gap-1"
                >
                  {copiedKey === 'pld-json' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  Copy JSON
                </button>
              </div>
              <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-fuchsia-300 select-all overflow-x-auto">
                {JSON.stringify(auditResult.payload, null, 2)}
              </pre>
            </div>

          </div>

          {/* Dictionary Secret Cracker & Signature Verifier */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" /> Instant Dictionary Secret Cracker & Signature Verifier
              </h3>
              <button
                onClick={handleCrackSecret}
                disabled={isCracking}
                className="px-4 py-1.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-bold text-xs flex items-center gap-1.5 transition-all shadow-md disabled:opacity-50"
              >
                {isCracking ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Unlock className="w-3.5 h-3.5" />}
                {isCracking ? 'Testing Wordlist...' : 'Brute-Force Secret'}
              </button>
            </div>

            <div className="flex flex-col sm:flex-row gap-3 items-center">
              <input
                type="text"
                value={secretInput}
                onChange={e => setSecretInput(e.target.value)}
                placeholder="Enter HMAC Secret Key to verify (or click Brute-Force Secret)..."
                className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-amber-300 placeholder-slate-600 focus:outline-none focus:border-amber-500"
              />
            </div>

            {secretVerification && (
              <div
                className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
                  secretVerification === 'MATCH'
                    ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-300'
                    : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                {secretVerification === 'MATCH' ? <Check className="w-4 h-4 flex-shrink-0" /> : <AlertCircle className="w-4 h-4 flex-shrink-0" />}
                <span>
                  {secretVerification === 'MATCH'
                    ? `Signature is valid for this secret (${auditResult.algorithm}).`
                    : secretVerification === 'MISMATCH'
                    ? `Signature does NOT match this secret (${auditResult.algorithm}).`
                    : `${auditResult.algorithm} signatures need the issuer's public key to verify; a shared secret does not apply.`}
                </span>
              </div>
            )}

            {crackedResult && (
              <div
                className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
                  crackedResult.includes('CRACKED')
                    ? 'bg-rose-950/40 border-rose-600/60 text-rose-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{crackedResult}</span>
              </div>
            )}
          </div>

        </div>
      ) : (
        <div className="p-8 rounded-2xl bg-slate-900/40 border border-slate-800 text-center text-xs font-mono text-slate-400">
          Paste a valid 3-part base64url encoded JWT token above to start security auditing.
        </div>
      )}
    </div>
  );
}
