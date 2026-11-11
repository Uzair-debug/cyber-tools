'use client';

import React, { useState } from 'react';
import {
  Lock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  RefreshCw,
  Copy,
  Check,
  Download,
  Calendar,
  Layers,
  Key,
  Globe2,
  Sparkles,
  Server,
  FileCode,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { SslCertificateData } from '@/lib/types';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

const PRESETS = [
  { label: 'github.com', host: 'github.com', port: 443 },
  { label: 'google.com', host: 'google.com', port: 443 },
  { label: 'cloudflare.com', host: 'cloudflare.com', port: 443 },
];

export function SslInspector() {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('443');
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState<SslCertificateData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('ssl');

  const handleScan = async (targetHost = host, targetPort = port) => {
    if (!targetHost.trim()) return;
    setIsLoading(true);
    setError(null);

    try {
      const cleanHost = targetHost.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      if (cleanHost) addEntry(cleanHost);
      const res = await fetch(`/api/ssl?target=${encodeURIComponent(cleanHost)}&port=${encodeURIComponent(targetPort)}`);
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.error || 'Failed to inspect SSL/TLS certificate.');
      }
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message || 'SSL inspection failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadJson = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssl-cert-${data.host}.json`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400">
            <Lock className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                SSL / TLS Certificate & Cipher Inspector
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Perform live TLS handshakes to extract certificate chains, expiration countdowns, SANs & cipher security ratings
            </p>
          </div>
        </div>
      </div>

      {/* Top Search Bar & Presets */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-3 items-center">
          <div className="relative flex-1 w-full">
            <Lock className="w-4 h-4 text-emerald-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={host}
              onChange={e => setHost(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
              placeholder="Enter domain or hostname (e.g. example.com or github.com)..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-emerald-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition-colors shadow-inner"
            />
          </div>
          <div className="w-24 flex-shrink-0">
            <input
              type="number"
              value={port}
              onChange={e => setPort(e.target.value)}
              placeholder="Port"
              className="w-full px-3 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-slate-200 text-center focus:outline-none focus:border-emerald-500"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={isLoading || !host.trim()}
            className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-emerald-500 text-slate-950 font-extrabold text-xs flex items-center justify-center gap-2 transition-all shadow-lg disabled:opacity-50"
          >
            {isLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {isLoading ? 'Inspecting TLS...' : 'Inspect SSL/TLS'}
          </button>
        </div>

        {/* Quick Presets */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => {
              setHost(val);
              handleScan(val, port);
            }}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-emerald-400" /> Presets:
          </span>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setHost(p.host);
                setPort(p.port.toString());
                handleScan(p.host, p.port.toString());
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-emerald-300 hover:text-emerald-200 transition-all"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2.5 shadow-lg">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State */}
      {!data && !isLoading && !error && (
        <div className="p-12 rounded-2xl bg-slate-900/40 border border-slate-800/60 text-center space-y-4 shadow-xl">
          <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 w-fit mx-auto">
            <Lock className="w-8 h-8" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-200 mb-1">Live SSL/TLS Certificate & Cipher Suite Inspector</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Performs live TLS handshakes to extract X.509 certificate chains, SANs, expiration countdowns, and cryptographic cipher strength ratings.
            </p>
          </div>
        </div>
      )}

      {/* Loaded Certificate Dashboard */}
      {data && (
        <div className="space-y-6 animate-in fade-in duration-300">

          {/* Data source notice when no live handshake was possible */}
          {data.source === 'certificate-transparency' && (
            <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-700/60 flex items-start gap-2 text-[11px] font-mono text-amber-200">
              <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
              <span>
                A live TLS handshake was not possible from this server, so these details come from the most recent certificate in public
                Certificate Transparency logs. It may not be the certificate currently served. Protocol, cipher, OCSP stapling, trust and
                the served chain could not be observed.
              </span>
            </div>
          )}

          {/* Trust failure notice */}
          {data.source === 'live-handshake' && data.isTrusted === false && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-700/60 flex items-start gap-2 text-[11px] font-mono text-rose-200">
              <XCircle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
              <span>
                Certificate is NOT trusted{data.hostnameMatches === false ? ` (does not match ${data.host})` : ''}
                {data.trustError ? `: ${data.trustError}` : ''}
              </span>
            </div>
          )}
          
          {/* Top Score & High-Level Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            
            {/* Grade Card */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex items-center gap-4">
              <div
                className={`w-16 h-16 rounded-2xl flex items-center justify-center font-mono font-extrabold text-2xl border shadow-inner ${
                  data.grade === 'A+' || data.grade === 'A'
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/60'
                    : data.grade === 'B'
                    ? 'bg-amber-950/80 text-amber-300 border-amber-500/60'
                    : 'bg-rose-950/80 text-rose-300 border-rose-500/60'
                }`}
              >
                {data.grade}
              </div>
              <div className="space-y-0.5">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">SECURITY GRADE</span>
                <p className="text-xs font-mono font-bold text-slate-200">{data.grade === 'A+' ? 'EXCELLENT' : data.grade === 'A' ? 'SECURE' : 'ACTION REQUIRED'}</p>
                <p className="text-[10px] font-mono text-slate-400 leading-tight">{data.gradeReason}</p>
              </div>
            </div>

            {/* Expiry Card */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">DAYS REMAINING</span>
                <Calendar className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <div className="text-xl font-mono font-bold text-slate-100 flex items-center gap-2">
                <span>{data.daysRemaining} Days</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                    data.daysRemaining > 30
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : data.daysRemaining > 7
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}
                >
                  {data.isExpired ? 'EXPIRED' : data.daysRemaining > 30 ? 'HEALTHY' : 'EXPIRING SOON'}
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 truncate">Exp: {data.validTo ? new Date(data.validTo).toLocaleDateString() : 'Unknown'}</p>
            </div>

            {/* Protocol Card */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">PROTOCOL & CIPHER</span>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              </div>
              <div className="text-base font-mono font-bold text-slate-100">{data.protocol ?? 'Not observed'}</div>
              <p className="text-[10px] font-mono text-emerald-300 truncate" title={data.cipherSuite?.name}>
                {data.cipherSuite?.name ?? 'Cipher unknown (no live handshake)'}
              </p>
              <div className="flex gap-1.5 pt-0.5">
                {data.cipherSuite?.isPfs && (
                  <span className="px-1.5 py-0.2 rounded text-[8px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-300 font-bold">
                    PFS Enabled
                  </span>
                )}
                {data.cipherSuite?.isAead && (
                  <span className="px-1.5 py-0.2 rounded text-[8px] font-mono bg-cyan-950 border border-cyan-800 text-cyan-300 font-bold">
                    AEAD
                  </span>
                )}
              </div>
            </div>

            {/* Public Key Card */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">PUBLIC KEY STRENGTH</span>
                <Key className="w-3.5 h-3.5 text-amber-400" />
              </div>
              <div className="text-base font-mono font-bold text-slate-100">
                {data.publicKey
                  ? `${data.publicKey.type}${data.publicKey.bits ? ` ${data.publicKey.bits}-bit` : ''}`
                  : 'Unknown'}
              </div>
              <p className="text-[10px] font-mono text-slate-400" title={data.serialNumber ?? undefined}>
                Serial:{' '}
                <span className="text-slate-200 font-bold">
                  {data.serialNumber
                    ? data.serialNumber.length > 14 ? `${data.serialNumber.slice(0, 14)}...` : data.serialNumber
                    : 'Unknown'}
                </span>
              </p>
              <div className="pt-0.5">
                <button
                  onClick={downloadJson}
                  className="px-2 py-1 rounded bg-slate-950 hover:bg-slate-800 border border-slate-700 text-[10px] font-mono text-cyan-300 flex items-center gap-1"
                >
                  <Download className="w-3 h-3" /> Download JSON
                </button>
              </div>
            </div>

          </div>

          {/* Deep Certificate Details Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Subject & Issuer Details */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200">
                <Globe2 className="w-4 h-4 text-emerald-400" />
                <span>Subject & Authority Identity</span>
              </div>

              <div className="space-y-3 text-xs font-mono">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 block uppercase">PRIMARY COMMON NAME (CN)</span>
                  <div className="text-slate-100 font-bold flex items-center justify-between">
                    <span>{data.subject.commonName}</span>
                    <button
                      onClick={() => copyToClipboard(data.subject.commonName, 'cn')}
                      className="text-slate-400 hover:text-emerald-400"
                    >
                      {copiedKey === 'cn' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  {data.subject.organization && (
                    <p className="text-[11px] text-slate-400">Org: <span className="text-slate-200 font-semibold">{data.subject.organization}</span></p>
                  )}
                  {data.subject.country && (
                    <p className="text-[11px] text-slate-400">Location: <span className="text-slate-200">{data.subject.locality || ''} {data.subject.state || ''} ({data.subject.country})</span></p>
                  )}
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 block uppercase">ISSUING CERTIFICATE AUTHORITY (CA)</span>
                  <div className="text-slate-100 font-bold flex items-center justify-between">
                    <span>{data.issuer.commonName}</span>
                    <button
                      onClick={() => copyToClipboard(data.issuer.commonName, 'issuer')}
                      className="text-slate-400 hover:text-emerald-400"
                    >
                      {copiedKey === 'issuer' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  {data.issuer.organization && (
                    <p className="text-[11px] text-slate-400">Org: <span className="text-slate-200 font-semibold">{data.issuer.organization}</span></p>
                  )}
                </div>

                {/* Fingerprints */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 block uppercase mb-0.5">SHA-256 FINGERPRINT</span>
                    <div className="flex items-center justify-between text-[11px] text-cyan-300 select-all">
                      <span className="truncate pr-2">{data.fingerprints.sha256 ?? 'Unknown'}</span>
                      <button
                        onClick={() => data.fingerprints.sha256 && copyToClipboard(data.fingerprints.sha256, 'sha256')}
                        className="text-slate-400 hover:text-cyan-400 flex-shrink-0"
                      >
                        {copiedKey === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Subject Alternative Names (SANs) & Chain */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>Subject Alternative Names ({data.sanList.length})</span>
                </div>
                <button
                  onClick={() => copyToClipboard(data.sanList.join(', '), 'sans')}
                  className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  {copiedKey === 'sans' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  Copy All
                </button>
              </div>

              {/* SANs badge cloud */}
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 max-h-40 overflow-y-auto flex flex-wrap gap-1.5">
                {data.sanList.map((san, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-700 text-[10px] font-mono text-slate-300 select-all hover:border-cyan-500 transition-colors"
                  >
                    {san}
                  </span>
                ))}
              </div>

              {/* Certificate Chain */}
              {data.certificateChain.length > 0 && (
              <div className="space-y-2 pt-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
                  TRUST PATH / CERTIFICATE CHAIN ({data.certificateChain.length} LEVELS)
                </span>
                <div className="space-y-1.5">
                  {data.certificateChain.map((cert, idx) => (
                    <div key={idx} className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2 truncate pr-2">
                        <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold flex-shrink-0">
                          {idx + 1}
                        </span>
                        <div className="truncate">
                          <span className="text-slate-200 font-bold block truncate">{cert.subject}</span>
                          <span className="text-[10px] text-slate-500 block truncate">Issued by: {cert.issuer}</span>
                        </div>
                      </div>
                      <span className="text-[10px] text-slate-400 flex-shrink-0">
                        {cert.validTo ? new Date(cert.validTo).toLocaleDateString() : ''}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              )}

            </div>

          </div>

        </div>
      )}
    </div>
  );
}
