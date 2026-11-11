'use client';

import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  RefreshCw,
  Copy,
  Check,
  Code2,
  Lock,
  Sparkles,
  Cookie,
  FileCode,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import { SecurityHeadersData } from '@/lib/types';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

const PRESETS = [
  { label: 'mozilla.org', url: 'https://www.mozilla.org' },
  { label: 'github.com', url: 'https://github.com' },
  { label: 'cloudflare.com', url: 'https://cloudflare.com' },
];

export function SecurityHeadersEvaluator() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState<SecurityHeadersData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [selectedSnippetTab, setSelectedSnippetTab] = useState<'nginx' | 'apache' | 'cloudflare' | 'nextjs'>('nginx');
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('headers');

  const handleScan = async (targetUrl = url) => {
    if (!targetUrl.trim()) return;
    setIsLoading(true);
    setError(null);

    try {
      let clean = targetUrl.trim();
      if (!/^https?:\/\//i.test(clean)) clean = 'https://' + clean;
      addEntry(clean);
      const res = await fetch(`/api/headers?url=${encodeURIComponent(clean)}`);
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.error || 'Failed to analyze security headers.');
      }
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Headers scan failed.');
    } finally {
      setIsLoading(false);
    }
  };

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
          <div className="p-3 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                HTTP Security Headers & CSP Evaluator
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Audit web server response headers, evaluate CSP directives, HSTS compliance, and clickjacking defenses
            </p>
          </div>
        </div>
      </div>

      {/* Top Search Bar & Presets */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-3 items-center">
          <div className="relative flex-1 w-full">
            <Lock className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
              placeholder="Enter target website URL (e.g. example.com or https://github.com)..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-cyan-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors shadow-inner"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={isLoading || !url.trim()}
            className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-extrabold text-xs flex items-center justify-center gap-2 transition-all shadow-lg disabled:opacity-50"
          >
            {isLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {isLoading ? 'Auditing Headers...' : 'Audit Security Headers'}
          </button>
        </div>

        {/* Quick Presets */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => {
              setUrl(val);
              handleScan(val);
            }}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-cyan-400" /> Presets:
          </span>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setUrl(p.url);
                handleScan(p.url);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-cyan-300 hover:text-cyan-200 transition-all"
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
          <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 w-fit mx-auto">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-200 mb-1">HTTP Security Headers & CSP Evaluator</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Performs real-time HTTP response analysis evaluating HSTS, Content-Security-Policy injection risks, Clickjacking defenses, CORS policies, and cookie flags.
            </p>
          </div>
        </div>
      )}

      {/* Loaded Dashboard */}
      {data && (
        <div className="space-y-6 animate-in fade-in duration-300">
          
          {/* Top Score Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            
            {/* Grade Card */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex items-center gap-4">
              <div
                className={`w-16 h-16 rounded-2xl flex items-center justify-center font-mono font-extrabold text-2xl border shadow-inner ${
                  data.grade === 'A+' || data.grade === 'A'
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/60'
                    : data.grade === 'B'
                    ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/60'
                    : data.grade === 'C'
                    ? 'bg-amber-950/80 text-amber-300 border-amber-500/60'
                    : 'bg-rose-950/80 text-rose-300 border-rose-500/60'
                }`}
              >
                {data.grade}
              </div>
              <div className="space-y-0.5">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">HARDENING GRADE</span>
                <p className="text-xs font-mono font-bold text-slate-200">
                  {data.score}/100 SCORE
                </p>
                <p className="text-[10px] font-mono text-slate-400">
                  Status: {data.statusCode} OK
                </p>
              </div>
            </div>

            {/* Passed Count */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">ENFORCED HEADERS</span>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              </div>
              <div className="text-xl font-mono font-bold text-emerald-400">
                {data.headersEvaluated.filter(h => h.status === 'PASS').length} Passed
              </div>
              <p className="text-[10px] font-mono text-slate-400">Robust browser hardening</p>
            </div>

            {/* Warnings Count */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">ROOM TO IMPROVE</span>
                <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
              </div>
              <div className="text-xl font-mono font-bold text-amber-400">
                {data.headersEvaluated.filter(h => h.status === 'WARN').length} Warnings
              </div>
              <p className="text-[10px] font-mono text-slate-400">Partial or sub-optimal rules</p>
            </div>

            {/* Missing/Failed Count */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">MISSING HEADERS</span>
                <XCircle className="w-3.5 h-3.5 text-rose-400" />
              </div>
              <div className="text-xl font-mono font-bold text-rose-400">
                {data.headersEvaluated.filter(h => h.status === 'FAIL').length} Missing
              </div>
              <p className="text-[10px] font-mono text-slate-400">Actionable vulnerabilities</p>
            </div>

          </div>

          {/* Detailed Evaluated Security Headers List */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-slate-200 tracking-normal flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" /> Security Headers Deep Audit ({data.headersEvaluated.length})
            </h3>

            <div className="space-y-2.5">
              {data.headersEvaluated.map((hdr, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-2xl border transition-all ${
                    hdr.status === 'PASS'
                      ? 'bg-emerald-950/20 border-emerald-800/40'
                      : hdr.status === 'WARN'
                      ? 'bg-amber-950/20 border-amber-800/40'
                      : hdr.status === 'FAIL'
                      ? 'bg-rose-950/20 border-rose-800/40'
                      : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between flex-wrap gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-xs text-slate-100">{hdr.name}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold ${
                          hdr.status === 'PASS'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                            : hdr.status === 'WARN'
                            ? 'bg-amber-950 text-amber-300 border border-amber-700'
                            : hdr.status === 'FAIL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-700'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {hdr.status} (+{hdr.scoreImpact} pts)
                      </span>
                    </div>

                    {hdr.value && (
                      <button
                        onClick={() => copyToClipboard(hdr.value || '', `hdr-${idx}`)}
                        className="text-[11px] font-mono text-slate-400 hover:text-cyan-300 flex items-center gap-1"
                      >
                        {copiedKey === `hdr-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        Copy Value
                      </button>
                    )}
                  </div>

                  <p className="text-xs font-mono text-slate-300 leading-relaxed mb-2">{hdr.summary}</p>

                  {hdr.value && (
                    <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 text-[11px] font-mono text-cyan-300 overflow-x-auto select-all">
                      {hdr.value}
                    </pre>
                  )}

                  {hdr.recommendation && (
                    <div className="mt-2 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-amber-300">
                      <span className="font-bold text-amber-400">Remediation: </span>
                      <code className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-200 border border-slate-800 select-all">
                        {hdr.recommendation}
                      </code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Cookies & Remediation Snippets Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Cookie Security Flags */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                  <Cookie className="w-4 h-4 text-amber-400" /> Cookie Security Attributes ({data.cookies.length})
                </h3>
              </div>

              {data.cookies.length === 0 ? (
                <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 text-center text-xs font-mono text-slate-400">
                  No Set-Cookie response headers observed on root path.
                </div>
              ) : (
                <div className="space-y-2">
                  {data.cookies.map((c, idx) => (
                    <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 text-xs font-mono">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-100 font-bold">{c.name}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            c.status === 'SECURE'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {c.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[10px]">
                        <span className={c.hasSecure ? 'text-emerald-400 font-bold' : 'text-rose-400'}>
                          Secure: {c.hasSecure ? '✓' : '✗'}
                        </span>
                        <span className="text-slate-600">|</span>
                        <span className={c.hasHttpOnly ? 'text-emerald-400 font-bold' : 'text-rose-400'}>
                          HttpOnly: {c.hasHttpOnly ? '✓' : '✗'}
                        </span>
                        <span className="text-slate-600">|</span>
                        <span className="text-slate-300">
                          SameSite: <strong className="text-cyan-300">{c.sameSite}</strong>
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Quick Remediation Code Generator */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" /> One-Click Remediation Snippets
                </h3>
                <button
                  onClick={() => copyToClipboard(data.remediationSnippets[selectedSnippetTab], 'snippet')}
                  className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  {copiedKey === 'snippet' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  Copy Configuration
                </button>
              </div>

              {/* Tabs */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-[11px] font-mono">
                {(['nginx', 'apache', 'cloudflare', 'nextjs'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setSelectedSnippetTab(tab)}
                    className={`flex-1 py-1.5 rounded-lg font-bold capitalize transition-all ${
                      selectedSnippetTab === tab
                        ? 'bg-violet-600/30 text-cyan-300 border border-cyan-500/40 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {/* Code Viewer */}
              <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-200 max-h-56 overflow-y-auto select-all">
                {data.remediationSnippets[selectedSnippetTab]}
              </pre>
            </div>

          </div>

        </div>
      )}
    </div>
  );
}
