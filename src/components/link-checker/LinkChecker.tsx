'use client';

import React, { useState } from 'react';
import {
  Link2,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Copy,
  Check,
  Download,
  Terminal,
  Sparkles,
  Layers,
  ChevronDown,
  ChevronUp,
  SlidersHorizontal,
  Info,
  Clock,
  Globe,
  Lock,
  Unlock,
  CornerDownRight,
  FileCode,
  FileSpreadsheet,
  Zap,
  Flame,
  Search,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import {
  SingleLinkCheckResult,
  LinkHopInfo,
  BatchLinkCheckResponse,
  BatchLinkItemResult,
} from '@/lib/types';
import { useToolHistory } from '@/lib/useToolHistory';
import { csvCell } from '@/lib/utils';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

type ActiveViewTab = 'single' | 'batch' | 'guide';

const PRESET_SAMPLES = [
  {
    name: 'Shortened Link (Redirect Tracer)',
    url: 'https://tinyurl.com/cybertools-demo',
    desc: 'Tests 301/302 shortener expansion & hops',
  },
  {
    name: 'HTTPS Auto-Upgrade (http://github.com)',
    url: 'http://github.com',
    desc: 'Inspects HTTP 301 redirect to secure HTTPS',
  },
  {
    name: 'Open-Redirect Query Vector',
    url: 'https://example.org/login?redirect=https://evil-phishing-portal.xyz/steal&token=secret_123',
    desc: 'Heuristic flags embedded external URLs & secrets',
  },
  {
    name: 'IDN / Punycode Homoglyph',
    url: 'https://xn--e1afmkfd.xn--p1ai',
    desc: 'Simulates Cyrillic lookalike domain spoofing',
  },
  {
    name: 'Direct Cloudflare Destination',
    url: 'https://www.cloudflare.com',
    desc: 'Clean corporate endpoint with strong HSTS/CSP',
  },
];

const USER_AGENTS = [
  {
    label: 'Chrome 124 (Desktop Windows)',
    value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberToolbox/2.0',
  },
  {
    label: 'Safari (iPhone iOS 17)',
    value: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  },
  {
    label: 'Googlebot Crawler',
    value: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  },
  {
    label: 'Python Requests / Security Bot',
    value: 'python-requests/2.31.0 CyberSec-Audit/2.0',
  },
  {
    label: 'cURL Command Line',
    value: 'curl/8.4.0',
  },
];

export function LinkChecker() {
  const [activeTab, setActiveTab] = useState<ActiveViewTab>('single');

  // Single URL state
  const [singleUrl, setSingleUrl] = useState('');
  const [loadingSingle, setLoadingSingle] = useState(false);
  const [singleResult, setSingleResult] = useState<SingleLinkCheckResult | null>(null);
  const [singleError, setSingleError] = useState<string | null>(null);
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [selectedUa, setSelectedUa] = useState(USER_AGENTS[0].value);
  const [maxHops, setMaxHops] = useState(10);
  const [expandedHops, setExpandedHops] = useState<Record<number, boolean>>({});
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('link_checker');

  // Batch URL state
  const [batchInput, setBatchInput] = useState('');
  const [loadingBatch, setLoadingBatch] = useState(false);
  const [batchResult, setBatchResult] = useState<BatchLinkCheckResponse | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchFilter, setBatchFilter] = useState<'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'error' | 'risk'>('all');
  const [batchSearchQuery, setBatchSearchQuery] = useState('');

  // Copy helper
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleHopDetails = (hopNum: number) => {
    setExpandedHops(prev => ({ ...prev, [hopNum]: !prev[hopNum] }));
  };

  const handleAnalyzeSingle = async (urlToTest?: string) => {
    const target = urlToTest || singleUrl;
    if (!target.trim()) return;
    addEntry(target.trim());
    if (urlToTest) setSingleUrl(urlToTest);

    setLoadingSingle(true);
    setSingleError(null);

    try {
      const res = await fetch('/api/link-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'single',
          url: target.trim(),
          maxHops,
          userAgent: selectedUa,
          timeoutMs: 8000,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to inspect URL');
      }

      setSingleResult(data);
      if (urlToTest) setSingleUrl(urlToTest);
    } catch (err: any) {
      setSingleError(err.message || 'An error occurred while connecting to the target.');
      setSingleResult(null);
    } finally {
      setLoadingSingle(false);
    }
  };

  // Run batch analysis
  const handleAnalyzeBatch = async () => {
    const urls = batchInput
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0 && !u.startsWith('#'));

    if (urls.length === 0) return;

    setLoadingBatch(true);
    setBatchError(null);

    try {
      const res = await fetch('/api/link-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'batch',
          urls,
          userAgent: selectedUa,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to run batch analysis');
      }

      setBatchResult(data);
    } catch (err: any) {
      setBatchError(err.message || 'An error occurred during batch URL checking.');
      setBatchResult(null);
    } finally {
      setLoadingBatch(false);
    }
  };

  const loadBatchSample = () => {
    const sample = [
      'https://github.com',
      'http://github.com',
      'https://tinyurl.com/cybertools-demo',
      'https://www.cloudflare.com',
      'https://httpbin.org/status/404',
      'https://httpbin.org/status/500',
      'https://example.com/auth?redirect=https://evil-phish.xyz',
    ].join('\n');
    setBatchInput(sample);
  };

  // Export reports
  const exportSingleJson = () => {
    if (!singleResult) return;
    const blob = new Blob([JSON.stringify(singleResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `link-analysis-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportSingleMarkdown = () => {
    if (!singleResult) return;
    const md = `# Link & Redirection Security Report
- **Target URL**: \`${singleResult.inputUrl}\`
- **Defanged URL**: \`${singleResult.urlBreakdown.defanged}\`
- **Final Destination**: \`${singleResult.finalUrl}\`
- **Final Status**: ${singleResult.finalStatusCode} (${singleResult.finalStatusText})
- **Risk Score**: ${singleResult.riskScore}/100 [${singleResult.riskLevel}]
- **Total Redirect Hops**: ${singleResult.hopCount}
- **Latency**: ${singleResult.totalDurationMs} ms
- **Scanned At**: ${singleResult.scanTimestamp}

## Redirection Chain
${singleResult.hops.map(h => `${h.hopNumber}. [${h.statusCode} ${h.statusText}] \`${h.url}\` (${h.durationMs}ms)`).join('\n')}

## Security Findings
${singleResult.findings.map(f => `- **[${f.severity}]** ${f.title}: ${f.description}`).join('\n')}
`;

    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `link-report-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportBatchCsv = () => {
    if (!batchResult) return;
    const headers = ['Input URL', 'Final URL', 'Status Code', 'Status Text', 'Hops', 'Latency (ms)', 'Risk Level', 'Has Redirect'];
    const rows = batchResult.results.map(r =>
      [
        r.inputUrl,
        r.finalUrl,
        r.statusCode,
        r.statusText,
        r.hopCount,
        r.durationMs,
        r.riskLevel,
        r.hasRedirect ? 'YES' : 'NO',
      ].map(csvCell)
    );
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `batch-links-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getStatusColor = (code: number) => {
    if (code >= 200 && code < 300) return 'text-emerald-400 bg-emerald-950/70 border-emerald-700/60';
    if (code >= 300 && code < 400) return 'text-amber-400 bg-amber-950/70 border-amber-700/60';
    if (code >= 400 && code < 500) return 'text-rose-400 bg-rose-950/70 border-rose-700/60';
    if (code >= 500) return 'text-red-400 bg-red-950/70 border-red-700/60';
    return 'text-slate-400 bg-slate-900 border-slate-700';
  };

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-red-950 text-red-300 border border-red-700 shadow-sm">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-orange-950 text-orange-300 border border-orange-700 shadow-sm">HIGH RISK</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-amber-950 text-amber-300 border border-amber-700">MEDIUM RISK</span>;
      case 'LOW':
        return <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-blue-950 text-blue-300 border border-blue-700">LOW RISK</span>;
      default:
        return <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-emerald-950 text-emerald-300 border border-emerald-700">SAFE / VERIFIED</span>;
    }
  };

  const filteredBatchResults = batchResult?.results.filter(item => {
    if (batchFilter === '2xx' && item.statusGroup !== '2xx') return false;
    if (batchFilter === '3xx' && item.statusGroup !== '3xx') return false;
    if (batchFilter === '4xx' && item.statusGroup !== '4xx') return false;
    if (batchFilter === '5xx' && item.statusGroup !== '5xx') return false;
    if (batchFilter === 'error' && item.statusGroup !== 'error') return false;
    if (batchFilter === 'risk' && !(item.riskLevel === 'HIGH' || item.riskLevel === 'CRITICAL')) return false;

    if (batchSearchQuery.trim()) {
      const q = batchSearchQuery.toLowerCase();
      return item.inputUrl.toLowerCase().includes(q) || item.finalUrl.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Module Header Card */}
      <div className="relative overflow-hidden rounded-2xl bg-slate-900/60 border border-slate-800 p-6 shadow-2xl backdrop-blur-xl">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="flex items-center gap-3.5">
            <div className="p-3 rounded-xl bg-sky-500/20 border border-sky-500/40 text-sky-300 shadow-inner">
              <Link2 className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-xl font-bold text-slate-100 tracking-tight">
                  Link & Redirection Security Checker
                </h1>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                Trace full URL redirection chains, unshorten hidden links, detect malicious IDN punycode, open-redirect parameters, protocol downgrades, and assess threat scoring in real time.
              </p>
            </div>
          </div>

          {/* Navigation View Switcher */}
          <div className="flex items-center bg-slate-950/80 p-1 rounded-xl border border-slate-800 self-start lg:self-auto shadow-inner">
            <button
              onClick={() => setActiveTab('single')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                activeTab === 'single'
                  ? 'bg-sky-500/20 text-sky-200 border border-sky-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Deep-Dive Hop Tracer</span>
            </button>
            <button
              onClick={() => setActiveTab('batch')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                activeTab === 'batch'
                  ? 'bg-sky-500/20 text-sky-200 border border-sky-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Batch Link Verifier</span>
            </button>
            <button
              onClick={() => setActiveTab('guide')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                activeTab === 'guide'
                  ? 'bg-sky-500/20 text-sky-200 border border-sky-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Info className="w-3.5 h-3.5" />
              <span>Threat Guide</span>
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. DEEP-DIVE SINGLE URL INSPECTOR TAB */}
      {/* ========================================================================= */}
      {activeTab === 'single' && (
        <div className="space-y-6">
          {/* URL Input Box & Controls */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl backdrop-blur-md">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleAnalyzeSingle();
              }}
              className="space-y-3"
            >
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Globe className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    value={singleUrl}
                    onChange={(e) => setSingleUrl(e.target.value)}
                    placeholder="Enter URL to inspect (e.g. https://tinyurl.com/xyz or https://example.com/login?redirect=...)"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all font-mono"
                  />
                </div>

                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
                    className={`px-3 py-2.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all ${
                      showAdvancedOptions
                        ? 'bg-slate-800 border-sky-500/50 text-sky-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                    }`}
                    title="Toggle Advanced Request Options"
                  >
                    <SlidersHorizontal className="w-3.5 h-3.5" />
                    <span>Options</span>
                  </button>

                  <button
                    type="submit"
                    disabled={loadingSingle || !singleUrl.trim()}
                    className="px-5 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white font-bold text-xs flex items-center gap-2 shadow-lg transition-all cursor-pointer"
                  >
                    {loadingSingle ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Tracing Hops...</span>
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3.5 h-3.5" />
                        <span>Inspect Link</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Advanced Config Panel */}
              {showAdvancedOptions && (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/90 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs animate-in fade-in duration-150">
                  <div>
                    <label className="block text-slate-400 font-mono mb-1 font-semibold">
                      Client User-Agent Simulation
                    </label>
                    <select
                      value={selectedUa}
                      onChange={(e) => setSelectedUa(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
                    >
                      {USER_AGENTS.map((ua, i) => (
                        <option key={i} value={ua.value}>
                          {ua.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <div className="flex items-center justify-between text-slate-400 font-mono mb-1 font-semibold">
                      <span>Max Redirection Hops</span>
                      <span className="text-sky-300 font-bold">{maxHops} Hops</span>
                    </div>
                    <input
                      type="range"
                      min="1"
                      max="15"
                      value={maxHops}
                      onChange={(e) => setMaxHops(parseInt(e.target.value, 10))}
                      className="w-full accent-sky-400 cursor-pointer"
                    />
                  </div>
                </div>
              )}

              {/* Preset Samples */}
              <div className="flex items-center gap-1.5 flex-wrap pt-1">
                <ToolHistoryDropdown
                  history={history}
                  onSelect={(val) => {
                    setSingleUrl(val);
                    handleAnalyzeSingle(val);
                  }}
                  onRemove={removeEntry}
                  onClear={clearHistory}
                />
                <span className="text-[11px] font-mono text-slate-400 mr-1 flex items-center gap-1">
                  <Terminal className="w-3 h-3 text-sky-400" /> Presets:
                </span>
                {PRESET_SAMPLES.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleAnalyzeSingle(preset.url)}
                    className="px-2.5 py-1 rounded-lg bg-slate-950/80 hover:bg-slate-800 border border-slate-800 hover:border-sky-500/40 text-[11px] text-slate-300 hover:text-sky-200 transition-all font-mono"
                    title={preset.desc}
                  >
                    {preset.name}
                  </button>
                ))}
              </div>
            </form>
          </div>

          {/* Error Message */}
          {singleError && (
            <div className="p-4 rounded-xl bg-red-950/60 border border-red-700/60 text-red-200 text-xs flex items-start gap-3 animate-in fade-in">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-bold text-red-100">Analysis Failed</p>
                <p className="mt-0.5 text-red-300 font-mono">{singleError}</p>
              </div>
            </div>
          )}

          {/* Single Inspection Results View */}
          {singleResult && (
            <div className="space-y-6 animate-in fade-in duration-200">
              {/* Verdict Hero Banner */}
              <div className="relative overflow-hidden rounded-2xl bg-slate-900/60 border border-slate-800 p-6 shadow-2xl">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  {/* Left: Final Destination & Summary */}
                  <div className="space-y-3 flex-1 min-w-0">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      {getRiskBadge(singleResult.riskLevel)}
                      <span className="text-xs font-mono text-slate-400">
                        Total Latency: <strong className="text-slate-200">{singleResult.totalDurationMs} ms</strong>
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Hops: <strong className="text-slate-200">{singleResult.hopCount}</strong>
                      </span>
                      {singleResult.hasProtocolDowngrade && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700">
                          HTTPS ➔ HTTP DOWNGRADE
                        </span>
                      )}
                      {singleResult.hasRedirectLoop && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950 text-red-300 border border-red-700">
                          REDIRECT LOOP
                        </span>
                      )}
                    </div>

                    <div>
                      <div className="text-[11px] uppercase text-slate-400 tracking-wider">
                        Terminal Destination
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-base sm:text-lg font-bold font-mono text-slate-100 break-all">
                          {singleResult.finalUrl}
                        </span>
                        <button
                          onClick={() => copyToClipboard(singleResult.finalUrl, 'final-url')}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors flex-shrink-0"
                          title="Copy Final Destination"
                        >
                          {copiedKey === 'final-url' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                      <span>Initial Entry:</span>
                      <span className="text-slate-300 truncate max-w-md">{singleResult.inputUrl}</span>
                    </div>
                  </div>

                  {/* Right: Risk Score Radial / Meter */}
                  <div className="flex items-center gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800/80 flex-shrink-0">
                    <div className="text-center">
                      <div className="text-[10px] uppercase text-slate-400 tracking-wider">Risk Score</div>
                      <div className={`text-3xl font-extrabold font-mono mt-1 ${
                        singleResult.riskScore >= 70 ? 'text-red-400' :
                        singleResult.riskScore >= 40 ? 'text-amber-400' :
                        singleResult.riskScore >= 15 ? 'text-blue-400' : 'text-emerald-400'
                      }`}>
                        {singleResult.riskScore}
                        <span className="text-xs text-slate-500">/100</span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        {singleResult.riskScore >= 70 ? 'High Threat Potential' :
                         singleResult.riskScore >= 40 ? 'Moderate Anomaly' :
                         singleResult.riskScore >= 15 ? 'Low Warning' : 'Clean / Benign'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Action Bar */}
                <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between gap-3 flex-wrap text-xs">
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={() => copyToClipboard(singleResult.urlBreakdown.defanged, 'defanged')}
                      className="px-3 py-1.5 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-700/70 text-slate-200 flex items-center gap-1.5 transition-all font-mono text-[11px]"
                    >
                      {copiedKey === 'defanged' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy Defanged IOC</span>
                    </button>

                    <button
                      onClick={() => copyToClipboard(singleResult.hops.map(h => `${h.hopNumber}. [${h.statusCode}] ${h.url}`).join('\n'), 'hops-chain')}
                      className="px-3 py-1.5 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-700/70 text-slate-200 flex items-center gap-1.5 transition-all font-mono text-[11px]"
                    >
                      {copiedKey === 'hops-chain' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy Full Chain</span>
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={exportSingleMarkdown}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition-all font-semibold"
                    >
                      <FileCode className="w-3.5 h-3.5 text-sky-400" />
                      <span>Export MD</span>
                    </button>

                    <button
                      onClick={exportSingleJson}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition-all font-semibold"
                    >
                      <Download className="w-3.5 h-3.5 text-sky-400" />
                      <span>Export JSON</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Redirection Chain Visualizer */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <CornerDownRight className="w-4 h-4 text-sky-400" />
                    <h2 className="text-sm font-bold text-slate-200">
                      Sequential Redirection Chain ({singleResult.hops.length} {singleResult.hops.length === 1 ? 'Step' : 'Hops'})
                    </h2>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    {singleResult.isRedirected ? 'Multi-Hop Redirect Path' : 'Direct Single Hop'}
                  </span>
                </div>

                <div className="space-y-3">
                  {singleResult.hops.map((hop, index) => {
                    const isExpanded = !!expandedHops[hop.hopNumber];
                    const isLast = index === singleResult.hops.length - 1;

                    return (
                      <div
                        key={hop.hopNumber}
                        className={`rounded-xl border p-4 transition-all ${
                          isLast
                            ? 'bg-slate-950/90 border-sky-500/40 shadow-md'
                            : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                          <div className="flex items-start sm:items-center gap-3">
                            <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 text-slate-300 font-mono font-bold text-xs flex items-center justify-center flex-shrink-0 mt-0.5 sm:mt-0">
                              {hop.hopNumber}
                            </div>

                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusColor(hop.statusCode)}`}>
                                  {hop.statusCode} {hop.statusText}
                                </span>
                                <span className="text-xs font-mono font-bold text-slate-100 break-all">
                                  {hop.url}
                                </span>
                              </div>

                              {hop.location && (
                                <div className="flex items-center gap-1.5 text-[11px] font-mono text-amber-300/90 pl-1">
                                  <ArrowRight className="w-3 h-3 text-amber-400 flex-shrink-0" />
                                  <span>Redirects to: <strong className="text-amber-200 break-all">{hop.location}</strong></span>
                                </div>
                              )}
                            </div>
                          </div>

                          <div className="flex items-center gap-2 self-end sm:self-center flex-shrink-0 text-xs font-mono">
                            <span className="text-slate-400 flex items-center gap-1">
                              <Clock className="w-3 h-3 text-slate-500" />
                              {hop.durationMs}ms
                            </span>

                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              hop.isTls ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                            }`}>
                              {hop.protocol}
                            </span>

                            <button
                              onClick={() => toggleHopDetails(hop.hopNumber)}
                              className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
                              title="Toggle Header Inspector"
                            >
                              {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </div>

                        {/* Collapsible Headers Inspector */}
                        {isExpanded && (
                          <div className="mt-3 pt-3 border-t border-slate-800/80 animate-in fade-in duration-150">
                            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                              Response Headers ({Object.keys(hop.headers).length})
                            </div>
                            <div className="bg-slate-900/90 rounded-lg p-2.5 max-h-48 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1">
                              {Object.entries(hop.headers).map(([k, v]) => (
                                <div key={k} className="flex gap-2">
                                  <span className="text-sky-400 flex-shrink-0">{k}:</span>
                                  <span className="text-slate-300 break-all">{v}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Security Findings & Heuristics Breakdown */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Findings Card */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-sky-400" />
                      <h2 className="text-sm font-bold text-slate-200">
                        Threat & Security Heuristic Indicators ({singleResult.findings.length})
                      </h2>
                    </div>
                  </div>

                  {singleResult.findings.length === 0 ? (
                    <div className="p-6 rounded-xl bg-slate-950/60 border border-slate-800 text-center text-xs text-slate-400">
                      <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                      No risk indicators or anomalies detected in the URL structure.
                    </div>
                  ) : (
                    <div className="space-y-2.5 max-h-96 overflow-y-auto pr-1">
                      {singleResult.findings.map(finding => (
                        <div
                          key={finding.id}
                          className={`p-3.5 rounded-xl border text-xs space-y-1 ${
                            finding.severity === 'CRITICAL'
                              ? 'bg-red-950/30 border-red-800/60 text-red-200'
                              : finding.severity === 'HIGH'
                              ? 'bg-orange-950/30 border-orange-800/60 text-orange-200'
                              : finding.severity === 'MEDIUM'
                              ? 'bg-amber-950/30 border-amber-800/60 text-amber-200'
                              : finding.severity === 'SAFE'
                              ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
                              : 'bg-slate-950/50 border-slate-800 text-slate-300'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-bold">{finding.title}</span>
                            <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                              finding.severity === 'CRITICAL' ? 'bg-red-900 text-red-200' :
                              finding.severity === 'HIGH' ? 'bg-orange-900 text-orange-200' :
                              finding.severity === 'MEDIUM' ? 'bg-amber-900 text-amber-200' :
                              finding.severity === 'SAFE' ? 'bg-emerald-900 text-emerald-200' : 'bg-slate-800 text-slate-400'
                            }`}>
                              {finding.severity}
                            </span>
                          </div>
                          <p className="text-[11px] opacity-90">{finding.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* URL Decomposition & Query Parameters Card */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
                  <div className="flex items-center gap-2">
                    <FileSpreadsheet className="w-4 h-4 text-sky-400" />
                    <h2 className="text-sm font-bold text-slate-200">
                      URL Structural Decomposition
                    </h2>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">Protocol</div>
                      <div className="text-slate-200 font-bold mt-0.5">{singleResult.urlBreakdown.protocol}</div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">Port</div>
                      <div className="text-slate-200 font-bold mt-0.5">{singleResult.urlBreakdown.port}</div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">TLD</div>
                      <div className="text-sky-300 font-bold mt-0.5">.{singleResult.urlBreakdown.tld || 'none'}</div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 col-span-2">
                      <div className="text-[10px] text-slate-500 uppercase">Hostname / Domain</div>
                      <div className="text-slate-200 font-bold mt-0.5 truncate">{singleResult.urlBreakdown.hostname}</div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">IDN / Punycode</div>
                      <div className={`font-bold mt-0.5 ${singleResult.urlBreakdown.isPunycode ? 'text-rose-400' : 'text-slate-400'}`}>
                        {singleResult.urlBreakdown.isPunycode ? 'YES (Spoof)' : 'NO'}
                      </div>
                    </div>
                  </div>

                  {/* Query Parameters Table */}
                  <div>
                    <div className="text-[11px] uppercase text-slate-400 tracking-wider mb-2 font-bold">
                      Parsed Query Parameters ({singleResult.urlBreakdown.queryParams.length})
                    </div>
                    {singleResult.urlBreakdown.queryParams.length === 0 ? (
                      <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800/80 text-center text-xs text-slate-500 font-mono">
                        No query parameters attached to URL.
                      </div>
                    ) : (
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {singleResult.urlBreakdown.queryParams.map((param, i) => (
                          <div
                            key={i}
                            className={`p-2 rounded-lg border text-xs font-mono ${
                              param.isSuspicious
                                ? 'bg-amber-950/30 border-amber-800/60 text-amber-200'
                                : 'bg-slate-950/60 border-slate-800 text-slate-300'
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-sky-400 font-bold">{param.key}</span>
                              {param.isSuspicious && (
                                <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-700 font-bold">
                                  SUSPICIOUS
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-300 break-all mt-0.5">{param.value}</div>
                            {param.reason && (
                              <div className="text-[10px] text-amber-400 mt-0.5">{param.reason}</div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. BATCH MULTI-LINK VERIFIER TAB */}
      {/* ========================================================================= */}
      {activeTab === 'batch' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-bold text-slate-200">
                  Bulk URL Status & Redirection Verifier
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Paste a list of links (one per line, up to 25 URLs) to verify status codes, hops, and risk ratings concurrently.
                </p>
              </div>
              <button
                type="button"
                onClick={loadBatchSample}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono flex items-center gap-1.5 transition-colors"
              >
                <Terminal className="w-3.5 h-3.5 text-sky-400" />
                <span>Load Sample Batch</span>
              </button>
            </div>

            <textarea
              rows={6}
              value={batchInput}
              onChange={(e) => setBatchInput(e.target.value)}
              placeholder="https://example.com&#10;https://tinyurl.com/xyz&#10;http://insecure-domain.org&#10;https://github.com"
              className="w-full p-3.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 font-mono"
            />

            <div className="flex items-center justify-between mt-3">
              <span className="text-xs font-mono text-slate-500">
                {batchInput.split('\n').filter(u => u.trim()).length} URLs queued
              </span>

              <button
                onClick={handleAnalyzeBatch}
                disabled={loadingBatch || !batchInput.trim()}
                className="px-5 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white font-bold text-xs flex items-center gap-2 shadow-lg transition-all cursor-pointer"
              >
                {loadingBatch ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Scanning Batch...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>Run Batch Verification</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Batch Error */}
          {batchError && (
            <div className="p-4 rounded-xl bg-red-950/60 border border-red-700/60 text-red-200 text-xs flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-bold text-red-100">Batch Error</p>
                <p className="mt-0.5 text-red-300 font-mono">{batchError}</p>
              </div>
            </div>
          )}

          {/* Batch Results View */}
          {batchResult && (
            <div className="space-y-5 animate-in fade-in duration-200">
              {/* Summary Badges Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 text-center">
                  <div className="text-[10px] uppercase text-slate-400">Total Scanned</div>
                  <div className="text-xl font-bold font-mono text-slate-100 mt-0.5">{batchResult.total}</div>
                </div>
                <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-center">
                  <div className="text-[10px] uppercase text-emerald-400">2xx Success</div>
                  <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{batchResult.summary.successCount}</div>
                </div>
                <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-800/60 text-center">
                  <div className="text-[10px] uppercase text-amber-400">3xx Redirects</div>
                  <div className="text-xl font-bold font-mono text-amber-300 mt-0.5">{batchResult.summary.redirectCount}</div>
                </div>
                <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-center">
                  <div className="text-[10px] uppercase text-rose-400">4xx Client Err</div>
                  <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{batchResult.summary.clientErrorCount}</div>
                </div>
                <div className="p-3 rounded-xl bg-red-950/40 border border-red-800/60 text-center">
                  <div className="text-[10px] uppercase text-red-400">5xx Server Err</div>
                  <div className="text-xl font-bold font-mono text-red-300 mt-0.5">{batchResult.summary.serverErrorCount}</div>
                </div>
                <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-center">
                  <div className="text-[10px] uppercase text-rose-400">High / Critical</div>
                  <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{batchResult.summary.highRiskCount}</div>
                </div>
              </div>

              {/* Table Controls & Filter */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  {/* Search filter */}
                  <div className="relative flex-1 max-w-xs">
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Filter by domain or path..."
                      value={batchSearchQuery}
                      onChange={(e) => setBatchSearchQuery(e.target.value)}
                      className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
                    />
                  </div>

                  {/* Filter Pills */}
                  <div className="flex items-center gap-1.5 flex-wrap text-xs font-mono">
                    {(['all', '2xx', '3xx', '4xx', '5xx', 'error', 'risk'] as const).map(tab => (
                      <button
                        key={tab}
                        onClick={() => setBatchFilter(tab)}
                        className={`px-2.5 py-1 rounded-lg transition-all font-semibold ${
                          batchFilter === tab
                            ? 'bg-sky-500/20 text-sky-200 border border-sky-500/40'
                            : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        {tab.toUpperCase()}
                      </button>
                    ))}

                    <button
                      onClick={exportBatchCsv}
                      className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1 transition-colors ml-auto font-sans"
                    >
                      <Download className="w-3 h-3 text-sky-400" />
                      <span>Export CSV</span>
                    </button>
                  </div>
                </div>

                {/* Table */}
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Input Target</th>
                        <th className="py-2.5 px-3">Final Destination</th>
                        <th className="py-2.5 px-3 text-center">Hops</th>
                        <th className="py-2.5 px-3 text-right">Latency</th>
                        <th className="py-2.5 px-3 text-center">Risk</th>
                        <th className="py-2.5 px-3 text-center">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850 font-mono">
                      {filteredBatchResults && filteredBatchResults.length > 0 ? (
                        filteredBatchResults.map((item) => (
                          <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusColor(item.statusCode)}`}>
                                {item.statusCode ? item.statusCode : 'ERR'}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={item.inputUrl}>
                              {item.inputUrl}
                            </td>
                            <td className="py-2.5 px-3 text-slate-200 max-w-xs truncate" title={item.finalUrl}>
                              <span className="flex items-center gap-1">
                                {item.hasRedirect && <ArrowRight className="w-3 h-3 text-amber-400 flex-shrink-0" />}
                                {item.finalUrl}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-center text-slate-400">
                              {item.hopCount}
                            </td>
                            <td className="py-2.5 px-3 text-right text-slate-400">
                              {item.durationMs}ms
                            </td>
                            <td className="py-2.5 px-3 text-center whitespace-nowrap">
                              {getRiskBadge(item.riskLevel)}
                            </td>
                            <td className="py-2.5 px-3 text-center">
                              <button
                                onClick={() => {
                                  setActiveTab('single');
                                  handleAnalyzeSingle(item.inputUrl);
                                }}
                                className="p-1 rounded bg-slate-800 hover:bg-sky-500/20 text-slate-400 hover:text-sky-300 transition-colors"
                                title="Inspect Deep-Dive Hops"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                            No links matched the selected filter.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. THREAT GUIDE & CHEATSHEET TAB */}
      {/* ========================================================================= */}
      {activeTab === 'guide' && (
        <div className="space-y-6 animate-in fade-in duration-150">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Guide Card 1: HTTP Redirection Mechanics */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
              <div className="flex items-center gap-2 text-sky-400">
                <Layers className="w-4 h-4" />
                <h3 className="text-sm font-bold text-slate-100">
                  HTTP Redirection Status Codes
                </h3>
              </div>
              <div className="space-y-2 text-xs text-slate-300">
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <div className="font-bold text-amber-300 font-mono">301 Moved Permanently</div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Permanent redirection cached aggressively by browsers and CDNs. Used for canonical domains and HTTP-to-HTTPS upgrades.
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <div className="font-bold text-amber-300 font-mono">302 Found (Temporary Redirect)</div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Traditional temporary redirect. Modern shorteners (bit.ly, t.co) use 301/302 to forward traffic and collect click analytics.
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <div className="font-bold text-amber-300 font-mono">307 Temporary / 308 Permanent</div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Strict modern redirects that preserve the original HTTP method (e.g. POST payload cannot be rewritten as GET).
                  </p>
                </div>
              </div>
            </div>

            {/* Guide Card 2: Common URL Exploits & Phishing Tactics */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
              <div className="flex items-center gap-2 text-rose-400">
                <Flame className="w-4 h-4" />
                <h3 className="text-sm font-bold text-slate-100">
                  Phishing & Malicious URL Vector Cheatsheet
                </h3>
              </div>
              <div className="space-y-2 text-xs text-slate-300">
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <div className="font-bold text-rose-300 font-mono">IDN Homoglyph Attack (Punycode)</div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Attackers register domains with lookalike Cyrillic or Greek characters (e.g., <code className="text-sky-300">xn--...</code>) that render visually identical to trusted brands like <code className="text-sky-300">apple.com</code>.
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <div className="font-bold text-amber-300 font-mono">Open-Redirect Vulnerabilities</div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Vulnerable legitimate portals with parameters like <code className="text-sky-300">?next=https://evil.com</code> allow attackers to craft links starting with trusted domains that redirect to credentials harvesters.
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <div className="font-bold text-orange-300 font-mono">Traffic Distribution Systems (TDS)</div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Multi-hop redirect chains that profile user-agents, IP geolocations, and sandboxes before serving polymorphic payload or malware.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
