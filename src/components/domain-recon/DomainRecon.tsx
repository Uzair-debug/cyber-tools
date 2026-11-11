'use client';

import React, { useState, useMemo } from 'react';
import {
  Globe2,
  Search,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Server,
  FileCheck,
  Copy,
  Check,
  RefreshCw,
  Download,
  FileText,
  Table,
  Key,
  Lock,
  Layers,
  Cpu,
  Mail,
  Building,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { DkimSelectorResult, DnsErrorResponse, DnsRecordResult, DomainReconData, PolicyEvaluation, SubdomainResult, WhoisData } from '@/lib/types';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { useToolHistory } from '@/lib/useToolHistory';
import { csvCell } from '@/lib/utils';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

function formatDate(dateStr?: string): string {
  if (!dateStr) return 'Not Disclosed';
  try {
    const d = new Date(dateStr);
    if (!isNaN(d.getTime())) {
      return d.toISOString().split('T')[0];
    }
  } catch {
    // fallback
  }
  return dateStr.slice(0, 10);
}

function formatCountry(codeOrName?: string): string {
  if (!codeOrName) return 'N/A';
  const c = codeOrName.trim().toUpperCase();
  const countryMap: Record<string, string> = {
    ZA: 'South Africa (ZA)',
    US: 'United States (US)',
    GB: 'United Kingdom (GB)',
    UK: 'United Kingdom (UK)',
    DE: 'Germany (DE)',
    FR: 'France (FR)',
    CA: 'Canada (CA)',
    AU: 'Australia (AU)',
    NL: 'Netherlands (NL)',
    IE: 'Ireland (IE)',
    IN: 'India (IN)',
    JP: 'Japan (JP)',
    BR: 'Brazil (BR)',
    SG: 'Singapore (SG)',
  };
  return countryMap[c] || codeOrName;
}

function getTxtRecordPurpose(val: string): string {
  const lower = val.toLowerCase();
  if (lower.startsWith('v=spf1')) return 'SPF Mail Sender Policy';
  if (lower.startsWith('v=dmarc1')) return 'DMARC Email Authentication';
  if (lower.includes('google-site-verification')) return 'Google Domain Verification';
  if (lower.includes('ms=ms') || lower.includes('microsoft')) return 'Microsoft 365 Verification';
  if (lower.includes('apple-domain-verification')) return 'Apple Domain Verification';
  if (lower.includes('atlassian-domain-verification')) return 'Atlassian Verification';
  if (lower.includes('facebook-domain-verification')) return 'Meta / Facebook Verification';
  if (lower.includes('docusign')) return 'DocuSign Domain Verification';
  if (lower.includes('adobe-idp-site-verification')) return 'Adobe Identity Verification';
  if (lower.includes('cisco-ci-domain-verification')) return 'Cisco Webex Verification';
  if (lower.includes('zoho-verification')) return 'Zoho Domain Verification';
  if (lower.startsWith('v=stsv1')) return 'MTA-STS Security Policy';
  if (lower.startsWith('v=bimi1')) return 'BIMI Brand Avatar Assertion';
  return 'Domain Policy / Verification';
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function DomainRecon() {
  const [domain, setDomain] = useState('');
  const [customDkimSelector, setCustomDkimSelector] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isDkimSearching, setIsDkimSearching] = useState(false);
  const [data, setData] = useState<DomainReconData | null>(null);
  const [whoisData, setWhoisData] = useState<{ whois: WhoisData; subdomains: SubdomainResult[] } | null>(null);
  const [error, setError] = useState<DnsErrorResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'records' | 'mail_security' | 'whois'>('records');
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('domain');

  const handleLookup = async (targetDomain = domain, dkimSelector = customDkimSelector) => {
    if (!targetDomain.trim()) return;
    setIsLoading(true);
    setError(null);

    try {
      const clean = targetDomain
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/:\d+$/, '');
      if (clean) addEntry(clean);
      const dkimParam = dkimSelector.trim() ? `&dkimSelector=${encodeURIComponent(dkimSelector.trim())}` : '';
      
      const [dnsRes, whoisRes] = await Promise.all([
        fetch(`/api/dns?domain=${encodeURIComponent(clean)}${dkimParam}`),
        fetch(`/api/whois?domain=${encodeURIComponent(clean)}`),
      ]);

      if (!dnsRes.ok) {
        let errJson: any = null;
        try {
          errJson = await dnsRes.json();
        } catch {
          // Non-JSON error response
        }

        if (errJson && errJson.error) {
          setError(errJson as DnsErrorResponse);
        } else {
          setError({
            error: `DNS Query Failed (HTTP ${dnsRes.status})`,
            code: dnsRes.status === 404 ? 'NXDOMAIN' : dnsRes.status === 504 ? 'DNS_TIMEOUT' : 'RESOLVER_ERROR',
            domain: clean,
            details: dnsRes.statusText || 'The DNS resolver failed to complete the lookup.',
            suggestion: 'Verify domain name spelling or retry in a few moments.',
          });
        }
        setData(null);
        return;
      }

      const dnsJson = await dnsRes.json();
      setData(dnsJson);

      if (whoisRes.ok) {
        const whoisJson = await whoisRes.json();
        setWhoisData(whoisJson);
      }
    } catch (err: any) {
      setError({
        error: 'Network Communication Error',
        code: 'NETWORK_ERROR',
        domain: targetDomain,
        details: err.message || 'Unable to communicate with the DNS recon API service.',
        suggestion: 'Ensure your internet connection is active and the local server is reachable.',
      });
      setData(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCustomDkimLookup = async () => {
    if (!customDkimSelector.trim() || !domain.trim()) return;
    setIsDkimSearching(true);
    await handleLookup(domain, customDkimSelector);
    setIsDkimSearching(false);
  };

  const copyToClipboard = (text: string, identifier?: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(identifier || text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Export functions
  const downloadHtmlReport = () => {
    if (!data) return;
    // DNS values (TXT records especially) are attacker-controlled, so everything is escaped
    const esc = escapeHtml;
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Security Dossier - ${esc(data.domain)}</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
    h1, h2 { color: #38bdf8; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { border: 1px solid #334155; padding: 8px 12px; text-align: left; }
    th { background: #1e293b; color: #94a3b8; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; background: #0369a1; }
  </style>
</head>
<body>
  <h1>Security &amp; Infrastructure Dossier: ${esc(data.domain)}</h1>
  <p><strong>Queried At:</strong> ${new Date().toUTCString()}</p>
  <p><strong>Primary IP:</strong> ${esc(data.resolvedIp || 'N/A')}</p>
  <p><strong>Hosting Organization:</strong> ${esc(data.hosting?.webHost.company || 'N/A')}</p>
  <h2>DNS Infrastructure Records</h2>
  <table>
    <tr><th>Type</th><th>Destination / Value</th><th>Resolved IP</th><th>TTL</th><th>Org / Service Provider</th></tr>
    ${Object.entries(data.records).flatMap(([type, rec]) => 
      rec.records.map(r => `<tr><td><span class="badge">${esc(type)}</span></td><td>${esc(r.value)}</td><td>${esc(r.resolvedIp || '')}</td><td>${r.ttl !== undefined ? `${r.ttl}s` : 'unknown'}</td><td>${esc(r.orgProvider || '')}</td></tr>`)
    ).join('')}
  </table>
</body>
</html>`;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-report-${data.domain}.html`;
    a.click();
  };

  const downloadCsv = () => {
    if (!data) return;
    let csv = 'Record Type,Destination / Value,Resolved IP,TTL,Org / Service Provider\n';
    Object.entries(data.records).forEach(([type, rec]) => {
      rec.records.forEach(r => {
        csv += [type, r.value, r.resolvedIp, r.ttl !== undefined ? `${r.ttl}s` : 'unknown', r.orgProvider].map(csvCell).join(',') + '\n';
      });
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-records-${data.domain}.csv`;
    a.click();
  };

  const copyMarkdown = () => {
    if (!data) return;
    let md = `# Security Dossier: ${data.domain}\n\n`;
    md += `**Primary IP:** ${data.resolvedIp || 'N/A'}\n`;
    md += `**Web Hosting:** ${data.hosting?.webHost.company || 'N/A'}\n`;
    md += `**Mail Provider:** ${data.hosting?.mailHost.provider || 'N/A'}\n\n`;
    md += `| Type | Value | Resolved IP | TTL | Provider |\n|---|---|---|---|---|\n`;
    Object.entries(data.records).forEach(([type, rec]) => {
      rec.records.forEach(r => {
        md += `| ${type} | \`${r.value}\` | ${r.resolvedIp || ''} | ${r.ttl !== undefined ? `${r.ttl}s` : 'unknown'} | ${r.orgProvider || ''} |\n`;
      });
    });
    copyToClipboard(md, 'markdown-report');
  };

  const aRecords = data?.records['A']?.records || [];
  const nsRecords = data?.records['NS']?.records || [];
  const mxRecords = data?.records['MX']?.records || [];
  const txtRecords = data?.records['TXT']?.records || [];

  // Dynamic Cyber Security Posture Meter (0 - 100)
  const securityPosture = useMemo(() => {
    if (!data) {
      return {
        score: 0,
        grade: 'UNKNOWN',
        label: 'NO DATA',
        stroke1: '#64748b',
        stroke2: '#475569',
        textClass: 'text-slate-400',
        badgeClass: 'bg-slate-800 text-slate-300 border-slate-700',
        icon: ShieldAlert,
      };
    }

    let score = 0;

    // SPF Evaluation (up to 25 pts)
    const spfStatus = data.policies?.spf?.status;
    if (spfStatus === 'valid') score += 25;
    else if (spfStatus === 'warning') score += 15;

    // DMARC Evaluation (up to 30 pts)
    const dmarcStatus = data.policies?.dmarc?.status;
    if (dmarcStatus === 'valid') {
      const p = data.policies?.dmarc?.parsedTags?.['p']?.toLowerCase();
      if (p === 'reject') score += 30;
      else if (p === 'quarantine') score += 25;
      else score += 15;
    } else if (dmarcStatus === 'warning') {
      score += 10;
    }

    // DNSSEC (up to 15 pts)
    const dnssecActive = data.dnssec?.enabled || whoisData?.whois?.dnssec;
    if (dnssecActive) score += 15;

    // Nameserver Redundancy (up to 15 pts)
    const nsCount = data.records?.['NS']?.records?.length || 0;
    if (nsCount >= 4) score += 15;
    else if (nsCount >= 2) score += 10;
    else if (nsCount === 1) score += 5;

    // MX Routing & MTA-STS (up to 15 pts)
    const hasMx = (data.records?.['MX']?.records?.length || 0) > 0;
    if (hasMx) score += 10;
    if (data.policies?.mtaSts?.status === 'valid') score += 5;

    if (score >= 80) {
      return {
        score,
        grade: 'OPTIMAL POSTURE',
        label: 'SECURE',
        stroke1: '#10b981',
        stroke2: '#06b6d4',
        textClass: 'text-emerald-400',
        badgeClass: 'bg-emerald-950/80 border-emerald-500/40 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.25)]',
        icon: ShieldCheck,
      };
    } else if (score >= 60) {
      return {
        score,
        grade: 'ELEVATED POSTURE',
        label: 'MODERATE',
        stroke1: '#06b6d4',
        stroke2: '#3b82f6',
        textClass: 'text-cyan-400',
        badgeClass: 'bg-cyan-950/80 border-cyan-500/40 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.25)]',
        icon: ShieldCheck,
      };
    } else if (score >= 40) {
      return {
        score,
        grade: 'NEEDS HARDENING',
        label: 'ATTENTION',
        stroke1: '#f59e0b',
        stroke2: '#ea580c',
        textClass: 'text-amber-400',
        badgeClass: 'bg-amber-950/80 border-amber-500/40 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.25)]',
        icon: AlertTriangle,
      };
    } else {
      return {
        score,
        grade: 'CRITICAL EXPOSURE',
        label: 'AT RISK',
        stroke1: '#f43f5e',
        stroke2: '#e11d48',
        textClass: 'text-rose-400',
        badgeClass: 'bg-rose-950/80 border-rose-500/40 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.25)]',
        icon: ShieldAlert,
      };
    }
  }, [data, whoisData]);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-400">
            <Globe2 className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                Domain & DNS Infrastructure Recon
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Analyze DNS records, hosting topology, mail security (SPF/DKIM/DMARC) & WHOIS domain registration
            </p>
          </div>
        </div>
      </div>

      {/* Top Domain Search Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl flex flex-col sm:flex-row gap-3 items-center">
        <div className="relative flex-1 w-full">
          <Globe2 className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLookup()}
            placeholder="Enter target domain (e.g. microsoft.com, google.com, cloudflare.com)..."
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-cyan-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors shadow-inner"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => {
              setDomain(val);
              handleLookup(val);
            }}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <button
            onClick={() => handleLookup()}
            disabled={isLoading || !domain.trim()}
            className="flex-1 sm:flex-none px-6 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-extrabold text-xs flex items-center justify-center gap-2 transition-all shadow-lg disabled:opacity-50"
          >
            {isLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {isLoading ? 'Scanning...' : 'Scan Domain'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-rose-800/60 shadow-2xl space-y-3.5 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="p-2.5 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-400 flex-shrink-0 mt-0.5">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="text-sm font-bold text-rose-200">
                    {error.error}
                  </h3>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${
                      error.code === 'NXDOMAIN'
                        ? 'bg-amber-950/80 text-amber-300 border-amber-600/60'
                        : error.code === 'DNS_TIMEOUT'
                        ? 'bg-purple-950/80 text-purple-300 border-purple-600/60'
                        : error.code === 'INVALID_DOMAIN'
                        ? 'bg-rose-950/80 text-rose-300 border-rose-600/60'
                        : 'bg-red-950/80 text-red-300 border-red-600/60'
                    }`}
                  >
                    {error.code}
                  </span>
                </div>
                {error.details && (
                  <p className="text-xs text-slate-300 font-mono leading-relaxed">
                    {error.details}
                  </p>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-center flex-shrink-0">
              <button
                onClick={() => handleLookup()}
                disabled={isLoading}
                className="px-3 py-1.5 rounded-lg bg-rose-900/60 hover:bg-rose-800/70 border border-rose-700/60 text-rose-200 text-xs font-mono font-bold flex items-center gap-1.5 transition-all shadow"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
                Retry Scan
              </button>
              <button
                onClick={() => setError(null)}
                className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 text-xs font-mono transition-all"
                title="Dismiss error"
              >
                Dismiss
              </button>
            </div>
          </div>

          {error.suggestion && (
            <div className="flex items-start gap-2 pt-2.5 border-t border-rose-900/40 text-xs text-rose-300/90 font-mono bg-rose-950/20 -mx-5 -mb-3.5 p-3 px-5 rounded-b-2xl">
              <span className="text-amber-400 font-bold flex-shrink-0">💡 Remediation:</span>
              <span>{error.suggestion}</span>
            </div>
          )}
        </div>
      )}

      {/* Loaded Content: 2-Column Split Dashboard (Fitted, no sideways scroll) */}
      {data && (
        <div className="flex flex-col lg:flex-row gap-5 items-start w-full animate-in fade-in duration-300">
          
          {/* ================= LEFT COLUMN: Intelligence & Diagnostics ================= */}
          <div className="w-full lg:w-[280px] xl:w-[320px] flex-shrink-0 space-y-5">
            
            {/* Card 1: Quick Intelligence Overview */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800/90 shadow-xl space-y-4">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 tracking-wider">
                <span className="text-rose-400">📍</span>
                <span>Quick Intelligence Overview</span>
              </div>

              {/* Cyber Security Posture Gauge */}
              <div className="flex flex-col items-center justify-center pt-1">
                <div className="relative w-32 h-32 flex items-center justify-center p-2 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-inner">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <defs>
                      <linearGradient id="scoreGaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor={securityPosture.stroke1} />
                        <stop offset="100%" stopColor={securityPosture.stroke2} />
                      </linearGradient>
                      <filter id="scoreGlow" x="-20%" y="-20%" width="140%" height="140%">
                        <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor={securityPosture.stroke1} floodOpacity="0.45" />
                      </filter>
                    </defs>
                    {/* Outer Radar Calibration Ring */}
                    <circle
                      cx="50"
                      cy="50"
                      r="45"
                      stroke="#334155"
                      strokeWidth="1"
                      strokeDasharray="2 6"
                      fill="none"
                      opacity="0.5"
                    />
                    {/* Background Track */}
                    <circle
                      cx="50"
                      cy="50"
                      r="37"
                      stroke="#1e293b"
                      strokeWidth="6"
                      fill="none"
                    />
                    {/* Dynamic Progress Arc */}
                    <circle
                      cx="50"
                      cy="50"
                      r="37"
                      stroke="url(#scoreGaugeGradient)"
                      strokeWidth="6"
                      strokeLinecap="round"
                      strokeDasharray="232.48"
                      strokeDashoffset={232.48 - (232.48 * Math.max(securityPosture.score, 4)) / 100}
                      fill="none"
                      filter="url(#scoreGlow)"
                      className="transition-all duration-700 ease-out"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none pointer-events-none">
                    <securityPosture.icon className="w-4 h-4 mb-0.5 transition-colors" style={{ color: securityPosture.stroke1 }} />
                    <div className="flex items-baseline leading-none">
                      <span className="text-2xl font-black font-mono text-slate-50 tracking-tight">
                        {securityPosture.score}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 font-bold ml-0.5">%</span>
                    </div>
                    <span className={`mt-1 px-1.5 py-0.5 rounded text-[8px] font-bold tracking-wider uppercase border ${securityPosture.badgeClass}`}>
                      {securityPosture.label}
                    </span>
                  </div>
                </div>

                {/* Posture Status Label */}
                <div className="w-full flex items-center justify-center gap-1.5 pt-2">
                  <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: securityPosture.stroke1 }} />
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-300">
                    {securityPosture.grade}
                  </span>
                </div>

                {/* Security Protocols Telemetry Bar */}
                <div className="grid grid-cols-3 gap-1.5 w-full pt-2">
                  <div className={`px-1.5 py-1 rounded-lg text-center border text-[9px] font-mono font-bold ${
                    data.policies?.spf?.status === 'valid'
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : data.policies?.spf?.status === 'warning'
                      ? 'bg-amber-950/40 border-amber-500/40 text-amber-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}>
                    SPF {data.policies?.spf?.status === 'valid' ? '✓' : '✗'}
                  </div>
                  <div className={`px-1.5 py-1 rounded-lg text-center border text-[9px] font-mono font-bold ${
                    data.policies?.dmarc?.status === 'valid'
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : data.policies?.dmarc?.status === 'warning'
                      ? 'bg-amber-950/40 border-amber-500/40 text-amber-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}>
                    DMARC {data.policies?.dmarc?.status === 'valid' ? '✓' : '✗'}
                  </div>
                  <div className={`px-1.5 py-1 rounded-lg text-center border text-[9px] font-mono font-bold ${
                    (data.dnssec?.enabled || whoisData?.whois?.dnssec)
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400'
                  }`}>
                    DNSSEC {(data.dnssec?.enabled || whoisData?.whois?.dnssec) ? '✓' : '✗'}
                  </div>
                </div>
              </div>

              {/* Metadata Fields with Parenthesized Content */}
              <div className="space-y-1.5 text-xs font-mono pt-1">
                <div className="text-slate-300 break-words text-[11px]">
                  <span className="text-slate-400 font-semibold">Org name: </span>
                  <span className="text-rose-300 font-bold">
                    ({whoisData?.whois?.registrantOrg || whoisData?.whois?.organization || 'Privacy Protected / Not Disclosed'})
                  </span>
                </div>
                <div className="text-slate-300 break-words text-[11px]">
                  <span className="text-slate-400 font-semibold">Registrar: </span>
                  <span className="text-blue-400 font-bold">
                    ({whoisData?.whois?.registrar || 'Not Disclosed / Privacy Protected'})
                  </span>
                </div>
                <div className="text-slate-300 break-words text-[11px]">
                  <span className="text-slate-400 font-semibold">Web Host: </span>
                  <span className="text-cyan-300 font-bold">
                    ({data.hosting?.webHost?.company || 'Unresolved'})
                  </span>
                </div>
                <div className="text-slate-300 text-[11px]">
                  <span className="text-slate-400 font-semibold">Country: </span>
                  <span className="text-slate-100 font-bold">
                    ({formatCountry(whoisData?.whois?.country || data.hosting?.webHost?.country)})
                  </span>
                </div>
                <div className="text-slate-300 text-[10px]">
                  <span className="text-slate-400 font-semibold">Created: </span>
                  <span className="text-slate-200">
                    {whoisData?.whois?.creationDate?.slice(0, 10) || 'N/A'}
                  </span>
                  <span className="text-slate-500 mx-1">|</span>
                  <span className="text-slate-400 font-semibold">Exp: </span>
                  <span className="text-slate-200">
                    {whoisData?.whois?.expirationDate?.slice(0, 10) || 'N/A'}
                  </span>
                </div>
              </div>

              {/* Quick Export Action Buttons */}
              <div className="grid grid-cols-3 gap-1.5 pt-2 border-t border-slate-800/80">
                <button
                  onClick={downloadHtmlReport}
                  className="px-2 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-[10px] font-bold font-mono flex items-center justify-center gap-1 transition-all"
                  title="Download full HTML report"
                >
                  <Download className="w-3 h-3" />
                  HTML
                </button>
                <button
                  onClick={copyMarkdown}
                  className="px-2 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[10px] font-mono font-semibold flex items-center justify-center gap-1 transition-all"
                  title="Copy markdown report"
                >
                  <FileText className="w-3 h-3 text-cyan-400" />
                  Markdown
                </button>
                <button
                  onClick={downloadCsv}
                  className="px-2 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[10px] font-mono font-semibold flex items-center justify-center gap-1 transition-all"
                  title="Export CSV"
                >
                  <Table className="w-3 h-3 text-amber-400" />
                  CSV
                </button>
              </div>
            </div>

            {/* Card 2: Security & Health Diagnostics */}
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800/90 shadow-xl space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 tracking-wider">
                <span className="text-cyan-400">🛡️</span>
                <span>Security & Health Diagnostics</span>
              </div>

              <div className="space-y-2.5">
                {/* Diagnostic Item 1: SPF Health */}
                <div className={`p-3 rounded-xl border space-y-1 ${
                  data.policies?.spf?.status === 'valid'
                    ? 'bg-emerald-950/20 border-emerald-500/40'
                    : data.policies?.spf?.status === 'warning'
                    ? 'bg-amber-950/20 border-amber-500/40'
                    : 'bg-rose-950/20 border-rose-500/40'
                }`}>
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <span className={`text-[11px] font-mono font-bold flex items-center gap-1 ${
                      data.policies?.spf?.status === 'valid' ? 'text-emerald-300' : data.policies?.spf?.status === 'warning' ? 'text-amber-300' : 'text-rose-300'
                    }`}>
                      {data.policies?.spf?.status === 'valid' ? <Check className="w-3 h-3 text-emerald-400" /> : <span>▲</span>} SPF Authentication
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${
                      data.policies?.spf?.status === 'valid'
                        ? 'bg-emerald-900/80 border border-emerald-600/60 text-emerald-200'
                        : data.policies?.spf?.status === 'warning'
                        ? 'bg-amber-900/80 border border-amber-600/60 text-amber-200'
                        : 'bg-rose-900/80 border border-rose-600/60 text-rose-200'
                    }`}>
                      {data.policies?.spf?.status === 'valid' ? 'Secure' : data.policies?.spf?.status === 'warning' ? 'Warning' : 'Missing'}
                    </span>
                  </div>
                  <p className="text-[10px] font-mono text-slate-300 leading-snug">
                    {data.policies?.spf?.status === 'valid'
                      ? 'Authoritative SPF policy is actively protecting this domain from spoofing.'
                      : data.policies?.spf?.recommendations?.[0] || 'Deploy an enforcing SPF DNS record to prevent unauthorized mail sender forgery.'}
                  </p>
                </div>

                {/* Diagnostic Item 2: DMARC Policy */}
                <div className={`p-3 rounded-xl border space-y-1 ${
                  data.policies?.dmarc?.status === 'valid'
                    ? 'bg-emerald-950/20 border-emerald-500/40'
                    : data.policies?.dmarc?.status === 'warning'
                    ? 'bg-amber-950/20 border-amber-500/40'
                    : 'bg-rose-950/20 border-rose-500/40'
                }`}>
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <span className={`text-[11px] font-mono font-bold flex items-center gap-1 ${
                      data.policies?.dmarc?.status === 'valid' ? 'text-emerald-300' : data.policies?.dmarc?.status === 'warning' ? 'text-amber-300' : 'text-rose-300'
                    }`}>
                      {data.policies?.dmarc?.status === 'valid' ? <Check className="w-3 h-3 text-emerald-400" /> : <span>▲</span>} DMARC Enforcement
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${
                      data.policies?.dmarc?.status === 'valid'
                        ? 'bg-emerald-900/80 border border-emerald-600/60 text-emerald-200'
                        : data.policies?.dmarc?.status === 'warning'
                        ? 'bg-amber-900/80 border border-amber-600/60 text-amber-200'
                        : 'bg-rose-900/80 border border-rose-600/60 text-rose-200'
                    }`}>
                      {data.policies?.dmarc?.status === 'valid' ? 'Enforcing' : data.policies?.dmarc?.status === 'warning' ? 'Monitoring' : 'Missing'}
                    </span>
                  </div>
                  <p className="text-[10px] font-mono text-slate-300 leading-snug">
                    {data.policies?.dmarc?.status === 'valid'
                      ? `Active policy (p=${data.policies?.dmarc?.parsedTags?.['p'] || 'enforce'}) protecting against domain impersonation.`
                      : data.policies?.dmarc?.recommendations?.[0] || 'Deploy DMARC policy (_dmarc TXT record) with quarantine or reject policy.'}
                  </p>
                </div>

                {/* Diagnostic Item 3: Nameserver Failover Redundancy */}
                <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/40 space-y-1">
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <span className="text-[11px] font-mono font-bold text-emerald-300 flex items-center gap-1">
                      <Check className="w-3 h-3 text-emerald-400" /> NS Redundancy
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-emerald-900/80 border border-emerald-600/60 text-emerald-200 font-bold">
                      {nsRecords.length >= 2 ? 'Secure' : 'Warning'}
                    </span>
                  </div>
                  <p className="text-[10px] font-mono text-slate-300 leading-snug">
                    Verified {nsRecords.length || 0} active authoritative nameservers for resilient failover.
                  </p>
                </div>
              </div>
            </div>

          </div>

          {/* ================= RIGHT COLUMN: Navigation Tabs & Records Table ================= */}
          <div className="flex-1 min-w-0 w-full">
            <Tabs value={activeTab} onValueChange={val => setActiveTab(val as any)} className="w-full space-y-5">
              {/* Top Navigation Tabs */}
              <TabsList className="p-1.5 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-center gap-1.5 overflow-x-auto w-full justify-start h-auto">
                <TabsTrigger
                  value="records"
                  className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold flex items-center gap-2 whitespace-nowrap data-[state=active]:bg-violet-600/30 data-[state=active]:text-cyan-200 data-[state=active]:border data-[state=active]:border-cyan-500/50"
                >
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  Web & Authority (A, NS, MX, TXT)
                </TabsTrigger>
                <TabsTrigger
                  value="mail_security"
                  className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold flex items-center gap-2 whitespace-nowrap data-[state=active]:bg-violet-600/30 data-[state=active]:text-cyan-200 data-[state=active]:border data-[state=active]:border-cyan-500/50"
                >
                  <Mail className="w-3.5 h-3.5 text-emerald-400" />
                  Mail Security (SPF / DMARC / DKIM / TLS-RPT / STS)
                </TabsTrigger>
                <TabsTrigger
                  value="whois"
                  className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold flex items-center gap-2 whitespace-nowrap data-[state=active]:bg-violet-600/30 data-[state=active]:text-cyan-200 data-[state=active]:border data-[state=active]:border-cyan-500/50"
                >
                  <Building className="w-3.5 h-3.5 text-purple-400" />
                  WhoIs & RDAP Ownership
                </TabsTrigger>
              </TabsList>

              {/* TAB 1: DNS Record Resolution & Infrastructure Fingerprinting */}
              <TabsContent value="records" className="mt-0">
              <div className="space-y-4">
                {/* Title & Subtitle */}
                <div>
                  <h2 className="text-sm font-bold text-slate-100 tracking-tight">
                    DNS Record Resolution & Infrastructure Fingerprinting
                  </h2>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Real-time asynchronous querying of core routing records with automated IP geolocation and WhoIs ISP matching.
                  </p>
                </div>

                {/* Structured Table - Fully Fitted Without Sideways Scroll */}
                <div className="rounded-2xl bg-slate-950/90 border border-slate-800/90 overflow-hidden shadow-2xl">
                  <div className="w-full overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 text-[10px] tracking-wider uppercase">
                        <tr>
                          <th className="p-3 w-16 text-center whitespace-nowrap">TYPE</th>
                          <th className="p-3 whitespace-nowrap">DESTINATION / VALUE</th>
                          <th className="p-3 whitespace-nowrap">RESOLVED IP + FLAG</th>
                          <th className="p-3 w-16 text-center whitespace-nowrap">TTL</th>
                          <th className="p-3 whitespace-nowrap">ORG / SERVICE PROVIDER</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900">
                        
                        {/* 1. A INFRASTRUCTURE RECORDS */}
                        {aRecords.length > 0 && (
                          <>
                            <tr className=" bg-slate-900/60 text-cyan-300 font-bold border-t border-b border-blue-800/60">
                              <td colSpan={5} className="p-2.5 px-3">
                                <div className="flex items-center gap-2 text-xs font-bold tracking-normal whitespace-nowrap">
                                  <span className="p-1 rounded bg-blue-500/20 text-cyan-400 text-[11px]">🌐</span>
                                  <span>A INFRASTRUCTURE RECORDS ({aRecords.length})</span>
                                </div>
                              </td>
                            </tr>
                            {aRecords.map((rec, i) => (
                              <tr key={`a-${i}`} className="hover:bg-slate-900/50 transition-colors border-b border-slate-900">
                                <td className="p-3 text-center">
                                  <span className="px-2 py-0.5 rounded bg-blue-950 text-cyan-300 border border-blue-800 text-[10px] font-bold">
                                    A
                                  </span>
                                </td>
                                <td className="p-3 text-slate-100 font-bold select-all">{rec.value}</td>
                                <td className="p-3 text-slate-200">
                                  <span className="inline-flex items-center gap-1.5 font-mono">
                                    {rec.resolvedIp || rec.value}
                                    <button
                                      onClick={() => copyToClipboard(rec.value, `a-ip-${i}`)}
                                      className="px-1.5 py-0.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[9px] text-slate-400 hover:text-cyan-300 inline-flex items-center gap-0.5"
                                    >
                                      {copiedText === `a-ip-${i}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                                      Copy
                                    </button>
                                  </span>
                                </td>
                                <td className="p-3 text-slate-400 text-center text-[11px]">{rec.ttl !== undefined ? `${rec.ttl}s` : '—'}</td>
                                <td className="p-3 text-slate-200 font-semibold text-[11px]">{rec.orgProvider || 'N/A'}</td>
                              </tr>
                            ))}
                          </>
                        )}

                        {/* 2. NS INFRASTRUCTURE RECORDS */}
                        {nsRecords.length > 0 && (
                          <>
                            <tr className=" bg-slate-900/60 text-indigo-300 font-bold border-t border-b border-indigo-800/60">
                              <td colSpan={5} className="p-2.5 px-3">
                                <div className="flex items-center gap-2 text-xs font-bold tracking-normal whitespace-nowrap">
                                  <span className="p-1 rounded bg-indigo-500/20 text-indigo-400 text-[11px]">🌐</span>
                                  <span>NS INFRASTRUCTURE RECORDS ({nsRecords.length})</span>
                                </div>
                              </td>
                            </tr>
                            {nsRecords.map((rec, i) => (
                              <tr key={`ns-${i}`} className="hover:bg-slate-900/50 transition-colors border-b border-slate-900">
                                <td className="p-3 text-center">
                                  <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-bold">
                                    NS
                                  </span>
                                </td>
                                <td className="p-3 text-slate-200 font-mono select-all">{rec.value}</td>
                                <td className="p-3 text-slate-200">
                                  <span className="inline-flex items-center gap-1.5 font-mono">
                                    {rec.resolvedIp || 'Unresolved'}
                                    <button
                                      onClick={() => copyToClipboard(rec.resolvedIp?.split(' ')[0] || rec.value, `ns-ip-${i}`)}
                                      className="px-1.5 py-0.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[9px] text-slate-400 hover:text-cyan-300 inline-flex items-center gap-0.5"
                                    >
                                      {copiedText === `ns-ip-${i}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                                      Copy
                                    </button>
                                  </span>
                                </td>
                                <td className="p-3 text-slate-400 text-center text-[11px]">{rec.ttl !== undefined ? `${rec.ttl}s` : '—'}</td>
                                <td className="p-3 text-slate-200 font-semibold text-[11px]">{rec.orgProvider || 'Unknown'}</td>
                              </tr>
                            ))}
                          </>
                        )}

                        {/* 3. MX INFRASTRUCTURE RECORDS */}
                        {mxRecords.length > 0 && (
                          <>
                            <tr className=" bg-slate-900/60 text-emerald-300 font-bold border-t border-b border-emerald-800/60">
                              <td colSpan={5} className="p-2.5 px-3">
                                <div className="flex items-center gap-2 text-xs font-bold tracking-normal whitespace-nowrap">
                                  <span className="p-1 rounded bg-emerald-500/20 text-emerald-400 text-[11px]">✉️</span>
                                  <span>MX INFRASTRUCTURE RECORDS ({mxRecords.length})</span>
                                </div>
                              </td>
                            </tr>
                            {mxRecords.map((rec, i) => (
                              <tr key={`mx-${i}`} className="hover:bg-slate-900/50 transition-colors border-b border-slate-900">
                                <td className="p-3 text-center">
                                  <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                                    MX
                                  </span>
                                </td>
                                <td className="p-3 text-slate-100 font-mono select-all">
                                  <span className="text-slate-400 font-normal mr-1">[Pref: {rec.priority ?? '?'}]</span>
                                  {rec.value}
                                </td>
                                <td className="p-3 text-slate-200">
                                  <span className="inline-flex items-center gap-1.5 font-mono">
                                    {rec.resolvedIp || 'Unresolved'}
                                    <button
                                      onClick={() => copyToClipboard(rec.resolvedIp?.split(' ')[0] || rec.value, `mx-ip-${i}`)}
                                      className="px-1.5 py-0.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[9px] text-slate-400 hover:text-cyan-300 inline-flex items-center gap-0.5"
                                    >
                                      {copiedText === `mx-ip-${i}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                                      Copy
                                    </button>
                                  </span>
                                </td>
                                <td className="p-3 text-slate-400 text-center text-[11px]">{rec.ttl !== undefined ? `${rec.ttl}s` : '—'}</td>
                                <td className="p-3 text-slate-200 font-semibold text-[11px]">{rec.orgProvider || 'Unknown'}</td>
                              </tr>
                            ))}
                          </>
                        )}

                        {/* 4. TXT INFRASTRUCTURE RECORDS */}
                        {txtRecords.length > 0 && (
                          <>
                            <tr className=" bg-slate-900/60 text-amber-300 font-bold border-t border-b border-amber-800/60">
                              <td colSpan={5} className="p-2.5 px-3">
                                <div className="flex items-center gap-2 text-xs font-bold tracking-normal whitespace-nowrap">
                                  <span className="p-1 rounded bg-amber-500/20 text-amber-400 text-[11px]">📄</span>
                                  <span>TXT INFRASTRUCTURE RECORDS ({txtRecords.length})</span>
                                </div>
                              </td>
                            </tr>
                            {txtRecords.map((rec, i) => (
                              <tr key={`txt-${i}`} className="hover:bg-slate-900/50 transition-colors border-b border-slate-900">
                                <td className="p-3 text-center">
                                  <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold">
                                    TXT
                                  </span>
                                </td>
                                <td className="p-3 text-slate-200 font-mono select-all break-all">{rec.value}</td>
                                <td className="p-3 text-slate-400 font-mono text-[11px]">{rec.resolvedIp || '-'}</td>
                                <td className="p-3 text-slate-400 text-center text-[11px]">{rec.ttl !== undefined ? `${rec.ttl}s` : '—'}</td>
                                <td className="p-3 text-slate-200 font-semibold text-[11px]">{getTxtRecordPurpose(rec.value)}</td>
                              </tr>
                            ))}
                          </>
                        )}

                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </TabsContent>

            {/* TAB 2: Mail Security (SPF, DMARC, DKIM, BIMI, MTA-STS) */}
            <TabsContent value="mail_security" className="mt-0">
              <div className="space-y-6">
                {/* Custom DKIM Lookup Box */}
                <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-amber-300 flex items-center gap-2">
                      <Key className="w-4 h-4" /> DKIM (DomainKeys Identified Mail) Selectors Explorer
                    </h3>
                    <span className="text-[11px] font-mono text-slate-400">
                      {(data.dkimSelectors || []).filter(d => d.status !== 'not_found').length} Active Selectors Discovered
                    </span>
                  </div>

                  <div className="flex gap-2 items-center">
                    <input
                      type="text"
                      value={customDkimSelector}
                      onChange={e => setCustomDkimSelector(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleCustomDkimLookup()}
                      placeholder="Enter custom DKIM selector (e.g. selector1, s1, mail, 2024)..."
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-amber-300 placeholder-slate-600 focus:outline-none focus:border-amber-500"
                    />
                    <button
                      onClick={handleCustomDkimLookup}
                      disabled={isDkimSearching || !customDkimSelector.trim()}
                      className="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                    >
                      {isDkimSearching ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                      Check Selector
                    </button>
                  </div>

                  {/* Discovered Selectors */}
                  <div className="divide-y divide-slate-800/60 pt-2">
                    {(data.dkimSelectors || [])
                      .filter(d => d.status !== 'not_found')
                      .map((dkim, idx) => (
                        <div key={idx} className="py-3 flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2.5">
                            <span className="px-2.5 py-1 rounded bg-amber-950 border border-amber-700 text-amber-300 font-mono font-bold text-xs">
                              {dkim.selector}
                            </span>
                            <span className="text-xs font-mono text-slate-300">{dkim.fqdn}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {dkim.keyLengthBits && (
                              <span
                                className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                                  dkim.isKeySecure
                                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                                    : 'bg-amber-950 text-amber-300 border border-amber-700'
                                }`}
                              >
                                {dkim.keyLengthBits}-bit {dkim.keyType || 'RSA'} ({dkim.isKeySecure ? 'Strong' : 'Weak'})
                              </span>
                            )}
                            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-mono">
                              {dkim.recordType === 'CNAME' ? 'CNAME Delegation' : 'Direct TXT Key'}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>

                {/* Policy Cards */}
                <PolicyCard policy={data.policies.spf} />
                <PolicyCard policy={data.policies.dmarc} />
                <PolicyCard policy={data.policies.bimi} />
                <PolicyCard policy={data.policies.mtaSts} />
              </div>
            </TabsContent>

            {/* TAB 3: Whois & RDAP Ownership */}
            <TabsContent value="whois" className="mt-0">
              {whoisData && (
              <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-6 shadow-xl">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs text-slate-300 tracking-normal font-bold">
                    Authoritative Registrar & Registry WHOIS Record
                  </h3>
                  <span className="text-[11px] font-mono text-cyan-400">Port 43 TCP Query</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block mb-1 text-[11px]">REGISTRAR</span>
                    <span className="text-cyan-300 font-bold text-sm">{whoisData.whois.registrar || 'Not Disclosed / Privacy Protected'}</span>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block mb-1 text-[11px]">REGISTRANT ORG</span>
                    <span className="text-slate-100 font-bold text-sm break-words">
                      {whoisData.whois.registrantOrg || whoisData.whois.organization || 'Privacy Protected / Not Disclosed'}
                    </span>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block mb-1 text-[11px]">REGISTRATION DATE</span>
                    <span className="text-emerald-400 font-bold">
                      {whoisData.whois.creationDate?.slice(0, 10) || 'N/A'}
                    </span>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block mb-1 text-[11px]">EXPIRATION DATE</span>
                    <span className="text-amber-400 font-bold">
                      {whoisData.whois.expirationDate?.slice(0, 10) || 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Raw WHOIS Output */}
                {whoisData.whois.rawWhois && (
                  <div className="pt-2">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-slate-400">RAW WHOIS REGISTRY RESPONSE:</span>
                      <button
                        onClick={() => copyToClipboard(whoisData.whois.rawWhois || '', 'raw-whois')}
                        className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                      >
                        {copiedText === 'raw-whois' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        Copy Raw WHOIS
                      </button>
                    </div>
                    <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-64 overflow-y-auto select-all">
                      {whoisData.whois.rawWhois}
                    </pre>
                  </div>
                )}
              </div>
              )}
            </TabsContent>
          </Tabs>
        </div>
        </div>
      )}
    </div>
  );
}

function PolicyCard({ policy }: { policy: PolicyEvaluation }) {
  return (
    <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800/90 space-y-3 shadow-xl">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <span className="text-sm font-extrabold text-slate-100 font-mono">{policy.protocol} POLICY VALIDATOR</span>
          <span
            className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${
              policy.status === 'valid'
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : policy.status === 'warning'
                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                : 'bg-rose-950 text-rose-400 border border-rose-800'
            }`}
          >
            {policy.status} ({policy.strictness})
          </span>
        </div>
      </div>

      <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 select-all overflow-x-auto">
        {policy.policy}
      </pre>

      {/* Recommendations */}
      {policy.recommendations.length > 0 && (
        <div className="space-y-1.5 pt-1">
          {policy.recommendations.map((rec, idx) => (
            <div key={idx} className="flex items-center gap-2 text-xs text-emerald-300">
              <ShieldCheck className="w-4 h-4 flex-shrink-0 text-emerald-400" />
              <span>{rec}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
