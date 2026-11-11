'use client';

import React, { useState } from 'react';
import {
  Lock,
  Terminal,
  Layers,
  ChevronRight,
  Activity,
  FolderOpen,
  Globe2,
  KeyRound,
  Radio,
  Search,
} from 'lucide-react';
import { TabId, TabItem, TOOLS } from '../layout/Sidebar';
import { useCase } from '../shared/CaseContext';

interface DashboardOverviewProps {
  onSelectTab: (tabId: TabId) => void;
  onOpenScratchpad: () => void;
  onOpenCaseReport: () => void;
}

export function DashboardOverview({
  onSelectTab,
  onOpenScratchpad,
  onOpenCaseReport,
}: DashboardOverviewProps) {
  const { caseItems } = useCase();
  const [triageInput, setTriageInput] = useState('');
  const [detectedType, setDetectedType] = useState<{
    type: string;
    targetTab: TabId;
    reason: string;
    color: string;
  } | null>(null);

  // Auto-detect IOC or target type in real time
  const handleTriageChange = (val: string) => {
    setTriageInput(val);
    const clean = val.trim();
    if (!clean) {
      setDetectedType(null);
      return;
    }

    // IP detection
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(clean)) {
      setDetectedType({
        type: 'IPv4 Host Address',
        targetTab: 'ip',
        reason: 'Audit IP Threat Score, ASN Geolocation & AbuseIPDB reputation',
        color: 'text-sky-400',
      });
      return;
    }

    // CIDR detection
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(clean)) {
      setDetectedType({
        type: 'CIDR Subnet Block',
        targetTab: 'cidr',
        reason: 'Calculate subnet bounds, broadcast range & usable hosts',
        color: 'text-emerald-400',
      });
      return;
    }

    // Port detection
    if (/^[0-9]{1,5}(,[0-9]{1,5})*$/.test(clean) || /^[0-9]{1,5}-[0-9]{1,5}$/.test(clean)) {
      setDetectedType({
        type: 'Target Port(s)',
        targetTab: 'ports',
        reason: 'Inspect service vulnerabilities and evasion flag reference',
        color: 'text-sky-400',
      });
      return;
    }

    // Hash detection
    if (/^[a-fA-F0-9]{32}$/.test(clean) || /^[a-fA-F0-9]{40}$/.test(clean) || /^[a-fA-F0-9]{64}$/.test(clean)) {
      setDetectedType({
        type: 'Cryptographic Hash',
        targetTab: 'crypto',
        reason: 'Verify HMAC, generate digests & cross-reference threat databases',
        color: 'text-purple-400',
      });
      return;
    }

    // JWT detection
    if (/^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(clean)) {
      setDetectedType({
        type: 'JSON Web Token (JWT)',
        targetTab: 'jwt',
        reason: 'Decode claims, audit expiration timestamps & test alg:none flaws',
        color: 'text-rose-400',
      });
      return;
    }

    // Email address
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      setDetectedType({
        type: 'Email Address',
        targetTab: 'email',
        reason: 'Evaluate sender reputation, SPF/DKIM/DMARC & phishing risk',
        color: 'text-sky-400',
      });
      return;
    }

    // URL or Domain
    if (/^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/.test(clean)) {
      if (clean.startsWith('http://') || clean.startsWith('https://') || clean.includes('/')) {
        setDetectedType({
          type: 'Live Web URL',
          targetTab: 'links',
          reason: 'Scan redirection hops, SSL certificate chain & headers',
          color: 'text-emerald-400',
        });
      } else {
        setDetectedType({
          type: 'Domain Name',
          targetTab: 'domain',
          reason: 'Query authoritative DNS, WHOIS registry & email security policies',
          color: 'text-sky-400',
        });
      }
      return;
    }

    // Default fallback
    setDetectedType({
      type: 'Raw Text / IoC Block',
      targetTab: 'ioc-extractor',
      reason: 'Parse regex indicators (IPs, URLs, Hashes, Domains) in bulk',
      color: 'text-purple-400',
    });
  };

  const handleLaunchTriage = () => {
    if (detectedType) {
      onSelectTab(detectedType.targetTab);
    }
  };

  const reconTools = TOOLS.filter(t => t.category === 'RECON');
  const webTools = TOOLS.filter(t => t.category === 'WEB');
  const threatTools = TOOLS.filter(t => t.category === 'THREAT');
  const cryptoTools = TOOLS.filter(t => t.category === 'CRYPTO');

  return (
    <div className="space-y-8 pb-16 max-w-7xl mx-auto animate-in fade-in duration-200">
      {/* 1. Clean Header Banner */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-card)] p-6 sm:p-8 shadow-sm">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-6">
          <div className="space-y-3 flex-1 min-w-0">

            {/* Title & Description */}
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-50">
                  Security Overview
                </h1>
              </div>
              <p className="text-sm text-[var(--text-muted)] mt-1.5 leading-relaxed max-w-2xl">
                Unified security reconnaissance, threat surface intelligence &amp; cryptographic analysis suite.
              </p>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex items-center gap-3 flex-shrink-0">
            <button
              onClick={onOpenCaseReport}
              className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-[var(--bg-surface)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-slate-50 transition-all shadow-sm"
            >
              <div className="p-2 rounded-lg bg-purple-500/15 border border-purple-500/30 text-purple-300">
                <FolderOpen className="w-4 h-4" />
              </div>
              <div className="text-left">
                <div className="text-[10px] text-slate-400 uppercase font-semibold tracking-wider">
                  Case Dossier
                </div>
                <div className="text-xs font-bold text-slate-50 flex items-center gap-1">
                  <span>{caseItems.length} findings</span>
                  <ChevronRight className="w-3 h-3 text-slate-400" />
                </div>
              </div>
            </button>

            <button
              onClick={onOpenScratchpad}
              className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-[var(--bg-surface)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-slate-50 transition-all shadow-sm"
            >
              <div className="p-2 rounded-lg bg-sky-500/15 border border-sky-500/30 text-sky-300">
                <Terminal className="w-4 h-4" />
              </div>
              <div className="text-left">
                <div className="text-[10px] text-slate-400 uppercase font-semibold tracking-wider">
                  Quick Defanger
                </div>
                <div className="text-xs font-bold text-slate-50 flex items-center gap-1">
                  <span>IOC Utility</span>
                  <ChevronRight className="w-3 h-3 text-slate-400" />
                </div>
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Target & IOC Quick Triage Input */}
      <div className="p-5 sm:p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-card)] shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-[var(--accent-text)]" />
            <span className="text-xs font-bold tracking-normal text-slate-200">
              Target &amp; IOC Quick Triage
            </span>
          </div>
          <span className="text-xs text-[var(--text-muted)] font-mono">
            Auto-detects IP, domain, hash, JWT, port, CIDR &amp; email
          </span>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch gap-2.5">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="Paste any IOC (e.g. 192.168.1.1, 443, https://example.com, 10.0.0.0/24, SHA-256)..."
              value={triageInput}
              onChange={e => handleTriageChange(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleLaunchTriage()}
              className="w-full px-4 py-3 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>

          <button
            onClick={handleLaunchTriage}
            disabled={!detectedType}
            className="px-6 py-3 rounded-xl font-semibold text-xs transition-all disabled:opacity-40 flex items-center justify-center gap-2 bg-[var(--accent)] text-white hover:opacity-90 shadow-sm whitespace-nowrap"
          >
            <span>Analyze Target</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {detectedType && (
          <div className="p-3 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-wrap items-center gap-3 text-xs font-mono">
            <span className={`font-bold px-2 py-0.5 rounded bg-[var(--bg-card)] border border-[var(--border-subtle)] ${detectedType.color}`}>
              {detectedType.type}
            </span>
            <span className="text-slate-300">{detectedType.reason}</span>
            <button
              onClick={handleLaunchTriage}
              className="ml-auto text-[var(--accent-text)] hover:underline font-semibold flex items-center gap-1"
            >
              Open {TOOLS.find(t => t.id === detectedType.targetTab)?.label} →
            </button>
          </div>
        )}
      </div>

      {/* 3. Featured Tools */}
      <div>
        <div className="flex items-center justify-between mb-3.5">
          <h2 className="text-xs font-bold tracking-normal text-slate-300">
            Featured Security Tools
          </h2>
          <span className="text-xs text-[var(--text-muted)] font-mono">Quick Access</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Port Intel */}
          <div
            onClick={() => onSelectTab('ports')}
            className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-card)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-card-hover)] p-5 flex flex-col justify-between cursor-pointer transition-all duration-150 group"
          >
            <div>
              <div className="flex items-center justify-between mb-3.5">
                <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
                  <Radio className="w-4 h-4" />
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-sky-950/60 border border-sky-500/30 text-sky-300">
                  PORTS
                </span>
              </div>
              <h3 className="text-sm font-bold text-slate-50 group-hover:text-[var(--accent-text)] transition-colors">
                Port &amp; Service Intel
              </h3>
              <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-relaxed">
                Port reference database, Nmap stealth evasion syntax &amp; common service vulnerabilities.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between text-xs font-mono text-[var(--text-muted)] group-hover:text-slate-50">
              <span>Open Tool</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </div>

          {/* Card 2: Password Entropy */}
          <div
            onClick={() => onSelectTab('password')}
            className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-card)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-card-hover)] p-5 flex flex-col justify-between cursor-pointer transition-all duration-150 group"
          >
            <div>
              <div className="flex items-center justify-between mb-3.5">
                <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  <KeyRound className="w-4 h-4" />
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/60 border border-rose-500/30 text-rose-300">
                  AUTH
                </span>
              </div>
              <h3 className="text-sm font-bold text-slate-50 group-hover:text-rose-300 transition-colors">
                Password &amp; Entropy
              </h3>
              <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-relaxed">
                Compound dictionary segmentation, pattern decomposition &amp; cracking time metrics.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between text-xs font-mono text-[var(--text-muted)] group-hover:text-slate-50">
              <span>Open Tool</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </div>

          {/* Card 3: SSL Inspector */}
          <div
            onClick={() => onSelectTab('ssl')}
            className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-card)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-card-hover)] p-5 flex flex-col justify-between cursor-pointer transition-all duration-150 group"
          >
            <div>
              <div className="flex items-center justify-between mb-3.5">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <Lock className="w-4 h-4" />
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/60 border border-emerald-500/30 text-emerald-300">
                  TLS / SSL
                </span>
              </div>
              <h3 className="text-sm font-bold text-slate-50 group-hover:text-emerald-300 transition-colors">
                SSL / TLS Inspector
              </h3>
              <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-relaxed">
                X.509 certificate chains, SAN discovery, expiration tracking &amp; Certificate Transparency logs.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between text-xs font-mono text-[var(--text-muted)] group-hover:text-slate-50">
              <span>Open Tool</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </div>

          {/* Card 4: Purview Audit */}
          <div
            onClick={() => onSelectTab('purview')}
            className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-card)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-card-hover)] p-5 flex flex-col justify-between cursor-pointer transition-all duration-150 group"
          >
            <div>
              <div className="flex items-center justify-between mb-3.5">
                <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
                  <Activity className="w-4 h-4" />
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-950/60 border border-purple-500/30 text-purple-300">
                  LOGS
                </span>
              </div>
              <h3 className="text-sm font-bold text-slate-50 group-hover:text-purple-300 transition-colors">
                Purview Audit Triage
              </h3>
              <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-relaxed">
                Parse Microsoft 365 audit records, evaluate session anomalies &amp; correlate threats.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between text-xs font-mono text-[var(--text-muted)] group-hover:text-slate-50">
              <span>Open Tool</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </div>
        </div>
      </div>

      {/* 4. Complete Tool Directory by Category */}
      <div className="space-y-6">
        {/* Category 1: Recon & Perimeter */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Globe2 className="w-4 h-4 text-sky-400" />
            <h2 className="text-xs font-bold tracking-normal text-slate-200">
              Reconnaissance &amp; Perimeter ({reconTools.length} Tools)
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3.5">
            {reconTools.map(tool => (
              <ToolCard key={tool.id} tool={tool} onSelect={() => onSelectTab(tool.id)} />
            ))}
          </div>
        </div>

        {/* Category 2: Web & App Security */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Lock className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-bold tracking-normal text-slate-200">
              Web &amp; Application Security ({webTools.length} Tools)
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {webTools.map(tool => (
              <ToolCard key={tool.id} tool={tool} onSelect={() => onSelectTab(tool.id)} />
            ))}
          </div>
        </div>

        {/* Category 3: Threat Hunting & SIEM */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Terminal className="w-4 h-4 text-purple-400" />
            <h2 className="text-xs font-bold tracking-normal text-slate-200">
              Threat Hunting &amp; SIEM ({threatTools.length} Tools)
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {threatTools.map(tool => (
              <ToolCard key={tool.id} tool={tool} onSelect={() => onSelectTab(tool.id)} />
            ))}
          </div>
        </div>

        {/* Category 4: Cryptography & Utilities */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Layers className="w-4 h-4 text-amber-400" />
            <h2 className="text-xs font-bold tracking-normal text-slate-200">
              Cryptography &amp; Identity Utilities ({cryptoTools.length} Tools)
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3.5">
            {cryptoTools.map(tool => (
              <ToolCard key={tool.id} tool={tool} onSelect={() => onSelectTab(tool.id)} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function ToolCard({
  tool,
  onSelect,
}: {
  tool: TabItem;
  onSelect: () => void;
}) {
  const Icon = tool.icon;
  return (
    <div
      onClick={onSelect}
      className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-card)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-card-hover)] flex flex-col justify-between h-full cursor-pointer transition-all duration-150 group"
    >
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="p-2 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-slate-300 group-hover:text-slate-50">
            <Icon className="w-4 h-4" />
          </div>
          {tool.badge && (
            <span className="text-[9px] font-mono font-semibold px-2 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-slate-300">
              {tool.badge}
            </span>
          )}
        </div>
        <h4 className="text-xs font-bold text-slate-100 group-hover:text-slate-50 transition-colors truncate">
          {tool.label}
        </h4>
        <p className="text-[11px] text-[var(--text-muted)] mt-1 line-clamp-2 leading-relaxed">
          {tool.description}
        </p>
      </div>

      <div className="mt-3.5 pt-2.5 border-t border-[var(--border-subtle)] flex items-center justify-between text-[10px] font-mono text-slate-400 group-hover:text-[var(--accent-text)]">
        <span>Open Tool</span>
        <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
      </div>
    </div>
  );
}
