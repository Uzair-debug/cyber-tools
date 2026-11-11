'use client';

import React from 'react';
import { Logo } from '@/components/shared/Logo';
import {
  Mail,
  Globe2,
  Radio,
  Binary,
  KeyRound,
  Network,
  ChevronLeft,
  ChevronRight,
  Shield,
  Layers,
  Sparkles,
  Zap,
  Lock,
  ShieldCheck,
  Key,
  Terminal,
  Target,
  Link2,
  ShieldAlert,
  FileSearch,
  Sliders,
  FolderOpen,
  Monitor,
  Globe,
  LayoutDashboard,
  Search,
  X,
} from 'lucide-react';
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from '@/components/ui/tooltip';

export type TabId =
  | 'dashboard'
  | 'email'
  | 'domain'
  | 'ip'
  | 'ports'
  | 'cidr'
  | 'ssl'
  | 'headers'
  | 'jwt'
  | 'links'
  | 'purview'
  | 'windows-events'
  | 'powershell'
  | 'intel-pivot'
  | 'cvss'
  | 'siem'
  | 'mitre'
  | 'ioc-extractor'
  | 'converter'
  | 'crypto'
  | 'password'
  | 'cheatsheet';

export interface TabItem {
  id: TabId;
  label: string;
  category: 'RECON' | 'WEB' | 'THREAT' | 'CRYPTO';
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  badge?: string;
  theme: {
    activeBg: string;
    activeBorder: string;
    activeText: string;
    iconBg: string;
    iconBorder: string;
    iconColor: string;
    badgeBg: string;
    badgeBorder: string;
    badgeText: string;
    accentBar: string;
  };
}

export const TOOLS: TabItem[] = [
  // 1. RECON & INFRASTRUCTURE
  {
    id: 'email',
    label: 'Email & Threat Analyzer',
    category: 'RECON',
    icon: Mail,
    description: '.EML header hops, SPF/DKIM/DMARC verdicts & phishing scoring',
    theme: {
      activeBg: ' bg-amber-500/15 to-transparent',
      activeBorder: 'border-amber-500/50',
      activeText: 'text-amber-200',
      iconBg: 'bg-amber-500/20',
      iconBorder: 'border-amber-500/40',
      iconColor: 'text-amber-300',
      badgeBg: 'bg-amber-950/80',
      badgeBorder: 'border-amber-700/60',
      badgeText: 'text-amber-300',
      accentBar: 'bg-amber-400',
    },
  },
  {
    id: 'domain',
    label: 'Domain & DNS Recon',
    category: 'RECON',
    icon: Globe2,
    description: 'A/MX/TXT records, DKIM selectors discovery & WHOIS owner',
    theme: {
      activeBg: ' bg-emerald-500/15 to-transparent',
      activeBorder: 'border-emerald-500/50',
      activeText: 'text-emerald-200',
      iconBg: 'bg-emerald-500/20',
      iconBorder: 'border-emerald-500/40',
      iconColor: 'text-emerald-300',
      badgeBg: 'bg-emerald-950/80',
      badgeBorder: 'border-emerald-700/60',
      badgeText: 'text-emerald-300',
      accentBar: 'bg-emerald-400',
    },
  },
  {
    id: 'ip',
    label: 'IP & Threat Reputation',
    category: 'RECON',
    icon: Radio,
    description: 'GeoIP, ASN route lookup, reverse DNS & port scanning',
    theme: {
      activeBg: ' bg-indigo-500/15 to-transparent',
      activeBorder: 'border-indigo-500/50',
      activeText: 'text-indigo-200',
      iconBg: 'bg-indigo-500/20',
      iconBorder: 'border-indigo-500/40',
      iconColor: 'text-indigo-300',
      badgeBg: 'bg-indigo-950/80',
      badgeBorder: 'border-indigo-700/60',
      badgeText: 'text-indigo-300',
      accentBar: 'bg-indigo-400',
    },
  },
  {
    id: 'ports',
    label: 'Port & Service Intelligence',
    category: 'RECON',
    icon: Radio,
    description: 'Ports 0-65535 encyclopedia, known exploits & Nmap builder',
    theme: {
      activeBg: ' bg-blue-500/15 to-transparent',
      activeBorder: 'border-blue-500/50',
      activeText: 'text-blue-200',
      iconBg: 'bg-blue-500/20',
      iconBorder: 'border-blue-500/40',
      iconColor: 'text-blue-300',
      badgeBg: 'bg-blue-950/80',
      badgeBorder: 'border-blue-700/60',
      badgeText: 'text-blue-300',
      accentBar: 'bg-blue-400',
    },
  },
  {
    id: 'cidr',
    label: 'CIDR Subnet Calculator',
    category: 'RECON',
    icon: Network,
    description: 'IPv4 subnet ranges, netmask, wildcard & binary allocation',
    theme: {
      activeBg: ' bg-teal-500/15 to-transparent',
      activeBorder: 'border-teal-500/50',
      activeText: 'text-teal-200',
      iconBg: 'bg-teal-500/20',
      iconBorder: 'border-teal-500/40',
      iconColor: 'text-teal-300',
      badgeBg: 'bg-teal-950/80',
      badgeBorder: 'border-teal-700/60',
      badgeText: 'text-teal-300',
      accentBar: 'bg-teal-400',
    },
  },

  // 2. WEB & APP SECURITY
  {
    id: 'ssl',
    label: 'SSL/TLS Certificate Inspector',
    category: 'WEB',
    icon: Lock,
    description: 'X.509 certificate chain, expiry alerts, SANs & cipher rating',
    theme: {
      activeBg: ' bg-emerald-500/15 to-transparent',
      activeBorder: 'border-emerald-500/50',
      activeText: 'text-emerald-200',
      iconBg: 'bg-emerald-500/20',
      iconBorder: 'border-emerald-500/40',
      iconColor: 'text-emerald-300',
      badgeBg: 'bg-emerald-950/80',
      badgeBorder: 'border-emerald-700/60',
      badgeText: 'text-emerald-300',
      accentBar: 'bg-emerald-400',
    },
  },
  {
    id: 'headers',
    label: 'Security Headers Evaluator',
    category: 'WEB',
    icon: ShieldCheck,
    description: 'HSTS, CSP injection check, XFO, CORS & cookie security flags',
    theme: {
      activeBg: ' bg-cyan-500/15 to-transparent',
      activeBorder: 'border-cyan-500/50',
      activeText: 'text-cyan-200',
      iconBg: 'bg-cyan-500/20',
      iconBorder: 'border-cyan-500/40',
      iconColor: 'text-cyan-300',
      badgeBg: 'bg-cyan-950/80',
      badgeBorder: 'border-cyan-700/60',
      badgeText: 'text-cyan-300',
      accentBar: 'bg-cyan-400',
    },
  },
  {
    id: 'jwt',
    label: 'JWT Auditor & Exploit Checker',
    category: 'WEB',
    icon: Key,
    description: 'Base64 decoder, alg:none exploit test & HMAC dictionary cracker',
    theme: {
      activeBg: ' bg-fuchsia-500/15 to-transparent',
      activeBorder: 'border-fuchsia-500/50',
      activeText: 'text-fuchsia-200',
      iconBg: 'bg-fuchsia-500/20',
      iconBorder: 'border-fuchsia-500/40',
      iconColor: 'text-fuchsia-300',
      badgeBg: 'bg-fuchsia-950/80',
      badgeBorder: 'border-fuchsia-700/60',
      badgeText: 'text-fuchsia-300',
      accentBar: 'bg-fuchsia-400',
    },
  },
  {
    id: 'links',
    label: 'Link & Redirection Checker',
    category: 'WEB',
    icon: Link2,
    description: 'Multi-hop tracer, shortener unmasking, IDN punycode & threat scoring',
    theme: {
      activeBg: ' bg-sky-500/15 to-transparent',
      activeBorder: 'border-sky-500/50',
      activeText: 'text-sky-200',
      iconBg: 'bg-sky-500/20',
      iconBorder: 'border-sky-500/40',
      iconColor: 'text-sky-300',
      badgeBg: 'bg-sky-950/80',
      badgeBorder: 'border-sky-700/60',
      badgeText: 'text-sky-300',
      accentBar: 'bg-sky-400',
    },
  },

  // 3. THREAT HUNTING & SIEM
  {
    id: 'purview',
    label: 'Defender & Purview Audit',
    category: 'THREAT',
    icon: ShieldAlert,
    description: 'M365 UAL triage, Global Admin tampering, BEC rules & privilege abuse',
    theme: {
      activeBg: ' bg-red-500/15 to-transparent',
      activeBorder: 'border-red-500/50',
      activeText: 'text-red-200',
      iconBg: 'bg-red-500/20',
      iconBorder: 'border-red-500/40',
      iconColor: 'text-red-300',
      badgeBg: 'bg-red-950/80',
      badgeBorder: 'border-red-700/60',
      badgeText: 'text-red-300',
      accentBar: 'bg-red-400',
    },
  },
  {
    id: 'windows-events',
    label: 'Windows Event & Sysmon Triage',
    category: 'THREAT',
    icon: Monitor,
    description: 'Triage XML/JSON event exports: log clearing, brute force, RDP, accounts, services, command lines',
    theme: {
      activeBg: ' bg-purple-500/15 to-transparent',
      activeBorder: 'border-purple-500/50',
      activeText: 'text-purple-200',
      iconBg: 'bg-purple-500/20',
      iconBorder: 'border-purple-500/40',
      iconColor: 'text-purple-300',
      badgeBg: 'bg-purple-950/80',
      badgeBorder: 'border-purple-700/60',
      badgeText: 'text-purple-300',
      accentBar: 'bg-purple-400',
    },
  },
  {
    id: 'powershell',
    label: 'Tenant PowerShell & IR Hub',
    category: 'THREAT',
    icon: Terminal,
    description: 'M365 incident response scripts, rogue forwarders hunter & deobfuscator',
    theme: {
      activeBg: ' bg-blue-500/15 to-transparent',
      activeBorder: 'border-blue-500/50',
      activeText: 'text-blue-200',
      iconBg: 'bg-blue-500/20',
      iconBorder: 'border-blue-500/40',
      iconColor: 'text-blue-300',
      badgeBg: 'bg-blue-950/80',
      badgeBorder: 'border-blue-700/60',
      badgeText: 'text-blue-300',
      accentBar: 'bg-blue-400',
    },
  },
  {
    id: 'intel-pivot',
    label: 'Threat Intel Pivot Hub',
    category: 'THREAT',
    icon: Globe,
    description: '1-click multi-engine IOC launcher (VirusTotal, AbuseIPDB, Shodan, Talos)',
    theme: {
      activeBg: ' bg-cyan-500/15 to-transparent',
      activeBorder: 'border-cyan-500/50',
      activeText: 'text-cyan-200',
      iconBg: 'bg-cyan-500/20',
      iconBorder: 'border-cyan-500/40',
      iconColor: 'text-cyan-300',
      badgeBg: 'bg-cyan-950/80',
      badgeBorder: 'border-cyan-700/60',
      badgeText: 'text-cyan-300',
      accentBar: 'bg-cyan-400',
    },
  },
  {
    id: 'cvss',
    label: 'CVSS v3.1 Calculator',
    category: 'THREAT',
    icon: ShieldAlert,
    description: 'Vulnerability scoring, vector builder & FIRST.org severity math',
    theme: {
      activeBg: ' bg-rose-500/15 to-transparent',
      activeBorder: 'border-rose-500/50',
      activeText: 'text-rose-200',
      iconBg: 'bg-rose-500/20',
      iconBorder: 'border-rose-500/40',
      iconColor: 'text-rose-300',
      badgeBg: 'bg-rose-950/80',
      badgeBorder: 'border-rose-700/60',
      badgeText: 'text-rose-300',
      accentBar: 'bg-rose-400',
    },
  },
  {
    id: 'siem',
    label: 'SIEM Query Builder',
    category: 'THREAT',
    icon: Terminal,
    description: 'Builds IOC hunting queries for KQL, SPL, Elastic, Sigma and QRadar',
    theme: {
      activeBg: ' bg-blue-500/15 to-transparent',
      activeBorder: 'border-blue-500/50',
      activeText: 'text-blue-200',
      iconBg: 'bg-blue-500/20',
      iconBorder: 'border-blue-500/40',
      iconColor: 'text-blue-300',
      badgeBg: 'bg-blue-950/80',
      badgeBorder: 'border-blue-700/60',
      badgeText: 'text-blue-300',
      accentBar: 'bg-blue-400',
    },
  },
  {
    id: 'mitre',
    label: 'MITRE ATT&CK® Navigator',
    category: 'THREAT',
    icon: Target,
    description: 'Interactive tactics matrix, adversary TTPs & SOC detection rules',
    theme: {
      activeBg: ' bg-purple-500/15 to-transparent',
      activeBorder: 'border-purple-500/50',
      activeText: 'text-purple-200',
      iconBg: 'bg-purple-500/20',
      iconBorder: 'border-purple-500/40',
      iconColor: 'text-purple-300',
      badgeBg: 'bg-purple-950/80',
      badgeBorder: 'border-purple-700/60',
      badgeText: 'text-purple-300',
      accentBar: 'bg-purple-400',
    },
  },
  {
    id: 'ioc-extractor',
    label: 'Bulk IOC Extractor & Parser',
    category: 'THREAT',
    icon: FileSearch,
    description: 'Extract IPs, URLs, domains, hashes & CVEs from logs, then defang or refang them',
    theme: {
      activeBg: ' bg-violet-500/15 to-transparent',
      activeBorder: 'border-violet-500/50',
      activeText: 'text-violet-200',
      iconBg: 'bg-violet-500/20',
      iconBorder: 'border-violet-500/40',
      iconColor: 'text-violet-300',
      badgeBg: 'bg-violet-950/80',
      badgeBorder: 'border-violet-700/60',
      badgeText: 'text-violet-300',
      accentBar: 'bg-violet-400',
    },
  },

  // 4. CRYPTO & IDENTITY UTILITIES
  {
    id: 'converter',
    label: 'Data Conversion Hub',
    category: 'CRYPTO',
    icon: Binary,
    description: 'Base64, Hex, URL, Binary, ROT13, Timestamps & XOR ciphers',
    theme: {
      activeBg: ' bg-teal-500/15 to-transparent',
      activeBorder: 'border-teal-500/50',
      activeText: 'text-teal-200',
      iconBg: 'bg-teal-500/20',
      iconBorder: 'border-teal-500/40',
      iconColor: 'text-teal-300',
      badgeBg: 'bg-teal-950/80',
      badgeBorder: 'border-teal-700/60',
      badgeText: 'text-teal-300',
      accentBar: 'bg-teal-400',
    },
  },
  {
    id: 'crypto',
    label: 'Hash & Crypto Hub',
    category: 'CRYPTO',
    icon: Binary,
    description: 'MD5, SHA-1, SHA-256, SHA-512 & HMAC for text and files',
    theme: {
      activeBg: ' bg-pink-500/15 to-transparent',
      activeBorder: 'border-pink-500/50',
      activeText: 'text-pink-200',
      iconBg: 'bg-pink-500/20',
      iconBorder: 'border-pink-500/40',
      iconColor: 'text-pink-300',
      badgeBg: 'bg-pink-950/80',
      badgeBorder: 'border-pink-700/60',
      badgeText: 'text-pink-300',
      accentBar: 'bg-pink-400',
    },
  },
  {
    id: 'password',
    label: 'Password & Entropy',
    category: 'CRYPTO',
    icon: KeyRound,
    description: 'Shannon entropy & offline brute-force crack resistance time',
    theme: {
      activeBg: ' bg-rose-500/15 to-transparent',
      activeBorder: 'border-rose-500/50',
      activeText: 'text-rose-200',
      iconBg: 'bg-rose-500/20',
      iconBorder: 'border-rose-500/40',
      iconColor: 'text-rose-300',
      badgeBg: 'bg-rose-950/80',
      badgeBorder: 'border-rose-700/60',
      badgeText: 'text-rose-300',
      accentBar: 'bg-rose-400',
    },
  },
  {
    id: 'cheatsheet',
    label: 'Command Cheat-Sheet Hub',
    category: 'CRYPTO',
    icon: Terminal,
    description: 'Interactive playbooks for Windows, Linux, Git & Docker commands',
    theme: {
      activeBg: ' bg-emerald-500/15 to-transparent',
      activeBorder: 'border-emerald-500/50',
      activeText: 'text-emerald-200',
      iconBg: 'bg-emerald-500/20',
      iconBorder: 'border-emerald-500/40',
      iconColor: 'text-emerald-300',
      badgeBg: 'bg-emerald-950/80',
      badgeBorder: 'border-emerald-700/60',
      badgeText: 'text-emerald-300',
      accentBar: 'bg-emerald-400',
    },
  },
];

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (id: TabId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export function Sidebar({ activeTab, onSelectTab, collapsed, onToggleCollapse }: SidebarProps) {
  const [searchQuery, setSearchQuery] = React.useState('');

  const filteredTools = React.useMemo(() => {
    if (!searchQuery.trim()) return TOOLS;
    const q = searchQuery.toLowerCase();
    return TOOLS.filter(
      t =>
        t.label.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  const reconTools = filteredTools.filter(t => t.category === 'RECON');
  const webTools = filteredTools.filter(t => t.category === 'WEB');
  const threatTools = filteredTools.filter(t => t.category === 'THREAT');
  const cryptoTools = filteredTools.filter(t => t.category === 'CRYPTO');

  const renderSection = (title: string, icon: React.ReactNode, tools: TabItem[], colorScheme: string) => {
    if (tools.length === 0) return null;
    return (
      <div className="mb-5">
        {!collapsed && (
          <div className="px-3 mb-2 flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-slate-400">
            <div className="flex items-center gap-2">
              <span>{icon}</span>
              <span>{title}</span>
            </div>
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-[var(--bg-card)] border border-[var(--border-subtle)] text-slate-400 font-mono">
              {tools.length}
            </span>
          </div>
        )}
        <nav className="space-y-1.5">
          {tools.map(tool => {
            const Icon = tool.icon;
            const isActive = activeTab === tool.id;

            const buttonElement = (
              <button
                key={tool.id}
                onClick={() => onSelectTab(tool.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-left text-xs transition-colors duration-150 group relative ${
                  isActive
                    ? 'bg-[var(--bg-card)] border border-[var(--border-strong)] text-slate-50 font-semibold shadow-xs'
                    : 'text-slate-300 hover:bg-[var(--bg-card)] hover:text-slate-50 border border-transparent'
                }`}
              >
                <div
                  className={`p-1.5 rounded-lg transition-all flex-shrink-0 ${
                    isActive
                      ? `${tool.theme.iconBg} ${tool.theme.iconColor} border ${tool.theme.iconBorder} shadow-sm scale-105`
                      : `${tool.theme.iconBg} ${tool.theme.iconColor} opacity-75 group-hover:opacity-100 group-hover:scale-105 border border-transparent`
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                </div>
                {!collapsed && (
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-bold text-[11px] truncate tracking-tight">
                        {tool.label}
                      </span>
                      {tool.badge && (
                        <span
                          className={`text-[8px] px-1.5 py-0.2 rounded-full ${tool.theme.badgeBg} border ${tool.theme.badgeBorder} ${tool.theme.badgeText} font-mono font-black whitespace-nowrap flex-shrink-0`}
                        >
                          {tool.badge}
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {isActive && (
                  <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-l-full bg-[var(--accent)]" />
                )}
              </button>
            );

            if (collapsed) {
              return (
                <Tooltip key={tool.id}>
                  <TooltipTrigger asChild>{buttonElement}</TooltipTrigger>
                  <TooltipContent side="right" className="max-w-xs">
                    <div className="font-bold text-xs text-slate-50">{tool.label}</div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">{tool.description}</div>
                  </TooltipContent>
                </Tooltip>
              );
            }

            return buttonElement;
          })}
        </nav>
      </div>
    );
  };

  const isDashboardActive = activeTab === 'dashboard';

  return (
    <TooltipProvider delayDuration={100}>
      <aside
        className={`relative border-r border-[var(--border-subtle)] bg-[var(--bg-surface)] transition-all duration-200 flex flex-col justify-between shadow-xs flex-shrink-0 z-20 ${
          collapsed ? 'w-18' : 'w-72'
        }`}
      >
      <div className="p-3 flex-1 overflow-y-auto">
        {/* Collapse toggle button & Title */}
        <div className="flex items-center justify-between mb-3 px-1">
          {!collapsed && (
            <div className="flex items-center gap-2">
              <span className="text-xs tracking-normal text-slate-300 font-semibold">
                Security Tools
              </span>
              <span className="px-2 py-0.5 rounded-full bg-[var(--bg-card)] border border-[var(--border-subtle)] text-[10px] font-mono text-slate-400 font-medium">
                22
              </span>
            </div>
          )}
          <button
            onClick={onToggleCollapse}
            className="p-1.5 rounded-lg bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] text-slate-400 hover:text-slate-200 transition-colors ml-auto shadow-xs"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Top Pinned: Security Overview Dashboard */}
        <div className="mb-4">
          {(() => {
            const dashboardBtn = (
              <button
                onClick={() => onSelectTab('dashboard')}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left text-xs transition-colors duration-150 group relative ${
                  isDashboardActive
                    ? 'bg-[var(--bg-card)] border border-[var(--border-strong)] text-slate-50 font-semibold shadow-xs'
                    : 'text-slate-300 hover:bg-[var(--bg-card)] hover:text-slate-50 border border-transparent'
                }`}
              >
                <div
                  className={`p-2 rounded-lg transition-colors flex-shrink-0 ${
                    isDashboardActive
                      ? 'bg-[var(--bg-surface)] text-[var(--accent-text)] border border-[var(--border-strong)]'
                      : 'bg-[var(--bg-surface)] text-slate-400 border border-[var(--border-subtle)]'
                  }`}
                >
                  <LayoutDashboard className="w-4 h-4" />
                </div>
                {!collapsed && (
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-semibold text-xs text-slate-50">Security Overview</span>
                      <span className="text-[8px] px-1.5 py-0.5 rounded bg-[var(--accent-badge-bg)] border border-[var(--accent-badge-border)] text-[var(--accent-text)] font-bold uppercase">
                        OVERVIEW
                      </span>
                    </div>
                  </div>
                )}
                {isDashboardActive && (
                  <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-l-full bg-[var(--accent)]" />
                )}
              </button>
            );

            if (collapsed) {
              return (
                <Tooltip>
                  <TooltipTrigger asChild>{dashboardBtn}</TooltipTrigger>
                  <TooltipContent side="right" className="max-w-xs">
                    <div className="font-bold text-xs text-slate-50">Security Overview</div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">System Dashboard & Triage</div>
                  </TooltipContent>
                </Tooltip>
              );
            }
            return dashboardBtn;
          })()}
        </div>

        {/* Live Filter Search in Sidebar */}
        {!collapsed && (
          <div className="relative mb-4">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              placeholder="Search 22 tools..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-8 py-1.5 bg-[var(--bg-card)] border border-[var(--border-subtle)] focus:border-[var(--accent)] rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-50 p-0.5"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        )}

        {/* 1. Recon & Infrastructure (Cyan) */}
        {renderSection('Recon & Perimeter', <Globe2 className="w-3.5 h-3.5 text-cyan-400" />, reconTools, 'cyan')}

        {/* 2. Web & App Security (Emerald) */}
        {renderSection('Web & App Defense', <Lock className="w-3.5 h-3.5 text-emerald-400" />, webTools, 'emerald')}

        {/* 3. Threat Hunting & SIEM (Violet) */}
        {renderSection('Threat Hunting & SIEM', <Terminal className="w-3.5 h-3.5 text-purple-400" />, threatTools, 'purple')}

        {/* 4. Crypto & Identity Utilities (Amber) */}
        {renderSection('Crypto & Utilities', <Layers className="w-3.5 h-3.5 text-amber-400" />, cryptoTools, 'amber')}
      </div>

      {/* Footer Info */}
      {!collapsed && (
        <div className="p-3 pb-6 sm:pb-3 border-t border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[10px] text-slate-400 font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Logo className="w-4 h-4" />
            <span className="text-slate-50 font-bold tracking-wider">CYBER TOOLS</span>
          </div>
        </div>
      )}
    </aside>
  </TooltipProvider>
);
}
