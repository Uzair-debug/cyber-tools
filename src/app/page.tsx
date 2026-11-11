'use client';

import React, { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import { Sidebar, TabId, TOOLS } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { CommandPalette } from '@/components/layout/CommandPalette';
import { QuickScratchpadDrawer } from '@/components/layout/QuickScratchpadDrawer';
import { CaseReportDrawer } from '@/components/layout/CaseReportDrawer';
import { CaseProvider } from '@/components/shared/CaseContext';
import { ThemeProvider } from '@/components/shared/ThemeContext';
import { ToolErrorBoundary } from '@/components/shared/ToolErrorBoundary';
import { DashboardOverview } from '@/components/dashboard/DashboardOverview';
import { LayoutDashboard, ChevronLeft } from 'lucide-react';

// Each tool is code-split into its own chunk and only downloaded the first time it is opened
const ToolLoading = () => (
  <div className="p-8 rounded-2xl bg-[var(--bg-card)] border border-[var(--border-subtle)] text-center text-xs font-mono text-[var(--text-muted)]">
    Loading tool...
  </div>
);
const lazyTool = (load: () => Promise<React.ComponentType>) => dynamic(load, { loading: ToolLoading });

// 1. Recon & Infrastructure Modules
const EmailAnalyzer = lazyTool(() => import('@/components/email-analyzer/EmailAnalyzer').then(m => m.EmailAnalyzer));
const DomainRecon = lazyTool(() => import('@/components/domain-recon/DomainRecon').then(m => m.DomainRecon));
const IpThreatHub = lazyTool(() => import('@/components/ip-hub/IpThreatHub').then(m => m.IpThreatHub));
const PortIntelGuide = lazyTool(() => import('@/components/port-intel/PortIntelGuide').then(m => m.PortIntelGuide));
const CidrCalculator = lazyTool(() => import('@/components/cidr-calculator/CidrCalculator').then(m => m.CidrCalculator));

// 2. Web & App Security Modules
const SslInspector = lazyTool(() => import('@/components/ssl-inspector/SslInspector').then(m => m.SslInspector));
const SecurityHeadersEvaluator = lazyTool(() => import('@/components/security-headers/SecurityHeadersEvaluator').then(m => m.SecurityHeadersEvaluator));
const JwtAuditor = lazyTool(() => import('@/components/jwt-auditor/JwtAuditor').then(m => m.JwtAuditor));
const LinkChecker = lazyTool(() => import('@/components/link-checker/LinkChecker').then(m => m.LinkChecker));

// 3. Threat Hunting & SIEM Modules
const PurviewLogAnalyzer = lazyTool(() => import('@/components/purview-analyzer/PurviewLogAnalyzer').then(m => m.PurviewLogAnalyzer));
const WindowsEventAnalyzer = lazyTool(() => import('@/components/windows-events/WindowsEventAnalyzer').then(m => m.WindowsEventAnalyzer));
const TenantPowerShellHub = lazyTool(() => import('@/components/tenant-powershell/TenantPowerShellHub').then(m => m.TenantPowerShellHub));
const ThreatIntelPivot = lazyTool(() => import('@/components/intel-pivot/ThreatIntelPivot').then(m => m.ThreatIntelPivot));
const CvssCalculator = lazyTool(() => import('@/components/cvss-calculator/CvssCalculator').then(m => m.CvssCalculator));
const SiemQueryTranslator = lazyTool(() => import('@/components/siem-translator/SiemQueryTranslator').then(m => m.SiemQueryTranslator));
const MitreNavigator = lazyTool(() => import('@/components/mitre-navigator/MitreNavigator').then(m => m.MitreNavigator));
const IocExtractor = lazyTool(() => import('@/components/ioc-extractor/IocExtractor').then(m => m.IocExtractor));

// 4. Crypto & Identity Utilities Modules
const DataConverter = lazyTool(() => import('@/components/data-converter/DataConverter').then(m => m.DataConverter));
const HashCryptoUtility = lazyTool(() => import('@/components/hash-crypto/HashCryptoUtility').then(m => m.HashCryptoUtility));
const PasswordAnalyzer = lazyTool(() => import('@/components/password-analyzer/PasswordAnalyzer').then(m => m.PasswordAnalyzer));
const CommandCheatSheetHub = lazyTool(() => import('@/components/cheatsheet-hub/CommandCheatSheetHub').then(m => m.CommandCheatSheetHub));

const TOOL_PANES: Array<[TabId, React.ComponentType]> = [
  ['email', EmailAnalyzer],
  ['domain', DomainRecon],
  ['ip', IpThreatHub],
  ['ports', PortIntelGuide],
  ['cidr', CidrCalculator],
  ['ssl', SslInspector],
  ['headers', SecurityHeadersEvaluator],
  ['jwt', JwtAuditor],
  ['links', LinkChecker],
  ['purview', PurviewLogAnalyzer],
  ['windows-events', WindowsEventAnalyzer],
  ['powershell', TenantPowerShellHub],
  ['intel-pivot', ThreatIntelPivot],
  ['cvss', CvssCalculator],
  ['siem', SiemQueryTranslator],
  ['mitre', MitreNavigator],
  ['ioc-extractor', IocExtractor],
  ['converter', DataConverter],
  ['crypto', HashCryptoUtility],
  ['password', PasswordAnalyzer],
  ['cheatsheet', CommandCheatSheetHub],
];

export default function Home() {
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [scratchpadOpen, setScratchpadOpen] = useState(false);
  const [caseReportOpen, setCaseReportOpen] = useState(false);

  // Preserve active working state across tool switches (prevent unmounting on tab change)
  const [visitedTabs, setVisitedTabs] = useState<Set<TabId>>(() => new Set<TabId>(['dashboard']));

  useEffect(() => {
    setVisitedTabs(prev => {
      if (prev.has(activeTab)) return prev;
      const next = new Set(prev);
      next.add(activeTab);
      return next;
    });
  }, [activeTab]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const activeToolObj = TOOLS.find(t => t.id === activeTab);
  const isDashboard = activeTab === 'dashboard';

  return (
    <ThemeProvider>
      <CaseProvider>
        <div className="flex h-screen w-screen overflow-hidden bg-[var(--bg-app)] text-[var(--text-main)] transition-colors duration-200 relative">
        {/* Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative z-10">
          {/* Header */}
          <Header
            activeTabTitle={activeToolObj?.label || 'Security Overview'}
            activeTab={activeTab}
            onSelectTab={setActiveTab}
            onOpenCommandPalette={() => setCommandPaletteOpen(true)}
            onToggleScratchpad={() => setScratchpadOpen(!scratchpadOpen)}
            onToggleCaseReport={() => setCaseReportOpen(!caseReportOpen)}
          />

          {/* Scrollable Tool Work Area */}
          <main className="flex-1 overflow-y-auto p-3 sm:p-4 md:p-6 w-full mx-auto relative">
            {/* Sub-Header Banner (when inside a specific tool) */}
            {!isDashboard && activeToolObj && (
              <div className="mb-6 flex flex-wrap items-center justify-between gap-3 p-3 sm:p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border-subtle)] shadow-sm">
                <div className="flex items-center gap-2 sm:gap-3 min-w-0">
                  <button
                    onClick={() => setActiveTab('dashboard')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-xs font-medium text-slate-200 transition-colors"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                    <span>Overview</span>
                  </button>

                  <div className="h-4 w-px bg-[var(--border-subtle)] hidden sm:block" />

                  <span className="text-sm text-[var(--text-muted)] hidden lg:inline truncate max-w-xl">
                    {activeToolObj.description}
                  </span>
                </div>

              </div>
            )}

            {/* Dashboard / Mission Control */}
            <div className={isDashboard ? 'block' : 'hidden'}>
              <DashboardOverview
                onSelectTab={setActiveTab}
                onOpenScratchpad={() => setScratchpadOpen(true)}
                onOpenCaseReport={() => setCaseReportOpen(true)}
              />
            </div>

            {/* Tools stay mounted once visited, so each has its own error boundary */}
            {TOOL_PANES.filter(([id]) => visitedTabs.has(id)).map(([id, Tool]) => (
              <div key={id} className={activeTab === id ? 'block' : 'hidden'}>
                <ToolErrorBoundary title={TOOLS.find(t => t.id === id)?.label ?? 'This tool'}>
                  <Tool />
                </ToolErrorBoundary>
              </div>
            ))}
          </main>
        </div>

        {/* Global Command Palette */}
        <CommandPalette
          isOpen={commandPaletteOpen}
          onClose={() => setCommandPaletteOpen(false)}
          onSelectTab={tabId => setActiveTab(tabId)}
        />

        {/* Persistent Quick Defanger / Scratchpad Drawer */}
        <QuickScratchpadDrawer
          isOpen={scratchpadOpen}
          onClose={() => setScratchpadOpen(false)}
        />

        {/* Unified Investigation Case Workspace & Report Drawer */}
        <CaseReportDrawer
          isOpen={caseReportOpen}
          onClose={() => setCaseReportOpen(false)}
        />
        </div>
      </CaseProvider>
    </ThemeProvider>
  );
}
