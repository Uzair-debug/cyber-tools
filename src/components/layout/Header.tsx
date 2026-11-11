'use client';

import React from 'react';
import { Command, Terminal, FolderOpen, LayoutDashboard } from 'lucide-react';
import { useCase } from '@/components/shared/CaseContext';
import { TabId } from './Sidebar';
import { ThemeSwitcher } from './ThemeSwitcher';
import { Logo } from '@/components/shared/Logo';
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from '@/components/ui/tooltip';

interface HeaderProps {
  onOpenCommandPalette: () => void;
  onToggleScratchpad: () => void;
  onToggleCaseReport: () => void;
  activeTab: TabId;
  onSelectTab: (id: TabId) => void;
  activeTabTitle?: string;
}

export function Header({
  onOpenCommandPalette,
  onToggleScratchpad,
  onToggleCaseReport,
  activeTab,
  onSelectTab,
  activeTabTitle,
}: HeaderProps) {
  const { caseItems } = useCase();
  const isDashboard = activeTab === 'dashboard';

  return (
    <TooltipProvider delayDuration={200}>
      <header className="h-16 min-h-[4rem] border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30 shadow-sm flex-shrink-0 transition-colors duration-200">
        {/* Left: Clean Brand & Navigation Breadcrumb */}
        <div className="flex items-center gap-3 min-w-0 flex-shrink">
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={() => onSelectTab('dashboard')}
                className="p-1.5 rounded-lg bg-[var(--bg-card)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] shadow-xs flex-shrink-0 flex items-center justify-center transition-all focus:outline-none focus:ring-2 focus:ring-[var(--border-strong)]"
                aria-label="Return to Security Overview"
              >
                <Logo className="w-6 h-6" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Return to Security Overview</TooltipContent>
          </Tooltip>

          <div className="flex items-center gap-2 min-w-0 truncate">
            <button
              onClick={() => onSelectTab('dashboard')}
              className="font-bold text-sm sm:text-base tracking-tight text-slate-50 whitespace-nowrap hover:opacity-85 transition-opacity"
            >
              CYBER TOOLS
            </button>

            <span className="text-slate-600 font-mono text-sm hidden sm:inline">/</span>

            {!isDashboard ? (
              <div className="flex items-center gap-2 min-w-0 truncate">
                <span className="text-xs font-mono font-semibold text-slate-200 truncate">
                  {activeTabTitle || 'Module'}
                </span>
                <button
                  onClick={() => onSelectTab('dashboard')}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] text-[11px] font-mono font-medium text-[var(--accent-text)] transition-colors flex-shrink-0"
                >
                  <LayoutDashboard className="w-3 h-3" />
                  <span>Overview</span>
                </button>
              </div>
            ) : (
              <span className="text-[10px] uppercase px-2.5 py-0.5 rounded-full bg-[var(--accent-badge-bg)] text-[var(--accent-text)] border border-[var(--accent-badge-border)] font-semibold whitespace-nowrap hidden sm:inline-block">
                Overview
              </span>
            )}

          </div>
        </div>

        {/* Right: Clean, Professional Action Buttons */}
        <div className="flex items-center gap-2 sm:gap-2.5 flex-shrink-0 ml-4">
          {/* Investigation Case Report Trigger */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={onToggleCaseReport}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-slate-200 text-xs font-medium transition-all shadow-xs whitespace-nowrap focus:outline-none"
                aria-label="Open Investigation Workspace & Report"
              >
                <FolderOpen className="w-3.5 h-3.5 text-purple-400 flex-shrink-0" />
                <span className="hidden sm:inline">Case Dossier</span>
                {caseItems.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full bg-purple-600 text-white text-[10px] font-bold">
                    {caseItems.length}
                  </span>
                )}
              </button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Open Investigation Workspace & Report</TooltipContent>
          </Tooltip>

          {/* Command Palette Trigger */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={onOpenCommandPalette}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-slate-300 text-xs font-mono transition-all shadow-xs whitespace-nowrap focus:outline-none"
                aria-label="Search Tools & Commands"
              >
                <Command className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                <span className="hidden md:inline font-medium">Search</span>
                <kbd className="hidden sm:inline px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[10px] text-slate-400">
                  Ctrl+K
                </kbd>
              </button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Search Tools & Commands (Ctrl + K)</TooltipContent>
          </Tooltip>

          {/* Quick Defanger Drawer Trigger */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={onToggleScratchpad}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-slate-200 text-xs font-medium transition-all shadow-xs whitespace-nowrap focus:outline-none"
                aria-label="Quick Defanger / Scratchpad Drawer"
              >
                <Terminal className="w-3.5 h-3.5 text-[var(--accent-text)] flex-shrink-0" />
                <span className="hidden sm:inline">Quick Defanger</span>
              </button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Quick Defanger & Incident Scratchpad</TooltipContent>
          </Tooltip>

          {/* Theme Switcher */}
          <ThemeSwitcher />
        </div>
      </header>
    </TooltipProvider>
  );
}
