'use client';

import React from 'react';
import { Search, Terminal, FolderOpen } from 'lucide-react';
import { useCase } from '@/components/shared/CaseContext';
import { TabId } from './Sidebar';
import { ThemeSwitcher } from './ThemeSwitcher';
import { Logo } from '@/components/shared/Logo';

interface HeaderProps {
  onOpenCommandPalette: () => void;
  onToggleScratchpad: () => void;
  onToggleCaseReport: () => void;
  activeTab: TabId;
  onSelectTab: (id: TabId) => void;
  activeTabTitle?: string;
}

const ghostButton =
  'flex items-center gap-1.5 h-8 px-2.5 rounded-lg text-[13px] text-[var(--text-muted)] hover:text-[var(--text-main)] hover:bg-[var(--bg-card)] transition-colors whitespace-nowrap';

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
    <header className="h-12 min-h-[3rem] border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 sm:px-5 flex items-center gap-3 sticky top-0 z-30 flex-shrink-0">
      {/* Breadcrumb: the home link, then the open tool */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 min-w-0 flex-1">
        <button
          onClick={() => onSelectTab('dashboard')}
          className="flex items-center gap-2 rounded-md text-[13px] font-semibold text-[var(--text-main)] hover:opacity-80 transition-opacity flex-shrink-0"
        >
          <Logo className="w-5 h-5" />
          <span className="hidden sm:inline">Cyber Tools</span>
        </button>
        {!isDashboard && activeTabTitle && (
          <>
            <span aria-hidden className="text-[var(--border-strong)]">/</span>
            <span aria-current="page" className="text-[13px] text-[var(--text-muted)] truncate">
              {activeTabTitle}
            </span>
          </>
        )}
      </nav>

      {/* Search looks like a field because it opens one */}
      <button
        onClick={onOpenCommandPalette}
        className="hidden md:flex items-center gap-2 h-8 w-64 lg:w-72 px-2.5 rounded-lg bg-[var(--bg-app)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-[13px] text-[var(--text-muted)] transition-colors"
        aria-label="Search tools (Ctrl+K)"
      >
        <Search className="w-3.5 h-3.5 flex-shrink-0" />
        <span className="flex-1 text-left">Search tools</span>
        <kbd className="px-1.5 py-px rounded border border-[var(--border-subtle)] text-[11px] font-mono">Ctrl K</kbd>
      </button>

      <div className="flex items-center gap-0.5 flex-shrink-0">
        <button onClick={onOpenCommandPalette} className={`${ghostButton} md:hidden`} aria-label="Search tools">
          <Search className="w-4 h-4" />
        </button>
        <button onClick={onToggleCaseReport} className={ghostButton} aria-label={`Open case dossier, ${caseItems.length} findings`}>
          <FolderOpen className="w-4 h-4" />
          <span className="hidden lg:inline">Case dossier</span>
          {caseItems.length > 0 && (
            <span className="min-w-[1.25rem] px-1 rounded-full bg-[var(--accent)] text-white text-[11px] font-semibold text-center leading-5">
              {caseItems.length}
            </span>
          )}
        </button>
        <button onClick={onToggleScratchpad} className={ghostButton} aria-label="Open defanger and scratchpad">
          <Terminal className="w-4 h-4" />
          <span className="hidden lg:inline">Defanger</span>
        </button>
        <ThemeSwitcher />
      </div>
    </header>
  );
}
