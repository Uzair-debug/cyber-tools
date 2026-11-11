'use client';

import React, { useEffect, useState } from 'react';
import { Search, X, Shield, ArrowRight, LayoutDashboard } from 'lucide-react';
import { TabId, TOOLS } from './Sidebar';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTab: (tabId: TabId) => void;
}

export function CommandPalette({ isOpen, onClose, onSelectTab }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const inputRef = React.useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      const timer = setTimeout(() => {
        inputRef.current?.focus();
      }, 60);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const showDashboard =
    !query.trim() ||
    'overview'.includes(query.toLowerCase()) ||
    'security overview'.includes(query.toLowerCase()) ||
    'dashboard'.includes(query.toLowerCase()) ||
    'home'.includes(query.toLowerCase()) ||
    'triage'.includes(query.toLowerCase());

  const filtered = TOOLS.filter(
    t =>
      t.label.toLowerCase().includes(query.toLowerCase()) ||
      t.description.toLowerCase().includes(query.toLowerCase()) ||
      t.category.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <Dialog open={isOpen} onOpenChange={open => !open && onClose()}>
      <DialogContent
        hideCloseButton
        onOpenAutoFocus={e => {
          e.preventDefault();
          inputRef.current?.focus();
        }}
        className="w-full max-w-xl bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-xl shadow-2xl p-0 overflow-hidden top-[25%] sm:top-[25%]"
      >
        <div className="sr-only">
          <DialogTitle>Command Palette</DialogTitle>
          <DialogDescription>
            Search and navigate to security tools, decoders, or recon engines.
          </DialogDescription>
        </div>

        {/* Search input header */}
        <div className="flex items-center px-4 py-3 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)]">
          <Search className="w-4 h-4 text-[var(--accent-text)] mr-3 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search security tools, decoders, or recon engines..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            autoFocus
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
          />
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-[var(--bg-card-hover)] focus:outline-none"
            aria-label="Close command palette"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2">
          {showDashboard && (
            <button
              onClick={() => {
                onSelectTab('dashboard');
                onClose();
              }}
              className="w-full flex items-center justify-between p-3 rounded-xl hover:bg-[var(--bg-card-hover)] transition-colors text-left group border border-[var(--border-subtle)] bg-[var(--bg-surface)] mb-1"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[var(--bg-card)] text-slate-300 group-hover:text-slate-50 transition-colors">
                  <LayoutDashboard className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-50">
                      Security Overview
                    </span>
                    <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-[var(--bg-card)] text-slate-300 border border-[var(--border-subtle)] font-bold">
                      OVERVIEW
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    System Overview, Universal Target Triage &amp; 21 Security Analyzers
                  </p>
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:translate-x-0.5 transition-all" />
            </button>
          )}

          {filtered.length === 0 && !showDashboard ? (
            <div className="p-6 text-center text-xs text-slate-400 font-mono">
              No matching modules found for &quot;{query}&quot;
            </div>
          ) : (
            <div className="space-y-1">
              {filtered.map(tool => {
                const Icon = tool.icon;
                return (
                  <button
                    key={tool.id}
                    onClick={() => {
                      onSelectTab(tool.id);
                      onClose();
                    }}
                    className="w-full flex items-center justify-between p-3 rounded-xl hover:bg-slate-800/80 transition-colors text-left group"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-slate-800 group-hover:bg-cyan-500/20 text-slate-300 group-hover:text-cyan-400 transition-colors">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                            {tool.label}
                          </span>
                          <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 font-bold">
                            {tool.category}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 truncate max-w-md">{tool.description}</p>
                      </div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2.5 bg-slate-950/80 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between font-mono">
          <span>Navigate tools instantly</span>
          <div className="flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[10px]">ESC</span> to close
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
