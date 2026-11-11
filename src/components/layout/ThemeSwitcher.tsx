'use client';

import React from 'react';
import { Check, ChevronDown, Palette } from 'lucide-react';
import { useTheme, THEMES } from '../shared/ThemeContext';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';

export function ThemeSwitcher() {
  const { theme, setTheme, activeThemeConfig } = useTheme();

  return (
    <DropdownMenu>
      {/* Switcher Button Trigger */}
      <DropdownMenuTrigger asChild>
        <button
          className="flex items-center gap-1.5 h-8 px-2.5 rounded-lg text-[13px] text-[var(--text-muted)] hover:text-[var(--text-main)] hover:bg-[var(--bg-card)] transition-colors flex-shrink-0 group"
          aria-label={`Theme: ${activeThemeConfig.name}`}
        >
          <Palette className="w-4 h-4" />
          <span className="hidden xl:inline">{activeThemeConfig.name}</span>
          <ChevronDown className="w-3 h-3 transition-transform duration-150 group-data-[state=open]:rotate-180" />
        </button>
      </DropdownMenuTrigger>

      {/* Dropdown Menu Content */}
      <DropdownMenuContent align="end" className="w-64 p-2 bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-xl shadow-xl">
        <DropdownMenuLabel className="px-2 py-1.5 text-xs font-medium text-[var(--text-muted)]">Theme</DropdownMenuLabel>

        <DropdownMenuSeparator className="bg-[var(--border-subtle)]" />

        <div className="space-y-1 mt-1">
          {THEMES.map(t => {
            const isActive = theme === t.id;
            return (
              <DropdownMenuItem
                key={t.id}
                onClick={() => setTheme(t.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-left text-xs transition-colors ${
                  isActive
                    ? 'bg-[var(--bg-surface)] border border-[var(--border-strong)] font-semibold text-slate-50'
                    : 'text-slate-300 hover:bg-[var(--bg-surface)] hover:text-slate-50 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <span aria-hidden className="w-4 h-4 rounded-full border border-[var(--border-strong)] flex-shrink-0" style={{ background: t.previewColor }} />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs">{t.name}</span>
                    </div>
                    <span className="text-[11px] text-slate-400 block">
                      {t.subtitle}
                    </span>
                  </div>
                </div>
                {isActive && <Check className="w-4 h-4 text-[var(--accent-text)]" />}
              </DropdownMenuItem>
            );
          })}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
