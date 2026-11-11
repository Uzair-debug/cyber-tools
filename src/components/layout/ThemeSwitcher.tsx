'use client';

import React from 'react';
import { Palette, Check, ChevronDown } from 'lucide-react';
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
          className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-slate-200 text-xs font-mono font-medium transition-all shadow-xs flex-shrink-0 group focus:outline-none"
          aria-label="Switch Theme Palette"
        >
          <span className="text-sm">{activeThemeConfig.icon}</span>
          <span className="hidden xl:inline text-slate-300">{activeThemeConfig.name}</span>
          <ChevronDown className="w-3 h-3 text-slate-400 transition-transform duration-150 group-data-[state=open]:rotate-180" />
        </button>
      </DropdownMenuTrigger>

      {/* Dropdown Menu Content */}
      <DropdownMenuContent align="end" className="w-64 p-2 bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-xl shadow-xl">
        <div className="px-2 py-1.5 flex items-center justify-between">
          <DropdownMenuLabel className="p-0 flex items-center gap-1.5 text-slate-300 font-mono text-xs">
            <Palette className="w-3.5 h-3.5 text-[var(--accent-text)]" />
            <span>Theme Palette</span>
          </DropdownMenuLabel>
          <span className="text-[10px] font-mono text-[var(--accent-text)] font-semibold">{THEMES.length} Presets</span>
        </div>

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
                  <span className="text-base">{t.icon}</span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs">{t.name}</span>
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ backgroundColor: t.previewColor }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-400 font-mono block">
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
