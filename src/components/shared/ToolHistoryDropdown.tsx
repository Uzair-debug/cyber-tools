'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Clock, Trash2, X, ArrowUpRight, History } from 'lucide-react';
import { ToolHistoryEntry, formatRelativeTime } from '@/lib/useToolHistory';

export interface ToolHistoryDropdownProps {
  history: ToolHistoryEntry[];
  onSelect: (value: string, entry: ToolHistoryEntry) => void;
  onRemove?: (id: string) => void;
  onClear?: () => void;
  title?: string;
  placeholder?: string;
  align?: 'left' | 'right';
  className?: string;
}

export function ToolHistoryDropdown({
  history,
  onSelect,
  onRemove,
  onClear,
  title = 'Recent Checks',
  placeholder = 'No recent checks recorded yet',
  align = 'left',
  className = '',
}: ToolHistoryDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click or Escape key
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const hasHistory = history.length > 0;

  return (
    <div className={`relative inline-block ${className}`} ref={dropdownRef}>
      {/* Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen(prev => !prev)}
        className={`px-3 py-2 rounded-xl text-xs font-mono font-medium flex items-center gap-1.5 transition-all cursor-pointer ${
          hasHistory
            ? 'bg-slate-900/90 hover:bg-slate-800/90 border border-slate-700/80 text-cyan-300 hover:text-cyan-200 shadow-sm'
            : 'bg-slate-950/60 border border-slate-800/60 text-slate-500 hover:text-slate-400'
        }`}
        title={hasHistory ? `View ${history.length} recent checks` : 'No recent checks'}
      >
        <History className="w-3.5 h-3.5 text-cyan-400" />
        <span>History</span>
        {hasHistory && (
          <span className="px-1.5 py-0.2 rounded-full bg-cyan-950/80 border border-cyan-500/40 text-[10px] font-bold text-cyan-300">
            {history.length}
          </span>
        )}
      </button>

      {/* Flyout Popover */}
      {isOpen && (
        <div
          className={`absolute top-full mt-2 w-72 sm:w-80 rounded-2xl bg-slate-950/95 border border-slate-800 shadow-2xl backdrop-blur-xl z-50 p-3 space-y-2 animate-in fade-in zoom-in-95 duration-150 ${
            align === 'right' ? 'right-0' : 'left-0'
          }`}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-1 pb-1.5 border-b border-slate-800/80">
            <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{title}</span>
            </div>

            {hasHistory && onClear && (
              <button
                type="button"
                onClick={() => {
                  onClear();
                  setIsOpen(false);
                }}
                className="text-[10px] font-mono text-slate-400 hover:text-rose-400 flex items-center gap-1 transition-colors px-1.5 py-0.5 rounded hover:bg-rose-950/40"
              >
                <Trash2 className="w-3 h-3" />
                <span>Clear All</span>
              </button>
            )}
          </div>

          {/* List of Entries */}
          {hasHistory ? (
            <div className="max-h-64 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
              {history.map(entry => (
                <div
                  key={entry.id}
                  className="group flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl bg-slate-900/60 hover:bg-slate-900 border border-slate-800/60 hover:border-cyan-500/40 transition-all cursor-pointer"
                  onClick={() => {
                    onSelect(entry.value, entry);
                    setIsOpen(false);
                  }}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-mono font-semibold text-slate-200 group-hover:text-cyan-300 truncate">
                        {entry.value}
                      </span>
                      <ArrowUpRight className="w-3 h-3 text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 mt-0.5">
                      <span>{formatRelativeTime(entry.timestamp)}</span>
                      {entry.label && (
                        <>
                          <span>•</span>
                          <span className="text-slate-400 truncate">{entry.label}</span>
                        </>
                      )}
                    </div>
                  </div>

                  {onRemove && (
                    <button
                      type="button"
                      onClick={e => {
                        e.stopPropagation();
                        onRemove(entry.id);
                      }}
                      className="p-1 rounded-lg text-slate-600 hover:text-rose-400 hover:bg-rose-950/50 opacity-60 group-hover:opacity-100 transition-all flex-shrink-0"
                      title="Remove entry"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs font-mono text-slate-500">
              <Clock className="w-6 h-6 text-slate-700 mx-auto mb-2 opacity-50" />
              <p>{placeholder}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
