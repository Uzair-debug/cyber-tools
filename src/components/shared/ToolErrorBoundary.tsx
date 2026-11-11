'use client';

import React from 'react';
import { catchError, type ErrorInfo } from 'next/error';
import { AlertTriangle, RotateCcw } from 'lucide-react';

function ToolErrorFallback({ title }: { title: string }, { error, retry }: ErrorInfo) {
  const message = error instanceof Error ? error.message : String(error);

  return (
    <div role="alert" className="p-6 rounded-2xl bg-[var(--bg-card)] border border-[var(--border-subtle)] space-y-3">
      <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
        <AlertTriangle className="w-4 h-4 text-rose-400" />
        {title} stopped working
      </div>
      <p className="text-xs text-slate-400">
        Your other tools and the investigation case are not affected. Reloading the page clears unsaved work in every tool.
      </p>
      <p className="text-xs font-mono text-slate-500 break-all">{message}</p>
      <button
        onClick={() => retry()}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-subtle)] text-xs font-medium text-slate-200 transition-colors"
      >
        <RotateCcw className="w-3.5 h-3.5" />
        Try again
      </button>
    </div>
  );
}

// One boundary per tool: tools stay mounted while hidden, so an uncaught render error in any of
// them would otherwise take down the whole portal
export const ToolErrorBoundary = catchError(ToolErrorFallback);
