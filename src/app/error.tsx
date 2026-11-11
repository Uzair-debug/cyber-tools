'use client';

import { useEffect } from 'react';

// Catches errors in the portal shell (sidebar, header, drawers). Tools have their own ToolErrorBoundary.
export default function Error({ error, retry }: { error: unknown; retry: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <main className="min-h-screen flex items-center justify-center p-6">
      <div role="alert" className="max-w-md p-6 rounded-2xl bg-[var(--bg-card)] border border-[var(--border-subtle)] space-y-3">
        <h1 className="text-sm font-bold text-slate-100">The portal hit an unexpected error</h1>
        <p className="text-xs text-slate-400">Your investigation case is saved in this browser and will still be there.</p>
        <button
          onClick={() => retry()}
          className="px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-xs font-medium text-slate-200"
        >
          Try again
        </button>
      </div>
    </main>
  );
}
