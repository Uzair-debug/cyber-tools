'use client';

import { useState, useEffect, useCallback } from 'react';

export interface ToolHistoryEntry {
  id: string;
  value: string;
  label?: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface UseToolHistoryOptions {
  maxItems?: number;
  /**
   * false = keep history in memory for this page session only, never in localStorage.
   * Use it for tools whose inputs can be secrets (tokens, passwords, plaintext to hash or encrypt).
   */
  persist?: boolean;
}

const STORAGE_PREFIX = 'cyber_tool_history_';

/**
 * Format timestamp into clean, concise relative time (e.g. Just now, 5m ago, 2h ago, Yesterday)
 */
export function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diffSec = Math.floor((now - timestamp) / 1000);

  if (diffSec < 45) return 'Just now';
  if (diffSec < 90) return '1m ago';

  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;

  const diffDay = Math.floor(diffHour / 24);
  if (diffDay === 1) return 'Yesterday';
  if (diffDay < 7) return `${diffDay}d ago`;

  const date = new Date(timestamp);
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/**
 * Reusable local-first history hook for tools requiring repeated user queries/inputs.
 * Deduplicates inputs, maintains chronological order, caps entries, and guarantees SSR safety.
 */
export function useToolHistory(toolKey: string, options: UseToolHistoryOptions = {}) {
  const maxItems = options.maxItems ?? 10;
  const persistEnabled = options.persist ?? true;
  const storageKey = `${STORAGE_PREFIX}${toolKey}`;
  const [history, setHistory] = useState<ToolHistoryEntry[]>([]);
  const [isLoaded, setIsLoaded] = useState(false);

  // Load from localStorage on client-side mount (SSR hydration safe)
  useEffect(() => {
    try {
      if (!persistEnabled) {
        // Remove anything an older version of the portal stored for this tool
        localStorage.removeItem(storageKey);
        return;
      }
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          setHistory(parsed);
        }
      }
    } catch {
      // Storage disabled, blocked or parsing error
    } finally {
      setIsLoaded(true);
    }
  }, [storageKey, persistEnabled]);

  // Persist utility
  const persist = useCallback(
    (newHistory: ToolHistoryEntry[]) => {
      if (!persistEnabled) return;
      try {
        localStorage.setItem(storageKey, JSON.stringify(newHistory));
      } catch {
        // Handle storage quota limits or privacy blocking
      }
    },
    [storageKey, persistEnabled]
  );

  // Add new history entry, moving duplicates to the top
  const addEntry = useCallback(
    (value: string, label?: string, metadata?: Record<string, any>) => {
      const cleanValue = value.trim();
      if (!cleanValue) return;

      setHistory(prev => {
        // Filter out duplicate values (case-insensitive for domains/URLs/IPs)
        const filtered = prev.filter(
          item => item.value.trim().toLowerCase() !== cleanValue.toLowerCase()
        );

        const newEntry: ToolHistoryEntry = {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          value: cleanValue,
          label: label?.trim() || undefined,
          timestamp: Date.now(),
          metadata,
        };

        const updated = [newEntry, ...filtered].slice(0, maxItems);
        persist(updated);
        return updated;
      });
    },
    [maxItems, persist]
  );

  // Remove a single entry
  const removeEntry = useCallback(
    (id: string) => {
      setHistory(prev => {
        const updated = prev.filter(item => item.id !== id);
        persist(updated);
        return updated;
      });
    },
    [persist]
  );

  // Clear all entries for this tool
  const clearHistory = useCallback(() => {
    setHistory([]);
    try {
      localStorage.removeItem(storageKey);
    } catch {
      // ignore
    }
  }, [storageKey]);

  return {
    history,
    isLoaded,
    addEntry,
    removeEntry,
    clearHistory,
  };
}
