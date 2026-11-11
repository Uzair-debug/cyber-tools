'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';

export interface CaseItem {
  id: string;
  tool: string;
  title: string;
  category: 'RECON' | 'WEB' | 'THREAT' | 'CRYPTO';
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
  timestamp: string;
  summary: string;
  details: Record<string, any>;
  notes?: string;
}

interface CaseContextType {
  caseItems: CaseItem[];
  addItem: (item: Omit<CaseItem, 'id' | 'timestamp'>) => void;
  removeItem: (id: string) => void;
  updateNotes: (id: string, notes: string) => void;
  clearCase: () => void;
  exportMarkdown: () => string;
  exportJson: () => string;
}

const CaseContext = createContext<CaseContextType | undefined>(undefined);

const LOCAL_STORAGE_KEY = 'cyber_tools_case_items_v1';

export function CaseProvider({ children }: { children: React.ReactNode }) {
  const [caseItems, setCaseItems] = useState<CaseItem[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (saved) {
        setCaseItems(JSON.parse(saved));
      }
    } catch (e) {
      console.error('Failed to load case items from localStorage', e);
    }
    setMounted(true);
  }, []);

  useEffect(() => {
    if (mounted) {
      try {
        localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(caseItems));
      } catch (e) {
        console.error('Failed to save case items to localStorage', e);
      }
    }
  }, [caseItems, mounted]);

  const addItem = (item: Omit<CaseItem, 'id' | 'timestamp'>) => {
    const newItem: CaseItem = {
      ...item,
      id: `case_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
    };
    setCaseItems(prev => [newItem, ...prev]);
  };

  const removeItem = (id: string) => {
    setCaseItems(prev => prev.filter(item => item.id !== id));
  };

  const updateNotes = (id: string, notes: string) => {
    setCaseItems(prev =>
      prev.map(item => (item.id === id ? { ...item, notes } : item))
    );
  };

  const clearCase = () => {
    setCaseItems([]);
  };

  const exportMarkdown = (): string => {
    const lines: string[] = [];
    lines.push('# SOC Incident Investigation Report');
    lines.push(`**Generated on:** ${new Date().toUTCString()}`);
    lines.push(`**Total Findings:** ${caseItems.length}`);
    lines.push('');
    lines.push('---');
    lines.push('');

    if (caseItems.length === 0) {
      lines.push('*No findings recorded in this investigation.*');
      return lines.join('\n');
    }

    // Summary Matrix
    lines.push('## Executive Summary & Findings Matrix');
    lines.push('');
    lines.push('| # | Tool | Title | Category | Severity | Timestamp |');
    lines.push('|---|---|---|---|---|---|');
    caseItems.forEach((item, index) => {
      lines.push(
        `| ${index + 1} | ${item.tool} | ${item.title} | ${item.category} | ${item.severity || 'INFO'} | ${item.timestamp.split('T')[0]} |`
      );
    });
    lines.push('');
    lines.push('---');
    lines.push('');

    // Detailed Evidence Section
    lines.push('## Detailed Evidence & Analysis');
    lines.push('');
    caseItems.forEach((item, index) => {
      lines.push(`### ${index + 1}. [${item.tool}] ${item.title}`);
      lines.push(`- **Severity:** \`${item.severity || 'INFO'}\``);
      lines.push(`- **Category:** ${item.category}`);
      lines.push(`- **Logged At:** ${item.timestamp}`);
      lines.push(`- **Summary:** ${item.summary}`);
      if (item.notes) {
        lines.push(`- **Analyst Notes:** *${item.notes}*`);
      }
      lines.push('');
      lines.push('```json');
      lines.push(JSON.stringify(item.details, null, 2));
      lines.push('```');
      lines.push('');
    });

    lines.push('---');
    lines.push('*Report generated automatically via Cyber Tools Portal (Zero-Trust Security Suite).*');

    return lines.join('\n');
  };

  const exportJson = (): string => {
    return JSON.stringify(
      {
        reportMeta: {
          title: 'Cyber Tools Investigation Bundle',
          generatedAt: new Date().toISOString(),
          totalFindings: caseItems.length,
        },
        findings: caseItems,
      },
      null,
      2
    );
  };

  return (
    <CaseContext.Provider
      value={{
        caseItems,
        addItem,
        removeItem,
        updateNotes,
        clearCase,
        exportMarkdown,
        exportJson,
      }}
    >
      {children}
    </CaseContext.Provider>
  );
}

export function useCase() {
  const context = useContext(CaseContext);
  if (!context) {
    throw new Error('useCase must be used within a CaseProvider');
  }
  return context;
}
