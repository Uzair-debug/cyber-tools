'use client';

import React, { useState } from 'react';
import {
  X,
  FileText,
  Download,
  Copy,
  Check,
  Trash2,
  ChevronDown,
  ChevronUp,
  FolderOpen,
  Edit3,
} from 'lucide-react';
import { useCase, CaseItem } from '@/components/shared/CaseContext';
import {
  Dialog,
  SheetContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';

interface CaseReportDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export function CaseReportDrawer({ isOpen, onClose }: CaseReportDrawerProps) {
  const { caseItems, removeItem, updateNotes, clearCase, exportMarkdown, exportJson } = useCase();
  const [copiedMd, setCopiedMd] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editingNotesId, setEditingNotesId] = useState<string | null>(null);
  const [noteInput, setNoteInput] = useState('');

  const handleCopyMd = () => {
    navigator.clipboard.writeText(exportMarkdown());
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(exportJson());
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleDownloadMd = () => {
    const content = exportMarkdown();
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-investigation-report-${new Date().toISOString().split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    const content = exportJson();
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-case-bundle-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const startEditNotes = (item: CaseItem) => {
    setEditingNotesId(item.id);
    setNoteInput(item.notes || '');
  };

  const saveNotes = (id: string) => {
    updateNotes(id, noteInput);
    setEditingNotesId(null);
  };

  const getSeverityBadge = (sev?: string) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-950/80 border border-rose-500/50 text-rose-400">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-orange-950/80 border border-orange-500/50 text-orange-400">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-950/80 border border-amber-500/50 text-amber-400">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-400">
            LOW
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-950/80 border border-cyan-500/50 text-cyan-400">
            INFO
          </span>
        );
    }
  };

  const criticalCount = caseItems.filter(i => i.severity === 'CRITICAL').length;
  const highCount = caseItems.filter(i => i.severity === 'HIGH').length;
  const medCount = caseItems.filter(i => i.severity === 'MEDIUM').length;

  return (
    <Dialog open={isOpen} onOpenChange={open => !open && onClose()}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-2xl md:max-w-2xl p-0 bg-[var(--bg-surface)] border-l border-slate-800 shadow-2xl flex flex-col"
      >
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800/80 bg-[var(--bg-app)] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-indigo-500/20 border border-indigo-500/40 text-indigo-400">
              <FolderOpen className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <DialogTitle className="text-base sm:text-lg font-bold text-slate-100">
                  Investigation Workspace & Report
                </DialogTitle>
                <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                  {caseItems.length} findings
                </span>
              </div>
              <DialogDescription className="text-xs text-slate-400">
                Unified SOC evidence collection, analyst notes & 1-click report export
              </DialogDescription>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors focus:outline-none"
            aria-label="Close case drawer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Metrics Bar */}
        {caseItems.length > 0 && (
          <div className="px-4 py-2.5 bg-slate-900/60 border-b border-slate-800/60 flex items-center justify-between text-xs">
            <div className="flex items-center space-x-3 text-slate-300">
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>{criticalCount} Critical</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                <span>{highCount} High</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                <span>{medCount} Med</span>
              </span>
            </div>
            <button
              onClick={clearCase}
              className="text-xs text-slate-400 hover:text-rose-400 transition-colors flex items-center space-x-1"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear All</span>
            </button>
          </div>
        )}

        {/* Main Item List */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-3">
          {caseItems.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8 border-2 border-dashed border-slate-800 rounded-2xl">
              <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 text-slate-500 mb-3">
                <FileText className="w-8 h-8" />
              </div>
              <h3 className="text-sm font-semibold text-slate-300">No findings logged yet</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Click the <strong>&quot;Add to Investigation&quot;</strong> button on any tool (IP Lookup, Domain Recon, SSL, Security Headers, CVSS, etc.) to collect evidence here.
              </p>
            </div>
          ) : (
            caseItems.map((item, index) => {
              const isExpanded = expandedId === item.id;
              const isEditingNotes = editingNotesId === item.id;

              return (
                <div
                  key={item.id}
                  className="p-3.5 bg-slate-900/70 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-all space-y-2.5"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center space-x-2 min-w-0">
                      <span className="text-xs font-mono text-slate-500">#{index + 1}</span>
                      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300">
                        {item.tool}
                      </span>
                      {getSeverityBadge(item.severity)}
                    </div>
                    <div className="flex items-center space-x-1">
                      <button
                        onClick={() => setExpandedId(isExpanded ? null : item.id)}
                        className="p-1 text-slate-400 hover:text-slate-200 rounded"
                        aria-label={isExpanded ? 'Collapse item details' : 'Expand item details'}
                      >
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4" />
                        ) : (
                          <ChevronDown className="w-4 h-4" />
                        )}
                      </button>
                      <button
                        onClick={() => removeItem(item.id)}
                        className="p-1 text-slate-400 hover:text-rose-400 rounded"
                        title="Remove finding"
                        aria-label="Remove finding"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  <div className="text-sm font-medium text-slate-200 truncate">
                    {item.title}
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2">{item.summary}</p>

                  {/* Analyst Notes */}
                  <div className="pt-1">
                    {isEditingNotes ? (
                      <div className="space-y-2">
                        <textarea
                          value={noteInput}
                          onChange={e => setNoteInput(e.target.value)}
                          placeholder="Add analyst observations, mitigation, or follow-up notes..."
                          className="w-full text-xs bg-black/50 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                          rows={2}
                        />
                        <div className="flex justify-end space-x-2">
                          <button
                            onClick={() => setEditingNotesId(null)}
                            className="px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200 font-mono"
                          >
                            Cancel
                          </button>
                          <button
                            onClick={() => saveNotes(item.id)}
                            className="px-2.5 py-1 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded-md font-mono"
                          >
                            Save Notes
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between text-xs bg-slate-950/60 border border-slate-800/60 rounded-lg px-2.5 py-1.5">
                        <span className="text-slate-400 italic truncate">
                          {item.notes ? `Note: "${item.notes}"` : 'No analyst notes attached'}
                        </span>
                        <button
                          onClick={() => startEditNotes(item)}
                          className="text-slate-400 hover:text-indigo-300 ml-2 flex items-center space-x-1"
                        >
                          <Edit3 className="w-3 h-3" />
                          <span>{item.notes ? 'Edit' : 'Add Note'}</span>
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Expandable JSON details */}
                  {isExpanded && (
                    <div className="pt-2 border-t border-slate-800">
                      <pre className="text-xs font-mono bg-black/60 p-2.5 rounded-lg text-slate-300 overflow-x-auto max-h-48">
                        {JSON.stringify(item.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Export Actions Footer */}
        {caseItems.length > 0 && (
          <div className="p-4 bg-[var(--bg-app)] border-t border-slate-800/80 space-y-2.5">
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={handleCopyMd}
                className="flex items-center justify-center space-x-2 py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl border border-slate-700 transition-colors"
              >
                {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedMd ? 'Copied Markdown!' : 'Copy Markdown Report'}</span>
              </button>
              <button
                onClick={handleDownloadMd}
                className="flex items-center justify-center space-x-2 py-2 px-3 bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold rounded-xl shadow-lg transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .MD Report</span>
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={handleCopyJson}
                className="flex items-center justify-center space-x-1.5 py-1.5 px-3 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs rounded-lg border border-slate-800 transition-colors"
              >
                {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedJson ? 'Copied JSON!' : 'Copy JSON'}</span>
              </button>
              <button
                onClick={handleDownloadJson}
                className="flex items-center justify-center space-x-1.5 py-1.5 px-3 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs rounded-lg border border-slate-800 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download JSON Bundle</span>
              </button>
            </div>
          </div>
        )}
      </SheetContent>
    </Dialog>
  );
}
