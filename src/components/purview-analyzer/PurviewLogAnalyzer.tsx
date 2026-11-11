'use client';

import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldAlert,
  FileText,
  Upload,
  Copy,
  Check,
  Download,
  Trash2,
  Filter,
  Search,
  AlertTriangle,
  FolderPlus,
  Play,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
  Activity,
  FileCode,
  ShieldCheck,
  UserX,
  UserCheck,
  RotateCcw,
  Eye,
  X,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  Sliders,
  Target,
  Plus,
  Shield,
  Tag,
  Calendar,
  CheckSquare,
  Square,
  RefreshCw,
  ExternalLink,
  Printer,
} from 'lucide-react';
import {
  parsePurviewLogs,
  summarizeAuditData,
  applyTargetScope,
  isPrivateOrInternalIp,
  isServiceAccount,
  ParsedAuditRecord,
  CustomAuditRule,
  AuditTargetScope,
  PurviewReportOptions,
  DEFAULT_CUSTOM_RULES,
  DEFAULT_TARGET_SCOPE,
  DEFAULT_REPORT_OPTIONS,
} from './purview-parser';
import { buildPurviewReportModel, renderPurviewReportMarkdown, renderPurviewReportHtml } from './purview-report';
import type { PurviewParseRequest, PurviewParseResponse } from './purview-parser.worker';
import { useCase } from '@/components/shared/CaseContext';
import { csvCell } from '@/lib/utils';

type QuickThreatFilter =
  | 'ALL'
  | 'CRITICAL_HIGH'
  | 'SESSION_HIJACKING'
  | 'DELETIONS'
  | 'RENAMINGS'
  | 'PRIVILEGE'
  | 'FORWARDING'
  | 'OAUTH';

type PurviewViewTab = 'table' | 'scope' | 'rules' | 'report';

export function PurviewLogAnalyzer() {
  const [rawInput, setRawInput] = useState('');
  const [isInputExpanded, setIsInputExpanded] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [records, setRecords] = useState<ParsedAuditRecord[]>([]);
  const [truncatedNotice, setTruncatedNotice] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [maxRecordsLimit, setMaxRecordsLimit] = useState<number>(100000);
  const [uploadedFileInfo, setUploadedFileInfo] = useState<{
    name: string;
    sizeFormatted: string;
    isLargeStream?: boolean;
  } | null>(null);

  // Active full log content ref to decouple analysis engine from DOM textarea memory limits
  const activeContentRef = React.useRef<string>('');

  // Active view tab
  const [activeTab, setActiveTab] = useState<PurviewViewTab>('table');

  // Audit Target Scope specifications ("Specify what you want to audit")
  const [targetScope, setTargetScope] = useState<AuditTargetScope>(DEFAULT_TARGET_SCOPE);

  // Custom Detection Rules engine
  const [customRules, setCustomRules] = useState<CustomAuditRule[]>(DEFAULT_CUSTOM_RULES);
  const [isAddRuleModalOpen, setIsAddRuleModalOpen] = useState(false);
  const [newRuleDraft, setNewRuleDraft] = useState<Partial<CustomAuditRule>>({
    severity: 'HIGH',
    enabled: true,
    match: {},
  });

  // Customized Executive Report options
  const [reportOptions, setReportOptions] = useState<PurviewReportOptions>(DEFAULT_REPORT_OPTIONS);

  // Table filtering & search
  const [quickFilter, setQuickFilter] = useState<QuickThreatFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedWorkload, setSelectedWorkload] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Selected event modal/drawer
  const [selectedRecord, setSelectedRecord] = useState<ParsedAuditRecord | null>(null);

  const [copiedReport, setCopiedReport] = useState(false);
  const [addedToCase, setAddedToCase] = useState(false);

  const { addItem } = useCase();

  // Parsing runs in a Web Worker so large logs don't freeze the page.
  // Each run gets an id; results from superseded runs are ignored.
  const parserWorkerRef = React.useRef<Worker | null>(null);
  const parseRequestIdRef = React.useRef(0);

  useEffect(() => {
    return () => {
      parserWorkerRef.current?.terminate();
      parserWorkerRef.current = null;
    };
  }, []);

  const getParserWorker = (): Worker | null => {
    if (parserWorkerRef.current) return parserWorkerRef.current;
    if (typeof Worker === 'undefined') return null;
    try {
      parserWorkerRef.current = new Worker(new URL('./purview-parser.worker.ts', import.meta.url));
      return parserWorkerRef.current;
    } catch {
      return null;
    }
  };

  const applyParseResult = (parsed: ParsedAuditRecord[], truncated: boolean) => {
    setRecords(parsed);
    setTruncatedNotice(truncated);
    setCurrentPage(1);
    setIsInputExpanded(false);
  };

  // Keyboard shortcut to close drawer on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedRecord) {
        setSelectedRecord(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedRecord]);

  // Primary analysis runner
  const handleRunAnalysis = (inputToParse?: string, activeRules = customRules, limit = maxRecordsLimit) => {
    // If inputToParse is provided, use it.
    // Otherwise, prioritize the in-memory complete file (activeContentRef.current).
    // NEVER fall back to rawInput if it is only the preview placeholder starting with '// [Loaded file:'
    let content = inputToParse;
    if (!content) {
      if (activeContentRef.current && activeContentRef.current.trim() && !activeContentRef.current.startsWith('// [Loaded file:')) {
        content = activeContentRef.current;
      } else if (rawInput && rawInput.trim() && !rawInput.startsWith('// [Loaded file:')) {
        content = rawInput;
      } else if (activeContentRef.current && activeContentRef.current.trim()) {
        content = activeContentRef.current;
      }
    }

    if (!content || !content.trim()) {
      setRecords([]);
      return;
    }

    // Only update activeContentRef if an actual new log input was passed in
    if (inputToParse && !inputToParse.startsWith('// [Loaded file:')) {
      activeContentRef.current = inputToParse;
    }

    setIsAnalyzing(true);
    setParseError(null);

    const requestId = ++parseRequestIdRef.current;
    const worker = getParserWorker();

    if (worker) {
      worker.onmessage = (event: MessageEvent<PurviewParseResponse>) => {
        const response = event.data;
        if (response.id !== parseRequestIdRef.current) return; // superseded by a newer run
        if (response.ok) {
          applyParseResult(response.records, response.truncated);
        } else {
          setParseError(response.error);
        }
        setIsAnalyzing(false);
      };
      worker.onerror = event => {
        if (requestId !== parseRequestIdRef.current) return;
        setParseError(event.message || 'Audit log parser crashed (the file may be too large for browser memory).');
        setIsAnalyzing(false);
        worker.terminate();
        parserWorkerRef.current = null;
      };
      const request: PurviewParseRequest = { id: requestId, content, rules: activeRules, limit };
      worker.postMessage(request);
      return;
    }

    // Fallback when Web Workers are unavailable: parse on the main thread after a paint
    setTimeout(() => {
      try {
        const { records: parsed, truncated } = parsePurviewLogs(content, activeRules, limit);
        applyParseResult(parsed, truncated);
      } catch (e: any) {
        setParseError(e.message || 'Error parsing audit logs');
      } finally {
        setIsAnalyzing(false);
      }
    }, 50);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Reset input value so re-uploading the same file triggers onChange
    e.target.value = '';

    const fileSizeMb = file.size / (1024 * 1024);
    const sizeStr = fileSizeMb >= 1 ? `${fileSizeMb.toFixed(1)} MB` : `${(file.size / 1024).toFixed(0)} KB`;
    
    // Safety chunking: Read up to 200MB to fully accommodate 69,000+ to 100,000+ enterprise events
    const MAX_CHUNK_BYTES = 200 * 1024 * 1024;
    const isLargeStream = file.size > MAX_CHUNK_BYTES;
    const fileToRead = isLargeStream ? file.slice(0, MAX_CHUNK_BYTES) : file;

    setUploadedFileInfo({
      name: file.name,
      sizeFormatted: sizeStr,
      isLargeStream,
    });
    setParseError(null);
    setIsAnalyzing(true);

    const reader = new FileReader();
    reader.onerror = () => {
      setParseError('Failed to read the file. Please check system file permissions.');
      setIsAnalyzing(false);
    };

    reader.onload = event => {
      try {
        const content = event.target?.result as string;
        if (!content || !content.trim()) {
          setParseError('The uploaded file is empty.');
          setIsAnalyzing(false);
          return;
        }

        activeContentRef.current = content;

        // CRITICAL MEMORY FIX:
        // Do NOT set 50MB into the textarea rawInput state!
        // Setting a huge string into <textarea value={rawInput}> crashes the Chromium DOM layout renderer.
        // Instead, show a concise header preview:
        const previewLines = content.split('\n').slice(0, 8).join('\n');
        const previewText = `// [Loaded file: ${file.name} (${sizeStr})]\n// Ingestion capacity set to ${maxRecordsLimit.toLocaleString()} events.\n// Preview of first records:\n\n${previewLines}\n\n// ... [Full log loaded in forensic memory. Click 'Run Audit Analysis' or switch capacity to re-evaluate] ...`;
        setRawInput(previewText);

        handleRunAnalysis(content, customRules, maxRecordsLimit);
      } catch (err: any) {
        setParseError(`Memory allocation error: ${err.message || 'File too large for browser memory.'}`);
        setIsAnalyzing(false);
      }
    };

    reader.readAsText(fileToRead);
  };

  // Rule management helpers
  const handleToggleRule = (ruleId: string) => {
    const updated = customRules.map(r => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
    setCustomRules(updated);
    if (activeContentRef.current.trim() || rawInput.trim()) {
      handleRunAnalysis(undefined, updated);
    }
  };

  const handleDeleteRule = (ruleId: string) => {
    const updated = customRules.filter(r => r.id !== ruleId);
    setCustomRules(updated);
    if (activeContentRef.current.trim() || rawInput.trim()) {
      handleRunAnalysis(undefined, updated);
    }
  };

  const handleSaveNewRule = () => {
    if (!newRuleDraft.name?.trim()) return;

    const ruleToAdd: CustomAuditRule = {
      id: `custom_rule_${Date.now()}`,
      name: newRuleDraft.name.trim(),
      enabled: true,
      severity: newRuleDraft.severity || 'HIGH',
      match: {
        operation: newRuleDraft.match?.operation?.trim() || undefined,
        actor: newRuleDraft.match?.actor?.trim() || undefined,
        clientIp: newRuleDraft.match?.clientIp?.trim() || undefined,
        workload: newRuleDraft.match?.workload?.trim() || undefined,
        target: newRuleDraft.match?.target?.trim() || undefined,
        resultStatus: newRuleDraft.match?.resultStatus || undefined,
      },
      threatCategory: newRuleDraft.threatCategory?.trim() || 'Custom Detection',
      threatDescription: newRuleDraft.threatDescription?.trim() || `Matched custom detection rule: ${newRuleDraft.name}`,
      mitreTactic: newRuleDraft.mitreTactic?.trim() || 'Custom Tactic',
    };

    const updated = [...customRules, ruleToAdd];
    setCustomRules(updated);
    setIsAddRuleModalOpen(false);
    setNewRuleDraft({ severity: 'HIGH', enabled: true, match: {} });

    if (activeContentRef.current.trim() || rawInput.trim()) {
      handleRunAnalysis(undefined, updated);
    }
  };

  const handleResetRulesToDefault = () => {
    setCustomRules(DEFAULT_CUSTOM_RULES);
    if (activeContentRef.current.trim() || rawInput.trim()) {
      handleRunAnalysis(undefined, DEFAULT_CUSTOM_RULES);
    }
  };

  // 1. Scoped records based on user-specified audit targets
  const scopedRecords = useMemo(() => {
    return applyTargetScope(records, targetScope);
  }, [records, targetScope]);

  // 2. Filtered records (scoped + quick filters + search bar)
  const filteredRecords = useMemo(() => {
    return scopedRecords.filter(r => {
      // Quick Threat Category Filter
      if (quickFilter === 'CRITICAL_HIGH') {
        if (r.severity !== 'CRITICAL' && r.severity !== 'HIGH') return false;
      } else if (quickFilter === 'SESSION_HIJACKING') {
        if (!r.threatCategory?.includes('Session') && !r.threatCategory?.includes('Token')) return false;
      } else if (quickFilter === 'DELETIONS') {
        if (!r.threatCategory?.includes('Account Deletion')) return false;
      } else if (quickFilter === 'RENAMINGS') {
        if (!r.threatCategory?.includes('Account Renaming') && !r.threatCategory?.includes('Credential / Status')) return false;
      } else if (quickFilter === 'PRIVILEGE') {
        if (!r.threatCategory?.includes('Privilege Escalation')) return false;
      } else if (quickFilter === 'FORWARDING') {
        if (!r.threatCategory?.includes('Email Forwarding')) return false;
      } else if (quickFilter === 'OAUTH') {
        if (!r.threatCategory?.includes('OAuth Consent')) return false;
      }

      // Workload & Severity quick dropdowns
      if (selectedWorkload !== 'ALL' && r.workload !== selectedWorkload) return false;
      if (selectedSeverity !== 'ALL' && r.severity !== selectedSeverity) return false;

      // Free Search Query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          r.operation.toLowerCase().includes(q) ||
          r.userId.toLowerCase().includes(q) ||
          r.target.toLowerCase().includes(q) ||
          (r.threatDescription && r.threatDescription.toLowerCase().includes(q)) ||
          (r.matchedRuleName && r.matchedRuleName.toLowerCase().includes(q)) ||
          r.clientIp.includes(q) ||
          r.workload.toLowerCase().includes(q);
        if (!match) return false;
      }

      return true;
    });
  }, [scopedRecords, quickFilter, selectedWorkload, selectedSeverity, searchQuery]);

  // Summary calculation (on current filtered & scoped records)
  const summary = useMemo(() => summarizeAuditData(filteredRecords), [filteredRecords]);

  // Incident report: one model feeds the Markdown text and the print-ready (PDF) page.
  // Only built while the report tab is open, since it walks every record in scope.
  const reportModel = useMemo(
    () => (activeTab === 'report' ? buildPurviewReportModel(summary, filteredRecords, reportOptions, targetScope) : null),
    [activeTab, summary, filteredRecords, reportOptions, targetScope]
  );
  const incidentReport = useMemo(() => (reportModel ? renderPurviewReportMarkdown(reportModel) : ''), [reportModel]);
  const reportHtml = useMemo(() => (reportModel ? renderPurviewReportHtml(reportModel) : ''), [reportModel]);
  const [reportView, setReportView] = useState<'formatted' | 'markdown'>('formatted');

  // Paginated records
  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / pageSize));
  const paginatedRecords = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredRecords.slice(start, start + pageSize);
  }, [filteredRecords, currentPage, pageSize]);

  // Active Scope Count (indicates if user specified custom audit targets)
  const activeScopeCount = useMemo(() => {
    let count = 0;
    if (targetScope.targetUsers.trim()) count++;
    if (targetScope.excludeServiceAccounts) count++;
    if (targetScope.targetIps.trim()) count++;
    if (targetScope.onlyExternalIps) count++;
    if (targetScope.targetOperations.trim()) count++;
    if (targetScope.targetWorkload !== 'ALL') count++;
    if (targetScope.targetSeverity !== 'ALL') count++;
    if (targetScope.resultStatus !== 'ALL') count++;
    if (targetScope.timeRangeStart.trim() || targetScope.timeRangeEnd.trim()) count++;
    if (targetScope.matchedRuleOnly !== 'ALL') count++;
    return count;
  }, [targetScope]);

  const activeRulesCount = useMemo(() => {
    return customRules.filter(r => r.enabled).length;
  }, [customRules]);

  // Unique actors and IPs from raw records for quick selection chips
  const uniqueAvailableActors = useMemo(() => {
    const set = new Set<string>();
    records.forEach(r => {
      if (r.userId && r.userId !== 'Unknown User') set.add(r.userId);
    });
    return Array.from(set).slice(0, 8);
  }, [records]);

  const uniqueAvailableIps = useMemo(() => {
    const set = new Set<string>();
    records.forEach(r => {
      if (r.clientIp && r.clientIp !== 'N/A') set.add(r.clientIp);
    });
    return Array.from(set).slice(0, 8);
  }, [records]);

  const handleCopyReport = () => {
    navigator.clipboard.writeText(incidentReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleDownloadReport = () => {
    const blob = new Blob([incidentReport], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(reportOptions.caseTitle || 'purview-audit-report')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')}-${new Date().toISOString().split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Prints the report from a hidden same-origin frame; the browser's "Save as PDF" writes the file locally.
  // The frame is sandboxed without scripts, and every log value in the page is HTML-escaped.
  const handleExportPdf = () => {
    if (!reportHtml) return;
    const frame = document.createElement('iframe');
    frame.setAttribute('sandbox', 'allow-same-origin allow-modals');
    frame.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0;visibility:hidden';
    frame.srcdoc = reportHtml;
    const originalTitle = document.title;
    const cleanup = () => {
      document.title = originalTitle;
      frame.remove();
    };
    frame.onload = () => {
      const win = frame.contentWindow;
      if (!win) return cleanup();
      // Chrome names the PDF after the top-level page title
      document.title = (reportOptions.caseTitle || 'purview-audit-report').replace(/[\\/:*?"<>|]+/g, '-');
      win.addEventListener('afterprint', () => setTimeout(cleanup, 0));
      win.focus();
      win.print();
      setTimeout(cleanup, 60_000); // fallback if afterprint never fires
    };
    document.body.appendChild(frame);
  };

  const handleDownloadSiemCsv = () => {
    if (filteredRecords.length === 0) return;
    const headers = [
      'Timestamp',
      'Severity',
      'Operation',
      'Workload',
      'UserId',
      'ClientIP',
      'Status',
      'Target',
      'ThreatCategory',
      'MatchedRule',
      'ThreatDescription',
      'MitreTactic',
    ];
    const rows = filteredRecords.map(r =>
      [
        r.creationTime,
        r.severity,
        r.operation,
        r.workload,
        r.userId,
        r.clientIp,
        r.resultStatus,
        r.target,
        r.threatCategory,
        r.matchedRuleName,
        r.threatDescription,
        r.mitreTactic,
      ].map(csvCell)
    );
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `purview-siem-audit-events-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleAddToCase = () => {
    const totalThreats = summary.threatsDetected.criticalCount + summary.threatsDetected.highCount;
    addItem({
      tool: 'Purview & Defender Analyzer',
      title: `${reportOptions.caseTitle || 'Microsoft Audit Triage'}: ${totalThreats} High/Critical Threats Detected`,
      category: 'THREAT',
      severity:
        summary.threatsDetected.criticalCount > 0
          ? 'CRITICAL'
          : summary.threatsDetected.highCount > 0
          ? 'HIGH'
          : 'MEDIUM',
      summary: `Analyzed ${summary.totalRecords} events in scope (${reportOptions.organization || 'Tenant'}). Identified ${summary.threatsDetected.criticalCount} Critical & ${summary.threatsDetected.highCount} High security events (${summary.threatGroups.accountDeletions.length} deletions, ${summary.threatGroups.accountRenamings.length} renamings).`,
      details: {
        totalRecords: summary.totalRecords,
        timeRange: summary.timeRange,
        threatsSummary: summary.threatsDetected,
        accountDeletions: summary.threatGroups.accountDeletions.length,
        accountRenamings: summary.threatGroups.accountRenamings.length,
        privilegeEscalations: summary.threatGroups.privilegeEscalations.length,
        uniqueActors: summary.uniqueUsers,
        uniqueIps: summary.uniqueIps,
        targetScope,
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-950/90 border border-rose-500/60 text-rose-300">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-orange-950/90 border border-orange-500/60 text-orange-300">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-950/80 border border-amber-500/50 text-amber-300">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-300">
            LOW
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[10px] font-semibold rounded bg-slate-800 text-slate-400">
            INFO
          </span>
        );
    }
  };

  // spellCheck={false} is inherited by every field below. Chrome's Enhanced Spell Check and
  // Edge's Microsoft Editor send typed or pasted text to their cloud services, which would leak the logs.
  return (
    <div className="space-y-5 max-w-7xl mx-auto" spellCheck={false}>
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400 shadow-md">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                Microsoft Defender & Purview Audit Analyzer
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Forensic triage for M365 UAL logs with custom detection rules, target scoping & executive incident reporting
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsInputExpanded(!isInputExpanded)}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-slate-400" />
            <span>{isInputExpanded ? 'Hide Raw Input' : 'Paste / Ingest Logs'}</span>
          </button>
          <button
            onClick={handleAddToCase}
            disabled={records.length === 0}
            className="flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg transition-all disabled:opacity-50"
          >
            {addedToCase ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <FolderPlus className="w-3.5 h-3.5" />}
            <span>{addedToCase ? 'Added to Case!' : 'Add to Investigation'}</span>
          </button>
        </div>
      </div>

      {/* Collapsible Ingestion Bar */}
      {isInputExpanded && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-slate-200">Raw Log Input (JSON, NDJSON, or CSV export)</span>
              {uploadedFileInfo && (
                <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/50 text-[11px] text-emerald-300 font-mono">
                  <span>📁 {uploadedFileInfo.name} ({uploadedFileInfo.sizeFormatted})</span>
                  {uploadedFileInfo.isLargeStream && <span className="text-amber-400 font-bold ml-1">⚡ Stream Mode</span>}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <label className="cursor-pointer px-3 py-1.5 text-xs font-semibold bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg flex items-center space-x-1.5 hover:border-red-500/50 transition-colors shadow-sm">
                <Upload className="w-3.5 h-3.5 text-red-400" />
                <span>Upload Audit Log (CSV, JSON, NDJSON)</span>
                <input type="file" accept=".json,.csv,.txt,.log" onChange={handleFileUpload} className="hidden" />
              </label>
            </div>
          </div>

          <textarea
            value={rawInput}
            onChange={e => {
              setRawInput(e.target.value);
              activeContentRef.current = e.target.value;
              setUploadedFileInfo(null);
            }}
            placeholder="Paste raw Microsoft Purview / Defender audit logs here, or click 'Upload File' for large CSV/JSON logs..."
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            className="w-full h-32 p-3 bg-black/60 border border-slate-800 rounded-xl font-mono text-xs text-slate-200 focus:outline-none focus:border-red-500 resize-none"
          />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => {
                  setRawInput('');
                  activeContentRef.current = '';
                  setUploadedFileInfo(null);
                  setRecords([]);
                  setTruncatedNotice(false);
                  setParseError(null);
                }}
                className="text-xs text-slate-400 hover:text-rose-400 flex items-center space-x-1"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear Input</span>
              </button>

              <div className="flex items-center space-x-1.5">
                <Sliders className="w-3 h-3 text-red-400" />
                <span className="text-xs text-slate-400 font-medium">Ingestion Capacity:</span>
                <select
                  value={maxRecordsLimit}
                  onChange={e => {
                    const newLimit = Number(e.target.value);
                    setMaxRecordsLimit(newLimit);
                    if (activeContentRef.current.trim() || rawInput.trim()) {
                      handleRunAnalysis(undefined, undefined, newLimit);
                    }
                  }}
                  className="bg-slate-950 border border-slate-700 text-slate-200 rounded-lg px-2.5 py-1 text-xs font-semibold focus:outline-none focus:border-red-500 cursor-pointer"
                >
                  <option value={5000}>5,000 events (Quick Preview)</option>
                  <option value={25000}>25,000 events (Standard)</option>
                  <option value={50000}>50,000 events (Deep Hunt)</option>
                  <option value={100000}>100,000 events (Enterprise / All 69k+)</option>
                  <option value={250000}>250,000 events (Maximum Volume)</option>
                </select>
              </div>
            </div>

            <button
              onClick={() => handleRunAnalysis()}
              disabled={isAnalyzing}
              className="px-4 py-2 bg-red-600 text-white text-xs font-bold rounded-xl flex items-center space-x-1.5 shadow-md disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isAnalyzing ? 'Analyzing Logs...' : 'Run Audit Analysis'}</span>
            </button>
          </div>

          {parseError && (
            <div className="p-2.5 bg-rose-950/60 border border-rose-800 rounded-lg text-xs text-rose-300 font-mono">
              ⚠️ {parseError}
            </div>
          )}
        </div>
      )}

      {/* Truncated Notice if log exceeded safe limit */}
      {truncatedNotice && (
        <div className="p-3 bg-amber-950/60 border border-amber-800/80 rounded-xl text-xs text-amber-300 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <span>
            ⚡ <strong>Event Limit Reached:</strong> Successfully processed the first <strong>{records.length.toLocaleString()}</strong> records. If your file contains more events, expand capacity to ingest up to 250,000 events.
          </span>
          {maxRecordsLimit < 250000 && (
            <button
              onClick={() => {
                const nextLimit = maxRecordsLimit <= 5000 ? 50000 : maxRecordsLimit <= 50000 ? 100000 : 250000;
                setMaxRecordsLimit(nextLimit);
                handleRunAnalysis(undefined, undefined, nextLimit);
              }}
              className="px-3 py-1 bg-amber-500 hover:bg-amber-400 text-black font-bold rounded-lg transition-colors text-xs shrink-0 self-start sm:self-auto"
            >
              Expand to {maxRecordsLimit <= 5000 ? '50,000' : maxRecordsLimit <= 50000 ? '100,000' : '250,000'} Events
            </button>
          )}
        </div>
      )}

      {/* KPI Metrics Dashboard Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Total in Scope</span>
          <span className="text-2xl font-black text-slate-50 mt-0.5">{summary.totalRecords}</span>
          <span className="text-[10px] text-slate-500">Raw: {records.length}</span>
        </div>

        <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/40 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-rose-300 tracking-wider flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
            Critical Threats
          </span>
          <span className="text-2xl font-black text-rose-400 mt-0.5">{summary.threatsDetected.criticalCount}</span>
          <span className="text-[10px] text-rose-300/80">Immediate Action</span>
        </div>

        <div className="p-3.5 rounded-xl bg-orange-950/30 border border-orange-500/40 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-orange-300 tracking-wider">High-Risk Actions</span>
          <span className="text-2xl font-black text-orange-400 mt-0.5">{summary.threatsDetected.highCount}</span>
          <span className="text-[10px] text-orange-300/80">Privileged / BEC</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Active Actors</span>
          <span className="text-2xl font-black text-cyan-400 mt-0.5">{summary.uniqueUsers.length}</span>
          <span className="text-[10px] text-slate-500">Principals</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center text-center col-span-2 sm:col-span-1">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Originating IPs</span>
          <span className="text-2xl font-black text-purple-400 mt-0.5">{summary.uniqueIps.length}</span>
          <span className="text-[10px] text-slate-500">Endpoints</span>
        </div>
      </div>

      {/* Main View Mode Selector (4 Dedicated Workflow Sub-Tabs) */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex flex-wrap items-center gap-2">
          {/* Tab 1: SIEM Event Explorer */}
          <button
            onClick={() => setActiveTab('table')}
            className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'table'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Event Explorer ({filteredRecords.length})</span>
          </button>

          {/* Tab 2: Specify Target Scope */}
          <button
            onClick={() => setActiveTab('scope')}
            className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'scope'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Target className="w-3.5 h-3.5 text-amber-400" />
            <span>Specify Audit Scope</span>
            {activeScopeCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-mono">
                {activeScopeCount} Active
              </span>
            )}
          </button>

          {/* Tab 3: Custom Detection Rules Manager */}
          <button
            onClick={() => setActiveTab('rules')}
            className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'rules'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Detection Rules ({activeRulesCount})</span>
          </button>

          {/* Tab 4: Executive Incident Report */}
          <button
            onClick={() => setActiveTab('report')}
            className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'report'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileText className="w-3.5 h-3.5 text-rose-400" />
            <span>Executive Report & Criteria</span>
          </button>
        </div>

        <div className="flex items-center space-x-2">
          {activeScopeCount > 0 && (
            <button
              onClick={() => setTargetScope(DEFAULT_TARGET_SCOPE)}
              className="text-[11px] text-amber-400 hover:text-amber-300 flex items-center gap-1 font-mono"
              title="Clear all target scope filters"
            >
              <RotateCcw className="w-3 h-3" />
              Reset Scope
            </button>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: SIEM EVENT EXPLORER & COMPACT TABLE */}
      {/* ========================================================================= */}
      {activeTab === 'table' && (
        <div className="space-y-4">
          {/* Quick Threat Group Filter Pills */}
          <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
            <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
              <span>⚡ Attack Pattern Filters:</span>
              <span className="text-[11px] text-slate-400 font-normal">
                Showing {filteredRecords.length} of {records.length} records
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <button
                onClick={() => {
                  setQuickFilter('ALL');
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                  quickFilter === 'ALL'
                    ? 'bg-slate-700 text-slate-50 border border-slate-600 shadow-sm'
                    : 'bg-black/40 hover:bg-slate-800 text-slate-400 border border-slate-800'
                }`}
              >
                All Events ({scopedRecords.length})
              </button>

              <button
                onClick={() => {
                  setQuickFilter('CRITICAL_HIGH');
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                  quickFilter === 'CRITICAL_HIGH'
                    ? 'bg-rose-600 text-white shadow-sm'
                    : 'bg-rose-950/40 hover:bg-rose-900/50 text-rose-300 border border-rose-800/50'
                }`}
              >
                <span>🚨 Critical & High Threats</span>
                <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                  {summary.threatsDetected.criticalCount + summary.threatsDetected.highCount}
                </span>
              </button>

              {summary.threatGroups.sessionHijackings.length > 0 && (
                <button
                  onClick={() => {
                    setQuickFilter('SESSION_HIJACKING');
                    setCurrentPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1.5 ${
                    quickFilter === 'SESSION_HIJACKING'
                      ? ' bg-red-600 text-white shadow-lg font-black animate-pulse'
                      : 'bg-rose-950/60 hover:bg-rose-900/70 text-rose-200 border border-rose-600/60'
                  }`}
                >
                  <span>🚨 Stolen Session Injection</span>
                  <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px] font-mono">
                    {summary.threatGroups.sessionHijackings.length}
                  </span>
                </button>
              )}

              {summary.threatGroups.accountDeletions.length > 0 && (
                <button
                  onClick={() => {
                    setQuickFilter('DELETIONS');
                    setCurrentPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                    quickFilter === 'DELETIONS'
                      ? 'bg-red-600 text-white shadow-sm'
                      : 'bg-red-950/40 hover:bg-red-900/50 text-red-300 border border-red-800/50'
                  }`}
                >
                  <span>🗑️ Account Deletions</span>
                  <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                    {summary.threatGroups.accountDeletions.length}
                  </span>
                </button>
              )}

              {summary.threatGroups.accountRenamings.length > 0 && (
                <button
                  onClick={() => {
                    setQuickFilter('RENAMINGS');
                    setCurrentPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                    quickFilter === 'RENAMINGS'
                      ? 'bg-orange-600 text-white shadow-sm'
                      : 'bg-orange-950/40 hover:bg-orange-900/50 text-orange-300 border border-orange-800/50'
                  }`}
                >
                  <span>✏️ UPN & Identity Renamings</span>
                  <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                    {summary.threatGroups.accountRenamings.length}
                  </span>
                </button>
              )}

              {summary.threatGroups.privilegeEscalations.length > 0 && (
                <button
                  onClick={() => {
                    setQuickFilter('PRIVILEGE');
                    setCurrentPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                    quickFilter === 'PRIVILEGE'
                      ? 'bg-purple-600 text-white shadow-sm'
                      : 'bg-purple-950/40 hover:bg-purple-900/50 text-purple-300 border border-purple-800/50'
                  }`}
                >
                  <span>👑 Privilege Escalation</span>
                  <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                    {summary.threatGroups.privilegeEscalations.length}
                  </span>
                </button>
              )}

              {summary.threatGroups.emailForwardings.length > 0 && (
                <button
                  onClick={() => {
                    setQuickFilter('FORWARDING');
                    setCurrentPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                    quickFilter === 'FORWARDING'
                      ? 'bg-amber-600 text-white shadow-sm'
                      : 'bg-amber-950/40 hover:bg-amber-900/50 text-amber-300 border border-amber-800/50'
                  }`}
                >
                  <span>✉️ Inbox Forwarding Rules</span>
                  <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                    {summary.threatGroups.emailForwardings.length}
                  </span>
                </button>
              )}

              {summary.threatGroups.oauthConsents.length > 0 && (
                <button
                  onClick={() => {
                    setQuickFilter('OAUTH');
                    setCurrentPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                    quickFilter === 'OAUTH'
                      ? 'bg-pink-600 text-white shadow-sm'
                      : 'bg-pink-950/40 hover:bg-pink-900/50 text-pink-300 border border-pink-800/50'
                  }`}
                >
                  <span>🔑 OAuth Consents</span>
                  <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                    {summary.threatGroups.oauthConsents.length}
                  </span>
                </button>
              )}
            </div>
          </div>

          {/* Active Scope Criteria Notification Banner (if any target filters applied) */}
          {activeScopeCount > 0 && (
            <div className="p-3 bg-amber-950/40 border border-amber-600/40 rounded-xl flex items-center justify-between gap-2 text-xs text-amber-200">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-bold flex items-center gap-1 text-amber-300">
                  <Target className="w-3.5 h-3.5 text-amber-400" /> Target Audit Scope Active ({activeScopeCount} filters):
                </span>
                {targetScope.targetUsers && (
                  <span className="px-2 py-0.5 bg-black/40 rounded border border-amber-700/50 font-mono text-[11px]">
                    Users: {targetScope.targetUsers}
                  </span>
                )}
                {targetScope.excludeServiceAccounts && (
                  <span className="px-2 py-0.5 bg-black/40 rounded border border-amber-700/50 font-mono text-[11px]">
                    Service Accounts Excluded
                  </span>
                )}
                {targetScope.targetIps && (
                  <span className="px-2 py-0.5 bg-black/40 rounded border border-amber-700/50 font-mono text-[11px]">
                    IPs: {targetScope.targetIps}
                  </span>
                )}
                {targetScope.onlyExternalIps && (
                  <span className="px-2 py-0.5 bg-black/40 rounded border border-amber-700/50 font-mono text-[11px]">
                    Public IPs Only
                  </span>
                )}
                {targetScope.targetOperations && (
                  <span className="px-2 py-0.5 bg-black/40 rounded border border-amber-700/50 font-mono text-[11px]">
                    Ops: {targetScope.targetOperations}
                  </span>
                )}
              </div>
              <button
                onClick={() => setTargetScope(DEFAULT_TARGET_SCOPE)}
                className="text-[11px] underline text-amber-300 hover:text-slate-50 flex-shrink-0"
              >
                Clear Scope
              </button>
            </div>
          )}

          {/* Search, Workload & Severity Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Search operation, actor UPN, target, IP address, or detection rule name..."
                className="w-full pl-9 pr-3 py-2 bg-black/40 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-red-500 font-mono text-xs"
              />
            </div>

            <div className="flex items-center space-x-2 flex-wrap gap-y-2">
              <span className="text-slate-500">Workload:</span>
              <select
                value={selectedWorkload}
                onChange={e => {
                  setSelectedWorkload(e.target.value);
                  setCurrentPage(1);
                }}
                className="px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 focus:outline-none text-xs"
              >
                <option value="ALL">All Workloads</option>
                {summary.uniqueWorkloads.map(w => (
                  <option key={w} value={w}>
                    {w}
                  </option>
                ))}
              </select>

              <span className="text-slate-500">Severity:</span>
              <select
                value={selectedSeverity}
                onChange={e => {
                  setSelectedSeverity(e.target.value);
                  setCurrentPage(1);
                }}
                className="px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 focus:outline-none text-xs"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>

              <button
                onClick={handleDownloadSiemCsv}
                disabled={filteredRecords.length === 0}
                className="flex items-center space-x-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors disabled:opacity-40"
                title="Export filtered records to SIEM CSV format"
              >
                <Download className="w-3.5 h-3.5 text-rose-400" />
                <span>Export CSV</span>
              </button>
            </div>
          </div>

          {/* Clean Paginated Table View */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--bg-app)] border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-3">Time (UTC)</th>
                    <th className="py-3 px-2">Severity</th>
                    <th className="py-3 px-3">Workload</th>
                    <th className="py-3 px-3">Operation (Action)</th>
                    <th className="py-3 px-3">Actor (User)</th>
                    <th className="py-3 px-3">Target / Rule Match</th>
                    <th className="py-3 px-3">IP Address</th>
                    <th className="py-3 px-2 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {paginatedRecords.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-10 text-center text-xs text-slate-400">
                        <div className="space-y-2">
                          <p className="font-semibold text-slate-300">No audit events match the specified criteria.</p>
                          <p className="text-[11px] text-slate-500">
                            Try adjusting your search query, attack filters, or reset the target scope.
                          </p>
                          {activeScopeCount > 0 && (
                            <button
                              onClick={() => setTargetScope(DEFAULT_TARGET_SCOPE)}
                              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-amber-300 text-xs font-bold"
                            >
                              Reset Scope Filters
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ) : (
                    paginatedRecords.map(item => {
                      const isHighRisk = item.severity === 'CRITICAL' || item.severity === 'HIGH';

                      return (
                        <tr
                          key={item.id}
                          className={`hover:bg-slate-800/50 transition-colors ${
                            isHighRisk ? 'bg-rose-950/15' : ''
                          }`}
                        >
                          <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                            {item.creationTime ? item.creationTime.replace('T', ' ').replace('Z', '') : 'No timestamp'}
                          </td>

                          <td className="py-2.5 px-2 whitespace-nowrap">
                            {getSeverityBadge(item.severity)}
                          </td>

                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300">
                              {item.workload}
                            </span>
                          </td>

                          <td className="py-2.5 px-3 font-mono text-xs font-bold text-red-300 whitespace-nowrap">
                            {item.operation}
                          </td>

                          <td className="py-2.5 px-3 font-mono text-xs text-slate-200 max-w-[180px] truncate" title={item.userId}>
                            {item.userId}
                          </td>

                          <td className="py-2.5 px-3 text-xs max-w-[240px] truncate">
                            {item.matchedRuleName ? (
                              <span className="text-cyan-300 font-semibold flex items-center gap-1">
                                <Shield className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                                {item.matchedRuleName}
                              </span>
                            ) : item.threatDescription ? (
                              <span className="text-amber-300 font-semibold">{item.threatCategory}: {item.target}</span>
                            ) : (
                              <span className="text-slate-400">{item.target}</span>
                            )}
                          </td>

                          <td className="py-2.5 px-3 font-mono text-xs text-purple-300 whitespace-nowrap">
                            {item.clientIp}
                          </td>

                          <td className="py-2.5 px-2 text-right whitespace-nowrap">
                            <button
                              onClick={() => setSelectedRecord(item)}
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-slate-50 rounded border border-slate-700 text-[11px] transition-colors"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="px-4 py-3 bg-[var(--bg-app)] border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-400">
              <div className="flex items-center space-x-2">
                <span>Rows per page:</span>
                <select
                  value={pageSize}
                  onChange={e => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="bg-black/50 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
                <span>
                  Page {currentPage} of {totalPages} ({filteredRecords.length} records)
                </span>
              </div>

              <div className="flex items-center space-x-1">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                  title="Previous Page"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                  title="Next Page"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: AUDIT TARGET SCOPE & INVESTIGATION SPECIFIER */}
      {/* ========================================================================= */}
      {activeTab === 'scope' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Target className="w-4 h-4 text-amber-400" /> Specify Investigation Scope & Target Parameters
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Tailor your forensic audit to focus strictly on suspect user accounts, suspicious IPs, specific operations, or distinct time windows.
                </p>
              </div>

              <button
                onClick={() => setTargetScope(DEFAULT_TARGET_SCOPE)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-300 flex items-center gap-1.5 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Scope</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              {/* Target User Accounts */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2.5">
                <label className="text-xs font-bold text-slate-300 tracking-normal block">
                  Target User Account(s) (UPN)
                </label>
                <input
                  type="text"
                  value={targetScope.targetUsers}
                  onChange={e => setTargetScope({ ...targetScope, targetUsers: e.target.value })}
                  placeholder="e.g. globaladmin_compromised@contoso.com, user2@contoso.com, *admin*"
                  className="w-full p-2.5 bg-black/60 border border-slate-700 rounded-lg text-xs font-mono text-cyan-300 focus:outline-none focus:border-red-500"
                />

                {uniqueAvailableActors.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase">Quick Add Detected Actors:</span>
                    <div className="flex flex-wrap gap-1">
                      {uniqueAvailableActors.map(user => (
                        <button
                          key={user}
                          onClick={() => {
                            const current = targetScope.targetUsers ? targetScope.targetUsers.split(',').map(s => s.trim()) : [];
                            if (!current.includes(user)) {
                              setTargetScope({ ...targetScope, targetUsers: [...current, user].join(', ') });
                            }
                          }}
                          className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[10px] font-mono text-slate-300 transition-colors"
                        >
                          + {user}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-2 border-t border-slate-800/80">
                  <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={targetScope.excludeServiceAccounts}
                      onChange={e => setTargetScope({ ...targetScope, excludeServiceAccounts: e.target.checked })}
                      className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                    />
                    <span>Exclude automated service accounts (Sync_*, MSOL_*, app@sharepoint)</span>
                  </label>
                </div>
              </div>

              {/* Target Originating IPs */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2.5">
                <label className="text-xs font-bold text-slate-300 tracking-normal block">
                  Target Client IP Address(es) / Prefixes
                </label>
                <input
                  type="text"
                  value={targetScope.targetIps}
                  onChange={e => setTargetScope({ ...targetScope, targetIps: e.target.value })}
                  placeholder="e.g. 185.220.101.45, 194.26.*"
                  className="w-full p-2.5 bg-black/60 border border-slate-700 rounded-lg text-xs font-mono text-purple-300 focus:outline-none focus:border-red-500"
                />

                {uniqueAvailableIps.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase">Quick Add Detected IPs:</span>
                    <div className="flex flex-wrap gap-1">
                      {uniqueAvailableIps.map(ip => (
                        <button
                          key={ip}
                          onClick={() => {
                            const current = targetScope.targetIps ? targetScope.targetIps.split(',').map(s => s.trim()) : [];
                            if (!current.includes(ip)) {
                              setTargetScope({ ...targetScope, targetIps: [...current, ip].join(', ') });
                            }
                          }}
                          className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[10px] font-mono text-purple-300 transition-colors"
                        >
                          + {ip}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-2 border-t border-slate-800/80">
                  <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={targetScope.onlyExternalIps}
                      onChange={e => setTargetScope({ ...targetScope, onlyExternalIps: e.target.checked })}
                      className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                    />
                    <span>Only External Public IPs (Filter out internal RFC1918 10./172./192.168.)</span>
                  </label>
                </div>
              </div>

              {/* Target Operations & Actions */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2.5">
                <label className="text-xs font-bold text-slate-300 tracking-normal block">
                  Target Operations & PowerShell Actions
                </label>
                <input
                  type="text"
                  value={targetScope.targetOperations}
                  onChange={e => setTargetScope({ ...targetScope, targetOperations: e.target.value })}
                  placeholder="e.g. *Delete*, *RoleAssignment*, New-InboxRule, UserLoggedIn"
                  className="w-full p-2.5 bg-black/60 border border-slate-700 rounded-lg text-xs font-mono text-red-300 focus:outline-none focus:border-red-500"
                />

                <div className="space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">Preset Wildcards:</span>
                  <div className="flex flex-wrap gap-1">
                    {['*Delete*', '*Role*', '*InboxRule*', '*Consent*', '*MailItemsAccessed*', '*Update user*'].map(preset => (
                      <button
                        key={preset}
                        onClick={() => {
                          const current = targetScope.targetOperations ? targetScope.targetOperations.split(',').map(s => s.trim()) : [];
                          if (!current.includes(preset)) {
                            setTargetScope({ ...targetScope, targetOperations: [...current, preset].join(', ') });
                          }
                        }}
                        className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[10px] font-mono text-red-300 transition-colors"
                      >
                        + {preset}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Workload, Status & Severity Scoping */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
                <label className="text-xs font-bold text-slate-300 tracking-normal block">
                  Workload, Result Status & Timeframe
                </label>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <span className="text-[11px] text-slate-400">Workload:</span>
                    <select
                      value={targetScope.targetWorkload}
                      onChange={e => setTargetScope({ ...targetScope, targetWorkload: e.target.value })}
                      className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-xs text-slate-200 mt-1 focus:outline-none"
                    >
                      <option value="ALL">All Workloads</option>
                      <option value="AzureActiveDirectory">AzureActiveDirectory (Entra ID)</option>
                      <option value="Exchange">Exchange Online</option>
                      <option value="SharePoint">SharePoint</option>
                      <option value="OneDrive">OneDrive</option>
                      <option value="SecurityComplianceCenter">Purview Compliance</option>
                    </select>
                  </div>

                  <div>
                    <span className="text-[11px] text-slate-400">Result Status:</span>
                    <select
                      value={targetScope.resultStatus}
                      onChange={e => setTargetScope({ ...targetScope, resultStatus: e.target.value })}
                      className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-xs text-slate-200 mt-1 focus:outline-none"
                    >
                      <option value="ALL">All Statuses</option>
                      <option value="Succeeded">Succeeded</option>
                      <option value="Failed">Failed / Denied</option>
                      <option value="Blocked">Blocked</option>
                      <option value="Unknown">Not recorded</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div>
                    <span className="text-[11px] text-slate-400">From Date (UTC):</span>
                    <input
                      type="text"
                      value={targetScope.timeRangeStart}
                      onChange={e => setTargetScope({ ...targetScope, timeRangeStart: e.target.value })}
                      placeholder="YYYY-MM-DD"
                      className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-xs text-slate-200 mt-1 font-mono focus:outline-none"
                    />
                  </div>

                  <div>
                    <span className="text-[11px] text-slate-400">To Date (UTC):</span>
                    <input
                      type="text"
                      value={targetScope.timeRangeEnd}
                      onChange={e => setTargetScope({ ...targetScope, timeRangeEnd: e.target.value })}
                      placeholder="YYYY-MM-DD"
                      className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-xs text-slate-200 mt-1 font-mono focus:outline-none"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Bottom Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <div className="text-xs text-slate-400">
                Current Filter matches <strong className="text-slate-50">{scopedRecords.length}</strong> of{' '}
                <strong className="text-slate-50">{records.length}</strong> total ingested events.
              </div>

              <button
                onClick={() => setActiveTab('table')}
                className="px-4 py-2 bg-red-600 text-white font-bold text-xs rounded-xl shadow-md flex items-center gap-1.5 transition-all"
              >
                <span>View Filtered Events ({scopedRecords.length})</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: CUSTOM DETECTION RULES MANAGER */}
      {/* ========================================================================= */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" /> Custom Detection Rules Engine
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Define custom threat patterns, assign severities and MITRE ATT&CK tactics to automatically flag suspicious operations.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleResetRulesToDefault}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-300 flex items-center gap-1.5 transition-colors"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset Defaults</span>
                </button>
                <button
                  onClick={() => setIsAddRuleModalOpen(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-md transition-all"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Detection Rule</span>
                </button>
              </div>
            </div>

            {/* Rules Cards List */}
            <div className="space-y-3">
              {customRules.map(rule => (
                <div
                  key={rule.id}
                  className={`p-4 rounded-xl border transition-all ${
                    rule.enabled
                      ? 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                      : 'bg-slate-950/30 border-slate-800/40 opacity-50'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center space-x-2.5">
                      <button
                        onClick={() => handleToggleRule(rule.id)}
                        className={`w-5 h-5 rounded flex items-center justify-center border transition-colors ${
                          rule.enabled
                            ? 'bg-red-600 border-red-500 text-white'
                            : 'bg-black/40 border-slate-700 text-transparent'
                        }`}
                        title={rule.enabled ? 'Click to disable rule' : 'Click to enable rule'}
                      >
                        <Check className="w-3.5 h-3.5" />
                      </button>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-xs text-slate-200">{rule.name}</span>
                          {getSeverityBadge(rule.severity)}
                          {rule.mitreTactic && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-300">
                              {rule.mitreTactic}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">{rule.threatDescription}</p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      {rule.id.startsWith('custom_') && (
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1.5 text-slate-500 hover:text-rose-400 rounded-lg hover:bg-slate-800 transition-colors"
                          title="Delete custom rule"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Matching Criteria Breakdown */}
                  <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex flex-wrap gap-2 text-[11px] font-mono text-slate-400">
                    {rule.match.operation && (
                      <span className="px-2 py-0.5 rounded bg-black/50 border border-slate-800">
                        Op: <strong className="text-red-300">{rule.match.operation}</strong>
                      </span>
                    )}
                    {rule.match.actor && (
                      <span className="px-2 py-0.5 rounded bg-black/50 border border-slate-800">
                        Actor: <strong className="text-cyan-300">{rule.match.actor}</strong>
                      </span>
                    )}
                    {rule.match.clientIp && (
                      <span className="px-2 py-0.5 rounded bg-black/50 border border-slate-800">
                        IP: <strong className="text-purple-300">{rule.match.clientIp}</strong>
                      </span>
                    )}
                    {rule.match.workload && (
                      <span className="px-2 py-0.5 rounded bg-black/50 border border-slate-800">
                        Workload: <strong className="text-slate-200">{rule.match.workload}</strong>
                      </span>
                    )}
                    {rule.match.resultStatus && (
                      <span className="px-2 py-0.5 rounded bg-black/50 border border-slate-800">
                        Status: <strong className="text-amber-300">{rule.match.resultStatus}</strong>
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Modal to Add New Custom Detection Rule */}
          {isAddRuleModalOpen && (
            <div className="fixed inset-0 z-50 overflow-hidden flex items-center justify-center p-4">
              <div
                className="absolute inset-0 bg-black/80 backdrop-blur-sm"
                onClick={() => setIsAddRuleModalOpen(false)}
              />

              <div className="relative w-full max-w-xl bg-[var(--bg-surface)] border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/40">
                      <Plus className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-sm text-slate-100">Create Custom Detection Rule</h3>
                      <p className="text-[11px] text-slate-400">Specify regex or wildcard conditions to match audit events</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setIsAddRuleModalOpen(false)}
                    className="text-slate-400 hover:text-slate-50"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="col-span-2 space-y-1">
                      <label className="font-bold text-slate-300">Rule Name *</label>
                      <input
                        type="text"
                        value={newRuleDraft.name || ''}
                        onChange={e => setNewRuleDraft({ ...newRuleDraft, name: e.target.value })}
                        placeholder="e.g. Mass File Exfiltration or Admin Login"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">Severity *</label>
                      <select
                        value={newRuleDraft.severity}
                        onChange={e => setNewRuleDraft({ ...newRuleDraft, severity: e.target.value as any })}
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none font-sans"
                      >
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                        <option value="INFO">Info</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">Operation Pattern (Regex / Wildcard)</label>
                      <input
                        type="text"
                        value={newRuleDraft.match?.operation || ''}
                        onChange={e =>
                          setNewRuleDraft({
                            ...newRuleDraft,
                            match: { ...newRuleDraft.match, operation: e.target.value },
                          })
                        }
                        placeholder="e.g. *delete* or Add-MailboxPermission"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">Actor Pattern (Email / Regex)</label>
                      <input
                        type="text"
                        value={newRuleDraft.match?.actor || ''}
                        onChange={e =>
                          setNewRuleDraft({
                            ...newRuleDraft,
                            match: { ...newRuleDraft.match, actor: e.target.value },
                          })
                        }
                        placeholder="e.g. admin* or attacker@external.com"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">Client IP Prefix / Pattern</label>
                      <input
                        type="text"
                        value={newRuleDraft.match?.clientIp || ''}
                        onChange={e =>
                          setNewRuleDraft({
                            ...newRuleDraft,
                            match: { ...newRuleDraft.match, clientIp: e.target.value },
                          })
                        }
                        placeholder="e.g. 185.220.*"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">Workload (Optional)</label>
                      <input
                        type="text"
                        value={newRuleDraft.match?.workload || ''}
                        onChange={e =>
                          setNewRuleDraft({
                            ...newRuleDraft,
                            match: { ...newRuleDraft.match, workload: e.target.value },
                          })
                        }
                        placeholder="e.g. Exchange or AzureActiveDirectory"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">Threat Category Name</label>
                      <input
                        type="text"
                        value={newRuleDraft.threatCategory || ''}
                        onChange={e => setNewRuleDraft({ ...newRuleDraft, threatCategory: e.target.value })}
                        placeholder="e.g. Unauthorized Mailbox Access"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="font-bold text-slate-300">MITRE ATT&CK Tactic / Technique</label>
                      <input
                        type="text"
                        value={newRuleDraft.mitreTactic || ''}
                        onChange={e => setNewRuleDraft({ ...newRuleDraft, mitreTactic: e.target.value })}
                        placeholder="e.g. Persistence (T1098)"
                        className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="font-bold text-slate-300">Threat Description / Assessment Narrative</label>
                    <textarea
                      value={newRuleDraft.threatDescription || ''}
                      onChange={e => setNewRuleDraft({ ...newRuleDraft, threatDescription: e.target.value })}
                      placeholder="Explain why this action constitutes a security risk..."
                      rows={2}
                      className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-800">
                  <button
                    onClick={() => setIsAddRuleModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveNewRule}
                    disabled={!newRuleDraft.name?.trim()}
                    className="px-4 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white font-bold disabled:opacity-40 shadow-md"
                  >
                    Save & Activate Rule
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: EXECUTIVE INCIDENT REPORT & CUSTOMIZER */}
      {/* ========================================================================= */}
      {activeTab === 'report' && (
        <div className="space-y-5">
          {/* Custom Report Configuration Box */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-rose-400" /> Customize Executive Report Criteria & Scope
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Specify case title, target entity, investigator name, classification, and select which sections to include. Export PDF uses the browser's Save as PDF, so the report never leaves this computer.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={handleCopyReport}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center space-x-1.5 transition-colors"
                >
                  {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedReport ? 'Copied!' : 'Copy Markdown'}</span>
                </button>
                <button
                  onClick={handleDownloadReport}
                  className="px-3 py-1.5 bg-red-600 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-all shadow-md"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .MD</span>
                </button>
                <button
                  onClick={handleExportPdf}
                  disabled={!reportHtml}
                  className="px-3 py-1.5 bg-red-600 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-all shadow-md"
                  title="Opens the print dialog: choose 'Save as PDF'. Nothing is uploaded."
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Export PDF</span>
                </button>
                <button
                  onClick={handleDownloadSiemCsv}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center space-x-1.5 transition-colors"
                  title="Download SIEM formatted CSV"
                >
                  <Download className="w-3.5 h-3.5 text-rose-400" />
                  <span>Download CSV</span>
                </button>
              </div>
            </div>

            {/* Case Parameters Form */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 text-xs">
              <div className="space-y-1">
                <label className="font-bold text-slate-300">Report / Case Title</label>
                <input
                  type="text"
                  value={reportOptions.caseTitle}
                  onChange={e => setReportOptions({ ...reportOptions, caseTitle: e.target.value })}
                  placeholder="e.g. Contoso M365 ATO Forensic Audit"
                  className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-300">Target Tenant / Organization</label>
                <input
                  type="text"
                  value={reportOptions.organization}
                  onChange={e => setReportOptions({ ...reportOptions, organization: e.target.value })}
                  placeholder="e.g. Contoso Global Corp"
                  className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-300">Lead Investigator Name</label>
                <input
                  type="text"
                  value={reportOptions.investigator}
                  onChange={e => setReportOptions({ ...reportOptions, investigator: e.target.value })}
                  placeholder="e.g. SOC Lead / IR Consultant"
                  className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-300">Security Classification</label>
                <select
                  value={reportOptions.classification}
                  onChange={e => setReportOptions({ ...reportOptions, classification: e.target.value as any })}
                  className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none"
                >
                  <option value="RESTRICTED">RESTRICTED</option>
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                  <option value="INTERNAL">INTERNAL</option>
                  <option value="TLP:AMBER">TLP:AMBER</option>
                  <option value="TLP:RED">TLP:RED</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-300">Findings to Include</label>
                <select
                  value={reportOptions.minSeverity}
                  onChange={e => setReportOptions({ ...reportOptions, minSeverity: e.target.value as PurviewReportOptions['minSeverity'] })}
                  className="w-full p-2 bg-black/60 border border-slate-700 rounded-lg text-slate-200 focus:outline-none"
                >
                  <option value="ALL">Low and above</option>
                  <option value="MEDIUM_PLUS">Medium and above</option>
                  <option value="HIGH_CRITICAL">High and Critical</option>
                  <option value="CRITICAL_ONLY">Critical only</option>
                </select>
              </div>
            </div>

            {/* Analyst Observations / Strategic Scope Notes */}
            <div className="space-y-1">
              <label className="font-bold text-slate-300 text-xs">
                Analyst Strategic Notes & Findings (Injected into Section 1)
              </label>
              <textarea
                value={reportOptions.analystNotes}
                onChange={e => setReportOptions({ ...reportOptions, analystNotes: e.target.value })}
                placeholder="Optional executive context, root-cause observations, or specific client remediation directives..."
                rows={2}
                className="w-full p-2.5 bg-black/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-red-500 resize-none font-sans"
              />
            </div>

            {/* Section Toggles */}
            <div className="pt-2 border-t border-slate-800 space-y-2">
              <div className="text-xs font-bold text-slate-300">Include Report Sections:</div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs text-slate-300">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeExecutiveSummary}
                    onChange={e => setReportOptions({ ...reportOptions, includeExecutiveSummary: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>Executive Summary</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeScopeSection}
                    onChange={e => setReportOptions({ ...reportOptions, includeScopeSection: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>Investigation Scope Matrix</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeCustomRulesSummary}
                    onChange={e => setReportOptions({ ...reportOptions, includeCustomRulesSummary: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>Matched Detection Rules</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeFindingsTable}
                    onChange={e => setReportOptions({ ...reportOptions, includeFindingsTable: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>Findings & Actions Table</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeThreatNarratives}
                    onChange={e => setReportOptions({ ...reportOptions, includeThreatNarratives: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>Detailed Threat Narratives</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeSessionHijacking}
                    onChange={e => setReportOptions({ ...reportOptions, includeSessionHijacking: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>AiTM Stolen Session Forensics</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reportOptions.includeRemediationPlaybook}
                    onChange={e => setReportOptions({ ...reportOptions, includeRemediationPlaybook: e.target.checked })}
                    className="rounded border-slate-700 bg-black/60 text-red-600 focus:ring-0"
                  />
                  <span>Remediation Runbook Playbook</span>
                </label>
              </div>
            </div>
          </div>

          {/* Report preview: the formatted view is exactly what Export PDF prints */}
          <div className="space-y-2">
            <div className="flex items-center gap-1 text-xs">
              {(['formatted', 'markdown'] as const).map(view => (
                <button
                  key={view}
                  onClick={() => setReportView(view)}
                  className={`px-3 py-1.5 rounded-lg font-semibold border transition-colors ${
                    reportView === view
                      ? 'bg-red-500/20 text-red-300 border-red-500/40'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  {view === 'formatted' ? 'PDF Preview' : 'Markdown'}
                </button>
              ))}
            </div>
            {reportView === 'formatted' ? (
              <iframe
                title="Report preview"
                sandbox=""
                srcDoc={reportHtml}
                className="w-full h-[900px] rounded-2xl border border-slate-800 bg-slate-200"
              />
            ) : (
              <div className="p-5 rounded-2xl bg-black/60 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all shadow-xl">
                {incidentReport}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Slide-Over Event Details Drawer & Pivot Hub */}
      {/* ========================================================================= */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 overflow-hidden">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
            onClick={() => setSelectedRecord(null)}
          />

          <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
            <div className="w-screen max-w-xl bg-[var(--bg-surface)] border-l border-slate-800 shadow-2xl flex flex-col">
              {/* Drawer Header */}
              <div className="p-4 border-b border-slate-800 bg-[var(--bg-app)] flex items-center justify-between">
                <div className="flex items-center space-x-2.5">
                  <div className="p-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-sm font-bold text-slate-100">{selectedRecord.operation}</h3>
                      {getSeverityBadge(selectedRecord.severity)}
                    </div>
                    <span className="text-xs text-slate-400 font-mono">{selectedRecord.creationTime || 'No timestamp'}</span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedRecord(null)}
                  className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
                {/* Threat Assessment Callout if present */}
                {(selectedRecord.threatDescription || selectedRecord.matchedRuleName) && (
                  <div className="p-3 bg-rose-950/30 border border-rose-800/60 rounded-xl space-y-1.5">
                    <div className="flex items-center justify-between font-bold text-rose-300">
                      <span>⚠️ {selectedRecord.matchedRuleName ? `Rule Matched: ${selectedRecord.matchedRuleName}` : selectedRecord.threatCategory}</span>
                      {selectedRecord.mitreTactic && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 border border-rose-700 text-rose-300">
                          {selectedRecord.mitreTactic}
                        </span>
                      )}
                    </div>
                    <p className="text-rose-200">{selectedRecord.threatDescription}</p>
                  </div>
                )}

                {/* Quick Investigative Pivoting Buttons */}
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                  <span className="text-[11px] font-bold text-slate-300 flex items-center gap-1.5 uppercase tracking-wider">
                    <Target className="w-3.5 h-3.5 text-amber-400" /> Investigative Scoping Pivots:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => {
                        setTargetScope({ ...targetScope, targetUsers: selectedRecord.userId });
                        setSelectedRecord(null);
                        setActiveTab('table');
                      }}
                      className="px-2.5 py-1 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 text-cyan-300 font-mono text-[11px] transition-colors"
                      title="Filter entire audit log to this user"
                    >
                      🎯 Scope to User: {selectedRecord.userId}
                    </button>

                    {selectedRecord.clientIp && selectedRecord.clientIp !== 'N/A' && (
                      <button
                        onClick={() => {
                          setTargetScope({ ...targetScope, targetIps: selectedRecord.clientIp });
                          setSelectedRecord(null);
                          setActiveTab('table');
                        }}
                        className="px-2.5 py-1 rounded-lg bg-purple-950/60 hover:bg-purple-900/60 border border-purple-800/60 text-purple-300 font-mono text-[11px] transition-colors"
                        title="Filter entire audit log to this IP"
                      >
                        🎯 Scope to IP: {selectedRecord.clientIp}
                      </button>
                    )}

                    <button
                      onClick={() => {
                        setNewRuleDraft({
                          name: `Detect ${selectedRecord.operation}`,
                          severity: selectedRecord.severity,
                          match: {
                            operation: selectedRecord.operation,
                            workload: selectedRecord.workload,
                          },
                          threatCategory: selectedRecord.threatCategory || 'Custom Flag',
                          threatDescription: `Flagged action: ${selectedRecord.operation} in ${selectedRecord.workload}`,
                          mitreTactic: selectedRecord.mitreTactic || 'Persistence (T1098)',
                        });
                        setSelectedRecord(null);
                        setActiveTab('rules');
                        setIsAddRuleModalOpen(true);
                      }}
                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 font-sans text-[11px] transition-colors"
                    >
                      🛡️ Create Rule from this Event
                    </button>
                  </div>
                </div>

                {/* Core Properties Matrix */}
                <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2">
                  <div className="font-bold text-slate-200 text-xs mb-1">Event Identity & Network</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-slate-500">Performing Actor:</span>
                      <div className="font-mono text-slate-200 font-bold break-all">{selectedRecord.userId}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Client IP:</span>
                      <div className="font-mono text-purple-300">{selectedRecord.clientIp}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Workload / Service:</span>
                      <div className="font-mono text-slate-300">{selectedRecord.workload}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Result Status:</span>
                      <div
                        className={`font-mono font-bold ${
                          selectedRecord.resultStatus === 'Succeeded'
                            ? 'text-emerald-400'
                            : selectedRecord.resultStatus === 'Unknown'
                            ? 'text-slate-400'
                            : 'text-rose-400'
                        }`}
                      >
                        {selectedRecord.resultStatus === 'Unknown' ? 'Not recorded' : selectedRecord.resultStatus}
                      </div>
                    </div>
                    {selectedRecord.sessionId && (
                      <div className="col-span-2 pt-1 border-t border-slate-800/60">
                        <span className="text-slate-500 flex items-center justify-between">
                          <span>Session ID:</span>
                          <button
                            onClick={() => navigator.clipboard.writeText(selectedRecord.sessionId || '')}
                            className="text-[10px] text-cyan-400 hover:underline"
                          >
                            Copy ID
                          </button>
                        </span>
                        <div className="font-mono text-cyan-300 text-[11px] break-all bg-black/40 p-1 rounded mt-0.5 border border-slate-800">
                          {selectedRecord.sessionId}
                        </div>
                      </div>
                    )}
                    {selectedRecord.userAgent && (
                      <div className="col-span-2 pt-1 border-t border-slate-800/60">
                        <span className="text-slate-500">User-Agent:</span>
                        <div className="font-mono text-slate-400 text-[10px] break-all bg-black/40 p-1 rounded mt-0.5">
                          {selectedRecord.userAgent}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Modified Attributes Comparison */}
                {selectedRecord.modifiedProperties && selectedRecord.modifiedProperties.length > 0 && (
                  <div className="p-3 bg-black/40 rounded-xl border border-slate-800 space-y-2">
                    <div className="font-bold text-amber-400 text-xs">Modified Attributes & Parameters</div>
                    <div className="space-y-1.5">
                      {selectedRecord.modifiedProperties.map((mod, i) => (
                        <div key={i} className="font-mono bg-black/60 p-2 rounded border border-slate-800/80">
                          <span className="text-slate-400 font-semibold">{mod.name}: </span>
                          {mod.oldValue && (
                            <span className="line-through text-slate-500 mr-2">{mod.oldValue}</span>
                          )}
                          <span className="text-emerald-400 font-bold">{mod.newValue || 'none'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Raw JSON Details */}
                <div className="space-y-1">
                  <span className="font-bold text-slate-400">Raw Audit Event Payload (JSON)</span>
                  <pre className="p-3 bg-black/70 border border-slate-800 rounded-xl font-mono text-[11px] text-slate-300 overflow-x-auto max-h-64 select-all">
                    {JSON.stringify(selectedRecord.rawDetails, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
