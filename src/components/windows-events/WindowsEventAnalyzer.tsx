'use client';

import React, { useState, useMemo, useEffect } from 'react';
import {
  Monitor,
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
  FileCode,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  X,
  Sparkles,
  Server,
} from 'lucide-react';
import {
  parseWindowsEvents,
  summarizeWindowsEvents,
  generateWindowsIncidentReport,
  SAMPLE_WINDOWS_XML,
  ACCOUNT_EVENT_IDS,
  ParsedWindowsEvent,
  LOGON_TYPES,
} from './windows-event-parser';
import { useCase } from '@/components/shared/CaseContext';

type QuickEventFilter = 'ALL' | 'CRITICAL_HIGH' | 'RDP' | 'FAILED_LOGONS' | 'ACCOUNT_TAMPER' | 'SERVICES' | 'SYSMON';

export function WindowsEventAnalyzer() {
  const [rawInput, setRawInput] = useState('');
  const [isInputExpanded, setIsInputExpanded] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [events, setEvents] = useState<ParsedWindowsEvent[]>([]);
  const [truncatedNotice, setTruncatedNotice] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<'table' | 'report'>('table');
  const [quickFilter, setQuickFilter] = useState<QuickEventFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string>('ALL');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Selected event modal/drawer
  const [selectedEvent, setSelectedEvent] = useState<ParsedWindowsEvent | null>(null);

  const [copiedReport, setCopiedReport] = useState(false);
  const [addedToCase, setAddedToCase] = useState(false);

  const { addItem } = useCase();

  // Keyboard shortcut to close drawer on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedEvent) {
        setSelectedEvent(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedEvent]);

  const handleRunAnalysis = (inputToParse = rawInput) => {
    if (!inputToParse.trim()) {
      setEvents([]);
      return;
    }
    setIsAnalyzing(true);
    setParseError(null);

    setTimeout(() => {
      try {
        const { events: parsed, truncated } = parseWindowsEvents(inputToParse);
        setEvents(parsed);
        setTruncatedNotice(truncated);
        setCurrentPage(1);
        setIsInputExpanded(false);
      } catch (e: any) {
        setParseError(e.message || 'Error parsing Windows event logs');
      } finally {
        setIsAnalyzing(false);
      }
    }, 50);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = event => {
      const content = event.target?.result as string;
      if (content) {
        setRawInput(content);
        handleRunAnalysis(content);
      }
    };
    reader.readAsText(file);
  };

  // Summary metrics
  const summary = useMemo(() => summarizeWindowsEvents(events), [events]);

  // Executive Report
  const incidentReport = useMemo(
    () => generateWindowsIncidentReport(summary, events),
    [summary, events]
  );

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      // 1. Quick Filter Pills
      if (quickFilter === 'CRITICAL_HIGH') {
        if (e.severity !== 'CRITICAL' && e.severity !== 'HIGH') return false;
      } else if (quickFilter === 'RDP') {
        if (e.eventId !== 4624 || e.logonType !== 10) return false;
      } else if (quickFilter === 'FAILED_LOGONS') {
        if (e.eventId !== 4625) return false;
      } else if (quickFilter === 'ACCOUNT_TAMPER') {
        if (!ACCOUNT_EVENT_IDS.includes(e.eventId)) return false;
      } else if (quickFilter === 'SERVICES') {
        if (e.eventId !== 7045 && e.eventId !== 4697) return false;
      } else if (quickFilter === 'SYSMON') {
        if (!((e.isSysmon && e.eventId === 1) || e.eventId === 4688)) return false;
      }

      // 2. Specific Event ID filter
      if (selectedEventId !== 'ALL' && e.eventId.toString() !== selectedEventId) return false;

      // 3. Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          e.eventId.toString().includes(q) ||
          e.computer.toLowerCase().includes(q) ||
          e.targetUser.toLowerCase().includes(q) ||
          e.subjectUser.toLowerCase().includes(q) ||
          e.ipAddress.includes(q) ||
          (e.threatCategory && e.threatCategory.toLowerCase().includes(q)) ||
          (e.serviceName && e.serviceName.toLowerCase().includes(q)) ||
          (e.servicePath && e.servicePath.toLowerCase().includes(q)) ||
          e.processName.toLowerCase().includes(q) ||
          (e.commandLine && e.commandLine.toLowerCase().includes(q));
        if (!match) return false;
      }

      return true;
    });
  }, [events, quickFilter, selectedEventId, searchQuery]);

  // Paginated records
  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, currentPage, pageSize]);

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
    a.download = `windows-security-event-report-${new Date().toISOString().split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleAddToCase = () => {
    const totalThreats = summary.threatsDetected.criticalCount + summary.threatsDetected.highCount;
    addItem({
      tool: 'Windows Event Analyzer',
      title: `Windows event triage: ${totalThreats} high/critical events`,
      category: 'THREAT',
      severity:
        summary.threatsDetected.criticalCount > 0
          ? 'CRITICAL'
          : summary.threatsDetected.highCount > 0
            ? 'HIGH'
            : summary.threatsDetected.mediumCount > 0
              ? 'MEDIUM'
              : 'INFO',
      summary: `Analyzed ${summary.totalEvents} events across ${summary.uniqueComputers.length} hosts. Detected ${summary.threatsDetected.criticalCount} Critical & ${summary.threatsDetected.highCount} High events.`,
      details: {
        totalEvents: summary.totalEvents,
        hosts: summary.uniqueComputers,
        rdpLogons: summary.rdpLogons.length,
        failedLogons: summary.failedLogons.length,
        accountTampering: summary.accountTampering.length,
        servicesCreated: summary.servicesCreated.length,
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-950 border border-rose-500 text-rose-300">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-orange-950 border border-orange-500 text-orange-300">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-950 border border-amber-500 text-amber-300">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-950 border border-emerald-500 text-emerald-300">LOW</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-semibold rounded bg-slate-800 text-slate-400">INFO</span>;
    }
  };

  return (
    <div className="space-y-5 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-400 shadow-md">
            <Monitor className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                Windows Event & Sysmon Triage
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Flags log clearing, brute force and password spray, RDP logons, account and group changes, new services and suspicious command lines
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setActiveTab(activeTab === 'table' ? 'report' : 'table')}
            disabled={events.length === 0}
            className={`flex items-center space-x-1.5 px-3 py-2 text-xs font-semibold rounded-xl border transition-all disabled:opacity-40 ${
              activeTab === 'report'
                ? ' bg-purple-600 border-purple-500 text-white shadow-lg font-bold'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
            }`}
            title="Toggle Executive Incident Summary Report"
          >
            <FileText className="w-3.5 h-3.5 text-purple-400" />
            <span>{activeTab === 'report' ? 'View Event Table' : 'Executive Summary'}</span>
          </button>
          <button
            onClick={() => setIsInputExpanded(!isInputExpanded)}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-slate-400" />
            <span>{isInputExpanded ? 'Hide Raw Input' : 'Paste / Ingest Logs'}</span>
          </button>
          <button
            onClick={handleAddToCase}
            disabled={events.length === 0}
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
            <span className="text-xs font-bold text-slate-200">
              Windows events as XML &lt;Event&gt; blocks or JSON (runs in your browser)
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-400">Sample Test:</span>
              <button
                onClick={() => {
                  setRawInput(SAMPLE_WINDOWS_XML);
                  handleRunAnalysis(SAMPLE_WINDOWS_XML);
                }}
                className="px-2.5 py-1 text-xs bg-purple-950/60 hover:bg-purple-900/60 border border-purple-700/50 text-purple-300 rounded-lg font-semibold transition-colors"
              >
                Load sample events
              </button>
              <label className="cursor-pointer px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg flex items-center space-x-1">
                <Upload className="w-3 h-3 text-slate-400" />
                <span>Upload XML/JSON File</span>
                <input type="file" accept=".xml,.json,.txt,.log" onChange={handleFileUpload} className="hidden" />
              </label>
            </div>
          </div>

          <textarea
            value={rawInput}
            onChange={e => setRawInput(e.target.value)}
            placeholder={'Paste XML events or JSON here. To export XML in PowerShell:\nGet-WinEvent -LogName Security -MaxEvents 500 | ForEach-Object { $_.ToXml() } | Out-File events.xml'}
            spellCheck={false}
            className="w-full h-32 p-3 bg-black/60 border border-slate-800 rounded-xl font-mono text-xs text-slate-200 focus:outline-none focus:border-purple-500 resize-none"
          />

          <div className="flex justify-between items-center">
            <button
              onClick={() => {
                setRawInput('');
                setEvents([]);
              }}
              className="text-xs text-slate-400 hover:text-rose-400 flex items-center space-x-1"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Input</span>
            </button>
            <button
              onClick={() => handleRunAnalysis()}
              disabled={isAnalyzing}
              className="px-4 py-2 bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold rounded-xl flex items-center space-x-1.5 shadow-md disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isAnalyzing ? 'Analyzing Logs...' : 'Run Windows Triage'}</span>
            </button>
          </div>

          {parseError && (
            <div className="p-2.5 bg-rose-950/60 border border-rose-800 rounded-lg text-xs text-rose-300 font-mono">
              ⚠️ {parseError}
            </div>
          )}
        </div>
      )}

      {/* Truncated Notice */}
      {truncatedNotice && (
        <div className="p-3 bg-amber-950/60 border border-amber-800/80 rounded-xl text-xs text-amber-300 flex items-center justify-between">
          <span>
            <strong>Only the first 5,000 events were analysed.</strong> Split the export into smaller files to triage the rest.
          </span>
        </div>
      )}

      {/* KPI Metrics Dashboard Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Total Events</span>
          <span className="text-2xl font-black text-slate-50 mt-0.5">{summary.totalEvents}</span>
        </div>

        <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/40 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-rose-300 tracking-wider flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
            Critical Threats
          </span>
          <span className="text-2xl font-black text-rose-400 mt-0.5">{summary.threatsDetected.criticalCount}</span>
        </div>

        <div className="p-3.5 rounded-xl bg-orange-950/30 border border-orange-500/40 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-orange-300 tracking-wider">High Risk</span>
          <span className="text-2xl font-black text-orange-400 mt-0.5">{summary.threatsDetected.highCount}</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center text-center">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Hosts / Computers</span>
          <span className="text-2xl font-black text-cyan-400 mt-0.5">{summary.uniqueComputers.length}</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center text-center col-span-2 sm:col-span-1">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Target Accounts</span>
          <span className="text-2xl font-black text-purple-400 mt-0.5">{summary.uniqueUsers.length}</span>
        </div>
      </div>

      {/* Quick Forensic Threat Filter Chips */}
      <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
        <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
          <span>⚡ Quick Forensic Event Filters:</span>
          <span className="text-[11px] text-slate-400 font-normal">
            Showing {filteredEvents.length} of {events.length} events
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
            All Events ({events.length})
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
            <span>🚨 All Critical & High</span>
            <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
              {summary.threatsDetected.criticalCount + summary.threatsDetected.highCount}
            </span>
          </button>

          {summary.rdpLogons.length > 0 && (
            <button
              onClick={() => {
                setQuickFilter('RDP');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                quickFilter === 'RDP'
                  ? 'bg-violet-600 text-white shadow-sm'
                  : 'bg-blue-950/40 hover:bg-blue-900/50 text-blue-300 border border-blue-800/50'
              }`}
            >
              <span>🖥️ RDP Logons (Type 10)</span>
              <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                {summary.rdpLogons.length}
              </span>
            </button>
          )}

          {summary.failedLogons.length > 0 && (
            <button
              onClick={() => {
                setQuickFilter('FAILED_LOGONS');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                quickFilter === 'FAILED_LOGONS'
                  ? 'bg-amber-600 text-white shadow-sm'
                  : 'bg-amber-950/40 hover:bg-amber-900/50 text-amber-300 border border-amber-800/50'
              }`}
            >
              <span>❌ Failed logons (4625)</span>
              <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                {summary.failedLogons.length}
              </span>
            </button>
          )}

          {summary.accountTampering.length > 0 && (
            <button
              onClick={() => {
                setQuickFilter('ACCOUNT_TAMPER');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                quickFilter === 'ACCOUNT_TAMPER'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'bg-purple-950/40 hover:bg-purple-900/50 text-purple-300 border border-purple-800/50'
              }`}
            >
              <span>👤 Account & group changes</span>
              <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                {summary.accountTampering.length}
              </span>
            </button>
          )}

          {summary.servicesCreated.length > 0 && (
            <button
              onClick={() => {
                setQuickFilter('SERVICES');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                quickFilter === 'SERVICES'
                  ? 'bg-pink-600 text-white shadow-sm'
                  : 'bg-pink-950/40 hover:bg-pink-900/50 text-pink-300 border border-pink-800/50'
              }`}
            >
              <span>⚙️ Services installed (7045/4697)</span>
              <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                {summary.servicesCreated.length}
              </span>
            </button>
          )}

          {summary.sysmonProcesses.length > 0 && (
            <button
              onClick={() => {
                setQuickFilter('SYSMON');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1 ${
                quickFilter === 'SYSMON'
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-300 border border-emerald-800/50'
              }`}
            >
              <span>💻 Process creation (Sysmon 1 / 4688)</span>
              <span className="px-1.5 py-0.2 rounded-full bg-black/40 text-[10px]">
                {summary.sysmonProcesses.length}
              </span>
            </button>
          )}
        </div>
      </div>

      {/* Main View Mode Selector (SIEM Table vs Executive Report) */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setActiveTab('table')}
            className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'table'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>SIEM Windows Events ({filteredEvents.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('report')}
            className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'report'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Executive Incident Report</span>
          </button>
        </div>
      </div>

      {/* TAB 1: SIEM EVENT EXPLORER & COMPACT TABLE */}
      {activeTab === 'table' && (
        <div className="space-y-3">
          {/* Search & Event ID Filter */}
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
                placeholder="Search Event ID, computer, target user, IP address, service, or command line..."
                className="w-full pl-9 pr-3 py-2 bg-black/40 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-slate-500">Filter Event ID:</span>
              <select
                value={selectedEventId}
                onChange={e => {
                  setSelectedEventId(e.target.value);
                  setCurrentPage(1);
                }}
                className="px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 focus:outline-none text-xs"
              >
                <option value="ALL">All Event IDs</option>
                {Object.keys(summary.eventCounts).map(eid => (
                  <option key={eid} value={eid}>
                    Event {eid} ({summary.eventCounts[Number(eid)]})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Clean Paginated Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--bg-app)] border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-3">Time</th>
                    <th className="py-3 px-2">Severity</th>
                    <th className="py-3 px-2">Event ID</th>
                    <th className="py-3 px-3">Computer / Host</th>
                    <th className="py-3 px-3">Target User</th>
                    <th className="py-3 px-3">Logon / Service / Details</th>
                    <th className="py-3 px-3">IP Address</th>
                    <th className="py-3 px-2 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {paginatedEvents.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-xs text-slate-500">
                        {events.length === 0
                          ? 'No Windows events loaded yet. Paste XML or JSON above, or click "Load sample events".'
                          : 'No events match the selected filters.'}
                      </td>
                    </tr>
                  ) : (
                    paginatedEvents.map(item => {
                      const isHighRisk = item.severity === 'CRITICAL' || item.severity === 'HIGH';

                      return (
                        <tr
                          key={item.id}
                          className={`hover:bg-slate-800/50 transition-colors ${
                            isHighRisk ? 'bg-rose-950/15' : ''
                          }`}
                        >
                          <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                            {item.timeCreated ? item.timeCreated.replace('T', ' ').replace('Z', '').split('.')[0] : 'N/A'}
                          </td>

                          <td className="py-2.5 px-2 whitespace-nowrap">
                            {getSeverityBadge(item.severity)}
                          </td>

                          <td className="py-2.5 px-2 whitespace-nowrap">
                            <span className="px-2 py-0.5 rounded bg-black/60 border border-slate-800 font-mono font-bold text-purple-300">
                              {item.eventId}
                            </span>
                          </td>

                          <td className="py-2.5 px-3 font-mono text-xs text-slate-300 max-w-[150px] truncate" title={item.computer}>
                            {item.computer}
                          </td>

                          <td className="py-2.5 px-3 font-mono text-xs text-slate-200 max-w-[150px] truncate" title={item.targetUser}>
                            {item.targetUser}
                          </td>

                          <td className="py-2.5 px-3 text-xs max-w-[250px] truncate">
                            {item.threatCategory ? (
                              <span className="text-amber-300 font-semibold">{item.threatCategory}</span>
                            ) : item.logonTypeDesc ? (
                              <span className="text-blue-300">{item.logonTypeDesc}</span>
                            ) : item.serviceName ? (
                              <span className="text-pink-300 font-mono">{item.serviceName}</span>
                            ) : (
                              <span className="text-slate-400">{item.processName}</span>
                            )}
                          </td>

                          <td className="py-2.5 px-3 font-mono text-xs text-purple-300 whitespace-nowrap">
                            {item.ipAddress}
                          </td>

                          <td className="py-2.5 px-2 text-right whitespace-nowrap">
                            <button
                              onClick={() => setSelectedEvent(item)}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-slate-50 rounded border border-slate-700 text-[11px] transition-colors"
                            >
                              View
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
                  Page {currentPage} of {totalPages} ({filteredEvents.length} total)
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

      {/* TAB 2: EXECUTIVE INCIDENT REPORT */}
      {activeTab === 'report' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <div>
              <h2 className="text-sm font-bold text-slate-200">Windows Security Incident Report</h2>
              <p className="text-xs text-slate-400">
                Generated Markdown incident narrative for SOC records & internal IT auditing
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
                className="px-3 py-1.5 bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-all shadow-md"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .MD</span>
              </button>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-black/60 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
            {incidentReport}
          </div>
        </div>
      )}

      {/* Slide-Over Event Details Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 overflow-hidden">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
            onClick={() => setSelectedEvent(null)}
          />

          <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
            <div className="w-screen max-w-xl bg-[var(--bg-surface)] border-l border-slate-800 shadow-2xl flex flex-col">
              {/* Header */}
              <div className="p-4 border-b border-slate-800 bg-[var(--bg-app)] flex items-center justify-between">
                <div className="flex items-center space-x-2.5">
                  <div className="p-2 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/40">
                    <Monitor className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-sm font-bold text-slate-100">Event ID {selectedEvent.eventId}</h3>
                      {getSeverityBadge(selectedEvent.severity)}
                    </div>
                    <span className="text-xs text-slate-400 font-mono">
                      {selectedEvent.timeCreated || 'Time not recorded'} · {selectedEvent.providerName}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
                {/* Threat Callout if present */}
                {selectedEvent.threatDescription && (
                  <div className="p-3 bg-purple-950/30 border border-purple-800/60 rounded-xl space-y-1.5">
                    <div className="flex items-center justify-between font-bold text-purple-300">
                      <span>⚠️ {selectedEvent.threatCategory}</span>
                      {selectedEvent.mitreTactic && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 border border-purple-700 text-purple-300">
                          {selectedEvent.mitreTactic}
                        </span>
                      )}
                    </div>
                    <p className="text-purple-200">{selectedEvent.threatDescription}</p>
                  </div>
                )}

                {/* Core Properties Matrix */}
                <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2">
                  <div className="font-bold text-slate-200 text-xs mb-1">Host & Authentication Identity</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-slate-500">Computer (Host):</span>
                      <div className="font-mono text-slate-200 font-bold break-all">{selectedEvent.computer}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">
                        {[4728, 4732, 4756].includes(selectedEvent.eventId) ? 'Group:' : 'Target Account:'}
                      </span>
                      <div className="font-mono text-purple-300 font-bold">{selectedEvent.targetUser}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Subject (Acting) Account:</span>
                      <div className="font-mono text-slate-200">{selectedEvent.subjectUser}</div>
                    </div>
                    {selectedEvent.memberName && (
                      <div>
                        <span className="text-slate-500">Member Added:</span>
                        <div className="font-mono text-slate-200 break-all">{selectedEvent.memberName}</div>
                      </div>
                    )}
                    <div>
                      <span className="text-slate-500">Remote IP Address:</span>
                      <div className="font-mono text-cyan-300">{selectedEvent.ipAddress}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Logon Type:</span>
                      <div className="font-mono text-amber-400 font-bold">
                        {selectedEvent.logonTypeDesc || (selectedEvent.logonType ? `Type ${selectedEvent.logonType}` : 'N/A')}
                      </div>
                    </div>
                    {selectedEvent.subStatusDesc && (
                      <div className="col-span-2">
                        <span className="text-slate-500">Failure Reason (SubStatus):</span>
                        <div className="font-mono text-rose-300 font-semibold">{selectedEvent.subStatusDesc} ({selectedEvent.subStatus})</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Service or Process Command Line */}
                {(selectedEvent.serviceName || selectedEvent.servicePath || selectedEvent.commandLine || selectedEvent.processName !== 'N/A') && (
                  <div className="p-3 bg-black/40 rounded-xl border border-slate-800 space-y-2 font-mono">
                    <div className="font-bold text-amber-400 text-xs font-sans">Execution & Service Properties</div>
                    {selectedEvent.serviceName && (
                      <div>
                        <span className="text-slate-500">Service Name: </span>
                        <span className="text-emerald-300 font-bold">{selectedEvent.serviceName}</span>
                      </div>
                    )}
                    {selectedEvent.servicePath && (
                      <div>
                        <span className="text-slate-500">Service Path: </span>
                        <span className="text-slate-300 break-all">{selectedEvent.servicePath}</span>
                      </div>
                    )}
                    {selectedEvent.processName !== 'N/A' && (
                      <div>
                        <span className="text-slate-500">Process Name: </span>
                        <span className="text-slate-300">{selectedEvent.processName}</span>
                      </div>
                    )}
                    {selectedEvent.commandLine && (
                      <div className="pt-1">
                        <span className="text-slate-500">Command Line: </span>
                        <div className="bg-black/60 p-2 rounded border border-slate-800 text-rose-300 break-all text-[11px]">
                          {selectedEvent.commandLine}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Raw Event XML or Details */}
                <div className="space-y-1">
                  <span className="font-bold text-slate-400">Raw Event Details</span>
                  <pre className="p-3 bg-black/70 border border-slate-800 rounded-xl font-mono text-[11px] text-slate-300 overflow-x-auto max-h-64 select-all">
                    {selectedEvent.rawXml || JSON.stringify(selectedEvent.rawDetails, null, 2)}
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
