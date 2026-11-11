'use client';

import React, { useState, useMemo } from 'react';
import {
  Globe,
  ExternalLink,
  Search,
  Copy,
  Check,
  FolderPlus,
  Shield,
  Layers,
  Sparkles,
  RotateCcw,
  Zap,
  Activity,
  AlertCircle,
  Hash,
  Radio,
  Server,
} from 'lucide-react';
import {
  classifyIoc,
  defangIoc,
  INTEL_ENGINES,
  PRESET_IOCS,
  IocType,
} from './intel-engines';
import { useCase } from '@/components/shared/CaseContext';
import { refangText } from '@/lib/defang';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

export function ThreatIntelPivot() {
  const [inputIoc, setInputIoc] = useState('185.220.101.45');
  const [copiedDefanged, setCopiedDefanged] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [addedToCase, setAddedToCase] = useState(false);

  const { addItem } = useCase();
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('intel_pivot');

  // Classify IOC
  const detectedType: IocType = useMemo(() => classifyIoc(inputIoc), [inputIoc]);
  const defangedValue = useMemo(() => defangIoc(inputIoc), [inputIoc]);
  const liveIoc = useMemo(() => refangText(inputIoc).trim(), [inputIoc]); // pivot links need the real value, even if a defanged one was pasted

  // Filter supported engines
  const matchingEngines = useMemo(() => {
    if (detectedType === 'UNKNOWN') return [];
    return INTEL_ENGINES.filter(e => e.supportedTypes.includes(detectedType));
  }, [detectedType]);

  const handleCopyDefanged = () => {
    navigator.clipboard.writeText(defangedValue);
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(inputIoc.trim());
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleOpenAllInTabs = () => {
    if (matchingEngines.length === 0) return;
    if (inputIoc.trim()) addEntry(inputIoc.trim());
    matchingEngines.forEach(eng => {
      const url = eng.buildUrl(liveIoc, detectedType);
      window.open(url, '_blank', 'noopener,noreferrer');
    });
  };

  const handleAddToCase = () => {
    addItem({
      tool: 'Threat Intel Pivot Hub',
      title: `Pivot Investigation: ${detectedType} [${defangedValue}]`,
      category: 'THREAT',
      severity: 'HIGH',
      summary: `Automated multi-engine pivot investigation for ${detectedType}: ${defangedValue}. Checked across ${matchingEngines.length} platforms.`,
      details: {
        rawIoc: inputIoc.trim(),
        defangedIoc: defangedValue,
        iocType: detectedType,
        applicableEngines: matchingEngines.map(e => e.name),
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  const getCategoryColor = (cat: string) => {
    switch (cat) {
      case 'Reputation & Malware':
        return 'text-rose-400 border-rose-500/30 bg-rose-950/20';
      case 'Infrastructure & Scanners':
        return 'text-cyan-400 border-cyan-500/30 bg-cyan-950/20';
      case 'Enterprise Threat Intel':
        return 'text-purple-400 border-purple-500/30 bg-purple-950/20';
      default:
        return 'text-slate-300 border-slate-700 bg-slate-800';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 shadow-md">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                Threat Intelligence Pivot Hub
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Single-pane query launcher across VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, URLhaus & Cisco Talos
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleAddToCase}
            disabled={!inputIoc.trim() || detectedType === 'UNKNOWN'}
            className="flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg transition-all disabled:opacity-50"
          >
            {addedToCase ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <FolderPlus className="w-3.5 h-3.5" />}
            <span>{addedToCase ? 'Added to Case!' : 'Add to Investigation'}</span>
          </button>
        </div>
      </div>

      {/* Input & Classification Ribbon */}
      <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-bold text-slate-200">Enter Indicator of Compromise (IOC):</span>
            {detectedType !== 'UNKNOWN' && (
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold">
                {detectedType}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <ToolHistoryDropdown
              history={history}
              onSelect={(val) => {
                setInputIoc(val);
                addEntry(val);
              }}
              onRemove={removeEntry}
              onClear={clearHistory}
            />
            <span className="text-xs text-slate-500">Presets:</span>
            {PRESET_IOCS.map(p => (
              <button
                key={p.ioc}
                onClick={() => setInputIoc(p.ioc)}
                className="px-2 py-1 bg-black/40 hover:bg-slate-800 border border-slate-700/60 rounded text-[11px] text-slate-300 font-mono transition-colors"
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Input Bar */}
        <div className="relative">
          <Search className="w-5 h-5 absolute left-3.5 top-3 text-slate-500" />
          <input
            type="text"
            value={inputIoc}
            onChange={e => setInputIoc(e.target.value)}
            onBlur={() => {
              if (inputIoc.trim() && detectedType !== 'UNKNOWN') addEntry(inputIoc.trim());
            }}
            onKeyDown={e => {
              if (e.key === 'Enter' && inputIoc.trim() && detectedType !== 'UNKNOWN') {
                addEntry(inputIoc.trim());
              }
            }}
            placeholder="Enter IP (e.g. 185.220.101.45), Domain, URL, Hash (MD5/SHA256), or CVE-2021-44228..."
            className="w-full pl-11 pr-24 py-3 bg-black/50 border border-slate-700 rounded-xl text-slate-100 font-mono text-sm focus:outline-none focus:border-cyan-500 shadow-inner"
          />
          {inputIoc && (
            <button
              onClick={() => setInputIoc('')}
              className="absolute right-3 top-2.5 px-2.5 py-1 text-xs text-slate-400 hover:text-slate-50 rounded bg-slate-800"
            >
              Clear
            </button>
          )}
        </div>

        {/* Defanged & Raw Output Quick Bar */}
        {inputIoc.trim() && detectedType !== 'UNKNOWN' && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-black/40 rounded-xl border border-slate-800 text-xs font-mono">
            <div className="flex items-center space-x-2 truncate">
              <span className="text-slate-500">Safe Defanged IOC:</span>
              <span className="text-emerald-300 font-bold truncate">{defangedValue}</span>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                onClick={handleCopyDefanged}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 flex items-center space-x-1 text-xs transition-colors"
              >
                {copiedDefanged ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedDefanged ? 'Copied Defanged!' : 'Copy Defanged'}</span>
              </button>
              <button
                onClick={handleCopyRaw}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 flex items-center space-x-1 text-xs transition-colors"
              >
                {copiedRaw ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedRaw ? 'Copied Raw!' : 'Copy Raw'}</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-bold text-slate-300">
            Applicable Engines ({matchingEngines.length} of {INTEL_ENGINES.length})
          </span>
          {detectedType === 'UNKNOWN' && (
            <span className="text-xs text-amber-400 font-semibold">
              ⚠️ Please enter a valid IP, Domain, Hash, or CVE to generate links.
            </span>
          )}
        </div>

        {matchingEngines.length > 0 && (
          <button
            onClick={handleOpenAllInTabs}
            className="px-4 py-2 bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold rounded-xl flex items-center space-x-2 shadow-lg transition-all"
          >
            <Zap className="w-4 h-4" />
            <span>Launch All {matchingEngines.length} Platforms in New Tabs</span>
          </button>
        )}
      </div>

      {/* Platform Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {matchingEngines.map(eng => {
          const directUrl = eng.buildUrl(liveIoc, detectedType);

          return (
            <div
              key={eng.id}
              className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between space-y-3 group shadow-md"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-slate-200 group-hover:text-cyan-300 transition-colors">
                    {eng.name}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-semibold ${getCategoryColor(eng.category)}`}>
                    {eng.category}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {eng.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 font-mono truncate max-w-[200px]" title={directUrl}>
                  {directUrl}
                </span>

                <a
                  href={directUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-3 py-1.5 bg-slate-800 hover:bg-cyan-600 hover:text-white text-slate-300 text-xs font-semibold rounded-lg border border-slate-700 hover:border-cyan-500 flex items-center space-x-1.5 transition-all shrink-0"
                >
                  <span>Launch</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
