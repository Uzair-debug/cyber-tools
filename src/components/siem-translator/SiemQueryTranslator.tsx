'use client';

import React, { useState, useMemo } from 'react';
import { Copy, Check, Sparkles, Terminal } from 'lucide-react';
import { SiemPlatform } from '@/lib/types';
import { buildQueries, extractIocs, PLATFORM_NOTES } from '@/lib/siem-queries';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

// Safe examples: RFC 5737 documentation IPs, RFC 2606 .example domains, and the EICAR test file
const SAMPLE_HUNTING_PRESETS = [
  {
    label: 'Example IPs',
    rawIocs: '192.0.2.10\n198.51.100.23\n203.0.113.77',
    title: 'Connections to suspicious IP addresses',
  },
  {
    label: 'EICAR test file hashes',
    rawIocs:
      '44d88612fea8a8f36de82e1278abb02f\n3395856ce81f2b7382dee72602f798b642f14140\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    title: 'EICAR antivirus test file',
  },
  {
    label: 'Defanged phishing URLs',
    rawIocs: 'hxxps://login-microsoft-secure[.]example/owa\nauth-contoso-update[.]example\n203.0.113.77:8443',
    title: 'Phishing infrastructure',
  },
];

export function SiemQueryTranslator() {
  const [inputText, setInputText] = useState(SAMPLE_HUNTING_PRESETS[0].rawIocs);
  const [queryTitle, setQueryTitle] = useState(SAMPLE_HUNTING_PRESETS[0].title);
  const [activePlatform, setActivePlatform] = useState<SiemPlatform>('kql');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('siem_translator', { persist: false }); // pasted case indicators: session-only history

  const extractedIocs = useMemo(() => extractIocs(inputText), [inputText]);
  const generatedQueries = useMemo(() => buildQueries(extractedIocs, queryTitle), [extractedIocs, queryTitle]);
  const hashCount = extractedIocs.md5.length + extractedIocs.sha1.length + extractedIocs.sha256.length;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-400">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                SIEM Query Builder
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Turn IPs, domains and file hashes into hunting queries for Defender/Sentinel, Splunk, Elastic, Sigma and QRadar
            </p>
          </div>
        </div>
      </div>

      {/* Hunting Presets */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-3">

        {/* Hunting Attack Presets */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => setInputText(val)}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-cyan-400" /> Examples:
          </span>
          {SAMPLE_HUNTING_PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setInputText(p.rawIocs);
                setQueryTitle(p.title);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-cyan-300 hover:text-cyan-200 transition-all"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input IOCs & Rule Title Section */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <label className="text-[10px] text-slate-500 uppercase tracking-wider font-bold block mb-1">
              Rule title
            </label>
            <input
              type="text"
              value={queryTitle}
              onChange={e => setQueryTitle(e.target.value)}
              className="w-full p-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex items-end">
            <div className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400 flex items-center gap-2">
              <span className="text-cyan-300 font-bold">{extractedIocs.ips.length} IPs</span>
              <span className="text-slate-600">|</span>
              <span className="text-purple-300 font-bold">{extractedIocs.domains.length} Domains</span>
              <span className="text-slate-600">|</span>
              <span className="text-amber-300 font-bold">{hashCount} Hashes</span>
            </div>
          </div>
        </div>

        <div>
          <label className="text-[10px] text-slate-500 uppercase tracking-wider font-bold block mb-1">
            Indicators: IPv4 addresses, domains or URLs (defanged is fine), MD5/SHA1/SHA256 hashes
          </label>
          <textarea
            value={inputText}
            onChange={e => setInputText(e.target.value)}
            onBlur={() => {
              if (inputText.trim()) addEntry(inputText.trim());
            }}
            rows={4}
            spellCheck={false}
            placeholder="Paste IP addresses, domains, or hashes..."
            className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
          {extractedIocs.unrecognised.length > 0 && (
            <p className="mt-1.5 text-xs text-amber-400 break-all">
              Not recognised, so left out of the queries ({extractedIocs.unrecognised.length}):{' '}
              <span className="font-mono">{extractedIocs.unrecognised.slice(0, 10).join(', ')}</span>
              {extractedIocs.unrecognised.length > 10 && ' ...'}
            </p>
          )}
        </div>
      </div>

      {/* Generated SIEM Query Output Tabs */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        
        {/* Platform Selection Buttons */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-1.5 overflow-x-auto bg-slate-950 p-1.5 rounded-xl border border-slate-800">
            {[
              { id: 'kql', label: 'Defender / Sentinel (KQL)' },
              { id: 'spl', label: 'Splunk (SPL)' },
              { id: 'elastic', label: 'Elastic (Lucene)' },
              { id: 'sigma', label: 'Sigma Rule (YAML)' },
              { id: 'qradar', label: 'IBM QRadar (AQL)' },
            ].map(p => (
              <button
                key={p.id}
                onClick={() => setActivePlatform(p.id as SiemPlatform)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all whitespace-nowrap ${
                  activePlatform === p.id
                    ? 'bg-violet-600/30 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => copyToClipboard(generatedQueries[activePlatform], 'siem-query')}
            className="px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-bold text-xs flex items-center gap-1.5 transition-all shadow-md"
          >
            {copiedKey === 'siem-query' ? <Check className="w-3.5 h-3.5 text-slate-950" /> : <Copy className="w-3.5 h-3.5" />}
            Copy {activePlatform.toUpperCase()} Query
          </button>
        </div>

        <p className="text-xs text-slate-400">{PLATFORM_NOTES[activePlatform]}</p>

        {/* Code Output Viewer */}
        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 select-all overflow-x-auto min-h-[160px] leading-relaxed">
          {generatedQueries[activePlatform]}
        </pre>

      </div>
    </div>
  );
}
