'use client';

import React, { useState, useMemo, useEffect } from 'react';
import {
  FileSearch,
  Copy,
  Check,
  Download,
  Trash2,
  Filter,
  Shield,
  FolderPlus,
  Sparkles,
  Layers,
  Unlink2,
  Link2,
} from 'lucide-react';
import { useCase } from '@/components/shared/CaseContext';
import { useToolHistory } from '@/lib/useToolHistory';
import { csvCell } from '@/lib/utils';
import { defangText, refangText } from '@/lib/defang';
import { extractIocs } from '@/lib/ioc';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

const SAMPLE_RAW_TEXT = `Incident Response Triage Notes - 2026-09-02
Attacker IP 185.220.101.5 accessed internal bastion from 10.0.4.15 and 192.168.1.50.
Phishing payload downloaded from hxxps://evil-phish-domain.xyz/login.php and http://cdn.malware-drop.ru/payload.exe.
C2 Beacon observed connecting to 45.33.32.156:443 and domain malicious-c2-server.top.
Dropper SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
Secondary DLL MD5: 5d41402abc4b2a76b9719d911017c592
Associated phishing emails sent from attacker-alert@spoofed-bank.com to victim_ceo@victim-corp.com.
Exploited vulnerability: CVE-2024-3400 and CVE-2023-46805.
`;

export function IocExtractor() {
  const [rawText, setRawText] = useState(SAMPLE_RAW_TEXT);
  const [defang, setDefang] = useState(true);
  const [dedup, setDedup] = useState(true);
  const [excludePrivateIps, setExcludePrivateIps] = useState(true);
  const [textMode, setTextMode] = useState<'defang' | 'refang'>('defang');
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [addedToCase, setAddedToCase] = useState(false);

  const { addItem } = useCase();
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('ioc_extractor', { persist: false }); // pasted incident notes and logs: session-only history

  // The standalone Defanger tool was merged into this one, so nothing else clears what it stored
  useEffect(() => {
    try {
      localStorage.removeItem('cyber_tool_history_defanger');
    } catch {
      // Storage disabled or blocked
    }
  }, []);

  const convertedText = textMode === 'defang' ? defangText(rawText) : refangText(rawText);

  // Extraction Pipeline
  const extracted = useMemo(() => {
    const iocs = extractIocs(rawText, { dedup, publicIpsOnly: excludePrivateIps });
    if (!defang) return iocs;

    return {
      ...iocs,
      ips: iocs.ips.map(defangText),
      domains: iocs.domains.map(defangText),
      urls: iocs.urls.map(defangText),
      emails: iocs.emails.map(defangText),
    };
  }, [rawText, defang, dedup, excludePrivateIps]);

  const totalIocsCount =
    extracted.ips.length +
    extracted.domains.length +
    extracted.urls.length +
    extracted.emails.length +
    extracted.cves.length +
    extracted.md5s.length +
    extracted.sha1s.length +
    extracted.sha256s.length;

  const handleCopyGroup = (type: string, items: string[]) => {
    navigator.clipboard.writeText(items.join('\n'));
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleExportCsv = () => {
    const lines = ['Type,IOC'];
    extracted.ips.forEach(i => lines.push(`IPv4,${csvCell(i)}`));
    extracted.domains.forEach(i => lines.push(`Domain,${csvCell(i)}`));
    extracted.urls.forEach(i => lines.push(`URL,${csvCell(i)}`));
    extracted.emails.forEach(i => lines.push(`Email,${csvCell(i)}`));
    extracted.cves.forEach(i => lines.push(`CVE,${csvCell(i)}`));
    extracted.md5s.forEach(i => lines.push(`MD5,${csvCell(i)}`));
    extracted.sha1s.forEach(i => lines.push(`SHA1,${csvCell(i)}`));
    extracted.sha256s.forEach(i => lines.push(`SHA256,${csvCell(i)}`));

    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `extracted-iocs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleAddToCase = () => {
    addItem({
      tool: 'IOC Extractor',
      title: `Extracted ${totalIocsCount} Threat IOCs`,
      category: 'THREAT',
      severity: 'HIGH',
      summary: `Parsed ${extracted.ips.length} IPs, ${extracted.domains.length} Domains, ${extracted.urls.length} URLs, ${extracted.sha256s.length + extracted.sha1s.length + extracted.md5s.length} Hashes, ${extracted.cves.length} CVEs`,
      details: extracted,
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  const IOC_GROUPS = [
    { title: 'IPv4 Addresses', items: extracted.ips, color: 'text-amber-400', bg: 'border-amber-500/30 bg-amber-950/20' },
    { title: 'Domains & Hosts', items: extracted.domains, color: 'text-emerald-400', bg: 'border-emerald-500/30 bg-emerald-950/20' },
    { title: 'URLs', items: extracted.urls, color: 'text-cyan-400', bg: 'border-cyan-500/30 bg-cyan-950/20' },
    { title: 'CVE IDs', items: extracted.cves, color: 'text-rose-400', bg: 'border-rose-500/30 bg-rose-950/20' },
    { title: 'SHA-256 Hashes', items: extracted.sha256s, color: 'text-purple-400', bg: 'border-purple-500/30 bg-purple-950/20' },
    { title: 'SHA-1 Hashes', items: extracted.sha1s, color: 'text-violet-400', bg: 'border-violet-500/30 bg-violet-950/20' },
    { title: 'MD5 Hashes', items: extracted.md5s, color: 'text-indigo-400', bg: 'border-indigo-500/30 bg-indigo-950/20' },
    { title: 'Email Addresses', items: extracted.emails, color: 'text-teal-400', bg: 'border-teal-500/30 bg-teal-950/20' },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-400">
            <FileSearch className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                Bulk IOC Extractor & Normalizer
              </h1>
              <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40">
                {totalIocsCount} IOCs Detected
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Paste raw logs, threat reports or incident notes to extract, classify, defang, refang & export IOCs
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleAddToCase}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-semibold rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg transition-all"
          >
            {addedToCase ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <FolderPlus className="w-3.5 h-3.5" />}
            <span>{addedToCase ? 'Added to Investigation!' : 'Add to Investigation'}</span>
          </button>
          <button
            onClick={handleExportCsv}
            disabled={totalIocsCount === 0}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Raw Text Input Area */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <span className="font-semibold text-slate-300">Raw Threat Intel / Log Input</span>
          <div className="flex items-center gap-3">
            <ToolHistoryDropdown
              history={history}
              onSelect={(val) => setRawText(val)}
              onRemove={removeEntry}
              onClear={clearHistory}
            />
            <button
              onClick={() => setRawText('')}
              className="text-slate-400 hover:text-rose-400 flex items-center space-x-1"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          </div>
        </div>
        <textarea
          value={rawText}
          onChange={e => setRawText(e.target.value)}
          onBlur={() => {
            if (rawText.trim()) addEntry(rawText.trim());
          }}
          placeholder="Paste raw unformatted text, incident notes, logs or emails here..."
          className="w-full h-44 p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl font-mono text-xs text-slate-200 focus:outline-none focus:border-purple-500 resize-none"
        />
      </div>

      {/* Extraction Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
        <div className="flex items-center space-x-4">
          <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={defang}
              onChange={e => setDefang(e.target.checked)}
              className="rounded bg-black border-slate-700 text-purple-600 focus:ring-0"
            />
            <span>Defang Output (e.g. hxxps://domain[.]com)</span>
          </label>

          <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={dedup}
              onChange={e => setDedup(e.target.checked)}
              className="rounded bg-black border-slate-700 text-purple-600 focus:ring-0"
            />
            <span>Deduplicate IOCs</span>
          </label>

          <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={excludePrivateIps}
              onChange={e => setExcludePrivateIps(e.target.checked)}
              className="rounded bg-black border-slate-700 text-purple-600 focus:ring-0"
            />
            <span>Exclude Private & Reserved IPs</span>
          </label>
        </div>
      </div>

      {/* Whole-Text Defang / Refang */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            {(['defang', 'refang'] as const).map(m => (
              <button
                key={m}
                onClick={() => setTextMode(m)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition-colors ${
                  textMode === m
                    ? 'bg-purple-500/20 text-purple-200 border-purple-500/50'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800'
                }`}
              >
                {m === 'defang' ? <Unlink2 className="w-3.5 h-3.5" /> : <Link2 className="w-3.5 h-3.5" />}
                {m === 'defang' ? 'Defang Whole Text' : 'Refang Whole Text'}
              </button>
            ))}
          </div>
          {convertedText && (
            <button
              onClick={() => handleCopyGroup('whole-text', [convertedText])}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1"
            >
              {copiedType === 'whole-text' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedType === 'whole-text' ? 'Copied' : 'Copy'}</span>
            </button>
          )}
        </div>
        <textarea
          readOnly
          value={convertedText}
          placeholder="The pasted text appears here with every indicator converted..."
          className="w-full h-32 p-3 bg-slate-950/90 border border-slate-800 rounded-lg font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none resize-none select-all"
        />
      </div>

      {/* Extracted IOC Groups Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {IOC_GROUPS.map(group => {
          const count = group.items.length;
          return (
            <div
              key={group.title}
              className={`p-4 rounded-xl border ${group.bg} flex flex-col justify-between space-y-3`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className={`text-xs font-bold ${group.color}`}>{group.title}</span>
                  <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-black/40 text-slate-300">
                    {count}
                  </span>
                </div>
                {count > 0 && (
                  <button
                    onClick={() => handleCopyGroup(group.title, group.items)}
                    className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1"
                  >
                    {copiedType === group.title ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                    <span>{copiedType === group.title ? 'Copied' : 'Copy'}</span>
                  </button>
                )}
              </div>

              {count === 0 ? (
                <div className="py-4 text-center text-xs text-slate-500 italic">
                  No {group.title.toLowerCase()} found in payload
                </div>
              ) : (
                <div className="max-h-36 overflow-y-auto space-y-1 font-mono text-xs text-slate-200">
                  {group.items.map((item, idx) => (
                    <div
                      key={idx}
                      className="px-2.5 py-1 rounded bg-black/50 border border-slate-800/80 truncate select-all"
                    >
                      {item}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
