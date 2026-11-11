'use client';

import React, { useState, useMemo } from 'react';
import {
  Terminal,
  Search,
  Copy,
  Check,
  FolderPlus,
  Sliders,
  Sparkles,
  Layers,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  Zap,
  Info,
  Tag,
  Monitor,
  HardDrive,
  GitBranch,
  Box,
  Wifi,
} from 'lucide-react';
import { COMMAND_ITEMS, CommandCategory, CommandItem } from './cheatsheet-data';
import { useCase } from '@/components/shared/CaseContext';

const CATEGORIES: { id: 'ALL' | CommandCategory; label: string; icon: any }[] = [
  { id: 'ALL', label: 'All Commands', icon: Sparkles },
  { id: 'Windows & PowerShell', label: 'Windows & PowerShell', icon: Monitor },
  { id: 'Linux & Bash', label: 'Linux & Bash', icon: Terminal },
  { id: 'Git Recovery', label: 'Git Recovery', icon: GitBranch },
  { id: 'Docker & Containers', label: 'Docker & Containers', icon: Box },
  { id: 'Networking & Diagnostics', label: 'Networking & Diagnostics', icon: Wifi },
];

export function CommandCheatSheetHub() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | CommandCategory>('ALL');

  // Custom live variables
  const [isVariablesOpen, setIsVariablesOpen] = useState(false);
  const [variables, setVariables] = useState<Record<string, string>>({
    host: '192.168.1.50',
    port: '443',
    source: 'C:\\Data',
    destination: 'D:\\Backup',
    user: 'admin',
    logPath: 'C:\\Logs\\robocopy.log',
    serviceName: 'nginx',
    containerId: 'my_container',
    ruleName: 'Allow_App_Inbound',
    newCommitMessage: 'fix: resolve production crash',
    searchString: 'database_password',
  });

  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [addedToCase, setAddedToCase] = useState(false);

  const { addItem } = useCase();

  // Helper to replace placeholders like <host>, <port> with custom variables
  const resolveCommand = (template: string) => {
    let result = template;
    Object.entries(variables).forEach(([key, val]) => {
      const placeholder = `<${key}>`;
      if (val) {
        result = result.split(placeholder).join(val);
      }
    });
    return result;
  };

  // Filter commands
  const filteredCommands = useMemo(() => {
    return COMMAND_ITEMS.filter(item => {
      const matchCat = selectedCategory === 'ALL' || item.category === selectedCategory;
      if (!matchCat) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchText =
          item.title.toLowerCase().includes(q) ||
          item.description.toLowerCase().includes(q) ||
          item.commandTemplate.toLowerCase().includes(q) ||
          item.tags.some(t => t.toLowerCase().includes(q));
        if (!matchText) return false;
      }

      return true;
    });
  }, [selectedCategory, searchQuery]);

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleResetVariables = () => {
    setVariables({
      host: '192.168.1.50',
      port: '443',
      source: 'C:\\Data',
      destination: 'D:\\Backup',
      user: 'admin',
      logPath: 'C:\\Logs\\robocopy.log',
      serviceName: 'nginx',
      containerId: 'my_container',
      ruleName: 'Allow_App_Inbound',
      newCommitMessage: 'fix: resolve production crash',
      searchString: 'database_password',
    });
  };

  const handleAddToCase = () => {
    addItem({
      tool: 'IT & DevOps Cheat-Sheet Hub',
      title: `Reference Playbook (${filteredCommands.length} Commands)`,
      category: 'RECON',
      severity: 'INFO',
      summary: `Logged administrative commands reference across ${selectedCategory}.`,
      details: {
        category: selectedCategory,
        matchingCount: filteredCommands.length,
        customVariables: variables,
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 shadow-md">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                IT & DevOps Command Cheat-Sheet Hub
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Interactive reference playbook for Windows & PowerShell, Linux, Git Emergency Recovery, Docker & Networking
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsVariablesOpen(!isVariablesOpen)}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Sliders className="w-3.5 h-3.5 text-emerald-400" />
            <span>{isVariablesOpen ? 'Hide Custom Variables' : 'Customize Variables (<host>, <port>...)'}</span>
          </button>
          <button
            onClick={handleAddToCase}
            className="flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg transition-all"
          >
            {addedToCase ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <FolderPlus className="w-3.5 h-3.5" />}
            <span>{addedToCase ? 'Added to Case!' : 'Add to Investigation'}</span>
          </button>
        </div>
      </div>

      {/* Collapsible Variables Customizer */}
      {isVariablesOpen && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 animate-in fade-in duration-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-slate-200">Dynamic Variable Replacer</span>
            </div>
            <button
              onClick={handleResetVariables}
              className="text-xs text-slate-400 hover:text-emerald-400 flex items-center space-x-1"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset Defaults</span>
            </button>
          </div>
          <p className="text-[11px] text-slate-400">
            Changing these values automatically updates all commands across the cheat sheet before copying:
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div>
              <label className="text-[10px] font-mono text-slate-400 block mb-1">&lt;host&gt;</label>
              <input
                type="text"
                value={variables.host}
                onChange={e => setVariables(v => ({ ...v, host: e.target.value }))}
                className="w-full px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 block mb-1">&lt;port&gt;</label>
              <input
                type="text"
                value={variables.port}
                onChange={e => setVariables(v => ({ ...v, port: e.target.value }))}
                className="w-full px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 block mb-1">&lt;source&gt;</label>
              <input
                type="text"
                value={variables.source}
                onChange={e => setVariables(v => ({ ...v, source: e.target.value }))}
                className="w-full px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 block mb-1">&lt;destination&gt;</label>
              <input
                type="text"
                value={variables.destination}
                onChange={e => setVariables(v => ({ ...v, destination: e.target.value }))}
                className="w-full px-2.5 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
        </div>
      )}

      {/* Search Bar */}
      <div className="relative">
        <Search className="w-5 h-5 absolute left-3.5 top-3 text-slate-500" />
        <input
          type="text"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search commands by task, tool (robocopy, rsync, ss, git, docker), or problem description..."
          className="w-full pl-11 pr-24 py-3 bg-black/50 border border-slate-700 rounded-xl text-slate-100 text-sm focus:outline-none focus:border-emerald-500 shadow-inner"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery('')}
            className="absolute right-3 top-2.5 px-2.5 py-1 text-xs text-slate-400 hover:text-slate-50 rounded bg-slate-800"
          >
            Clear
          </button>
        )}
      </div>

      {/* Category Filter Pills */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-3">
        {CATEGORIES.map(cat => {
          const Icon = cat.icon;
          const isSelected = selectedCategory === cat.id;

          return (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-all ${
                isSelected
                  ? 'bg-emerald-600 text-white shadow-md'
                  : 'bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{cat.label}</span>
            </button>
          );
        })}
      </div>

      {/* Matching Count */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Showing {filteredCommands.length} commands</span>
        {isVariablesOpen && (
          <span className="text-emerald-400 text-[11px] font-semibold flex items-center gap-1">
            <Check className="w-3 h-3" /> Live variable substitution active
          </span>
        )}
      </div>

      {/* Commands List */}
      <div className="space-y-4">
        {filteredCommands.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/40 rounded-2xl border border-slate-800 text-slate-500 text-xs">
            No commands match your search query. Try searching for "mirror", "port", "commit", or "docker".
          </div>
        ) : (
          filteredCommands.map(item => {
            const finalCommand = resolveCommand(item.commandTemplate);
            const isCopied = copiedId === item.id;

            return (
              <div
                key={item.id}
                className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700/80 transition-all space-y-3 group shadow-md"
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <div className="flex items-center space-x-2">
                      <h3 className="text-sm font-bold text-slate-200 group-hover:text-emerald-300 transition-colors">
                        {item.title}
                      </h3>
                      <span className="px-2 py-0.5 rounded bg-black/40 border border-slate-800 text-[10px] font-mono text-emerald-400 font-semibold">
                        {item.category}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{item.description}</p>
                  </div>

                  <button
                    onClick={() => handleCopy(item.id, finalCommand)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-emerald-600 hover:text-white text-slate-300 text-xs font-semibold rounded-lg border border-slate-700 hover:border-emerald-500 flex items-center space-x-1.5 transition-all self-start sm:self-auto shrink-0 shadow-sm"
                  >
                    {isCopied ? <Check className="w-3.5 h-3.5 text-slate-50" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{isCopied ? 'Copied!' : 'Copy Command'}</span>
                  </button>
                </div>

                {/* Command Snippet */}
                <div className="relative">
                  <pre className="p-3 bg-[var(--bg-app)] border border-slate-800 rounded-lg font-mono text-xs text-emerald-300 overflow-x-auto leading-relaxed select-all">
                    {finalCommand}
                  </pre>
                </div>

                {/* Explanation Notes if present */}
                {item.explanationNotes && item.explanationNotes.length > 0 && (
                  <div className="p-2.5 bg-black/40 rounded-lg border border-slate-800/80 space-y-1 text-[11px] text-slate-400">
                    <div className="text-slate-500 font-semibold text-[10px] uppercase tracking-wider flex items-center space-x-1">
                      <Info className="w-3 h-3 text-emerald-400" />
                      <span>Parameters & Flags Explained:</span>
                    </div>
                    <ul className="list-disc list-inside space-y-0.5 pl-1">
                      {item.explanationNotes.map((note, i) => (
                        <li key={i}>{note}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Tags */}
                <div className="flex flex-wrap items-center gap-1 pt-1">
                  {item.tags.map(tag => (
                    <span
                      key={tag}
                      onClick={() => setSearchQuery(tag)}
                      className="px-2 py-0.5 rounded bg-black/30 hover:bg-slate-800 text-[10px] text-slate-500 hover:text-slate-300 cursor-pointer font-mono transition-colors"
                    >
                      #{tag}
                    </span>
                  ))}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
