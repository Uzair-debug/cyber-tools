'use client';

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Sliders,
  Copy,
  Check,
  RotateCcw,
  FolderPlus,
} from 'lucide-react';
import { useCase } from '@/components/shared/CaseContext';
import { BaseMetrics, MetricId, parseCvss3Vector, scoreCvss31 } from '@/lib/cvss';

// Metric definitions for CVSS v3.1 (weights live in src/lib/cvss.ts)
interface MetricOption {
  label: string;
  value: string;
  description: string;
}

interface MetricCategory {
  id: MetricId;
  name: string;
  description: string;
  options: MetricOption[];
}

const CVSS_METRICS: MetricCategory[] = [
  {
    id: 'AV',
    name: 'Attack Vector (AV)',
    description: 'The context by which vulnerability exploitation is possible.',
    options: [
      { label: 'Network (N)', value: 'N', description: 'Exploitable remotely across internet (remotely exploitable)' },
      { label: 'Adjacent (A)', value: 'A', description: 'Limited to a shared physical or logical network (same subnet, Bluetooth, NFC)' },
      { label: 'Local (L)', value: 'L', description: 'Needs local access (shell, keyboard) or a user to open a malicious file' },
      { label: 'Physical (P)', value: 'P', description: 'Requires physical access to device (USB, console)' },
    ],
  },
  {
    id: 'AC',
    name: 'Attack Complexity (AC)',
    description: 'Conditions beyond attacker control that must exist to exploit.',
    options: [
      { label: 'Low (L)', value: 'L', description: 'Repeatable, straightforward exploitation without special conditions' },
      { label: 'High (H)', value: 'H', description: 'Depends on conditions the attacker cannot control (race condition, target-specific info, man-in-the-middle position)' },
    ],
  },
  {
    id: 'PR',
    name: 'Privileges Required (PR)',
    description: 'Level of privileges attacker must possess prior to exploiting.',
    options: [
      { label: 'None (N)', value: 'N', description: 'Unauthenticated attacker can exploit directly' },
      { label: 'Low (L)', value: 'L', description: 'Requires basic user privileges (or guest account)' },
      { label: 'High (H)', value: 'H', description: 'Requires significant (e.g. administrative) control over the component' },
    ],
  },
  {
    id: 'UI',
    name: 'User Interaction (UI)',
    description: 'Requirement for a human user to participate in exploitation.',
    options: [
      { label: 'None (N)', value: 'N', description: 'Vulnerability can be exploited without any user action' },
      { label: 'Required (R)', value: 'R', description: 'Requires victim to click phishing link, open file, or accept prompt' },
    ],
  },
  {
    id: 'S',
    name: 'Scope (S)',
    description: 'Whether vulnerability impacts resources beyond its authorization boundary.',
    options: [
      { label: 'Unchanged (U)', value: 'U', description: 'Compromised component and impacted component are identical' },
      { label: 'Changed (C)', value: 'C', description: 'Vulnerability in one component impacts another (e.g. Sandbox escape, VM escape)' },
    ],
  },
  {
    id: 'C',
    name: 'Confidentiality Impact (C)',
    description: 'Impact to the confidentiality of data managed by system.',
    options: [
      { label: 'High (H)', value: 'H', description: 'Total loss of confidentiality, or disclosure of some critical data (e.g. an admin password)' },
      { label: 'Low (L)', value: 'L', description: 'Some data disclosed, but the attacker does not control what is obtained' },
      { label: 'None (N)', value: 'N', description: 'No loss of confidentiality' },
    ],
  },
  {
    id: 'I',
    name: 'Integrity Impact (I)',
    description: 'Impact to trustworthiness and veracity of information.',
    options: [
      { label: 'High (H)', value: 'H', description: 'Attacker can modify any or all files, or some files with serious consequences' },
      { label: 'Low (L)', value: 'L', description: 'Modification of some data is possible without full system control' },
      { label: 'None (N)', value: 'N', description: 'No loss of integrity' },
    ],
  },
  {
    id: 'A',
    name: 'Availability Impact (A)',
    description: 'Impact to availability and uptime of affected component.',
    options: [
      { label: 'High (H)', value: 'H', description: 'Total loss of availability, sustained or persistent, or serious loss of some resource' },
      { label: 'Low (L)', value: 'L', description: 'Intermittent performance degradation or partial availability loss' },
      { label: 'None (N)', value: 'N', description: 'No impact to system availability' },
    ],
  },
];

const DEFAULT_METRICS: BaseMetrics = {
  AV: 'N',
  AC: 'L',
  PR: 'N',
  UI: 'N',
  S: 'U',
  C: 'H',
  I: 'H',
  A: 'H',
};

export function CvssCalculator() {
  const [metrics, setMetrics] = useState<BaseMetrics>(DEFAULT_METRICS);
  const [vectorInput, setVectorInput] = useState('');
  const [parseMessage, setParseMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [copiedVector, setCopiedVector] = useState(false);
  const [vulnTitle, setVulnTitle] = useState('');
  const [cveId, setCveId] = useState('');
  const [addedToCase, setAddedToCase] = useState(false);

  const { addItem } = useCase();

  const calculation = useMemo(() => {
    const r = scoreCvss31(metrics);
    const severityColor = {
      NONE: 'text-slate-400 bg-slate-900 border-slate-700',
      LOW: 'text-emerald-400 bg-emerald-950/80 border-emerald-500/50',
      MEDIUM: 'text-amber-400 bg-amber-950/80 border-amber-500/50',
      HIGH: 'text-orange-400 bg-orange-950/80 border-orange-500/50',
      CRITICAL: 'text-rose-400 bg-rose-950/80 border-rose-500/50',
    }[r.severity];
    return {
      baseScore: r.baseScore.toFixed(1),
      // The impact subscore can go negative with Scope Changed; it is reported as 0
      impact: Math.max(0, r.impact).toFixed(1),
      exploitability: r.exploitability.toFixed(1),
      vectorString: r.vector,
      severity: r.severity,
      severityColor,
    };
  }, [metrics]);

  const handleSelectMetric = (metricId: MetricId, value: string) => {
    setMetrics(prev => ({ ...prev, [metricId]: value }));
  };

  const handleCopyVector = () => {
    navigator.clipboard.writeText(calculation.vectorString);
    setCopiedVector(true);
    setTimeout(() => setCopiedVector(false), 2000);
  };

  const handleReset = () => {
    setMetrics(DEFAULT_METRICS);
    setVectorInput('');
    setParseMessage(null);
  };

  const handleParseVector = () => {
    if (!vectorInput.trim()) return;
    const result = parseCvss3Vector(vectorInput);
    if ('error' in result) {
      setParseMessage({ ok: false, text: result.error });
      return;
    }
    setMetrics(result.metrics);
    setParseMessage({
      ok: true,
      text: result.ignored.length
        ? `Vector loaded. Temporal and environmental metrics are not scored here, so these were ignored: ${result.ignored.join('/')}`
        : 'Vector loaded.',
    });
  };

  const handleAddToCase = () => {
    const title = [cveId.trim(), vulnTitle.trim()].filter(Boolean).join(': ') || 'Unnamed vulnerability';
    addItem({
      tool: 'CVSS Calculator',
      title,
      category: 'THREAT',
      severity: calculation.severity === 'NONE' ? 'INFO' : (calculation.severity as any),
      summary: `CVSS v3.1 Base Score ${calculation.baseScore} (${calculation.severity}) - Vector: ${calculation.vectorString}`,
      details: {
        cveId: cveId.trim(),
        vulnTitle: vulnTitle.trim(),
        baseScore: calculation.baseScore,
        severity: calculation.severity,
        vectorString: calculation.vectorString,
        metrics,
        impactScore: calculation.impact,
        exploitabilityScore: calculation.exploitability,
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Tool Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                CVSS v3.1 Calculator
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Base score and vector string, using the FIRST CVSS v3.1 formulas
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
            onClick={handleReset}
            className="flex items-center space-x-1 px-3 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* Score Dashboard Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Score Badge */}
        <div className="p-6 rounded-2xl bg-slate-900/60 to-[var(--bg-surface)] border border-slate-800 flex flex-col items-center justify-center text-center relative overflow-hidden">
          <div className="text-xs font-semibold tracking-normal text-slate-400 mb-2">
            Calculated Base Score
          </div>
          <div className="text-5xl font-black tracking-tight text-slate-50 mb-2">
            {calculation.baseScore}
            <span className="text-xl text-slate-500 font-normal"> / 10.0</span>
          </div>
          <div
            className={`px-3 py-1 rounded-full text-xs font-bold tracking-wider uppercase border ${calculation.severityColor}`}
          >
            {calculation.severity} SEVERITY
          </div>
          <div className="mt-3 text-[11px] text-slate-400">
            Impact subscore {calculation.impact}, exploitability {calculation.exploitability}
          </div>
        </div>

        {/* Vector String & Import */}
        <div className="md:col-span-2 p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-slate-300">Generated Vector String</span>
              <button
                onClick={handleCopyVector}
                className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center space-x-1"
              >
                {copiedVector ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedVector ? 'Copied!' : 'Copy Vector'}</span>
              </button>
            </div>
            <div className="p-2.5 rounded-xl bg-black/60 border border-slate-800 font-mono text-xs text-rose-300 break-all select-all">
              {calculation.vectorString}
            </div>
          </div>

          {/* Import Vector Bar */}
          <div className="flex items-center space-x-2 pt-2 border-t border-slate-800">
            <input
              type="text"
              value={vectorInput}
              onChange={e => {
                setVectorInput(e.target.value);
                setParseMessage(null);
              }}
              onKeyDown={e => e.key === 'Enter' && handleParseVector()}
              spellCheck={false}
              placeholder="Paste existing vector (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)..."
              className="flex-1 px-3 py-1.5 bg-black/40 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
            />
            <button
              onClick={handleParseVector}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 transition-colors"
            >
              Parse Vector
            </button>
          </div>
          {parseMessage && (
            <p className={`text-xs ${parseMessage.ok ? 'text-emerald-400' : 'text-rose-400'}`}>{parseMessage.text}</p>
          )}
        </div>
      </div>

      {/* Target Info Inputs for Report */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
        <div>
          <label className="block text-slate-400 font-medium mb-1">CVE / Vulnerability Identifier</label>
          <input
            type="text"
            value={cveId}
            onChange={e => setCveId(e.target.value)}
            placeholder="e.g. CVE-2024-3400"
            spellCheck={false}
            className="w-full px-3 py-1.5 bg-black/40 border border-slate-800 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-rose-500"
          />
        </div>
        <div>
          <label className="block text-slate-400 font-medium mb-1">Vulnerability Title / System Description</label>
          <input
            type="text"
            value={vulnTitle}
            onChange={e => setVulnTitle(e.target.value)}
            placeholder="e.g. PAN-OS GlobalProtect command injection"
            className="w-full px-3 py-1.5 bg-black/40 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-rose-500"
          />
        </div>
      </div>

      {/* Interactive Metric Selection Grid */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
          <Sliders className="w-4 h-4 text-rose-400" />
          <span>Base Metric Group</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {CVSS_METRICS.map(category => {
            const selectedValue = metrics[category.id];

            return (
              <div
                key={category.id}
                className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-all space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200">{category.name}</span>
                  <span className="text-xs font-mono font-bold text-rose-400">
                    {category.id}:{selectedValue}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{category.description}</p>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 pt-1">
                  {category.options.map(opt => {
                    const isSelected = selectedValue === opt.value;
                    return (
                      <button
                        key={opt.value}
                        onClick={() => handleSelectMetric(category.id, opt.value)}
                        className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-all text-center ${
                          isSelected
                            ? 'bg-rose-500/20 border border-rose-500/60 text-rose-300 shadow-sm'
                            : 'bg-black/30 hover:bg-slate-800/80 border border-slate-800 text-slate-400'
                        }`}
                        title={opt.description}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
