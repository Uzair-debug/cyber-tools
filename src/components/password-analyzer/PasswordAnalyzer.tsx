'use client';

import React, { useEffect, useMemo, useState } from 'react';
import {
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Copy,
  Check,
  Eye,
  EyeOff,
  RefreshCw,
  Cpu,
  Zap,
  Flame,
  Lock,
  AlertTriangle,
  Info,
  Server,
  Globe,
} from 'lucide-react';
import { analyzePassword, PasswordEstimator } from '@/lib/password-utils';

const EXAMPLE_PASSWORD = 'Summer#SecOps@2026!';

// Uniform index in [0, max) from the browser's CSPRNG, rejecting values that would bias the modulo
function secureRandomIndex(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do {
    window.crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

export function PasswordAnalyzer() {
  const [password, setPassword] = useState(EXAMPLE_PASSWORD);
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  // Generator State
  const [genLength, setGenLength] = useState(20);
  const [useUpper, setUseUpper] = useState(true);
  const [useLower, setUseLower] = useState(true);
  const [useDigits, setUseDigits] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);

  // zxcvbn's word lists are ~800 KB, so they load only when this tool is opened
  const [estimator, setEstimator] = useState<PasswordEstimator | null>(null);
  const [loadError, setLoadError] = useState(false);
  useEffect(() => {
    let active = true;
    import('zxcvbn')
      .then(mod => active && setEstimator(() => mod.default))
      .catch(() => active && setLoadError(true));
    return () => {
      active = false;
    };
  }, []);

  const analysis = useMemo(() => (estimator ? analyzePassword(password, estimator) : null), [password, estimator]);
  const example = useMemo(() => (estimator ? analyzePassword(EXAMPLE_PASSWORD, estimator) : null), [estimator]);

  const classes = [
    useLower && 'abcdefghijklmnopqrstuvwxyz',
    useUpper && 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    useDigits && '0123456789',
    useSymbols && '!@#$%^&*()_+-=[]{}|;:,.<>?',
  ].filter((c): c is string => Boolean(c));

  const generatePassword = () => {
    if (classes.length === 0) return;
    const charset = classes.join('');
    // Retry until every selected character type appears (rare for lengths of 8+)
    for (;;) {
      const chars = Array.from({ length: genLength }, () => charset[secureRandomIndex(charset.length)]);
      if (classes.every(c => chars.some(ch => c.includes(ch)))) {
        setPassword(chars.join(''));
        return;
      }
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const entropyDeficit = analysis ? Math.max(0, Math.round((analysis.theoreticalEntropy - analysis.entropy) * 10) / 10) : 0;

  return (
    <div className="space-y-6">
      {/* Standardized Header Banner */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center gap-2.5 mb-1.5">
          <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-md">
            <KeyRound className="w-5 h-5" />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-bold text-slate-50">
              Password Strength & Realistic Entropy Engine
            </h1>
          </div>
        </div>
        <p className="text-xs text-slate-300 max-w-3xl">
          Evaluate true effective cracking resistance against real-world GPU rigs (100 GH/s), rule-based wordlist mutations, and memory-hard KDFs—eliminating false "trillions of years" brute-force illusions.
        </p>
      </div>

      {/* Password Input & Generator Controls */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
        <div className="relative">
          <input
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Type or generate a password to inspect..."
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            className="w-full px-4 py-3.5 pr-24 rounded-xl bg-slate-950/90 border border-slate-800 text-sm font-mono text-rose-200 placeholder-slate-600 focus:outline-none focus:border-rose-500 shadow-inner"
          />
          <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
            <button
              onClick={() => setShowPassword(!showPassword)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              title={showPassword ? 'Hide Password' : 'Show Password'}
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
            <button
              onClick={() => copyToClipboard(password)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-300 hover:bg-slate-800"
              title="Copy Password"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Generator Controls */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-slate-300 font-bold">Length: {genLength}</span>
              <input
                type="range"
                min={8}
                max={48}
                value={genLength}
                onChange={e => setGenLength(parseInt(e.target.value, 10))}
                className="w-24 accent-rose-400"
              />
            </div>
            <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={useUpper}
                onChange={e => setUseUpper(e.target.checked)}
                className="accent-rose-400 rounded"
              />
              A-Z
            </label>
            <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={useLower}
                onChange={e => setUseLower(e.target.checked)}
                className="accent-rose-400 rounded"
              />
              a-z
            </label>
            <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={useDigits}
                onChange={e => setUseDigits(e.target.checked)}
                className="accent-rose-400 rounded"
              />
              0-9
            </label>
            <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={useSymbols}
                onChange={e => setUseSymbols(e.target.checked)}
                className="accent-rose-400 rounded"
              />
              !@#$
            </label>
          </div>

          <button
            onClick={generatePassword}
            disabled={classes.length === 0}
            title={classes.length === 0 ? 'Select at least one character type' : undefined}
            className="px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold text-xs flex items-center gap-1.5 transition-all shadow-md"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Generate Strong Random Password
          </button>
        </div>
      </div>

      {!analysis || !example ? (
        <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 text-xs text-slate-400">
          {loadError
            ? 'The password word lists failed to load. Reload the page to try again.'
            : 'Loading password word lists (runs in your browser; nothing is sent anywhere)...'}
        </div>
      ) : (
      <>
      {/* Forensic Reality Check Banner */}
      <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-600/50 flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <div className="p-2 rounded-lg bg-amber-500/20 text-amber-300 flex-shrink-0">
          <AlertTriangle className="w-5 h-5" />
        </div>
        <div className="space-y-1">
          <h4 className="text-xs font-bold text-amber-200">
            Cybersecurity Reality Check: Why Traditional Calculators Give False "Trillions of Years"
          </h4>
          <p className="text-[11px] text-slate-300 leading-relaxed">
            Naive tools calculate combinations as <code className="font-mono text-amber-300">95^Length</code>, assuming an attacker guesses every character randomly.
            In reality, attackers <strong>never</strong> use blind brute force on structured passwords. They use <strong>wordlists (RockYou / SecLists), combinator attacks, and Hashcat mutation rules</strong>.
            A password with dictionary words and years (like <code className="font-mono text-rose-300">{EXAMPLE_PASSWORD}</code>) drops from a theoretical {Math.round(example.theoreticalEntropy)} bits to about {Math.round(example.entropy)} bits, crackable in about <strong>{example.crackTimeOfflineBruteForce}</strong> against a fast hash at 100 billion guesses per second.
          </p>
        </div>
      </div>

      {/* Primary Entropy & Core Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Effective Realistic Entropy Gauge */}
        <div
          className={`p-5 rounded-xl border flex flex-col justify-between ${
            analysis.score >= 3
              ? 'bg-emerald-950/20 border-emerald-800/60'
              : analysis.score === 2
              ? 'bg-amber-950/20 border-amber-800/60'
              : 'bg-rose-950/20 border-rose-800/60'
          }`}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400 uppercase">Effective Entropy</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                  analysis.score >= 3
                    ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700'
                    : analysis.score === 2
                    ? 'bg-amber-900/60 text-amber-300 border border-amber-700'
                    : 'bg-rose-900/60 text-rose-300 border border-rose-700'
                }`}
              >
                {analysis.label}
              </span>
            </div>
            <div className="flex items-baseline gap-2 mb-1">
              <span className="text-4xl font-extrabold text-slate-100">{analysis.entropy}</span>
              <span className="text-xs font-mono text-slate-400">Realistic Bits</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden my-2">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  analysis.score >= 3 ? 'bg-emerald-500' : analysis.score === 2 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${Math.min(100, (analysis.entropy / 100) * 100)}%` }}
              />
            </div>
            {entropyDeficit > 0 && (
              <span className="text-[10px] text-rose-400 font-mono block">
                ⚠️ -{entropyDeficit} bits lost to dictionary/pattern structure
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-400 font-mono mt-2">Length: {analysis.passwordLength} chars</span>
        </div>

        {/* Theoretical vs Effective Comparison */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-3 flex flex-col justify-between">
          <div>
            <span className="text-xs text-slate-400 uppercase block mb-1">
              Entropy Breakdown
            </span>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between items-center p-2 rounded bg-black/40 border border-slate-800">
                <span className="text-slate-400">Effective (Realistic):</span>
                <span className="font-bold text-rose-300">{analysis.entropy} bits</span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-black/40 border border-slate-800">
                <span className="text-slate-400">Theoretical (Random):</span>
                <span className="font-bold text-cyan-400">{analysis.theoreticalEntropy} bits</span>
              </div>
            </div>
          </div>
          <p className="text-[10px] text-slate-400">
            Theoretical entropy assumes a random coin-flip. Effective entropy accounts for human predictability.
          </p>
        </div>

        {/* Pure Brute Force Baseline */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-2 flex flex-col justify-between">
          <div>
            <span className="text-xs text-slate-400 uppercase block mb-1">
              Pure Brute Force (Every Combination)
            </span>
            <div className="text-lg font-bold text-slate-300 font-mono">
              {analysis.crackTimePureBruteForce}
            </div>
          </div>
          <p className="text-[10px] text-slate-500">
            Only applicable if the attacker tests the entire uniform mathematical keyspace without using dictionary or mask optimizations.
          </p>
        </div>
      </div>

      {/* Real-World Attack Scenarios Matrix */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs text-slate-300 tracking-normal flex items-center gap-1.5">
            <Flame className="w-4 h-4 text-orange-400" />
            <span>Realistic Adversary Attack Vectors (How Long It Actually Takes)</span>
          </h3>
          <span className="text-[11px] text-slate-400">Fast hashes assume 100 billion guesses per second, about one high-end GPU</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {analysis.attackScenarios.map((scenario, i) => (
            <div
              key={i}
              className={`p-4 rounded-xl border flex flex-col justify-between space-y-3 ${
                scenario.riskLevel === 'CRITICAL'
                  ? 'bg-rose-950/20 border-rose-700/60'
                  : scenario.riskLevel === 'HIGH'
                  ? 'bg-orange-950/20 border-orange-700/60'
                  : scenario.riskLevel === 'MEDIUM'
                  ? 'bg-amber-950/20 border-amber-700/60'
                  : 'bg-emerald-950/20 border-emerald-800/60'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-slate-400 font-bold">{scenario.hashSpeed}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                      scenario.riskLevel === 'CRITICAL'
                        ? 'bg-rose-900/80 text-rose-200 border border-rose-600'
                        : scenario.riskLevel === 'HIGH'
                        ? 'bg-orange-900/80 text-orange-200 border border-orange-600'
                        : scenario.riskLevel === 'MEDIUM'
                        ? 'bg-amber-900/80 text-amber-200 border border-amber-600'
                        : 'bg-emerald-900/80 text-emerald-200 border border-emerald-600'
                    }`}
                  >
                    {scenario.riskLevel}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-slate-100">{scenario.name}</h4>
                <div className="text-base font-extrabold font-mono text-cyan-300">
                  {scenario.timeEstimate}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/60 space-y-1 text-[10px]">
                <div className="text-slate-400 font-mono">
                  <span className="text-slate-500">Method: </span>{scenario.technique}
                </div>
                <p className="text-slate-400 leading-snug">{scenario.explanation}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Forensic Pattern Decomposition */}
      {analysis.detectedPatterns.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs text-slate-300 tracking-normal flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>Forensic Pattern Decomposition (How Attackers Dismantle This Password)</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">
              {analysis.detectedPatterns.length} tokens identified
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
            {analysis.detectedPatterns.map((pat, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-black/50 border border-slate-800 space-y-1 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[9px] text-slate-500 uppercase">{pat.type.replace(/_/g, ' ')}</span>
                  <span className="text-[10px] font-mono text-amber-400 font-bold">~{pat.entropyCostBits}b</span>
                </div>
                <div className="font-mono text-xs font-bold text-rose-300 break-all">{pat.token}</div>
                <p className="text-[10px] text-slate-400 leading-tight pt-1 border-t border-slate-800/60">
                  {pat.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Character Distribution & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Character Distribution */}
        <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
          <h3 className="text-xs text-slate-400 tracking-normal">
            Character Set Breakdown
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-500 block">LOWERCASE</span>
              <span className="text-base font-bold text-cyan-400 font-mono">{analysis.charDistribution.lowercase}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-500 block">UPPERCASE</span>
              <span className="text-base font-bold text-cyan-400">{analysis.charDistribution.uppercase}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-500 block">DIGITS (0-9)</span>
              <span className="text-base font-bold text-cyan-400 font-mono">{analysis.charDistribution.digits}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-500 block">SYMBOLS</span>
              <span className="text-base font-bold text-cyan-400 font-mono">{analysis.charDistribution.special}</span>
            </div>
          </div>
        </div>

        {/* Warnings & Suggestions */}
        <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
          <h3 className="text-xs text-slate-400 tracking-normal">
            Security Guidance & Hardening Recommendations
          </h3>
          <div className="space-y-2">
            {analysis.warnings.map((w, i) => (
              <div key={i} className="flex items-center gap-2 text-xs text-rose-300">
                <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
                <span>{w}</span>
              </div>
            ))}
            {analysis.suggestions.map((s, i) => (
              <div key={i} className="flex items-center gap-2 text-xs text-emerald-300">
                <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>{s}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      </>
      )}
    </div>
  );
}
