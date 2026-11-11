'use client';

import React, { useState } from 'react';
import { Network, Copy, Check, Info, Layers } from 'lucide-react';
import { calculateCidr } from '@/lib/cidr-utils';
import { CidrCalculation } from '@/lib/types';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

export function CidrCalculator() {
  const [cidrInput, setCidrInput] = useState('192.168.1.0/24');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('cidr');

  let calculation: CidrCalculation | null = null;
  let error: string | null = null;

  try {
    calculation = calculateCidr(cidrInput);
  } catch (err: any) {
    error = err.message || 'Invalid CIDR format';
  }

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handlePrefixChange = (newPrefix: number) => {
    const ipBase = cidrInput.split('/')[0] || '192.168.1.0';
    setCidrInput(`${ipBase}/${newPrefix}`);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-teal-500/20 border border-teal-500/40 text-teal-400">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                CIDR & IPv4 Subnet Calculator
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Calculate IPv4 network ranges, broadcast addresses, wildcard masks, usable host counts, and subnet bitmasks
            </p>
          </div>
        </div>
      </div>

      {/* Input & Slider */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
          <div>
            <label className="text-xs font-mono text-teal-300 font-bold block mb-1.5">
              TARGET IP & CIDR NOTATION:
            </label>
            <input
              type="text"
              value={cidrInput}
              onChange={e => setCidrInput(e.target.value)}
              onBlur={() => {
                if (calculation && cidrInput.trim()) addEntry(cidrInput.trim());
              }}
              onKeyDown={e => {
                if (e.key === 'Enter' && calculation && cidrInput.trim()) {
                  addEntry(cidrInput.trim());
                }
              }}
              placeholder="e.g. 10.0.0.0/16, 172.16.0.0/24, 192.168.1.50/28"
              className="w-full p-3 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-teal-200 placeholder-slate-600 focus:outline-none focus:border-teal-500 shadow-inner"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1.5">
              <span className="text-xs font-mono text-slate-300 font-bold">
                SUBNET PREFIX: /{calculation ? calculation.prefix : 24}
              </span>
              <span className="text-xs font-mono text-teal-400 font-bold">
                Netmask: {calculation?.netmask || '255.255.255.0'}
              </span>
            </div>
            <input
              type="range"
              min={0}
              max={32}
              value={calculation ? calculation.prefix : 24}
              onChange={e => handlePrefixChange(parseInt(e.target.value, 10))}
              className="w-full accent-teal-400"
            />
          </div>
        </div>

        {/* Quick CIDR Presets */}
        <div className="flex items-center gap-2 flex-wrap pt-2">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => setCidrInput(val)}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <span className="text-[11px] font-mono text-slate-400 font-bold">Quick Presets:</span>
          {['10.0.0.0/8', '172.16.0.0/12', '192.168.1.0/24', '192.168.0.0/20', '10.200.0.0/28'].map(preset => (
            <button
              key={preset}
              onClick={() => setCidrInput(preset)}
              className="px-3 py-1 rounded-xl text-[11px] font-mono bg-slate-950 hover:bg-slate-800 border border-teal-500/30 text-teal-300 transition-colors font-bold shadow-xs"
            >
              {preset}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs font-mono">
          {error}
        </div>
      )}

      {calculation && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Main Calculation Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-500 block mb-1">NETWORK ADDRESS</span>
              <span className="text-sm font-bold text-slate-100 font-mono">{calculation.networkAddress}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-500 block mb-1">BROADCAST ADDRESS</span>
              <span className="text-sm font-bold text-cyan-400 font-mono">{calculation.broadcastAddress}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-500 block mb-1">USABLE HOSTS</span>
              <span className="text-sm font-bold text-emerald-400 font-mono">
                {calculation.usableHosts.toLocaleString()} <span className="text-xs text-slate-500 font-normal">/ {calculation.totalHosts.toLocaleString()} total</span>
              </span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-500 block mb-1">CLASS / TYPE</span>
              <span className="text-xs font-bold font-mono text-purple-300">
                {calculation.ipClass} ({calculation.scope})
              </span>
            </div>
          </div>

          {/* Detailed Range & Mask Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* IP Ranges */}
            <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3 font-mono text-xs">
              <h3 className="text-xs text-slate-400 tracking-normal mb-2">
                Subnet Boundaries & Masks
              </h3>
              <div className="flex justify-between items-center p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500">FIRST USABLE IP:</span>
                <span className="text-slate-200 font-bold">{calculation.firstUsableIp}</span>
              </div>
              <div className="flex justify-between items-center p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500">LAST USABLE IP:</span>
                <span className="text-slate-200 font-bold">{calculation.lastUsableIp}</span>
              </div>
              <div className="flex justify-between items-center p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500">SUBNET MASK:</span>
                <span className="text-cyan-300 font-bold">{calculation.netmask}</span>
              </div>
              <div className="flex justify-between items-center p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500">WILDCARD MASK:</span>
                <span className="text-slate-300 font-bold">{calculation.wildcard}</span>
              </div>
            </div>

            {/* Binary Bit Allocations */}
            <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3 font-mono text-xs">
              <h3 className="text-xs text-slate-400 tracking-normal mb-2">
                32-Bit Binary Representation
              </h3>
              <div>
                <span className="text-slate-500 block mb-1 text-[11px]">IP ADDRESS BINARY:</span>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 select-all tracking-wider">
                  {calculation.binaryIp}
                </div>
              </div>
              <div>
                <span className="text-slate-500 block mb-1 text-[11px]">NETMASK BINARY:</span>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-emerald-400 select-all tracking-wider">
                  {calculation.binaryNetmask}
                </div>
              </div>
            </div>
          </div>

          {/* Subnet Division Breakdown Table */}
          {calculation.subnetsBreakdown && calculation.subnetsBreakdown.length > 0 && (
            <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs text-slate-300 tracking-normal">
                  Partitioned Next-Tier Subnets (/{calculation.prefix + 2})
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-3">Subnet CIDR</th>
                      <th className="p-3">Network IP</th>
                      <th className="p-3">Usable Host Range</th>
                      <th className="p-3 text-right">Usable Hosts</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {calculation.subnetsBreakdown.map((sub, i) => (
                      <tr key={i} className="hover:bg-slate-900/60">
                        <td className="p-3 text-cyan-300 font-bold">{sub.cidr}</td>
                        <td className="p-3 text-slate-200">{sub.network}</td>
                        <td className="p-3 text-slate-400">{sub.usableRange}</td>
                        <td className="p-3 text-emerald-400 text-right">{sub.hosts}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
