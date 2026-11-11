'use client';

import React, { useState } from 'react';
import {
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
  MapPin,
  Server,
  Network,
  Activity,
  AlertTriangle,
  RefreshCw,
  Copy,
} from 'lucide-react';
import { IpThreatData } from '@/lib/types';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

export function IpThreatHub() {
  const [ip, setIp] = useState('1.1.1.1');
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState<IpThreatData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('ip');

  const handleScan = async (targetIp = ip) => {
    const clean = targetIp.trim();
    if (!clean) return;
    addEntry(clean);
    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/ip?ip=${encodeURIComponent(targetIp.trim())}`);
      if (!res.ok) {
        throw new Error('Failed to resolve IP intelligence');
      }
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Scan error');
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-indigo-500/20 border border-indigo-500/40 text-indigo-400">
            <Radio className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                IP & Threat Reputation Hub
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Query IP addresses for Autonomous System Numbers (ASN), ISP routing, geolocation, reverse PTR hostnames, and abuse threat scores
            </p>
          </div>
        </div>
      </div>

      {/* Input Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl flex flex-col sm:flex-row gap-3 items-center">
        <div className="relative flex-1 w-full">
          <Radio className="w-4 h-4 text-indigo-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={ip}
            onChange={e => setIp(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="Enter IPv4 or IPv6 address (e.g. 8.8.8.8, 1.1.1.1, 192.168.1.1)..."
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-indigo-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 shadow-inner"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <ToolHistoryDropdown
            history={history}
            onSelect={(val) => {
              setIp(val);
              handleScan(val);
            }}
            onRemove={removeEntry}
            onClear={clearHistory}
          />
          <button
            onClick={() => {
              setIp('8.8.8.8');
              handleScan('8.8.8.8');
            }}
            className="px-3.5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-indigo-500/30 text-indigo-300 text-xs font-mono transition-colors font-bold"
          >
            Google (8.8.8.8)
          </button>
          <button
            onClick={() => {
              setIp('1.1.1.1');
              handleScan('1.1.1.1');
            }}
            className="px-3.5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-purple-500/30 text-purple-300 text-xs font-mono transition-colors font-bold"
          >
            Cloudflare (1.1.1.1)
          </button>
          <button
            onClick={() => handleScan()}
            disabled={isLoading}
            className="flex-1 sm:flex-none px-6 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-extrabold text-xs flex items-center justify-center gap-2 transition-all shadow-lg disabled:opacity-50"
          >
            {isLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            {isLoading ? 'Scanning...' : 'Investigate IP'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {data && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Main Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Reputation Badge */}
            <div
              className={`p-5 rounded-xl border flex flex-col justify-between ${
                data.threatLevel === 'MALICIOUS'
                  ? 'bg-rose-950/20 border-rose-800/60'
                  : data.threatLevel === 'SUSPICIOUS'
                  ? 'bg-amber-950/20 border-amber-800/60'
                  : data.threatLevel === 'UNKNOWN'
                  ? 'bg-slate-900/50 border-slate-700'
                  : 'bg-emerald-950/20 border-emerald-800/60'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-slate-400 uppercase">Threat Reputation</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      data.threatLevel === 'MALICIOUS'
                        ? 'bg-rose-900/80 text-rose-300 border border-rose-700'
                        : data.threatLevel === 'SUSPICIOUS'
                        ? 'bg-amber-900/80 text-amber-300 border border-amber-700'
                        : data.threatLevel === 'UNKNOWN'
                        ? 'bg-slate-800 text-slate-300 border border-slate-600'
                        : 'bg-emerald-900/80 text-emerald-300 border border-emerald-700'
                    }`}
                  >
                    {data.threatLevel}
                  </span>
                </div>
                <div className="flex items-baseline gap-2 mb-2">
                  <span className="text-4xl font-extrabold text-slate-100">{data.threatScore}</span>
                  <span className="text-xs font-mono text-slate-400">/ 100 Blocklist Risk Score</span>
                </div>
              </div>
              <div className="space-y-1">
                <div className="text-[11px] text-slate-400 font-mono">
                  Classification: {data.isBogon ? 'Bogon / Reserved Space' : data.isPrivate ? 'Private / Non-public Address' : 'Public Internet Host'}
                </div>
                {data.categories && data.categories.length > 0 && (
                  <div className="text-[10px] text-slate-300 font-mono flex flex-wrap gap-1 mt-1">
                    {data.categories.map((cat, i) => (
                      <span
                        key={i}
                        className={`px-1.5 py-0.5 rounded border ${
                          data.threatLevel === 'MALICIOUS'
                            ? 'bg-rose-950/60 border-rose-800 text-rose-300'
                            : data.threatLevel === 'SUSPICIOUS'
                            ? 'bg-amber-950/60 border-amber-800 text-amber-300'
                            : data.threatLevel === 'UNKNOWN'
                            ? 'bg-slate-900 border-slate-700 text-slate-300'
                            : 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                        }`}
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* GeoIP Location */}
            <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 text-xs uppercase">
                <MapPin className="w-4 h-4" />
                <span>Geolocation & Timezone</span>
              </div>
              <div className="text-xs font-mono space-y-1">
                <div>
                  <span className="text-slate-500">COUNTRY: </span>
                  <span className="text-slate-200">{data.geo?.country} ({data.geo?.countryCode})</span>
                </div>
                <div>
                  <span className="text-slate-500">CITY / REGION: </span>
                  <span className="text-slate-200">{data.geo?.city}, {data.geo?.region}</span>
                </div>
                <div>
                  <span className="text-slate-500">COORDINATES: </span>
                  <span className="text-slate-400">{data.geo?.latitude || 0}, {data.geo?.longitude || 0}</span>
                </div>
              </div>
            </div>

            {/* ASN & Routing */}
            <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 text-xs uppercase">
                <Network className="w-4 h-4" />
                <span>Autonomous System (ASN)</span>
              </div>
              <div className="text-xs font-mono space-y-1">
                <div>
                  <span className="text-slate-500">ASN: </span>
                  <span className="text-slate-200 font-bold">{data.asn?.asn}</span>
                </div>
                <div>
                  <span className="text-slate-500">ORGANIZATION: </span>
                  <span className="text-slate-200">{data.asn?.name}</span>
                </div>
                <div>
                  <span className="text-slate-500">PTR HOSTNAME: </span>
                  <span className="text-cyan-300 break-all">{data.reverseDns || (data.isPrivate || data.isBogon ? 'Not looked up' : 'Lookup failed')}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Live Port Connectivity Probe Table */}
          <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h3 className="text-xs text-slate-400 tracking-normal flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                Live Service Port Exposure Probes (TCP Sockets)
              </h3>
              <span className="text-[10px] font-mono text-slate-500">
                1200ms Active Non-Blocking TCP Handshake
              </span>
            </div>
            {(!data.openPortsSimulated || data.openPortsSimulated.length === 0) && (
              <p className="text-[11px] font-mono text-slate-500">
                Not probed: {data.isPrivate || data.isBogon
                  ? 'non-public addresses are not scanned.'
                  : data.portProbeNote || 'no probe results were returned.'}
              </p>
            )}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {data.openPortsSimulated?.map(p => (
                <div
                  key={p.port}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-slate-200">Port {p.port}</span>
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded uppercase font-bold ${
                        p.state === 'open'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800 shadow-[0_0_8px_rgba(16,185,129,0.3)]'
                          : p.state === 'filtered'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-slate-900 text-slate-500 border border-slate-800'
                      }`}
                    >
                      {p.state}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">{p.service}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
