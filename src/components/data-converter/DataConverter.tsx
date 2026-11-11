'use client';

import React, { useState, useEffect } from 'react';
import {
  Binary,
  ArrowRightLeft,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  FolderPlus,
  Zap,
  Code2,
  Clock,
  Key,
} from 'lucide-react';
import { useCase } from '@/components/shared/CaseContext';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

type ConversionType =
  | 'base64'
  | 'hex'
  | 'url'
  | 'html'
  | 'binary'
  | 'rot13'
  | 'timestamp'
  | 'xor';

export function DataConverter() {
  const [conversionType, setConversionType] = useState<ConversionType>('base64');
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [input, setInput] = useState('Admin:SuperSecretPassword!2026');
  const [output, setOutput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [rotShift, setRotShift] = useState(13);
  const [xorKey, setXorKey] = useState('SECRET_KEY');
  const [addedToCase, setAddedToCase] = useState(false);
  const [detectedFormat, setDetectedFormat] = useState<string | null>(null);

  const { addItem } = useCase();
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('data_converter', { persist: false }); // decoded data often holds credentials: session-only history

  // Perform live conversion
  useEffect(() => {
    setError(null);
    if (!input) {
      setOutput('');
      return;
    }

    try {
      if (conversionType === 'base64') {
        if (mode === 'encode') {
          setOutput(btoa(unescape(encodeURIComponent(input))));
        } else {
          setOutput(decodeURIComponent(escape(atob(input.trim()))));
        }
      } else if (conversionType === 'hex') {
        if (mode === 'encode') {
          let hex = '';
          for (let i = 0; i < input.length; i++) {
            hex += input.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
          }
          setOutput(hex.trim());
        } else {
          const cleanHex = input.replace(/[^0-9a-fA-F]/g, '');
          if (cleanHex.length % 2 !== 0) {
            throw new Error('Hex string length must be even');
          }
          let str = '';
          for (let i = 0; i < cleanHex.length; i += 2) {
            str += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
          }
          setOutput(str);
        }
      } else if (conversionType === 'url') {
        if (mode === 'encode') {
          setOutput(encodeURIComponent(input));
        } else {
          setOutput(decodeURIComponent(input));
        }
      } else if (conversionType === 'html') {
        if (mode === 'encode') {
          setOutput(
            input.replace(/[\u00A0-\u9999<>&]/g, i => '&#' + i.charCodeAt(0) + ';')
          );
        } else {
          const doc = new DOMParser().parseFromString(input, 'text/html');
          setOutput(doc.documentElement.textContent || '');
        }
      } else if (conversionType === 'binary') {
        if (mode === 'encode') {
          let bin = '';
          for (let i = 0; i < input.length; i++) {
            bin += input.charCodeAt(i).toString(2).padStart(8, '0') + ' ';
          }
          setOutput(bin.trim());
        } else {
          const cleanBin = input.replace(/[^01]/g, '');
          let str = '';
          for (let i = 0; i < cleanBin.length; i += 8) {
            str += String.fromCharCode(parseInt(cleanBin.substr(i, 8), 2));
          }
          setOutput(str);
        }
      } else if (conversionType === 'rot13') {
        const shift = mode === 'encode' ? rotShift : (26 - (rotShift % 26)) % 26;
        const res = input.replace(/[a-zA-Z]/g, c => {
          const base = c <= 'Z' ? 65 : 97;
          return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
        });
        setOutput(res);
      } else if (conversionType === 'timestamp') {
        const num = Number(input.trim());
        if (isNaN(num)) {
          // Try parse date string to timestamp
          const date = new Date(input.trim());
          if (isNaN(date.getTime())) throw new Error('Invalid Date / Timestamp string');
          setOutput(
            `Unix Seconds: ${Math.floor(date.getTime() / 1000)}\nUnix Milliseconds: ${date.getTime()}\nISO 8601: ${date.toISOString()}\nUTC: ${date.toUTCString()}\nLocal: ${date.toLocaleString()}`
          );
        } else {
          // Epoch timestamp
          const date = num > 1e11 ? new Date(num) : new Date(num * 1000);
          setOutput(
            `ISO 8601: ${date.toISOString()}\nUTC: ${date.toUTCString()}\nLocal: ${date.toLocaleString()}\nUnix Seconds: ${Math.floor(date.getTime() / 1000)}\nUnix Milliseconds: ${date.getTime()}`
          );
        }
      } else if (conversionType === 'xor') {
        if (!xorKey) throw new Error('XOR Key required');
        let res = '';
        for (let i = 0; i < input.length; i++) {
          const charCode = input.charCodeAt(i) ^ xorKey.charCodeAt(i % xorKey.length);
          res += String.fromCharCode(charCode);
        }
        setOutput(res);
      }
    } catch (e: any) {
      setError(e.message || 'Conversion failed. Check input format.');
      setOutput('');
    }
  }, [input, conversionType, mode, rotShift, xorKey]);

  // Auto-detect format
  const handleAutoDetect = () => {
    const trimmed = input.trim();
    if (/^[0-9a-fA-F\s]{4,}$/.test(trimmed) && trimmed.length % 2 === 0) {
      setDetectedFormat('Hex (Hexadecimal)');
      setConversionType('hex');
      setMode('decode');
    } else if (/^[A-Za-z0-9+/=]{8,}$/.test(trimmed) && trimmed.length % 4 === 0) {
      setDetectedFormat('Base64');
      setConversionType('base64');
      setMode('decode');
    } else if (/^%[0-9A-Fa-f]{2}/.test(trimmed)) {
      setDetectedFormat('URL Encoded');
      setConversionType('url');
      setMode('decode');
    } else if (/^[01\s]{8,}$/.test(trimmed)) {
      setDetectedFormat('Binary');
      setConversionType('binary');
      setMode('decode');
    } else if (/^\d{10,13}$/.test(trimmed)) {
      setDetectedFormat('Unix Epoch Timestamp');
      setConversionType('timestamp');
      setMode('decode');
    } else {
      setDetectedFormat('Plain Text (No strong encoded signature detected)');
    }
  };

  const handleSwap = () => {
    if (output) {
      setInput(output);
      setMode(mode === 'encode' ? 'decode' : 'encode');
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAddToCase = async () => {
    // The case is stored in localStorage and decoded payloads often contain credentials, so only
    // sizes and a SHA-256 fingerprint of the output are recorded, never the content itself
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(output));
    const outputSha256 = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    addItem({
      tool: 'Data Converter',
      title: `${conversionType.toUpperCase()} ${mode.toUpperCase()}`,
      category: 'CRYPTO',
      severity: 'INFO',
      summary: `Converted payload (${conversionType}, mode: ${mode}); content not stored`,
      details: {
        type: conversionType,
        mode,
        inputLength: input.length,
        outputLength: output.length,
        outputSha256,
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  const CONVERTER_TABS: { id: ConversionType; label: string }[] = [
    { id: 'base64', label: 'Base64' },
    { id: 'hex', label: 'Hex / Raw Bytes' },
    { id: 'url', label: 'URL Percent' },
    { id: 'html', label: 'HTML Entities' },
    { id: 'binary', label: 'Binary (01001)' },
    { id: 'rot13', label: 'ROT13 / Caesar' },
    { id: 'timestamp', label: 'Epoch Timestamp' },
    { id: 'xor', label: 'XOR Cipher' },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-teal-500/20 border border-teal-500/40 text-teal-400">
            <Binary className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                Data Conversion & Encoding Hub
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Multi-format encoding, decoding, ciphers & timestamp converter with live auto-detection
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
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 border-b border-slate-800">
        {CONVERTER_TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setConversionType(tab.id)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all whitespace-nowrap ${
              conversionType === tab.id
                ? 'bg-teal-500/20 text-teal-300 border border-teal-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Control Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="inline-flex p-1 bg-black/40 rounded-lg border border-slate-800">
            <button
              onClick={() => setMode('encode')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                mode === 'encode'
                  ? 'bg-teal-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Encode
            </button>
            <button
              onClick={() => setMode('decode')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                mode === 'decode'
                  ? 'bg-teal-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Decode
            </button>
          </div>

          <button
            onClick={handleSwap}
            className="flex items-center space-x-1 px-2.5 py-1 text-xs text-slate-300 hover:text-slate-50 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors"
            title="Swap input & output"
          >
            <ArrowRightLeft className="w-3.5 h-3.5" />
            <span>Swap</span>
          </button>

          <button
            onClick={handleAutoDetect}
            className="flex items-center space-x-1 px-2.5 py-1 text-xs text-cyan-300 hover:text-cyan-200 bg-cyan-950/60 hover:bg-cyan-900/60 rounded-lg border border-cyan-700/50 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Auto-Detect</span>
          </button>
        </div>

        {/* Dynamic Controls for specific ciphers */}
        {conversionType === 'rot13' && (
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-400">Shift Key (1-25):</span>
            <input
              type="number"
              min={1}
              max={25}
              value={rotShift}
              onChange={e => setRotShift(parseInt(e.target.value) || 13)}
              className="w-16 px-2 py-1 bg-black/50 border border-slate-700 rounded text-slate-200 text-center"
            />
          </div>
        )}

        {conversionType === 'xor' && (
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-400">XOR Key:</span>
            <input
              type="text"
              value={xorKey}
              onChange={e => setXorKey(e.target.value)}
              className="px-2.5 py-1 bg-black/50 border border-slate-700 rounded text-slate-200"
            />
          </div>
        )}

        {detectedFormat && (
          <span className="text-xs text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2.5 py-0.5 rounded-full">
            Detected: {detectedFormat}
          </span>
        )}
      </div>

      {/* Editor Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Input */}
        <div className="flex flex-col space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1">
            <span className="font-semibold text-slate-300">Input Payload</span>
            <div className="flex items-center gap-3">
              <ToolHistoryDropdown
                history={history}
                onSelect={(val) => setInput(val)}
                onRemove={removeEntry}
                onClear={clearHistory}
              />
              <span>{input.length} chars</span>
            </div>
          </div>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onBlur={() => {
              if (input.trim()) addEntry(input.trim());
            }}
            placeholder="Type, paste encoded data, hex bytes, or timestamp here..."
            className="w-full h-64 p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl font-mono text-xs text-slate-200 focus:outline-none focus:border-teal-500 resize-none"
          />
        </div>

        {/* Output */}
        <div className="flex flex-col space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1">
            <span className="font-semibold text-teal-300">Converted Output</span>
            <button
              onClick={handleCopy}
              disabled={!output}
              className="text-xs text-teal-400 hover:text-teal-300 flex items-center space-x-1 disabled:opacity-50"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy Result'}</span>
            </button>
          </div>
          <textarea
            value={output}
            readOnly
            placeholder="Converted output will appear here live..."
            className="w-full h-64 p-3.5 bg-black/60 border border-slate-800 rounded-xl font-mono text-xs text-teal-300 focus:outline-none resize-none select-all"
          />
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-xl text-xs text-rose-300 font-mono">
          ⚠️ {error}
        </div>
      )}
    </div>
  );
}
