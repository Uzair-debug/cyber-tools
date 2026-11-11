'use client';

import React, { useState, useEffect } from 'react';
import { Binary, Upload, Copy, Check, Key, RefreshCw, Sparkles } from 'lucide-react';
import CryptoJS from 'crypto-js';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

export function HashCryptoUtility() {
  const [inputText, setInputText] = useState('CyberToolbox SecOps Workbench 2026');
  const [fileData, setFileData] = useState<CryptoJS.lib.WordArray | null>(null);
  const [hashes, setHashes] = useState({ md5: '', sha1: '', sha256: '', sha512: '' });
  const [hmacKey, setHmacKey] = useState('secret-soc-key');
  const [hmacAlgo, setHmacAlgo] = useState<'SHA256' | 'SHA512' | 'SHA1' | 'MD5'>('SHA256');
  const [hmacResult, setHmacResult] = useState('');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const { history, addEntry, removeEntry, clearHistory } = useToolHistory('hash_crypto', { persist: false }); // inputs may be passwords or plaintext: session-only history

  // The bytes being hashed: an uploaded file's contents, otherwise the typed text. While a file is
  // loaded the text box only shows its label, which must never be hashed in place of the file.
  const message = fileData ?? inputText;

  const changeInputText = (text: string) => {
    setFileData(null);
    setInputText(text);
  };

  // Compute hashes
  useEffect(() => {
    try {
      const md5 = CryptoJS.MD5(message).toString();
      const sha1 = CryptoJS.SHA1(message).toString();
      const sha256 = CryptoJS.SHA256(message).toString();
      const sha512 = CryptoJS.SHA512(message).toString();
      setHashes({ md5, sha1, sha256, sha512 });
    } catch {
      // ignore
    }
  }, [message]);

  // Compute HMAC
  useEffect(() => {
    try {
      let hmac = '';
      if (hmacAlgo === 'SHA256') hmac = CryptoJS.HmacSHA256(message, hmacKey).toString();
      else if (hmacAlgo === 'SHA512') hmac = CryptoJS.HmacSHA512(message, hmacKey).toString();
      else if (hmacAlgo === 'SHA1') hmac = CryptoJS.HmacSHA1(message, hmacKey).toString();
      else if (hmacAlgo === 'MD5') hmac = CryptoJS.HmacMD5(message, hmacKey).toString();
      setHmacResult(hmac);
    } catch {
      setHmacResult('Error generating HMAC');
    }
  }, [message, hmacKey, hmacAlgo]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = event => {
      const buffer = event.target?.result as ArrayBuffer;
      if (!buffer) return;

      setFileData(CryptoJS.lib.WordArray.create(buffer as any));
      setInputText(`[File: ${file.name} (${file.size} bytes)]`);
    };
    reader.readAsArrayBuffer(file);
    e.target.value = ''; // lets the same file be picked again
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex items-center gap-2.5 mb-1.5">
          <div className="p-2.5 rounded-xl bg-fuchsia-500/20 text-fuchsia-300 border border-fuchsia-500/40 shadow-md">
            <Binary className="w-5 h-5" />
          </div>
          <h1 className="text-xl font-bold text-slate-50">
            Hash & Cryptography Hub
          </h1>
        </div>
        <p className="text-xs text-slate-300 max-w-3xl">
          Compute real-time multi-algorithm hashes (MD5, SHA-1, SHA-256, SHA-512) for text and files, and generate HMAC signatures. For Base64, Hex and URL encoding, use the Data Conversion Hub.
        </p>
      </div>

      {/* 1. Multi-Hash Generator */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Binary className="w-4 h-4 text-fuchsia-400" />
            1. MULTI-ALGORITHM HASH CALCULATOR
          </h2>
          <label className="cursor-pointer px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-xs text-white font-mono font-extrabold flex items-center gap-2 transition-all shadow-md">
            <Upload className="w-3.5 h-3.5" />
            Hash Local File
            <input type="file" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="text-xs font-mono text-fuchsia-300 font-bold">INPUT STRING / PAYLOAD:</label>
            <ToolHistoryDropdown
              history={history}
              onSelect={changeInputText}
              onRemove={removeEntry}
              onClear={clearHistory}
            />
          </div>
          <textarea
            value={inputText}
            onChange={e => changeInputText(e.target.value)}
            onBlur={() => {
              if (inputText.trim() && !fileData) addEntry(inputText.trim());
            }}
            onKeyDown={e => {
              if (e.key === 'Enter' && e.ctrlKey && inputText.trim() && !fileData) {
                addEntry(inputText.trim());
              }
            }}
            rows={3}
            className="w-full p-3 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-fuchsia-200 placeholder-slate-600 focus:outline-none focus:border-fuchsia-500 shadow-inner resize-none"
            placeholder="Type or paste payload string..."
          />
        </div>

        {/* Calculated Hashes Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { algo: 'MD5 (128-bit)', val: hashes.md5, color: 'text-amber-300', border: 'border-amber-500/30' },
            { algo: 'SHA-1 (160-bit)', val: hashes.sha1, color: 'text-purple-300', border: 'border-purple-500/30' },
            { algo: 'SHA-256 (256-bit)', val: hashes.sha256, color: 'text-emerald-300', border: 'border-emerald-500/30' },
            { algo: 'SHA-512 (512-bit)', val: hashes.sha512, color: 'text-fuchsia-300', border: 'border-fuchsia-500/30' },
          ].map((h, i) => (
            <div key={i} className={`p-4 rounded-xl bg-slate-950/90 border ${h.border} space-y-1.5 shadow-sm`}>
              <div className="flex items-center justify-between">
                <span className={`text-xs font-mono font-bold ${h.color}`}>{h.algo}</span>
                <button
                  onClick={() => copyToClipboard(h.val, h.algo)}
                  className="text-slate-400 hover:text-fuchsia-300 transition-colors p-1"
                >
                  {copiedField === h.algo ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-xs font-mono text-slate-200 break-all select-all">{h.val}</div>
            </div>
          ))}
        </div>
      </div>

      {/* 2. HMAC Generator */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center gap-2">
          <Key className="w-4 h-4 text-pink-400" />
          <h2 className="text-sm font-bold text-slate-100">2. HMAC GENERATOR</h2>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-mono text-pink-300 block mb-1 font-bold">SECRET KEY:</label>
            <input
              type="text"
              value={hmacKey}
              onChange={e => setHmacKey(e.target.value)}
              className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-100 focus:outline-none focus:border-pink-500 shadow-inner"
            />
          </div>
          <div>
            <label className="text-xs font-mono text-pink-300 block mb-1 font-bold">ALGORITHM:</label>
            <select
              value={hmacAlgo}
              onChange={e => setHmacAlgo(e.target.value as any)}
              className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-pink-300 focus:outline-none focus:border-pink-500 shadow-inner"
            >
              <option value="SHA256">HMAC-SHA256</option>
              <option value="SHA512">HMAC-SHA512</option>
              <option value="SHA1">HMAC-SHA1</option>
              <option value="MD5">HMAC-MD5</option>
            </select>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs font-mono text-slate-400 font-bold">HMAC DIGEST RESULT:</label>
            {hmacResult && (
              <button
                onClick={() => copyToClipboard(hmacResult, 'hmac')}
                className="text-xs font-mono text-pink-400 hover:text-pink-300 flex items-center gap-1 font-bold"
              >
                {copiedField === 'hmac' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                Copy
              </button>
            )}
          </div>
          <textarea
            readOnly
            value={hmacResult}
            rows={3}
            className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-pink-300 select-all resize-none shadow-inner"
          />
        </div>
      </div>
    </div>
  );
}
