'use client';

import React, { useState } from 'react';
import { X, Copy, Check, Terminal, Unlink2, Link2, Sparkles } from 'lucide-react';
import { defangText, refangText } from '@/lib/defang';
import {
  Dialog,
  SheetContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';

interface QuickScratchpadDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export function QuickScratchpadDrawer({ isOpen, onClose }: QuickScratchpadDrawerProps) {
  const [inputText, setInputText] = useState('');
  const [mode, setMode] = useState<'defang' | 'refang' | 'notes'>('defang');
  const [notes, setNotes] = useState('');
  const [copied, setCopied] = useState(false);

  const convertedText = mode === 'defang' ? defangText(inputText) : mode === 'refang' ? refangText(inputText) : '';

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog open={isOpen} onOpenChange={open => !open && onClose()}>
      <SheetContent side="right" className="p-0 border-l border-slate-800 bg-slate-900 shadow-2xl flex flex-col">
        {/* Drawer Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <DialogTitle className="font-semibold text-sm text-slate-100">Quick Analyst Drawer</DialogTitle>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 focus:outline-none"
            aria-label="Close drawer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <DialogDescription className="sr-only">
          Quick analyst scratchpad for defanging URLs and storing live incident notes.
        </DialogDescription>

        {/* Mode Switcher */}
        <div className="p-3 bg-slate-950/30 border-b border-slate-800 grid grid-cols-3 gap-1">
          <button
            onClick={() => setMode('defang')}
            className={`py-1.5 px-2 rounded-lg text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors ${
              mode === 'defang'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Unlink2 className="w-3.5 h-3.5" />
            Defang
          </button>
          <button
            onClick={() => setMode('refang')}
            className={`py-1.5 px-2 rounded-lg text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors ${
              mode === 'refang'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Link2 className="w-3.5 h-3.5" />
            Refang
          </button>
          <button
            onClick={() => setMode('notes')}
            className={`py-1.5 px-2 rounded-lg text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors ${
              mode === 'notes'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            Notes
          </button>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 p-4 overflow-y-auto space-y-4">
          {mode !== 'notes' ? (
            <>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">
                  INPUT IOCS / URLS / DOMAINS:
                </label>
                <textarea
                  value={inputText}
                  onChange={e => setInputText(e.target.value)}
                  placeholder={
                    mode === 'defang'
                      ? 'Paste live URLs (http://evil.com) or IPs (192.168.1.1)...'
                      : 'Paste defanged IoCs (hxxps://evil[.]com)...'
                  }
                  rows={5}
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs text-slate-400 uppercase">
                    {mode === 'defang' ? 'Defanged Output:' : 'Refanged Output:'}
                  </label>
                  {convertedText && (
                    <button
                      onClick={() => handleCopy(convertedText)}
                      className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                    >
                      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  )}
                </div>
                <textarea
                  readOnly
                  value={convertedText}
                  placeholder="Results appear here automatically..."
                  rows={6}
                  className="w-full p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono text-cyan-300 placeholder-slate-700 focus:outline-none resize-none"
                />
              </div>
            </>
          ) : (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-mono text-slate-400">INCIDENT SCRATCHPAD & INVESTIGATION NOTES:</label>
                {notes && (
                  <button
                    onClick={() => handleCopy(notes)}
                    className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                )}
              </div>
              <textarea
                value={notes}
                onChange={e => setNotes(e.target.value)}
                placeholder="Keep working notes, case findings, timestamps, and IP addresses here..."
                rows={16}
                className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
              />
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/50 flex justify-between items-center text-[11px] font-mono text-slate-400">
          <span>Zero-Trust: 100% Client-Side</span>
          <button
            onClick={() => {
              setInputText('');
              setNotes('');
            }}
            className="hover:text-rose-400 transition-colors"
          >
            Clear
          </button>
        </div>
      </SheetContent>
    </Dialog>
  );
}
