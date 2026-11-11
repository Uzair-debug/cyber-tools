'use client';

import React, { useState } from 'react';
import { CornerDownLeft } from 'lucide-react';
import { TabId, TabItem, TOOLS, CATEGORIES } from '../layout/Sidebar';

interface DashboardOverviewProps {
  onSelectTab: (tabId: TabId) => void;
  onOpenScratchpad: () => void;
  onOpenCaseReport: () => void;
}

interface Detection {
  kind: string;
  targetTab: TabId;
  reason: string;
}

// Classifies a pasted indicator and picks the tool that answers the first question an analyst asks about it
export function detectIndicator(raw: string): Detection | null {
  const clean = raw.trim();
  if (!clean) return null;

  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(clean)) {
    return { kind: 'IPv4 address', targetTab: 'ip', reason: 'ASN, location, reverse DNS, open ports and blocklist status' };
  }
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(clean)) {
    return { kind: 'CIDR range', targetTab: 'cidr', reason: 'network and broadcast addresses, usable hosts and mask' };
  }
  if (/^[0-9]{1,5}(,[0-9]{1,5})*$/.test(clean) || /^[0-9]{1,5}-[0-9]{1,5}$/.test(clean)) {
    return { kind: 'Port', targetTab: 'ports', reason: 'the service, known exploits and default credentials' };
  }
  if (/^[a-fA-F0-9]{32}$/.test(clean) || /^[a-fA-F0-9]{40}$/.test(clean) || /^[a-fA-F0-9]{64}$/.test(clean)) {
    return { kind: 'File hash', targetTab: 'intel-pivot', reason: 'look it up on VirusTotal and other threat intel sources' };
  }
  if (/^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(clean)) {
    return { kind: 'JSON Web Token', targetTab: 'jwt', reason: 'decoded claims, expiry and alg:none or weak-secret flaws' };
  }
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
    return { kind: 'Email address', targetTab: 'domain', reason: "the sender domain's SPF, DKIM and DMARC records" };
  }
  if (/^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/.test(clean)) {
    if (/^https?:\/\//i.test(clean) || clean.includes('/')) {
      return { kind: 'URL', targetTab: 'links', reason: 'every redirect hop, the final destination and a risk score' };
    }
    return { kind: 'Domain', targetTab: 'domain', reason: 'DNS records, WHOIS and email security policies' };
  }
  return { kind: 'Text', targetTab: 'ioc-extractor', reason: 'every IP, domain, URL and hash found in it' };
}

const EXAMPLES = ['8.8.8.8', 'microsoft.com', '10.0.0.0/24', '44d88612fea8a8f36de82e1278abb02f'];

export function DashboardOverview({ onSelectTab }: DashboardOverviewProps) {
  const [input, setInput] = useState('');
  const detection = detectIndicator(input);
  const targetTool = detection ? TOOLS.find(t => t.id === detection.targetTab) : undefined;

  const open = async () => {
    if (!detection) return;
    // Tools keep their own inputs, so the indicator travels on the clipboard
    try {
      await navigator.clipboard.writeText(input.trim());
    } catch {
      // Clipboard can be blocked; the tool still opens
    }
    onSelectTab(detection.targetTab);
  };

  return (
    <div className="pb-16 space-y-12">
      {/* Triage: the one thing an analyst arrives with is an indicator */}
      <section aria-labelledby="triage-heading" className="pt-6 sm:pt-10 max-w-3xl">
        <h1 id="triage-heading" className="text-[28px] sm:text-[34px] leading-[1.15] font-semibold tracking-[-0.02em] text-[var(--text-main)]">
          What are you looking at?
        </h1>
        <p className="mt-2 text-[15px] text-[var(--text-muted)] max-w-[60ch]">
          Paste an IP, domain, URL, hash, token, email address or a block of log text. The portal picks the tool.
        </p>

        <form
          className="mt-6 flex flex-col sm:flex-row items-stretch rounded-xl border border-[var(--border-strong)] bg-[var(--bg-surface)] focus-within:border-[var(--accent)] transition-colors"
          onSubmit={e => {
            e.preventDefault();
            open();
          }}
        >
          <label htmlFor="triage-input" className="sr-only">
            Indicator
          </label>
          <input
            id="triage-input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="8.8.8.8"
            className="flex-1 min-w-0 bg-transparent px-4 sm:px-5 py-4 text-[17px] font-mono text-[var(--text-main)] placeholder:text-[var(--text-muted)] placeholder:opacity-50 focus:outline-none focus-visible:outline-none"
          />
          <button
            type="submit"
            disabled={!detection}
            className={`m-1.5 px-4 sm:px-5 py-2.5 sm:py-0 justify-center rounded-lg text-[14px] font-medium flex items-center gap-2 transition-colors ${
              detection
                ? 'bg-[var(--accent)] text-white hover:brightness-110'
                : 'text-[var(--text-muted)] cursor-not-allowed'
            }`}
          >
            <span>{targetTool ? `Open ${targetTool.label}` : 'Open tool'}</span>
            <CornerDownLeft className="w-4 h-4 hidden sm:block" />
          </button>
        </form>

        <div className="mt-3 min-h-[1.5rem] text-[14px]" aria-live="polite">
          {detection && targetTool ? (
            <p className="text-[var(--text-muted)]">
              <span className="text-[var(--text-main)] font-medium">{detection.kind}.</span>{' '}
              {targetTool.label} shows {detection.reason}. Opening it copies the indicator so you can paste it in.
            </p>
          ) : (
            <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1.5 text-[var(--text-muted)]">
              <span>Try</span>
              {EXAMPLES.map(ex => (
                <button
                  key={ex}
                  type="button"
                  onClick={() => setInput(ex)}
                  className="px-2 py-0.5 rounded-md border border-[var(--border-subtle)] font-mono text-[12.5px] text-[var(--text-main)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-card)] transition-colors max-w-[16rem] truncate"
                >
                  {ex}
                </button>
              ))}
            </p>
          )}
        </div>
      </section>

      {/* Directory: every tool, grouped the same way as the sidebar */}
      <section aria-labelledby="directory-heading">
        <h2 id="directory-heading" className="text-[15px] font-semibold text-[var(--text-main)] mb-4">
          All tools
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-8 gap-y-8">
          {CATEGORIES.map(cat => (
            <div key={cat.id}>
              <h3 className="text-[13px] font-medium text-[var(--text-muted)] pb-2 mb-1 border-b border-[var(--border-subtle)]">
                {cat.label}
              </h3>
              <ul>
                {TOOLS.filter(t => t.category === cat.id).map(tool => (
                  <li key={tool.id}>
                    <ToolRow tool={tool} onSelect={() => onSelectTab(tool.id)} />
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function ToolRow({ tool, onSelect }: { tool: TabItem; onSelect: () => void }) {
  const Icon = tool.icon;
  return (
    <button
      onClick={onSelect}
      className="w-[calc(100%+1rem)] -mx-2 px-2 py-2.5 rounded-lg flex items-start gap-3 text-left hover:bg-[var(--bg-card)] transition-colors group"
    >
      <Icon className="w-4 h-4 mt-0.5 flex-shrink-0 text-[var(--text-muted)] group-hover:text-[var(--accent-text)] transition-colors" />
      <span className="min-w-0">
        <span className="block text-[14px] font-medium text-[var(--text-main)] leading-snug">{tool.label}</span>
        <span className="block text-[13px] text-[var(--text-muted)] leading-snug mt-0.5 line-clamp-2">{tool.description}</span>
      </span>
    </button>
  );
}
