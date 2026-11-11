'use client';

import React, { useState, useMemo } from 'react';
import {
  Mail,
  Upload,
  FileText,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  ExternalLink,
  Paperclip,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Eye,
  Sparkles,
  ArrowDown,
  Info,
  FolderPlus,
  Download,
  Search,
  Code,
  ShieldX,
  Terminal,
  RefreshCw,
} from 'lucide-react';
import { parseEmailContent } from '@/lib/email-parser';
import { AuthVerdict, ParsedEmailData } from '@/lib/types';
import { useCase } from '@/components/shared/CaseContext';

const SAMPLE_PHISHING_RAW = `Received: from mail-relay-out.phish-gate.com (mail-relay-out.phish-gate.com [185.220.101.45])
	by mx.google.com with ESMTPS id abc123xyz for <victim@victimcorp.com>;
	Fri, 28 Aug 2026 06:12:30 +0000
Received: from internal-smtp.local ([10.0.4.12])
	by mail-relay-out.phish-gate.com with ESMTP id 987654;
	Fri, 28 Aug 2026 06:12:10 +0000
Authentication-Results: mx.google.com;
	dkim=fail header.i=@legitcorp-security.com;
	spf=fail (google.com: domain of support@legitcorp-security.com does not designate 185.220.101.45 as permitted sender) smtp.mailfrom=support@legitcorp-security.com;
	dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=legitcorp-security.com
From: "IT Support Helpdesk" <support@legitcorp-security.com>
Reply-To: "Security Dispatch" <harvest-creds@evil-tracker.xyz>
To: <victim@victimcorp.com>
Subject: URGENT: Immediate Action Required - Unauthorized Login Detected in your Account
Date: Fri, 28 Aug 2026 06:12:00 +0000
Message-ID: <001201d9f123$4a5b6c70$df124550$@legitcorp-security.com>
Return-Path: <spoofed-bounce@phish-gate.com>
X-Originating-IP: [185.220.101.45]
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_NextPart_000_0013"

------=_NextPart_000_0013
Content-Type: text/plain; charset="utf-8"

URGENT SECURITY ALERT:
We detected an unauthorized login attempt from an unknown IP in Moscow, Russia.
Your account will be suspended within 24 hours unless you verify your identity immediately.

Please click the secure authorization link below to verify your corporate credentials:
http://185.220.101.45/login-verify/reset-session.php

You can also review the attached incident details document:
Attached: Security_Update_Patch_v2.exe (Incident Report & Remediation Tool)

Regards,
IT Global Security Operations Team
------=_NextPart_000_0013
Content-Type: application/octet-stream; name="Security_Update_Patch_v2.exe"
Content-Disposition: attachment; filename="Security_Update_Patch_v2.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAAA=
------=_NextPart_000_0013--`;

const SAMPLE_LEGIT_RAW = `Received: from mail-relay.github.com (mail-relay.github.com [140.82.112.22])
	by mx.google.com with ESMTPS id xyz987abc for <dev@company.com>;
	Thu, 27 Aug 2026 14:22:15 +0000
Authentication-Results: mx.google.com;
	dkim=pass header.i=@github.com header.s=s20210408;
	spf=pass (google.com: domain of support@github.com designates 140.82.112.22 as permitted sender) smtp.mailfrom=support@github.com;
	dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=s20210408;
From: "GitHub Security" <support@github.com>
Reply-To: "GitHub Security" <support@github.com>
To: <dev@company.com>
Subject: [GitHub] Security Advisory: Review dependabot vulnerability alerts
Date: Thu, 27 Aug 2026 14:22:00 +0000
Message-ID: <github-alert-991203@github.com>
Return-Path: <support@github.com>
Content-Type: text/plain; charset="utf-8"

Hi Engineering Team,

Dependabot detected 1 potential security advisory in your repository dependencies.
All package signatures and integrity hashes have been verified.

Please review the recommendation on your repository dashboard:
https://github.com/myorg/myrepo/security/dependabot

Regards,
GitHub Security Advisory Bot`;

const SAMPLE_BEC_RAW = `Received: from vps-mail.hoster-bulletproof.net (vps-mail.hoster-bulletproof.net [91.240.118.82])
	by mx.company.com with ESMTP id bec456 for <cfo@company.com>;
	Wed, 26 Aug 2026 11:45:00 +0000
Authentication-Results: mx.company.com;
	dkim=none;
	spf=softfail (company.com: domain of ceo@company.com does not designate 91.240.118.82 as permitted sender) smtp.mailfrom=ceo@company.com;
	dmarc=fail (p=NONE) header.from=company.com
From: "Executive Office (CEO)" <ceo@company.com>
Reply-To: "Private Communications" <ceo-personal-dispatch@sec-offshore.cc>
To: <cfo@company.com>
Subject: CONFIDENTIAL: Urgent Wire Transfer Required for Project Alpha Closing
Date: Wed, 26 Aug 2026 11:44:00 +0000
Message-ID: <bec-transfer-0099@company.com>
Return-Path: <bounce@sec-offshore.cc>
X-Originating-IP: [91.240.118.82]
Content-Type: text/plain; charset="utf-8"

Hello,

I am currently in an executive board meeting and cannot take calls right now.
We need to finalize the confidential Project Alpha acquisition deposit before 3:00 PM today.

Please prepare an immediate domestic wire transfer of $84,500.00 to the partner escrow account.
Let me know as soon as you are at your desk so I can send the banking details.

Keep this strictly between us until the press release tomorrow.

Sent from my iPad`;

// Red only for results that count against the sender; "not found" and "none" are not failures
function verdictBadgeClass(status: AuthVerdict['status']): string {
  if (status === 'pass') return 'bg-emerald-950 text-emerald-400 border border-emerald-800';
  if (status === 'fail' || status === 'softfail' || status === 'permerror' || status === 'policy') {
    return 'bg-rose-950 text-rose-400 border border-rose-800';
  }
  if (status === 'missing') return 'bg-slate-900 text-slate-400 border border-slate-700';
  return 'bg-amber-950 text-amber-400 border border-amber-800';
}

function formatDelay(delaySec: number): string {
  return delaySec < 0 ? `${delaySec}s (clocks disagree)` : `+${delaySec}s`;
}

export function EmailAnalyzer() {
  const [rawText, setRawText] = useState('');
  const [isParsing, setIsParsing] = useState(false);
  const [emailData, setEmailData] = useState<ParsedEmailData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'verdicts' | 'hops' | 'urls' | 'attachments' | 'headers' | 'body'>('verdicts');
  const [addedToCase, setAddedToCase] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);
  const [searchHeadersTerm, setSearchHeadersTerm] = useState('');
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  const { addItem } = useCase();

  const handleParse = async (inputContent: string | ArrayBuffer) => {
    setIsParsing(true);
    setError(null);
    try {
      const result = await parseEmailContent(inputContent);
      setEmailData(result);
    } catch (err: any) {
      setError(err.message || 'Failed to parse email message.');
    } finally {
      setIsParsing(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async event => {
      const buffer = event.target?.result;
      if (buffer) {
        handleParse(buffer);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const loadSample = (sample: string) => {
    setRawText(sample);
    handleParse(sample);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyItem = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(id);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  // Case Dossier Integration
  const handleAddToCase = () => {
    if (!emailData) return;
    addItem({
      tool: 'Email Header & Threat Analyzer',
      title: `Email Threat: ${emailData.subject} (${emailData.phishingRiskLevel} Risk)`,
      category: 'THREAT',
      severity: emailData.phishingRiskLevel === 'CRITICAL' ? 'CRITICAL' : emailData.phishingRiskLevel === 'HIGH' ? 'HIGH' : emailData.phishingRiskLevel === 'MEDIUM' ? 'MEDIUM' : 'LOW',
      summary: `Analyzed email from '${emailData.from.address}'. Risk: ${emailData.phishingScore}/100. SPF: ${emailData.spf.status}, DKIM: ${emailData.dkim.status}, DMARC: ${emailData.dmarc.status}. Identified ${emailData.urls.length} URLs and ${emailData.attachments.length} attachments.`,
      details: {
        from: emailData.from,
        replyTo: emailData.replyTo,
        subject: emailData.subject,
        date: emailData.date,
        riskLevel: emailData.phishingRiskLevel,
        riskScore: emailData.phishingScore,
        spf: emailData.spf,
        dkim: emailData.dkim,
        dmarc: emailData.dmarc,
        indicators: emailData.phishingIndicators,
        urls: emailData.urls,
        attachments: emailData.attachments,
        hopsCount: emailData.hops.length,
      },
    });
    setAddedToCase(true);
    setTimeout(() => setAddedToCase(false), 2000);
  };

  // Generate Incident Markdown Report
  const incidentReport = useMemo(() => {
    if (!emailData) return '';
    const lines: string[] = [];
    lines.push('# Email Security Incident Investigation Report');
    lines.push(`**Generated:** ${new Date().toUTCString()}`);
    lines.push(`**Phishing Risk Assessment:** ${emailData.phishingRiskLevel} (${emailData.phishingScore}/100)`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 1. Message Metadata');
    lines.push(`- **Subject:** ${emailData.subject}`);
    lines.push(`- **Date:** ${emailData.date || 'No Date header'}`);
    lines.push(`- **From:** ${emailData.from.address ? `${emailData.from.name ? `${emailData.from.name} ` : ''}<${emailData.from.address}>` : 'No From address found'}`);
    lines.push(`- **Reply-To:** ${emailData.replyTo?.address ? `<${emailData.replyTo.address}>` : 'Not set (replies go to From)'}`);
    lines.push(`- **Return-Path:** ${emailData.returnPath || 'Not present'}`);
    lines.push(`- **Message-ID:** ${emailData.messageId || 'Not present'}`);
    lines.push('');
    lines.push('## 2. Authentication Results');
    lines.push('_As recorded by the receiving mail server. This tool reads these results; it does not re-check DNS or signatures._');
    lines.push('');
    lines.push(`| Protocol | Result | Details |`);
    lines.push(`|---|---|---|`);
    lines.push(`| **SPF** | \`${emailData.spf.status === 'missing' ? 'NOT FOUND' : emailData.spf.status.toUpperCase()}\` | ${emailData.spf.details} |`);
    lines.push(`| **DKIM** | \`${emailData.dkim.status === 'missing' ? 'NOT FOUND' : emailData.dkim.status.toUpperCase()}\` | ${emailData.dkim.details} |`);
    lines.push(`| **DMARC** | \`${emailData.dmarc.status === 'missing' ? 'NOT FOUND' : emailData.dmarc.status.toUpperCase()}\` | ${emailData.dmarc.details} |`);
    lines.push('');
    lines.push('## 3. Heuristic Threat Indicators');
    lines.push('_The risk score adds fixed points for each rule below. It is a triage aid, not a verdict._');
    lines.push('');
    if (emailData.phishingIndicators.length === 0) {
      lines.push('- None of the rules triggered.');
    } else {
      emailData.phishingIndicators.forEach(ind => {
        lines.push(`- [${ind.severity.toUpperCase()}] **${ind.title}** (+${ind.points} pts): ${ind.description}`);
      });
    }
    lines.push('');
    lines.push('## 4. Observable Indicators of Compromise (IOCs)');
    lines.push('### Extracted Hyperlinks:');
    if (emailData.urls.length === 0) {
      lines.push('- No hyperlinks found in body content.');
    } else {
      emailData.urls.forEach(u => {
        lines.push(`- \`${u.defanged}\` (${u.isSuspicious ? `FLAGGED: ${u.reasons.join(', ')}` : 'no flags'})`);
      });
      if (emailData.urlTotal > emailData.urls.length) {
        lines.push(`- _${emailData.urlTotal - emailData.urls.length} more links not listed (first ${emailData.urls.length} shown)._`);
      }
    }
    lines.push('');
    lines.push('### Attachment Inventory & Cryptographic Hashes:');
    if (emailData.attachments.length === 0) {
      lines.push('- No attachments found.');
    } else {
      emailData.attachments.forEach(att => {
        lines.push(`- **File:** \`${att.filename}\` (${att.isDangerousExt ? '🚨 DANGEROUS EXTENSION' : att.mimeType})`);
        lines.push(`  - MD5: \`${att.md5 || 'N/A'}\``);
        lines.push(`  - SHA-256: \`${att.sha256 || 'N/A'}\``);
      });
    }
    lines.push('');
    lines.push('## 5. Relay Transit Route');
    if (emailData.hops.length === 0) {
      lines.push('- No Received relay hops discovered.');
    } else {
      lines.push('_Hop 1 is the earliest Received header. Headers added before the message reached your own servers can be forged._');
      lines.push('');
      emailData.hops.forEach(h => {
        const parts = [
          `From: ${h.from ? `\`${h.from}\`` : 'not recorded'}`,
          `By: ${h.by ? `\`${h.by}\`` : 'not recorded'}`,
          `IP: ${h.ip ? `\`${h.ip}\`` : 'not recorded'}`,
          `Time: ${h.timestamp || 'not recorded'}`,
        ];
        if (h.delaySec !== null) parts.push(`Delay: ${formatDelay(h.delaySec)}`);
        lines.push(`- **Hop #${h.hopNumber}:** ${parts.join(' | ')}`);
      });
    }
    return lines.join('\n');
  }, [emailData]);

  const handleCopyReport = () => {
    navigator.clipboard.writeText(incidentReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleDownloadReport = () => {
    const blob = new Blob([incidentReport], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-forensic-report-${new Date().toISOString().split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportIocsJson = () => {
    if (!emailData) return;
    const iocs = {
      timestamp: new Date().toISOString(),
      subject: emailData.subject,
      sender: emailData.from.address,
      replyTo: emailData.replyTo?.address,
      returnPath: emailData.returnPath,
      relayIps: emailData.hops.map(h => h.ip).filter(Boolean),
      urls: emailData.urls.map(u => ({ url: u.original, defanged: u.defanged, domain: u.domain, suspicious: u.isSuspicious })),
      attachments: emailData.attachments.map(a => ({ filename: a.filename, md5: a.md5, sha256: a.sha256, dangerous: a.isDangerousExt })),
      phishingRisk: { score: emailData.phishingScore, level: emailData.phishingRiskLevel },
    };
    const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-iocs-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered Headers
  const filteredHeaderEntries = useMemo(() => {
    if (!emailData?.rawHeaders) return [];
    const entries = Object.entries(emailData.rawHeaders);
    if (!searchHeadersTerm.trim()) return entries;
    const term = searchHeadersTerm.toLowerCase();
    return entries.filter(([key, val]) => {
      const valStr = Array.isArray(val) ? val.join(' ') : String(val);
      return key.toLowerCase().includes(term) || valStr.toLowerCase().includes(term);
    });
  }, [emailData?.rawHeaders, searchHeadersTerm]);

  return (
    // spellCheck off for every field inside, so browser cloud spellcheckers never upload pasted mail
    <div className="space-y-6" spellCheck={false}>
      {/* Module Title & Hero */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl shadow-black/40">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 mb-1.5">
              <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-md">
                <Mail className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-slate-50">
                Email Header & Threat Analyzer
              </h1>
            </div>
            <p className="text-xs text-slate-300 max-w-3xl">
              Inspect RFC 822 / .EML headers, read the SPF / DKIM / DMARC results your mail server recorded, visualize relay hops, audit attachments, and extract IOCs in-browser.
            </p>
          </div>

          {/* Test Scenarios */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => loadSample(SAMPLE_PHISHING_RAW)}
              className="px-3 py-1.5 rounded-xl bg-rose-950/70 hover:bg-rose-900/70 border border-rose-600/60 text-rose-200 text-xs font-bold flex items-center gap-1.5 transition-all shadow-md"
              title="Test with an urgent spear-phishing attack containing a malware attachment and spoofed sender"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              <span>Phishing Attack</span>
            </button>
            <button
              onClick={() => loadSample(SAMPLE_BEC_RAW)}
              className="px-3 py-1.5 rounded-xl bg-amber-950/70 hover:bg-amber-900/70 border border-amber-600/60 text-amber-200 text-xs font-bold flex items-center gap-1.5 transition-all shadow-md"
              title="Test with a Business Email Compromise (BEC) wire transfer attempt with mismatched Reply-To"
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>BEC Wire Scam</span>
            </button>
            <button
              onClick={() => loadSample(SAMPLE_LEGIT_RAW)}
              className="px-3 py-1.5 rounded-xl bg-emerald-950/70 hover:bg-emerald-900/70 border border-emerald-600/60 text-emerald-200 text-xs font-bold flex items-center gap-1.5 transition-all shadow-md"
              title="Test with a legitimate cryptographic signed email (Passing SPF, DKIM, and DMARC)"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Verified Signed</span>
            </button>
          </div>
        </div>
      </div>

      {/* Input Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload Box */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-amber-500/20 hover:border-amber-500/50 transition-all flex flex-col justify-center items-center text-center shadow-xl shadow-black/30">
          <div className="p-3.5 rounded-2xl bg-amber-500/20 text-amber-300 mb-3 border border-amber-500/30">
            <Upload className="w-6 h-6" />
          </div>
          <h2 className="text-sm font-bold text-slate-100 mb-1">Upload .EML / .TXT Email File</h2>
          <p className="text-xs text-slate-400 mb-4 max-w-xs">
            Drag and drop or select your exported email file. Parsed locally in client memory without transmission to external servers.
          </p>
          <label className="cursor-pointer px-5 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-extrabold text-xs transition-all shadow-lg">
            Choose Email File
            <input type="file" accept=".eml,.txt" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>

        {/* Raw Header Paste */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col shadow-xl shadow-black/30">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-amber-300 font-bold">OR PASTE RAW RFC 822 HEADERS:</span>
            {rawText && (
              <button
                onClick={() => setRawText('')}
                className="text-[11px] font-mono text-slate-400 hover:text-rose-400 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
          <textarea
            value={rawText}
            onChange={e => setRawText(e.target.value)}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            placeholder="Paste raw email headers starting with Received:, From:, To:, Subject:..."
            rows={5}
            className="w-full p-3 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-amber-500 resize-none flex-1 mb-3 shadow-inner"
          />
          <button
            onClick={() => handleParse(rawText)}
            disabled={!rawText.trim() || isParsing}
            className="w-full py-2.5 rounded-xl bg-slate-900/60 disabled:opacity-50 text-amber-300 font-bold text-xs border border-slate-800 hover:border-slate-800 transition-all shadow-sm"
          >
            {isParsing ? 'Analyzing Email Payload...' : 'Analyze Raw Headers'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View */}
      {emailData && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Quick Action & SOC Incident Operations Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-md">
            <div className="flex items-center gap-2">
              <span className="text-xs text-amber-400 font-semibold tracking-normal">Triage Case:</span>
              <span className="text-xs text-slate-200 font-bold truncate max-w-sm sm:max-w-md">{emailData.subject}</span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={handleAddToCase}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md transition-all"
                title="Save findings to active investigation case dossier"
              >
                {addedToCase ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <FolderPlus className="w-3.5 h-3.5" />}
                <span>{addedToCase ? 'Added to Dossier!' : 'Add to Dossier'}</span>
              </button>

              <button
                onClick={handleCopyReport}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-colors"
                title="Copy ready-to-share Markdown incident summary"
              >
                {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedReport ? 'Copied!' : 'Copy Report'}</span>
              </button>

              <button
                onClick={handleDownloadReport}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-colors"
                title="Download full forensic incident report (.md)"
              >
                <Download className="w-3.5 h-3.5 text-amber-400" />
                <span>Download .MD</span>
              </button>

              <button
                onClick={handleExportIocsJson}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-colors"
                title="Export all extracted URLs, hashes, and relay IPs as JSON"
              >
                <Code className="w-3.5 h-3.5 text-cyan-400" />
                <span>Export IOCs (JSON)</span>
              </button>
            </div>
          </div>

          {/* Summary Overview Banner & Phishing Score */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Phishing Risk Gauge Card */}
            <div
              className={`p-5 rounded-xl border flex flex-col justify-between ${
                emailData.phishingRiskLevel === 'CRITICAL'
                  ? 'bg-rose-950/25 border-rose-800/60'
                  : emailData.phishingRiskLevel === 'HIGH'
                  ? 'bg-orange-950/25 border-orange-800/60'
                  : emailData.phishingRiskLevel === 'MEDIUM'
                  ? 'bg-amber-950/25 border-amber-800/60'
                  : 'bg-emerald-950/25 border-emerald-800/60'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs tracking-normal text-slate-400">Phishing Risk Score</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                      emailData.phishingRiskLevel === 'CRITICAL'
                        ? 'bg-rose-900/60 text-rose-300 border border-rose-700'
                        : emailData.phishingRiskLevel === 'HIGH'
                        ? 'bg-orange-900/60 text-orange-300 border border-orange-700'
                        : emailData.phishingRiskLevel === 'MEDIUM'
                        ? 'bg-amber-900/60 text-amber-300 border border-amber-700'
                        : 'bg-emerald-900/60 text-emerald-300 border border-emerald-700'
                    }`}
                  >
                    {emailData.phishingRiskLevel} RISK
                  </span>
                </div>
                <div className="flex items-baseline gap-2 mb-2">
                  <span className="text-4xl font-extrabold text-slate-100">{emailData.phishingScore}</span>
                  <span className="text-sm font-mono text-slate-400">/ 100</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden mb-3">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      emailData.phishingRiskLevel === 'CRITICAL'
                        ? 'bg-rose-500'
                        : emailData.phishingRiskLevel === 'HIGH'
                        ? 'bg-orange-500'
                        : emailData.phishingRiskLevel === 'MEDIUM'
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${emailData.phishingScore}%` }}
                  />
                </div>
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
                <span>{emailData.phishingIndicators.filter(i => i.points > 0).length} Threat Indicators</span>
                <span>{emailData.urls.length} Links · {emailData.attachments.length} Files</span>
              </div>
            </div>

            {/* Email Metadata */}
            <div className="md:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <span className="font-mono text-slate-500 block text-[11px]">SUBJECT:</span>
                  <span className="font-medium text-slate-200 break-words">{emailData.subject}</span>
                </div>
                <div>
                  <span className="font-mono text-slate-500 block text-[11px]">DATE:</span>
                  <span className="font-mono text-slate-300">{emailData.date || 'No Date header'}</span>
                </div>
                <div>
                  <span className="font-mono text-slate-500 block text-[11px]">FROM:</span>
                  <span className="font-mono text-slate-200 break-all">
                    {emailData.from.address
                      ? `${emailData.from.name ? `${emailData.from.name} ` : ''}<${emailData.from.address}>`
                      : 'No From address found'}
                  </span>
                </div>
                <div>
                  {(() => {
                    const fromClean = emailData.from.address.replace(/[<>]/g, '').trim().toLowerCase();
                    const replyClean = emailData.replyTo?.address ? emailData.replyTo.address.replace(/[<>]/g, '').trim().toLowerCase() : '';
                    const isMismatch = Boolean(replyClean && fromClean && replyClean !== fromClean);

                    return (
                      <>
                        <span className="font-mono text-slate-500 block text-[11px] flex items-center justify-between">
                          <span>REPLY-TO:</span>
                          {isMismatch && (
                            <span className="text-[10px] text-rose-400 font-bold">MISMATCH DETECTED</span>
                          )}
                        </span>
                        <span
                          className={`font-mono break-all ${
                            isMismatch
                              ? 'text-rose-400 font-bold bg-rose-950/40 px-1.5 py-0.5 rounded border border-rose-900/60 block'
                              : 'text-slate-300'
                          }`}
                        >
                          {emailData.replyTo?.address ? `<${emailData.replyTo.address}>` : 'Not set (replies go to From)'}
                        </span>
                      </>
                    );
                  })()}
                </div>
                <div className="sm:col-span-2">
                  <span className="font-mono text-slate-500 block text-[11px]">RETURN-PATH:</span>
                  <span className="font-mono text-slate-400 truncate block">
                    {emailData.returnPath || 'Not present'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="border-b border-slate-800 flex items-center gap-2 overflow-x-auto pb-1">
            <button
              onClick={() => setActiveTab('verdicts')}
              className={`px-3.5 py-2 rounded-t-lg text-xs font-medium flex items-center gap-2 transition-colors border-b-2 whitespace-nowrap ${
                activeTab === 'verdicts'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              Verdicts & Indicators
            </button>
            <button
              onClick={() => setActiveTab('hops')}
              className={`px-3.5 py-2 rounded-t-lg text-xs font-medium flex items-center gap-2 transition-colors border-b-2 whitespace-nowrap ${
                activeTab === 'hops'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Clock className="w-4 h-4" />
              Transit Hops ({emailData.hops.length})
            </button>
            <button
              onClick={() => setActiveTab('urls')}
              className={`px-3.5 py-2 rounded-t-lg text-xs font-medium flex items-center gap-2 transition-colors border-b-2 whitespace-nowrap ${
                activeTab === 'urls'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ExternalLink className="w-4 h-4" />
              Extracted URLs ({emailData.urls.length})
            </button>
            <button
              onClick={() => setActiveTab('attachments')}
              className={`px-3.5 py-2 rounded-t-lg text-xs font-medium flex items-center gap-2 transition-colors border-b-2 whitespace-nowrap ${
                activeTab === 'attachments'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Paperclip className="w-4 h-4" />
              Attachments ({emailData.attachments.length})
            </button>
            <button
              onClick={() => setActiveTab('headers')}
              className={`px-3.5 py-2 rounded-t-lg text-xs font-medium flex items-center gap-2 transition-colors border-b-2 whitespace-nowrap ${
                activeTab === 'headers'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-4 h-4" />
              Raw Headers ({Object.keys(emailData.rawHeaders).length})
            </button>
            <button
              onClick={() => setActiveTab('body')}
              className={`px-3.5 py-2 rounded-t-lg text-xs font-medium flex items-center gap-2 transition-colors border-b-2 whitespace-nowrap ${
                activeTab === 'body'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileText className="w-4 h-4" />
              Email Body
            </button>
          </div>

          {/* Tab Content: Verdicts */}
          {activeTab === 'verdicts' && (
            <div className="space-y-6">
              {/* SPF / DKIM / DMARC Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {([
                  ['SPF', emailData.spf],
                  ['DKIM', emailData.dkim],
                  ['DMARC', emailData.dmarc],
                ] as const).map(([label, verdict]) => (
                  <div key={label} className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-xs font-bold text-slate-300">{label} RESULT</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${verdictBadgeClass(verdict.status)}`}>
                          {verdict.status === 'missing' ? 'not found' : verdict.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mb-2">{verdict.details}</p>
                    </div>
                    {verdict.rawHeader && (
                      <div className="pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 truncate" title={verdict.rawHeader}>
                        {verdict.rawHeader}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-slate-500 -mt-3">
                These are the results the receiving mail server recorded in the headers. This tool reads them; it does not re-check DNS records or signatures.
              </p>

              {/* Threat Indicators List */}
              <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
                <h3 className="text-xs text-slate-400 tracking-normal">
                  Threat & Phishing Indicators Breakdown
                </h3>
                <div className="space-y-2">
                  {emailData.phishingIndicators.length === 0 ? (
                    <div className="p-3.5 rounded-lg border border-emerald-900/40 bg-emerald-950/20 text-emerald-300 text-xs flex items-center gap-2.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                      <div>
                        <span className="font-semibold block">No Heuristic Threat Indicators Triggered</span>
                        <span className="text-slate-400 text-[11px]">Checked: SPF / DKIM / DMARC results, Reply-To domain, urgency phrases, authority-style display names, high-risk attachment types, and link patterns. A clean result is not proof the message is safe.</span>
                      </div>
                    </div>
                  ) : (
                    emailData.phishingIndicators.map(indicator => (
                      <div
                        key={indicator.id}
                        className={`p-3 rounded-lg border flex items-start gap-3 ${
                          indicator.severity === 'critical'
                            ? 'bg-rose-950/30 border-rose-800/50 text-rose-200'
                            : indicator.severity === 'high'
                            ? 'bg-orange-950/30 border-orange-800/50 text-orange-200'
                            : indicator.severity === 'pass'
                            ? 'bg-emerald-950/30 border-emerald-800/50 text-emerald-200'
                            : 'bg-slate-950 border-slate-800 text-slate-300'
                        }`}
                      >
                        {indicator.severity === 'critical' || indicator.severity === 'high' ? (
                          <ShieldAlert className="w-4 h-4 text-rose-400 mt-0.5 flex-shrink-0" />
                        ) : indicator.severity === 'pass' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                        ) : (
                          <Info className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                        )}
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold">{indicator.title}</span>
                            <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-950/60 border border-slate-800">
                              +{indicator.points} pts
                            </span>
                          </div>
                          <p className="text-xs opacity-80 mt-0.5">{indicator.description}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab Content: Transit Hops Timeline */}
          {activeTab === 'hops' && (
            <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-4">
              <h3 className="text-xs text-slate-400 tracking-normal">
                Visual Transit Route & Relay Path Timeline
              </h3>
              <p className="text-[11px] text-slate-500">
                Oldest first. Received headers added before the message reached your own mail servers are written by the sending side and can be forged.
              </p>
              {emailData.hops.length === 0 ? (
                <p className="text-xs text-slate-500">No Received headers found.</p>
              ) : (
                <div className="relative border-l-2 border-slate-800 ml-4 pl-6 space-y-6">
                  {emailData.hops.map((hop, idx) => (
                    <div key={hop.hopNumber} className="relative group">
                      {/* Timeline Node */}
                      <div className="absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-slate-950 border-2 border-cyan-400 flex items-center justify-center">
                        <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                      </div>

                      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-cyan-300 font-mono">
                              HOP #{hop.hopNumber}
                            </span>
                            {idx === 0 && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700 font-bold">
                                Earliest Recorded Hop
                              </span>
                            )}
                            {idx === emailData.hops.length - 1 && emailData.hops.length > 1 && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                                Final Hop (Delivery)
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            {hop.delaySec !== null && hop.delaySec !== 0 && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
                                Delay: {formatDelay(hop.delaySec)}
                              </span>
                            )}
                            <span className="text-[11px] font-mono text-slate-400">{hop.timestamp || 'No timestamp'}</span>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                          <div>
                            <span className="text-slate-500">FROM: </span>
                            <span className="text-slate-300 break-all">{hop.from || 'Not recorded'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500">BY: </span>
                            <span className="text-slate-300 break-all">{hop.by || 'Not recorded'}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-slate-500">IP: </span>
                            <span className={hop.isPrivateIp ? 'text-slate-400' : 'text-emerald-400 font-bold'}>
                              {hop.ip || 'Not recorded'} {hop.isPrivateIp && '(Private Subnet)'}
                            </span>
                            {hop.ip && !hop.isPrivateIp && (
                              <button
                                onClick={() => copyItem(hop.ip, `hop-ip-${idx}`)}
                                className="text-slate-400 hover:text-cyan-300 p-0.5"
                                title="Copy Relay IP"
                              >
                                {copiedItem === `hop-ip-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            )}
                          </div>
                          <div>
                            <span className="text-slate-500">PROTOCOL: </span>
                            <span className="text-slate-400">{hop.with || 'Not recorded'}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab Content: Extracted URLs */}
          {activeTab === 'urls' && (
            <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
              <h3 className="text-xs text-slate-400 tracking-normal">
                Extracted Hyperlinks (Auto-Defanged)
              </h3>
              {emailData.urlTotal > emailData.urls.length && (
                <p className="text-[11px] text-amber-400">
                  Showing the first {emailData.urls.length} of {emailData.urlTotal} links.
                </p>
              )}
              {emailData.urls.length === 0 ? (
                <p className="text-xs text-slate-500">No hyperlinks detected in email body.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">Defanged URL</th>
                        <th className="p-3">Domain</th>
                        <th className="p-3">Flags</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {emailData.urls.map((url, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="p-3 text-cyan-300 max-w-md truncate select-all">{url.defanged}</td>
                          <td className="p-3 text-slate-300">{url.domain}</td>
                          <td className="p-3">
                            {url.isSuspicious ? (
                              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-semibold">
                                {url.reasons.join(', ')}
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700 text-[10px]">
                                No flags
                              </span>
                            )}
                          </td>
                          <td className="p-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => copyItem(url.defanged, `url-${i}`)}
                                className="text-slate-400 hover:text-cyan-300 p-1 rounded hover:bg-slate-800 transition-colors"
                                title="Copy Defanged URL"
                              >
                                {copiedItem === `url-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Tab Content: Attachments */}
          {activeTab === 'attachments' && (
            <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
              <h3 className="text-xs text-slate-400 tracking-normal">
                Attachment Inventory & Computed Cryptographic Hashes
              </h3>
              {emailData.attachments.length === 0 ? (
                <p className="text-xs text-slate-500">No attachments found in this email.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">Filename</th>
                        <th className="p-3">Type</th>
                        <th className="p-3">Size</th>
                        <th className="p-3">MD5 Hash</th>
                        <th className="p-3">SHA-256 Hash</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {emailData.attachments.map((att, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="p-3 font-semibold text-slate-200">
                            {att.filename}
                            {att.isDangerousExt && (
                              <span className="ml-2 px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold inline-flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3 text-rose-400" />
                                Dangerous Filetype
                              </span>
                            )}
                          </td>
                          <td className="p-3 text-slate-400">{att.mimeType}</td>
                          <td className="p-3 text-slate-300">{(att.size / 1024).toFixed(1)} KB</td>
                          <td className="p-3">
                            <div className="flex items-center gap-1.5">
                              <span className="text-cyan-400 select-all">{att.md5 || 'N/A'}</span>
                              {att.md5 && (
                                <button
                                  onClick={() => copyItem(att.md5, `md5-${i}`)}
                                  className="text-slate-400 hover:text-cyan-300 p-0.5"
                                  title="Copy MD5"
                                >
                                  {copiedItem === `md5-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              )}
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="flex items-center gap-1.5">
                              <span className="text-cyan-400 select-all truncate max-w-xs">{att.sha256 || 'N/A'}</span>
                              {att.sha256 && (
                                <button
                                  onClick={() => copyItem(att.sha256, `sha-${i}`)}
                                  className="text-slate-400 hover:text-cyan-300 p-0.5"
                                  title="Copy SHA-256"
                                >
                                  {copiedItem === `sha-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Tab Content: Raw RFC Headers Inspector */}
          {activeTab === 'headers' && (
            <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="relative flex-1">
                  <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    value={searchHeadersTerm}
                    onChange={e => setSearchHeadersTerm(e.target.value)}
                    placeholder="Search header keys or values (e.g. authentication, dkim, spf, received, x-originating)..."
                    className="w-full pl-9 pr-8 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                  {searchHeadersTerm && (
                    <button
                      onClick={() => setSearchHeadersTerm('')}
                      className="absolute right-2.5 top-2.5 text-xs text-slate-500 hover:text-slate-300"
                    >
                      ×
                    </button>
                  )}
                </div>

                <button
                  onClick={() => {
                    const allText = Object.entries(emailData.rawHeaders)
                      .map(([k, v]) => (Array.isArray(v) ? v.map(item => `${k}: ${item}`).join('\n') : `${k}: ${v}`))
                      .join('\n');
                    copyToClipboard(allText);
                  }}
                  className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl border border-slate-700 flex items-center gap-1.5 transition-colors shrink-0"
                >
                  <Copy className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Copy All Headers</span>
                </button>
              </div>

              {/* Headers Table */}
              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider">
                    <tr>
                      <th className="p-3 w-48">Header Field</th>
                      <th className="p-3">Value</th>
                      <th className="p-3 text-right w-20">Copy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredHeaderEntries.map(([key, value], idx) => {
                      const isSecurityHeader = [
                        'authentication-results',
                        'received-spf',
                        'dkim-signature',
                        'dmarc-filter',
                        'arc-seal',
                        'arc-authentication-results',
                        'x-originating-ip',
                      ].includes(key.toLowerCase());
                      const displayVal = Array.isArray(value) ? value.join('\n\n') : String(value);

                      return (
                        <tr key={idx} className={`hover:bg-slate-900/40 transition-colors ${isSecurityHeader ? 'bg-cyan-950/15' : ''}`}>
                          <td className="p-3 align-top">
                            <span className={`font-bold ${isSecurityHeader ? 'text-cyan-400' : 'text-slate-300'}`}>
                              {key}
                            </span>
                            {isSecurityHeader && (
                              <span className="block mt-0.5 text-[9px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-sans font-semibold w-fit">
                                Security
                              </span>
                            )}
                          </td>
                          <td className="p-3 text-slate-300 break-all whitespace-pre-wrap select-all font-mono text-[11px]">
                            {displayVal}
                          </td>
                          <td className="p-3 text-right align-top">
                            <button
                              onClick={() => copyItem(displayVal, `header-${idx}`)}
                              className="p-1 text-slate-400 hover:text-cyan-300 rounded transition-colors"
                              title="Copy header value"
                            >
                              {copiedItem === `header-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab Content: Body */}
          {activeTab === 'body' && (
            <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
              <h3 className="text-xs text-slate-400 tracking-normal">Raw Email Body Text</h3>
              <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-96 overflow-y-auto">
                {emailData.bodyText || emailData.bodyHtml || '(No text content)'}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
