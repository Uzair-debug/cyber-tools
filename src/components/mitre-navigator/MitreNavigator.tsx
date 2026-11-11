'use client';

import React, { useState, useMemo } from 'react';
import {
  Target,
  Search,
  Copy,
  Check,
  Shield,
  Layers,
  Terminal,
  FileCode,
  Sparkles,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';
import { MitreTechnique } from '@/lib/types';

const TACTICS = [
  { id: 'TA0001', name: 'Initial Access', color: 'border-cyan-500/40 text-cyan-400 bg-cyan-950/20' },
  { id: 'TA0002', name: 'Execution', color: 'border-blue-500/40 text-blue-400 bg-blue-950/20' },
  { id: 'TA0003', name: 'Persistence', color: 'border-indigo-500/40 text-indigo-400 bg-indigo-950/20' },
  { id: 'TA0004', name: 'Privilege Escalation', color: 'border-purple-500/40 text-purple-400 bg-purple-950/20' },
  { id: 'TA0005', name: 'Defense Evasion', color: 'border-pink-500/40 text-pink-400 bg-pink-950/20' },
  { id: 'TA0006', name: 'Credential Access', color: 'border-rose-500/40 text-rose-400 bg-rose-950/20' },
  { id: 'TA0007', name: 'Discovery', color: 'border-amber-500/40 text-amber-400 bg-amber-950/20' },
  { id: 'TA0008', name: 'Lateral Movement', color: 'border-orange-500/40 text-orange-400 bg-orange-950/20' },
  { id: 'TA0009', name: 'Collection', color: 'border-yellow-500/40 text-yellow-400 bg-yellow-950/20' },
  { id: 'TA0011', name: 'Command & Control', color: 'border-emerald-500/40 text-emerald-400 bg-emerald-950/20' },
  { id: 'TA0010', name: 'Exfiltration', color: 'border-teal-500/40 text-teal-400 bg-teal-950/20' },
  { id: 'TA0040', name: 'Impact', color: 'border-red-500/40 text-red-400 bg-red-950/20' },
];

const TECHNIQUES: MitreTechnique[] = [
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries send phishing messages with malicious attachments or links to gain initial credential access or execute payload code.',
    detection: 'Monitor inbound email logs for suspicious sender domains, SPF/DKIM failures, and anomalous user link clicks.',
    mitigation: 'Implement strict DMARC p=reject, inbound email sandboxing, and multi-factor authentication (FIDO2).',
    platforms: ['Linux', 'macOS', 'Windows', 'SaaS', 'Office 365'],
    dataSources: ['Email: Inbound Headers', 'Network Traffic: DNS', 'Application Log: SigninLogs'],
    sampleKqlQuery: `EmailEvents\n| where ThreatTypes has "Phish" or ThreatTypes has "Malware"\n| project TimeGenerated, SenderMailFromAddress, RecipientEmailAddress, Subject, DeliveryAction`,
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries exploit vulnerabilities in internet-facing web servers, firewalls, and remote services to achieve initial code execution.',
    detection: 'Inspect Web Application Firewall (WAF) blocks, web server access logs with anomalous URL parameters, and crash dumps.',
    mitigation: 'Enforce vulnerability management patching, WAF virtual patching, and network segmentation (DMZ).',
    platforms: ['Linux', 'Windows', 'Containers', 'Network'],
    dataSources: ['Application Log: Web Logs', 'Network Traffic: WAF Alerts'],
    sampleKqlQuery: `W3CIISLog\n| where csMethod in ("POST", "PUT") and scStatus in (200, 500)\n| where csUriStem matches regex @"(?i)(\\.php|\\.aspx|\\.env|cgi-bin)"`,
  },
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries abuse PowerShell, Windows Command Shell (cmd.exe), Python, or Unix Shells to execute arbitrary commands.',
    detection: 'Audit Sysmon Event ID 1 (Process Creation) and PowerShell ScriptBlock Logging (Event ID 4104).',
    mitigation: 'Enable PowerShell Constrained Language Mode and AppLocker / WDAC application whitelisting.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation', 'Script: Script Execution'],
    sampleKqlQuery: `DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")\n| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "downloadstring", "iex", "invoke-expression")`,
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries configure task schedulers (schtasks, cron) to execute malicious binaries at designated intervals or on system reboot.',
    detection: 'Monitor Windows Event ID 4698 (A scheduled task was created) and modifications to /etc/crontab.',
    mitigation: 'Restrict user permissions to create scheduled tasks and audit task creation events.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Scheduled Job: Scheduled Job Creation', 'Process: Process Creation'],
    sampleKqlQuery: `SecurityEvent\n| where EventID == 4698\n| project TimeGenerated, Computer, SubjectUserName, Activity, TaskName = tostring(parse_xml(EventData).EventData.Data[0].['#text'])`,
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries obtain and abuse legitimate credentials (compromised passwords, API keys) to bypass defensive barriers.',
    detection: 'Flag impossible travel sign-ins, anomalous access times, and token replay attacks in identity provider logs.',
    mitigation: 'Enforce phishing-resistant MFA, conditional access policies, and automated risk-based sign-in blocking.',
    platforms: ['Active Directory', 'Azure AD', 'AWS', 'Linux', 'Windows'],
    dataSources: ['User Account: User Account Authentication', 'Logon Session: Logon Session Creation'],
    sampleKqlQuery: `SigninLogs\n| where ResultType == 0\n| where NetworkLocationDetails != "[]"\n| summarize SigninCount = count() by UserPrincipalName, Location, IPAddress, AppDisplayName`,
  },
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries dump memory contents of LSASS or SAM registry hives to extract plaintext passwords and NTLM hashes.',
    detection: 'Monitor LSASS process handle access (Sysmon Event ID 10) with access masks like 0x1010 or 0x1FFFFF.',
    mitigation: 'Enable Windows Defender Credential Guard (Virtualization-based Security) and RunAsPPL on lsass.exe.',
    platforms: ['Windows', 'Linux'],
    dataSources: ['Process: Process Access', 'Command: Command Execution'],
    sampleKqlQuery: `DeviceEvents\n| where ActionType == "OpenProcessApiCall"\n| where FileName =~ "lsass.exe"\n| where AdditionalFields contains "0x1010" or AdditionalFields contains "0x1FFFFF"`,
  },
  {
    id: 'T1071',
    name: 'Application Layer Protocol (C2)',
    tactic: 'Command & Control',
    tacticId: 'TA0011',
    description: 'Adversaries communicate with command and control infrastructure using standard application protocols (HTTP, HTTPS, DNS, WebSockets).',
    detection: 'Detect periodic regular beaconing intervals and abnormal User-Agent strings in outbound proxy traffic.',
    mitigation: 'Enforce SSL/TLS decryption inspection at edge firewalls and block newly registered domains.',
    platforms: ['Linux', 'macOS', 'Windows', 'Network'],
    dataSources: ['Network Traffic: Flow', 'Network Traffic: DNS'],
    sampleKqlQuery: `DeviceNetworkEvents\n| where RemotePort in (80, 443, 8080, 8443)\n| summarize RequestCount = count(), UniqueRemoteIPs = dcount(RemoteIP) by InitiatingProcessFileName, bin(TimeGenerated, 5m)\n| where RequestCount > 50`,
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact (Ransomware)',
    tactic: 'Impact',
    tacticId: 'TA0040',
    description: 'Adversaries encrypt data on target systems to interrupt availability and demand ransom payments for decryption keys.',
    detection: 'Detect massive rapid file modification/renaming events and deletion of Volume Shadow Copies (vssadmin delete shadows).',
    mitigation: 'Maintain immutable offline air-gapped backups and deploy behavior-based endpoint EDR anti-ransomware shields.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File: File Modification', 'Process: Process Creation'],
    sampleKqlQuery: `DeviceProcessEvents\n| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete", "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled No")`,
  },
];

export function MitreNavigator() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique>(TECHNIQUES[0]);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Filtered techniques
  const filteredTechniques = useMemo(() => {
    return TECHNIQUES.filter(t => {
      const matchSearch =
        searchTerm === '' ||
        t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        t.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        t.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchTactic = !selectedTactic || t.tacticId === selectedTactic;
      return matchSearch && matchTactic;
    });
  }, [searchTerm, selectedTactic]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-400">
            <Target className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-slate-100">
                MITRE ATT&CK Enterprise Matrix Navigator
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Browse adversary tactics, techniques and sub-techniques, hunting detection queries & defense mitigation playbooks
            </p>
          </div>
        </div>
      </div>

      {/* Top Search Bar & Tactics Filter */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-3 items-center">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-purple-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              placeholder="Search MITRE ATT&CK techniques, IDs (e.g. T1566, Phishing, Ransomware)..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-purple-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors shadow-inner"
            />
          </div>
          {selectedTactic && (
            <button
              onClick={() => setSelectedTactic(null)}
              className="px-3 py-2 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300"
            >
              Clear Tactic Filter
            </button>
          )}
        </div>

        {/* Tactics horizontal pill list */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          <button
            onClick={() => setSelectedTactic(null)}
            className={`px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold whitespace-nowrap transition-all ${
              selectedTactic === null
                ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                : 'text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-850'
            }`}
          >
            All Tactics
          </button>
          {TACTICS.map(t => (
            <button
              key={t.id}
              onClick={() => setSelectedTactic(t.id === selectedTactic ? null : t.id)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold whitespace-nowrap transition-all border ${
                selectedTactic === t.id
                  ? `${t.color} border-current shadow-sm`
                  : 'text-slate-400 hover:text-slate-200 bg-slate-950 border-slate-800'
              }`}
            >
              {t.name}
            </button>
          ))}
        </div>
      </div>

      {/* Split Grid: Left Techniques Catalog / Right Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Techniques Catalog (5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 tracking-normal font-bold">
              TECHNIQUES ({filteredTechniques.length})
            </span>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {filteredTechniques.map(tech => {
              const isSelected = selectedTechnique.id === tech.id;
              return (
                <div
                  key={tech.id}
                  onClick={() => setSelectedTechnique(tech)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? ' bg-slate-900/60 border-slate-800 shadow-lg'
                      : 'bg-slate-900/60 hover:bg-slate-900 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300 text-[10px] font-mono font-bold">
                        {tech.id}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-100">{tech.name}</span>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 ${isSelected ? 'text-purple-400' : 'text-slate-600'}`} />
                  </div>
                  <span className="text-[10px] font-mono text-purple-400 block mb-1 font-semibold">{tech.tactic}</span>
                  <p className="text-[11px] font-mono text-slate-400 line-clamp-2 leading-relaxed">
                    {tech.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Detail Inspector (7 Cols) */}
        <div className="lg:col-span-7 space-y-5">
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5">
            
            {/* Header Title & ID */}
            <div className="flex items-start justify-between flex-wrap gap-2 pb-3 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="px-2.5 py-1 rounded-lg bg-purple-950 border border-purple-600 text-purple-300 font-mono font-bold text-xs">
                    {selectedTechnique.id}
                  </span>
                  <h2 className="text-base font-bold text-slate-100 tracking-tight">
                    {selectedTechnique.name}
                  </h2>
                </div>
                <span className="text-xs font-mono text-purple-400 font-semibold">
                  Tactic: {selectedTechnique.tactic} ({selectedTechnique.tacticId})
                </span>
              </div>

              <a
                href={`https://attack.mitre.org/techniques/${selectedTechnique.id}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-purple-300 hover:text-purple-200 flex items-center gap-1.5 transition-all"
              >
                <span>ATT&CK Doc</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
                TECHNIQUE OVERVIEW
              </span>
              <p className="text-xs font-mono text-slate-200 leading-relaxed">
                {selectedTechnique.description}
              </p>
            </div>

            {/* Platforms & Data Sources */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="text-[10px] font-bold text-slate-500 uppercase block">TARGET PLATFORMS</span>
                <div className="flex flex-wrap gap-1">
                  {selectedTechnique.platforms.map((p, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-300">
                      {p}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="text-[10px] font-bold text-slate-500 uppercase block">SOC DATA SOURCES</span>
                <div className="flex flex-wrap gap-1">
                  {selectedTechnique.dataSources.map((ds, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-300">
                      {ds}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Detection Logic & Sample KQL */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
                  SOC DETECTION & HUNTING RULE (KQL)
                </span>
                {selectedTechnique.sampleKqlQuery && (
                  <button
                    onClick={() => copyToClipboard(selectedTechnique.sampleKqlQuery || '', 'kql-mitre')}
                    className="text-[11px] font-mono text-purple-400 hover:text-purple-300 flex items-center gap-1"
                  >
                    {copiedKey === 'kql-mitre' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    Copy KQL
                  </button>
                )}
              </div>

              <p className="text-xs font-mono text-slate-300 mb-2">
                {selectedTechnique.detection}
              </p>

              {selectedTechnique.sampleKqlQuery && (
                <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-purple-300 select-all overflow-x-auto">
                  {selectedTechnique.sampleKqlQuery}
                </pre>
              )}
            </div>

            {/* Defensive Mitigations */}
            <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/40 space-y-1.5">
              <span className="text-xs font-mono font-bold text-emerald-300 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Defensive Mitigations & Controls
              </span>
              <p className="text-xs font-mono text-slate-200 leading-relaxed">
                {selectedTechnique.mitigation}
              </p>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}
