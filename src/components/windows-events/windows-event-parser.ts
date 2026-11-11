// Windows Security, System and Sysmon event parser and triage rules.
// Fields that are missing from an event are reported as 'N/A'; nothing is filled in with guesses.

export interface ParsedWindowsEvent {
  id: string;
  eventId: number;
  timeCreated: string;
  computer: string;
  channel: string;
  providerName: string;
  isSysmon: boolean;
  subjectUser: string;
  targetUser: string;
  memberName?: string;
  logonType?: number;
  logonTypeDesc?: string;
  ipAddress: string;
  port: string;
  processName: string;
  commandLine?: string;
  serviceName?: string;
  servicePath?: string;
  status?: string;
  subStatus?: string;
  subStatusDesc?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  threatCategory?: string;
  threatDescription?: string;
  mitreTactic?: string;
  rawXml?: string;
  rawDetails: Record<string, any>;
}

export interface WindowsAuditSummary {
  totalEvents: number;
  timeRange: { start: string; end: string };
  uniqueComputers: string[];
  uniqueUsers: string[];
  uniqueIps: string[];
  threatsDetected: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  eventCounts: Record<number, number>;
  rdpLogons: ParsedWindowsEvent[];
  failedLogons: ParsedWindowsEvent[];
  accountTampering: ParsedWindowsEvent[];
  servicesCreated: ParsedWindowsEvent[];
  sysmonProcesses: ParsedWindowsEvent[];
  logsCleared: ParsedWindowsEvent[];
  bruteForceSources: { ip: string; failures: number; accounts: number }[];
}

// 1. Dictionaries
export const LOGON_TYPES: Record<number, string> = {
  2: 'Interactive (console)',
  3: 'Network (SMB, shared folder, etc.)',
  4: 'Batch (scheduled task)',
  5: 'Service',
  7: 'Unlock',
  8: 'NetworkCleartext (e.g. IIS basic auth)',
  9: 'NewCredentials (RunAs /netonly)',
  10: 'RemoteInteractive (RDP)',
  11: 'CachedInteractive (cached domain credentials)',
  12: 'CachedRemoteInteractive',
  13: 'CachedUnlock',
};

export const NTSTATUS_CODES: Record<string, string> = {
  '0xc000006a': 'Wrong password',
  '0xc0000064': 'User name does not exist',
  '0xc000006d': 'Bad user name or password',
  '0xc000006e': 'Account restriction',
  '0xc000006f': 'Logon outside allowed hours',
  '0xc0000070': 'Logon from unauthorised workstation',
  '0xc0000071': 'Password expired',
  '0xc0000072': 'Account disabled',
  '0xc0000133': 'Clock out of sync with the domain controller',
  '0xc000015b': 'Logon type not granted on this machine',
  '0xc0000193': 'Account expired',
  '0xc0000224': 'Password must be changed at next logon',
  '0xc0000234': 'Account locked out',
  '0xc0000413': 'Blocked by authentication firewall',
};

// Groups where a new member gains admin-level or remote access
const PRIVILEGED_GROUPS = [
  'administrators',
  'domain admins',
  'enterprise admins',
  'schema admins',
  'account operators',
  'backup operators',
  'server operators',
  'print operators',
  'dnsadmins',
  'group policy creator owners',
  'remote desktop users',
  'remote management users',
  'hyper-v administrators',
  'enterprise key admins',
  'key admins',
];

// Built-in accounts whose special-privilege logons (4672) are routine
const ROUTINE_ACCOUNTS = new Set(['system', 'local service', 'network service', 'dwm-1', 'dwm-2', 'umfd-0', 'umfd-1']);

const SYSMON_EVENT_NAMES: Record<number, string> = {
  1: 'Process created',
  2: 'File creation time changed',
  3: 'Network connection',
  5: 'Process terminated',
  6: 'Driver loaded',
  7: 'Image (DLL) loaded',
  8: 'CreateRemoteThread',
  10: 'Process accessed',
  11: 'File created',
  12: 'Registry object created or deleted',
  13: 'Registry value set',
  15: 'Alternate data stream created',
  17: 'Named pipe created',
  22: 'DNS query',
  23: 'File deleted (archived)',
  25: 'Process tampering',
  26: 'File deleted',
};

const MAX_SAFE_EVENTS = 5000;
const BRUTE_FORCE_FAILURES = 10; // failures from one source IP
const SPRAY_ACCOUNTS = 5; // distinct accounts failing from one source IP

const NA = 'N/A';

// 2. Parsing
export function parseWindowsEvents(rawInput: string): { events: ParsedWindowsEvent[]; truncated: boolean } {
  const trimmed = rawInput.trim();
  if (!trimmed) return { events: [], truncated: false };
  const result = trimmed.startsWith('{') || trimmed.startsWith('[') ? parseJsonEvents(trimmed) : parseXmlEvents(trimmed);
  if (result.events.length === 0) {
    throw new Error('No Windows events found. Paste XML <Event> blocks (e.g. from wevtutil qe /f:xml) or a JSON array/lines of events.');
  }
  flagBruteForce(result.events);
  return result;
}

function parseJsonEvents(rawJson: string): { events: ParsedWindowsEvent[]; truncated: boolean } {
  let items: any[];
  try {
    if (rawJson.startsWith('[')) {
      items = JSON.parse(rawJson);
    } else {
      const lines = rawJson.split('\n').filter(l => l.trim().startsWith('{'));
      items = lines.length > 1 ? lines.map(l => JSON.parse(l)) : [JSON.parse(rawJson)];
    }
  } catch {
    throw new Error('Invalid JSON. Paste a JSON array, a single object, or one JSON object per line.');
  }
  const truncated = items.length > MAX_SAFE_EVENTS;
  const events = items
    .slice(0, MAX_SAFE_EVENTS)
    .filter(i => i && typeof i === 'object')
    .map((item, idx) => normalizeJsonEvent(item, idx));
  return { events, truncated };
}

function parseXmlEvents(rawXml: string): { events: ParsedWindowsEvent[]; truncated: boolean } {
  const events: ParsedWindowsEvent[] = [];
  const eventRegex = /<Event[\s>][\s\S]*?<\/Event>/gi;
  let match;
  let truncated = false;
  while ((match = eventRegex.exec(rawXml)) !== null) {
    if (events.length >= MAX_SAFE_EVENTS) {
      truncated = true;
      break;
    }
    events.push(extractXmlEvent(match[0], events.length));
  }
  return { events, truncated };
}

function decodeXml(s: string): string {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&amp;/g, '&');
}

function extractXmlEvent(xmlStr: string, index: number): ParsedWindowsEvent {
  const pick = (re: RegExp) => {
    const m = xmlStr.match(re);
    return m ? decodeXml(m[1].trim()) : '';
  };

  const data: Record<string, string> = {};
  // <Data Name="x">value</Data> (EventData)
  const dataRegex = /<Data\s+Name=['"]([^'"]+)['"]\s*(?:\/>|>([\s\S]*?)<\/Data>)/gi;
  let d;
  while ((d = dataRegex.exec(xmlStr)) !== null) data[d[1]] = decodeXml((d[2] || '').trim());
  // <UserData><Something><Field>value</Field>... (e.g. 1102 log cleared)
  const userData = xmlStr.match(/<UserData>([\s\S]*?)<\/UserData>/i);
  if (userData) {
    const leafRegex = /<(\w+)>([^<]*)<\/\1>/g;
    let l;
    while ((l = leafRegex.exec(userData[1])) !== null) if (!(l[1] in data)) data[l[1]] = decodeXml(l[2].trim());
  }

  return buildEvent(
    {
      eventId: parseInt(pick(/<EventID[^>]*>\s*(\d+)\s*<\/EventID>/i) || '0', 10),
      timeCreated: pick(/<TimeCreated[^>]*SystemTime=['"]([^'"]+)['"]/i),
      computer: pick(/<Computer>([^<]*)<\/Computer>/i),
      channel: pick(/<Channel>([^<]*)<\/Channel>/i),
      providerName: pick(/<Provider[^>]*\sName=['"]([^'"]+)['"]/i),
    },
    data,
    index,
    xmlStr
  );
}

// Get-WinEvent JSON writes dates as "/Date(1693725262120)/"
function normalizeTime(v: unknown): string {
  if (typeof v !== 'string' && typeof v !== 'number') return '';
  const m = String(v).match(/\/Date\((-?\d+)/);
  if (m) return new Date(Number(m[1])).toISOString();
  return String(v);
}

function normalizeJsonEvent(raw: any, index: number): ParsedWindowsEvent {
  // Merge the common nestings: Sentinel/flat exports, EventData objects, Winlogbeat's winlog.event_data
  const winlog = raw.winlog || {};
  const data: Record<string, string> = {};
  for (const src of [raw, raw.EventData, raw.event_data, winlog.event_data, raw.UserData]) {
    if (!src || typeof src !== 'object') continue;
    for (const [k, v] of Object.entries(src)) {
      if (v !== null && v !== undefined && typeof v !== 'object' && !(k in data)) data[k] = String(v);
    }
  }
  const first = (...vals: unknown[]) => {
    const v = vals.find(x => x !== undefined && x !== null && x !== '');
    return v === undefined ? '' : String(v);
  };
  return buildEvent(
    {
      eventId: Number(first(raw.EventID, raw.EventId, raw.eventId, raw.Id, winlog.event_id, raw.event?.code)) || 0,
      timeCreated: normalizeTime(first(raw.TimeCreated, raw.TimeGenerated, raw.Timestamp, raw['@timestamp'], raw.TimeCreatedUtc)),
      computer: first(raw.Computer, raw.MachineName, raw.DeviceName, winlog.computer_name, raw.host?.name, raw.Host),
      channel: first(raw.Channel, raw.LogName, winlog.channel),
      providerName: first(raw.ProviderName, raw.Provider, raw.SourceName, winlog.provider_name),
    },
    data,
    index,
    undefined,
    raw
  );
}

interface EventHeader {
  eventId: number;
  timeCreated: string;
  computer: string;
  channel: string;
  providerName: string;
}

function buildEvent(h: EventHeader, data: Record<string, string>, index: number, rawXml?: string, rawObj?: any): ParsedWindowsEvent {
  const get = (...keys: string[]) => {
    for (const k of keys) {
      const v = data[k];
      if (v !== undefined && v !== '' && v !== '-') return v;
    }
    return '';
  };
  const isSysmon = /sysmon/i.test(h.providerName) || /sysmon/i.test(h.channel);
  const logonTypeRaw = get('LogonType');
  const logonType = logonTypeRaw ? parseInt(logonTypeRaw, 10) : undefined;
  const status = get('Status').toLowerCase() || undefined;
  const subStatusRaw = get('SubStatus').toLowerCase();
  // SubStatus 0x0 means "see Status"
  const subStatus = subStatusRaw && subStatusRaw !== '0x0' ? subStatusRaw : status;

  const evt: ParsedWindowsEvent = {
    id: `winevt_${index}_${h.eventId}`,
    eventId: h.eventId,
    timeCreated: h.timeCreated,
    computer: h.computer || NA,
    channel: h.channel || NA,
    providerName: h.providerName || NA,
    isSysmon,
    subjectUser: get('SubjectUserName', 'User') || NA,
    targetUser: get('TargetUserName', 'TargetUser', 'Account', 'UserName') || NA,
    memberName: get('MemberName', 'MemberSid') || undefined,
    logonType: Number.isFinite(logonType) ? logonType : undefined,
    logonTypeDesc: logonType !== undefined && Number.isFinite(logonType) ? LOGON_TYPES[logonType] || `Logon type ${logonType}` : undefined,
    ipAddress: get('IpAddress', 'ClientAddress', 'SourceIp', 'SourceAddress') || NA,
    port: get('IpPort', 'ClientPort', 'SourcePort') || NA,
    // Image (Sysmon) and NewProcessName (4688) are the new process; ProcessName is the caller
    processName: get('Image', 'NewProcessName', 'ProcessName') || NA,
    commandLine: get('CommandLine', 'ProcessCommandLine') || undefined,
    serviceName: get('ServiceName') || undefined,
    servicePath: get('ImagePath', 'ServiceFileName') || undefined,
    status,
    subStatus,
    subStatusDesc: subStatus ? NTSTATUS_CODES[subStatus] : undefined,
    severity: 'INFO',
    rawXml,
    rawDetails: rawObj ?? data,
  };
  Object.assign(evt, evaluateWindowsThreat(evt, data));
  return evt;
}

// 3. Triage rules
type Verdict = Pick<ParsedWindowsEvent, 'severity' | 'threatCategory' | 'threatDescription' | 'mitreTactic'>;

const SEVERITY_RANK: Record<ParsedWindowsEvent['severity'], number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function isPublicIp(ip: string): boolean {
  const v4 = ip.replace(/^::ffff:/i, '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    return true;
  }
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    return !(l === '::1' || l === '::' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd'));
  }
  return false;
}

// PowerShell accepts any unambiguous prefix of -EncodedCommand (-e, -en, -enc ...) plus -ec
function hasEncodedCommand(cl: string): boolean {
  if (!/\b(powershell|pwsh)(\.exe)?\b/i.test(cl)) return false;
  return cl
    .split(/\s+/)
    .some(t => /^[-/]/.test(t) && (t.slice(1).toLowerCase() === 'ec' || 'encodedcommand'.startsWith(t.slice(1).toLowerCase())) && t.length > 1);
}

const COMMAND_RULES: { test: (cl: string) => boolean; verdict: Verdict }[] = [
  {
    test: cl => /mimikatz|sekurlsa::|lsadump::|kerberos::golden/i.test(cl),
    verdict: { severity: 'CRITICAL', threatCategory: 'Credential dumping tool', mitreTactic: 'Credential Access (T1003 - OS Credential Dumping)' },
  },
  {
    test: cl => /procdump.*lsass|comsvcs(\.dll)?[\s,]+#?(minidump|24)/i.test(cl),
    verdict: { severity: 'CRITICAL', threatCategory: 'LSASS memory dump', mitreTactic: 'Credential Access (T1003.001 - LSASS Memory)' },
  },
  {
    test: cl =>
      /vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no/i.test(cl),
    verdict: { severity: 'CRITICAL', threatCategory: 'Backup or shadow copy deletion', mitreTactic: 'Impact (T1490 - Inhibit System Recovery)' },
  },
  {
    test: hasEncodedCommand,
    verdict: { severity: 'HIGH', threatCategory: 'Encoded PowerShell command', mitreTactic: 'Execution (T1059.001 - PowerShell)' },
  },
  {
    test: cl => /downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer|bitsadmin(\.exe)?\s.*\/transfer/i.test(cl),
    verdict: { severity: 'HIGH', threatCategory: 'File download from the command line', mitreTactic: 'Command and Control (T1105 - Ingress Tool Transfer)' },
  },
  {
    test: cl => /certutil(\.exe)?\s.*[-/]urlcache/i.test(cl),
    verdict: { severity: 'HIGH', threatCategory: 'Certutil used to download a file', mitreTactic: 'Command and Control (T1105 - Ingress Tool Transfer)' },
  },
  {
    test: cl => /certutil(\.exe)?\s.*[-/]decode/i.test(cl),
    verdict: { severity: 'MEDIUM', threatCategory: 'Certutil used to decode a file', mitreTactic: 'Defense Evasion (T1140 - Deobfuscate/Decode Files)' },
  },
  {
    test: cl => /mshta(\.exe)?\s.*(https?:|javascript:|vbscript:)|regsvr32(\.exe)?\s.*\/i:\s*https?:|rundll32(\.exe)?\s.*javascript:/i.test(cl),
    verdict: { severity: 'HIGH', threatCategory: 'Signed binary proxy execution', mitreTactic: 'Defense Evasion (T1218 - System Binary Proxy Execution)' },
  },
  {
    test: cl => /\bnet1?(\.exe)?\s+(user|group|localgroup)\b.*(\/domain|admins)/i.test(cl),
    verdict: { severity: 'LOW', threatCategory: 'Account or group discovery', mitreTactic: 'Discovery (T1087 - Account Discovery)' },
  },
  {
    test: cl => /\bwhoami(\.exe)?\b/i.test(cl),
    verdict: { severity: 'LOW', threatCategory: 'User discovery (whoami)', mitreTactic: 'Discovery (T1033 - System Owner/User Discovery)' },
  },
];

const SUSPICIOUS_PATH = /\\users\\|\\temp\\|\\appdata\\|\\programdata\\|\\perflogs\\|^\\\\|\s\\\\|powershell|cmd(\.exe)?\s+\/c|%comspec%|mshta|rundll32|regsvr32|\.(bat|cmd|ps1|vbs|js|hta)\b/i;

function evaluateCommand(e: ParsedWindowsEvent, source: string): Verdict {
  const cl = e.commandLine || e.processName;
  for (const rule of COMMAND_RULES) {
    if (cl !== NA && rule.test(cl)) {
      return { ...rule.verdict, threatDescription: `${rule.verdict.threatCategory} (${source}): ${cl}` };
    }
  }
  return { severity: 'INFO', threatCategory: 'Process created', threatDescription: `Process created: ${e.processName}` };
}

function evaluateWindowsThreat(e: ParsedWindowsEvent, data: Record<string, string>): Verdict {
  const id = e.eventId;
  const provider = e.providerName.toLowerCase();
  const security = provider === 'n/a' || provider.includes('security-auditing');

  if (e.isSysmon) {
    if (id === 1) return evaluateCommand(e, 'Sysmon 1');
    if (id === 8) {
      return {
        severity: 'MEDIUM',
        threatCategory: 'Remote thread created in another process',
        threatDescription: `${data.SourceImage || 'A process'} created a thread in ${data.TargetImage || 'another process'}. Common in process injection, but also used by some legitimate software.`,
        mitreTactic: 'Defense Evasion (T1055 - Process Injection)',
      };
    }
    if (id === 10 && /\\lsass\.exe$/i.test(data.TargetImage || '')) {
      return {
        severity: 'HIGH',
        threatCategory: 'LSASS process accessed',
        threatDescription: `${data.SourceImage || 'A process'} opened lsass.exe (access mask ${data.GrantedAccess || 'unknown'}). Check whether this is security software or a credential dumper.`,
        mitreTactic: 'Credential Access (T1003.001 - LSASS Memory)',
      };
    }
    const name = SYSMON_EVENT_NAMES[id];
    return name ? { severity: 'INFO', threatCategory: `Sysmon: ${name}` } : { severity: 'INFO' };
  }

  if (id === 104 && (provider.includes('eventlog') || e.channel.toLowerCase() === 'system')) {
    return {
      severity: 'HIGH',
      threatCategory: 'Event log cleared',
      threatDescription: `The ${data.Channel || 'an'} event log was cleared by ${data.SubjectUserName || 'an unknown user'}.`,
      mitreTactic: 'Defense Evasion (T1070.001 - Clear Windows Event Logs)',
    };
  }
  if (id === 7045 && (provider.includes('service control manager') || provider === 'n/a')) {
    return serviceVerdict(e, 'System 7045');
  }
  // 1102 is logged by the Eventlog provider into the Security channel
  if (id === 1102 && (provider.includes('eventlog') || security)) {
    return {
      severity: 'CRITICAL',
      threatCategory: 'Security log cleared',
      threatDescription: `The Security event log was cleared by ${e.subjectUser}. Attackers do this to hide their activity.`,
      mitreTactic: 'Defense Evasion (T1070.001 - Clear Windows Event Logs)',
    };
  }
  if (!security) return { severity: 'INFO' };

  switch (id) {
    case 4720:
      return {
        severity: 'HIGH',
        threatCategory: 'User account created',
        threatDescription: `Account '${e.targetUser}' was created by '${e.subjectUser}'. Confirm it was authorised.`,
        mitreTactic: 'Persistence (T1136 - Create Account)',
      };
    case 4726:
      return {
        severity: 'MEDIUM',
        threatCategory: 'User account deleted',
        threatDescription: `Account '${e.targetUser}' was deleted by '${e.subjectUser}'.`,
        mitreTactic: 'Impact (T1531 - Account Access Removal)',
      };
    case 4738:
      return { severity: 'LOW', threatCategory: 'User account changed', threatDescription: `Account '${e.targetUser}' was changed by '${e.subjectUser}'.` };
    case 4740:
      return {
        severity: 'MEDIUM',
        threatCategory: 'Account locked out',
        threatDescription: `Account '${e.targetUser}' was locked out (caller computer: ${data.TargetDomainName || 'unknown'}).`,
      };
    case 4728:
    case 4732:
    case 4756: {
      // TargetUserName is the group; the member is MemberName (a DN) or MemberSid
      const group = e.targetUser;
      const member = (e.memberName || '').match(/^CN=([^,]+)/i)?.[1] || e.memberName || 'unknown member';
      const privileged = PRIVILEGED_GROUPS.includes(group.toLowerCase());
      return privileged
        ? {
            severity: 'CRITICAL',
            threatCategory: 'Member added to privileged group',
            threatDescription: `'${member}' was added to '${group}' by '${e.subjectUser}'.`,
            mitreTactic: 'Persistence (T1098 - Account Manipulation)',
          }
        : {
            severity: 'LOW',
            threatCategory: 'Member added to group',
            threatDescription: `'${member}' was added to '${group}' by '${e.subjectUser}'.`,
          };
    }
    case 4697:
      return serviceVerdict(e, 'Security 4697');
    case 4698: {
      const content = data.TaskContent || '';
      const suspicious = SUSPICIOUS_PATH.test(content);
      return {
        severity: suspicious ? 'HIGH' : 'MEDIUM',
        threatCategory: 'Scheduled task created',
        threatDescription: `Task '${data.TaskName || 'unknown'}' was created by '${e.subjectUser}'.${suspicious ? ' Its action runs from a user-writable path or a script host.' : ''}`,
        mitreTactic: 'Persistence (T1053.005 - Scheduled Task)',
      };
    }
    case 4625:
      // Single failures are routine; flagBruteForce() raises repeated failures from one source
      return {
        severity: 'LOW',
        threatCategory: 'Failed logon',
        threatDescription: `Logon failed for '${e.targetUser}' from ${e.ipAddress}. Reason: ${e.subStatusDesc || e.subStatus || 'not given'}.`,
      };
    case 4624:
      if (e.logonType === 10) {
        const external = e.ipAddress !== NA && isPublicIp(e.ipAddress);
        return {
          severity: external ? 'HIGH' : 'MEDIUM',
          threatCategory: external ? 'RDP logon from a public IP address' : 'RDP logon',
          threatDescription: `'${e.targetUser}' logged on over Remote Desktop from ${e.ipAddress}.${external ? ' RDP should not be reachable from the internet.' : ''}`,
          mitreTactic: 'Lateral Movement (T1021.001 - Remote Desktop Protocol)',
        };
      }
      return { severity: 'INFO' };
    case 4672: {
      const user = e.subjectUser;
      if (ROUTINE_ACCOUNTS.has(user.toLowerCase()) || user.endsWith('$')) return { severity: 'INFO' };
      return {
        severity: 'LOW',
        threatCategory: 'Admin-level logon',
        threatDescription: `'${user}' logged on with special (administrator-level) privileges.`,
      };
    }
    case 4688:
      return evaluateCommand(e, 'Security 4688');
    default:
      return { severity: 'INFO' };
  }
}

function serviceVerdict(e: ParsedWindowsEvent, source: string): Verdict {
  const path = e.servicePath || '';
  const psexec = /psexesvc|paexec|remcom/i.test(`${e.serviceName} ${path}`);
  const suspicious = psexec || SUSPICIOUS_PATH.test(path);
  return {
    severity: suspicious ? 'HIGH' : 'MEDIUM',
    threatCategory: psexec ? 'Remote execution service installed (PsExec-style)' : 'New service installed',
    threatDescription: `Service '${e.serviceName || 'unknown'}' installed (${source}). Path: ${path || 'not recorded'}.${
      suspicious && !psexec ? ' The path is user-writable or launches a script host.' : ''
    }`,
    mitreTactic: psexec ? 'Lateral Movement (T1569.002 - Service Execution)' : 'Persistence (T1543.003 - Windows Service)',
  };
}

// Raise repeated 4625s from one source: many failures (brute force) or many accounts (password spray)
function flagBruteForce(events: ParsedWindowsEvent[]) {
  const bySource = new Map<string, ParsedWindowsEvent[]>();
  for (const e of events) {
    if (e.eventId !== 4625 || e.ipAddress === NA) continue;
    const list = bySource.get(e.ipAddress) || [];
    list.push(e);
    bySource.set(e.ipAddress, list);
  }
  for (const [ip, list] of bySource) {
    const accounts = new Set(list.map(e => e.targetUser.toLowerCase())).size;
    const spray = accounts >= SPRAY_ACCOUNTS;
    if (list.length < BRUTE_FORCE_FAILURES && !spray) continue;
    for (const e of list) {
      e.severity = 'HIGH';
      e.threatCategory = spray ? 'Password spray' : 'Brute-force logon attempts';
      e.threatDescription = `${list.length} failed logons from ${ip} against ${accounts} account${accounts === 1 ? '' : 's'}. This one: '${e.targetUser}', reason: ${e.subStatusDesc || e.subStatus || 'not given'}.`;
      e.mitreTactic = spray ? 'Credential Access (T1110.003 - Password Spraying)' : 'Credential Access (T1110.001 - Password Guessing)';
    }
  }
}

// 4. Summary
const GROUP_MEMBERSHIP_EVENT_IDS = [4728, 4732, 4756];

export function summarizeWindowsEvents(events: ParsedWindowsEvent[]): WindowsAuditSummary {
  const computerSet = new Set<string>();
  const userSet = new Set<string>();
  const ipSet = new Set<string>();
  const eventCounts: Record<number, number> = {};
  const threats = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
  const rdpLogons: ParsedWindowsEvent[] = [];
  const failedLogons: ParsedWindowsEvent[] = [];
  const accountTampering: ParsedWindowsEvent[] = [];
  const servicesCreated: ParsedWindowsEvent[] = [];
  const sysmonProcesses: ParsedWindowsEvent[] = [];
  const logsCleared: ParsedWindowsEvent[] = [];
  const failuresBySource = new Map<string, { failures: number; accounts: Set<string> }>();

  for (const e of events) {
    if (e.computer !== NA) computerSet.add(e.computer);
    if (GROUP_MEMBERSHIP_EVENT_IDS.includes(e.eventId)) {
      // For group changes TargetUserName is the group, not an account; count the member that was added
      const member = (e.memberName || '').match(/^CN=([^,]+)/i)?.[1] || e.memberName;
      if (member) userSet.add(member);
    } else if (e.targetUser !== NA) {
      userSet.add(e.targetUser);
    }
    if (e.ipAddress !== NA) ipSet.add(e.ipAddress);
    eventCounts[e.eventId] = (eventCounts[e.eventId] || 0) + 1;

    if (e.severity === 'CRITICAL') threats.criticalCount++;
    else if (e.severity === 'HIGH') threats.highCount++;
    else if (e.severity === 'MEDIUM') threats.mediumCount++;
    else if (e.severity === 'LOW') threats.lowCount++;

    if (e.eventId === 4624 && e.logonType === 10) rdpLogons.push(e);
    if (e.eventId === 4625) {
      failedLogons.push(e);
      if (e.ipAddress !== NA) {
        const s = failuresBySource.get(e.ipAddress) || { failures: 0, accounts: new Set<string>() };
        s.failures++;
        s.accounts.add(e.targetUser.toLowerCase());
        failuresBySource.set(e.ipAddress, s);
      }
    }
    if (ACCOUNT_EVENT_IDS.includes(e.eventId)) accountTampering.push(e);
    if (e.eventId === 7045 || e.eventId === 4697) servicesCreated.push(e);
    if ((e.isSysmon && e.eventId === 1) || e.eventId === 4688) sysmonProcesses.push(e);
    if (e.eventId === 1102 || (e.eventId === 104 && e.severity !== 'INFO')) logsCleared.push(e);
  }

  const times = events
    .map(e => new Date(e.timeCreated).getTime())
    .filter(t => !isNaN(t))
    .sort((a, b) => a - b);

  return {
    totalEvents: events.length,
    timeRange: {
      start: times.length ? new Date(times[0]).toISOString() : NA,
      end: times.length ? new Date(times[times.length - 1]).toISOString() : NA,
    },
    uniqueComputers: Array.from(computerSet),
    uniqueUsers: Array.from(userSet),
    uniqueIps: Array.from(ipSet),
    threatsDetected: threats,
    eventCounts,
    rdpLogons,
    failedLogons,
    accountTampering,
    servicesCreated,
    sysmonProcesses,
    logsCleared,
    bruteForceSources: Array.from(failuresBySource, ([ip, s]) => ({ ip, failures: s.failures, accounts: s.accounts.size }))
      .filter(s => s.failures >= BRUTE_FORCE_FAILURES || s.accounts >= SPRAY_ACCOUNTS)
      .sort((a, b) => b.failures - a.failures),
  };
}

export const ACCOUNT_EVENT_IDS = [4720, 4726, 4738, 4740, 4728, 4732, 4756];

// 5. Markdown report, built only from what the events show
export function generateWindowsIncidentReport(summary: WindowsAuditSummary, events: ParsedWindowsEvent[]): string {
  const lines: string[] = [];
  const t = summary.threatsDetected;
  lines.push('# Windows Event Triage Report');
  lines.push(`**Generated:** ${new Date().toUTCString()}`);
  lines.push(`**Event time range:** \`${summary.timeRange.start}\` to \`${summary.timeRange.end}\``);
  lines.push(`**Events analysed:** ${summary.totalEvents}`);
  lines.push('');
  lines.push('## 1. Summary');
  if (t.criticalCount + t.highCount > 0) {
    lines.push(`**${t.criticalCount} critical** and **${t.highCount} high** severity events matched the triage rules.`);
  } else {
    lines.push('No events matched the critical or high triage rules. This does not rule out compromise: the rules cover common patterns only.');
  }
  lines.push('');
  lines.push(`- **Hosts:** ${summary.uniqueComputers.length}${summary.uniqueComputers.length ? ` (${summary.uniqueComputers.slice(0, 5).join(', ')})` : ''}`);
  lines.push(`- **Accounts:** ${summary.uniqueUsers.length}`);
  lines.push(`- **Source IPs:** ${summary.uniqueIps.length}${summary.uniqueIps.length ? ` (${summary.uniqueIps.slice(0, 5).join(', ')})` : ''}`);
  if (summary.logsCleared.length) lines.push(`- **Event logs cleared:** ${summary.logsCleared.length}`);
  if (summary.rdpLogons.length) lines.push(`- **RDP logons (type 10):** ${summary.rdpLogons.length}`);
  if (summary.failedLogons.length) lines.push(`- **Failed logons (4625):** ${summary.failedLogons.length}`);
  for (const s of summary.bruteForceSources) lines.push(`  - ${s.ip}: ${s.failures} failures against ${s.accounts} account(s)`);
  if (summary.accountTampering.length) lines.push(`- **Account and group changes:** ${summary.accountTampering.length}`);
  if (summary.servicesCreated.length) lines.push(`- **Services installed (7045/4697):** ${summary.servicesCreated.length}`);
  lines.push('');

  const highEvents = events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH');
  if (highEvents.length) {
    lines.push('## 2. High and critical findings');
    lines.push('');
    lines.push('| Time | Event ID | Severity | Computer | Account | Source IP | Finding |');
    lines.push('|---|---|---|---|---|---|---|');
    const cell = (s: string) => s.replace(/\|/g, '\\|');
    for (const e of highEvents) {
      lines.push(
        `| ${e.timeCreated || NA} | ${e.eventId} | ${e.severity} | ${cell(e.computer)} | ${cell(e.targetUser)} | ${e.ipAddress} | ${cell(e.threatCategory || NA)} |`
      );
    }
    lines.push('');
  }

  const steps: string[] = [];
  if (summary.logsCleared.length) steps.push('Find out who cleared the logs and why; recover the cleared period from your SIEM or log forwarder.');
  if (summary.bruteForceSources.length) steps.push('Block or investigate the brute-force source IPs, and check for a successful logon (4624) from them afterwards.');
  if (summary.rdpLogons.some(e => e.severity === 'HIGH')) steps.push('RDP logons came from public IP addresses: confirm them with the users and restrict RDP to a VPN or gateway.');
  else if (summary.rdpLogons.length) steps.push('Confirm the RDP sessions with the account owners.');
  if (summary.servicesCreated.length) steps.push('Check each new service binary path and signer (HKLM\\SYSTEM\\CurrentControlSet\\Services).');
  if (summary.accountTampering.length) steps.push('Confirm new accounts and group changes against change tickets.');
  if (events.some(e => e.severity !== 'INFO' && (e.eventId === 4688 || (e.isSysmon && e.eventId === 1)))) {
    steps.push('Review the flagged command lines and their parent processes on the affected hosts.');
  }
  if (steps.length) {
    lines.push('## 3. Suggested next steps');
    steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
    lines.push('');
  }
  lines.push('---');
  lines.push('*Generated by Cyber Tools Portal. Severity comes from simple rules; confirm findings before acting.*');
  return lines.join('\n');
}

// 6. Sample: RFC 5737 documentation IPs and fictional hosts
export const SAMPLE_WINDOWS_XML = `<Events>
${Array.from(
  { length: 12 },
  (_, i) => `  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-09-03T07:14:${String(10 + i * 3).padStart(2, '0')}.120Z" />
      <Computer>DC-SRV01.corp.contoso.com</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">${['Administrator', 'admin', 'helpdesk_svc', 'backup', 'j.smith', 'scanner'][i % 6]}</Data>
      <Data Name="IpAddress">203.0.113.45</Data>
      <Data Name="IpPort">${51240 + i}</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">${i % 3 === 0 ? '0xC0000064' : '0xC000006A'}</Data>
    </EventData>
  </Event>`
).join('\n')}
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-09-03T07:18:05.450Z" />
      <Computer>FINANCE-WS02.corp.contoso.com</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">helpdesk_svc</Data>
      <Data Name="IpAddress">203.0.113.45</Data>
      <Data Name="IpPort">54120</Data>
      <Data Name="LogonType">10</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4720</EventID>
      <TimeCreated SystemTime="2026-09-03T07:22:30.800Z" />
      <Computer>DC-SRV01.corp.contoso.com</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">backup_admin</Data>
      <Data Name="SubjectUserName">helpdesk_svc</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4732</EventID>
      <TimeCreated SystemTime="2026-09-03T07:23:02.100Z" />
      <Computer>DC-SRV01.corp.contoso.com</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="MemberName">CN=backup_admin,OU=Users,DC=corp,DC=contoso,DC=com</Data>
      <Data Name="TargetUserName">Administrators</Data>
      <Data Name="SubjectUserName">helpdesk_svc</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID Qualifiers="16384">7045</EventID>
      <TimeCreated SystemTime="2026-09-03T07:28:10.000Z" />
      <Computer>FINANCE-WS02.corp.contoso.com</Computer>
      <Channel>System</Channel>
    </System>
    <EventData>
      <Data Name="ServiceName">WindowsUpdateMonitor</Data>
      <Data Name="ImagePath">C:\\Users\\Public\\updater.exe</Data>
      <Data Name="ServiceType">user mode service</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>1</EventID>
      <TimeCreated SystemTime="2026-09-03T07:29:44.000Z" />
      <Computer>FINANCE-WS02.corp.contoso.com</Computer>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\vssadmin.exe</Data>
      <Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data>
      <Data Name="User">CORP\\helpdesk_svc</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Eventlog" />
      <EventID>1102</EventID>
      <TimeCreated SystemTime="2026-09-03T07:31:00.000Z" />
      <Computer>FINANCE-WS02.corp.contoso.com</Computer>
      <Channel>Security</Channel>
    </System>
    <UserData>
      <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>helpdesk_svc</SubjectUserName>
        <SubjectDomainName>CORP</SubjectDomainName>
      </LogFileCleared>
    </UserData>
  </Event>
</Events>`;
