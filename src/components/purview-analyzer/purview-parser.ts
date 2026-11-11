// Microsoft Purview & Defender Unified Audit Log (UAL) Forensic Parser & Detection Engine

export interface ParsedAuditRecord {
  id: string;
  creationTime: string;
  userId: string;
  operation: string;
  workload: string;
  clientIp: string;
  sessionId?: string;
  userAgent?: string;
  resultStatus: 'Succeeded' | 'Failed' | 'Blocked' | 'PartiallySucceeded' | 'Unknown';
  target: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  threatCategory?: string;
  threatDescription?: string;
  mitreTactic?: string;
  matchedRuleId?: string;
  matchedRuleName?: string;
  modifiedProperties?: { name: string; oldValue?: string; newValue?: string }[];
  rawDetails: Record<string, any>;
}

export interface CustomAuditRule {
  id: string;
  name: string;
  enabled: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  match: {
    operation?: string;       // Substring, regex pattern, or wildcard (*delete*)
    actor?: string;           // Substring, email, or regex
    clientIp?: string;        // IP, IP prefix (e.g. 185.220.*) or pattern
    workload?: string;        // Exact or substring match (e.g. Exchange, AzureActiveDirectory)
    target?: string;          // Target mailbox, user, object
    resultStatus?: string;    // Succeeded, Failed, Blocked, ALL
  };
  threatCategory: string;
  threatDescription: string;
  mitreTactic?: string;
}

export interface AuditTargetScope {
  targetUsers: string;            // Filter by specific user UPN(s) (comma or space separated)
  excludeServiceAccounts: boolean;// Filter out automated sync_*, msol_*, app@* accounts
  targetIps: string;              // Filter by IP or comma separated IPs
  onlyExternalIps: boolean;       // Filter out RFC1918 internal/loopback IPs
  targetOperations: string;       // Wildcard / regex / comma separated operations
  targetWorkload: string;         // 'ALL' or specific workload
  targetSeverity: string;         // 'ALL' or specific severity
  timeRangeStart: string;         // ISO or YYYY-MM-DD
  timeRangeEnd: string;           // ISO or YYYY-MM-DD
  resultStatus: string;           // 'ALL' | 'Succeeded' | 'Failed' | 'Blocked'
  matchedRuleOnly: string;        // 'ALL' or specific ruleId
}

export interface PurviewReportOptions {
  caseTitle: string;
  organization: string;
  investigator: string;
  classification: 'CONFIDENTIAL' | 'RESTRICTED' | 'INTERNAL' | 'TLP:AMBER' | 'TLP:RED';
  analystNotes: string;
  minSeverity: 'ALL' | 'MEDIUM_PLUS' | 'HIGH_CRITICAL' | 'CRITICAL_ONLY';
  includeExecutiveSummary: boolean;
  includeScopeSection: boolean;
  includeCustomRulesSummary: boolean;
  includeFindingsTable: boolean;
  includeThreatNarratives: boolean;
  includeSessionHijacking: boolean;
  includeRemediationPlaybook: boolean;
}

export const DEFAULT_CUSTOM_RULES: CustomAuditRule[] = [
  {
    id: 'rule_ga_delete',
    name: 'Global Admin & User Account Destruction',
    enabled: true,
    severity: 'CRITICAL',
    match: { operation: 'delete user|remove-user|hard delete user' },
    threatCategory: 'Account Deletion / Destruction',
    threatDescription: 'Account deprovisioning or hard deletion detected. Critical verification required to rule out unauthorized account destruction.',
    mitreTactic: 'Impact (T1531 - Account Access Removal)',
  },
  {
    id: 'rule_upn_tamper',
    name: 'Identity Renaming & UPN Manipulation',
    enabled: false, // Disabled by default to avoid flagging routine attribute and license syncs
    severity: 'HIGH',
    match: { operation: 'rename-user|update-userprincipalname|set-user' },
    threatCategory: 'Account Renaming & Identity Tampering',
    threatDescription: 'Account identity attributes modified. Typical attacker persistence and disguise technique.',
    mitreTactic: 'Persistence / Defense Evasion (T1098 - Account Manipulation)',
  },
  {
    id: 'rule_priv_escalation',
    name: 'Privileged Role Promotion & RoleAssignmentAdded',
    enabled: true,
    severity: 'CRITICAL',
    match: { operation: 'roleassignmentadded|add member to role|add-rolegroupmember|elevateaccess' },
    threatCategory: 'Privilege Escalation',
    threatDescription: 'High-privilege directory role assigned. Verify if Global Admin or Exchange admin escalation was authorized.',
    mitreTactic: 'Privilege Escalation (T1078 - Valid Accounts)',
  },
  {
    id: 'rule_bec_forwarding',
    name: 'Exchange Mailbox External Forwarding (BEC)',
    enabled: true,
    severity: 'HIGH',
    match: { operation: 'new-inboxrule|set-inboxrule|enable-inboxrule|updateinboxrules' },
    threatCategory: 'Email Forwarding Rule (BEC Indicator)',
    threatDescription: 'Mailbox forwarding or diversion rule established. Hallmarks of Business Email Compromise (BEC) exfiltration.',
    mitreTactic: 'Collection / Exfiltration (T1114.003 - Email Forwarding Rule)',
  },
  {
    id: 'rule_oauth_consent',
    name: 'Illicit OAuth App Consent & Service Principal Credentials',
    enabled: true,
    severity: 'HIGH',
    match: { operation: 'consenttoapplication|add service principal credentials|add-serviceprincipal|add app role assignment' },
    threatCategory: 'Illicit OAuth Consent / Rogue App',
    threatDescription: 'Third-party application consent or API credentials registered. Common vector for persistent covert API access.',
    mitreTactic: 'Persistence / Credential Access (T1528 - Steal Application Access Token)',
  },
  {
    id: 'rule_ca_tamper',
    name: 'Conditional Access Policy Modification / Disable',
    enabled: true,
    severity: 'CRITICAL',
    match: { operation: 'conditionalaccesspolicy|set-policy|disable policy|remove-policy' },
    threatCategory: 'Defense Evasion / Policy Tampering',
    threatDescription: 'Tenant Conditional Access or security policy modified. Adversaries disable MFA policies to maintain unauthorized access.',
    mitreTactic: 'Defense Evasion (T1562.001 - Disable or Modify Tools)',
  },
  {
    id: 'rule_mass_download',
    name: 'Mass File Download & Data Exfiltration',
    enabled: false, // Disabled by default to avoid flagging normal daily SharePoint file views
    severity: 'MEDIUM',
    match: { operation: 'filedownloadedextended|sharinglinkcreated' },
    threatCategory: 'Data Access / Potential Exfiltration',
    threatDescription: 'Anonymous external sharing link created or bulk file download in SharePoint/OneDrive.',
    mitreTactic: 'Exfiltration (T1567 - Exfiltration Over Web Service)',
  },
  {
    id: 'rule_external_invite',
    name: 'External Guest User Invited to Directory',
    enabled: true,
    severity: 'MEDIUM',
    match: { operation: 'invite external user|add guest|invitation' },
    threatCategory: 'External Access Expansion',
    threatDescription: 'External user invited into Azure AD tenant. Scrutinize invited email domain for suspicious origin.',
    mitreTactic: 'Persistence (T1136.003 - Cloud Account)',
  },
  {
    id: 'rule_auth_failures',
    name: 'Authentication Failure / Password Spray',
    enabled: true,
    severity: 'MEDIUM',
    match: { operation: 'userloginfailed', resultStatus: 'Failed' },
    threatCategory: 'Authentication Failure',
    threatDescription: 'Failed logon attempt recorded. Clustered failures indicate brute force or spray attacks.',
    mitreTactic: 'Credential Access (T1110 - Brute Force)',
  },
];

export const DEFAULT_TARGET_SCOPE: AuditTargetScope = {
  targetUsers: '',
  excludeServiceAccounts: false,
  targetIps: '',
  onlyExternalIps: false,
  targetOperations: '',
  targetWorkload: 'ALL',
  targetSeverity: 'ALL',
  timeRangeStart: '',
  timeRangeEnd: '',
  resultStatus: 'ALL',
  matchedRuleOnly: 'ALL',
};

export const DEFAULT_REPORT_OPTIONS: PurviewReportOptions = {
  caseTitle: 'Microsoft Purview & Defender Audit Report',
  organization: '',
  investigator: '',
  classification: 'RESTRICTED',
  analystNotes: '',
  minSeverity: 'ALL',
  includeExecutiveSummary: true,
  includeScopeSection: true,
  includeCustomRulesSummary: true,
  includeFindingsTable: true,
  includeThreatNarratives: true,
  includeSessionHijacking: true,
  includeRemediationPlaybook: true,
};

export function isPrivateOrInternalIp(ip: string): boolean {
  if (!ip || ip === 'N/A' || ip === '127.0.0.1' || ip === '::1' || ip.toLowerCase().startsWith('localhost') || ip.toLowerCase() === 'unknown') return true;
  // Purview can log IPv4 as IPv4-mapped IPv6 (::ffff:10.0.0.5) or with a port (10.0.0.5:51234)
  const v = ip.trim().toLowerCase().replace(/^\[|\](:\d+)?$/g, '').replace(/^::ffff:/, '');
  const v4 = v.replace(/:\d+$/, '');
  if (/^(10|127)\./.test(v4) || v4.startsWith('192.168.') || v4.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(v4)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(v4)) return true; // CGNAT 100.64.0.0/10
  if (v.includes(':') && (/^f[cd][0-9a-f]{0,2}:/.test(v) || /^fe[89ab][0-9a-f]?:/.test(v))) return true; // fc00::/7, fe80::/10
  return false;
}

export function isServiceAccount(userId: string): boolean {
  if (!userId) return false;
  const u = userId.toLowerCase();
  return (
    u.startsWith('sync_') ||
    u.startsWith('msol_') ||
    u.includes('app@sharepoint') ||
    u.includes('svc-') ||
    u.includes('service-') ||
    u.includes('aad-service-account') ||
    u.endsWith('@onmicrosoft.com/sync') ||
    u.includes('spn:') ||
    // The Windows SYSTEM principal only (e.g. "NT AUTHORITY\SYSTEM (Microsoft.Exchange.ServiceHost)").
    // A plain substring match exempted real users such as it.systems@contoso.com from detections.
    u === 'system' ||
    u.startsWith('nt authority\\system')
  );
}

export function matchesPattern(value: string, pattern: string): boolean {
  if (!pattern || !pattern.trim()) return true;
  if (!value) return false;
  const p = pattern.trim();
  const v = value.trim();

  // Try regex if contains special characters or pipe
  if (p.includes('|') || p.includes('^') || p.includes('$')) {
    try {
      const re = new RegExp(p, 'i');
      return re.test(v);
    } catch {
      // fallback to substring
    }
  }

  // Wildcard match (e.g. *delete* or admin*)
  if (p.includes('*')) {
    const regexPattern = '^' + p.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
    try {
      const re = new RegExp(regexPattern, 'i');
      return re.test(v);
    } catch {
      // fallback
    }
  }

  return v.toLowerCase().includes(p.toLowerCase());
}

export function applyTargetScope(
  records: ParsedAuditRecord[],
  scope: AuditTargetScope
): ParsedAuditRecord[] {
  return records.filter(r => {
    // 1. Exclude Service Accounts
    if (scope.excludeServiceAccounts && isServiceAccount(r.userId)) {
      return false;
    }

    // 2. Target Users
    if (scope.targetUsers && scope.targetUsers.trim()) {
      const users = scope.targetUsers.split(/[\s,]+/).map(u => u.trim().toLowerCase()).filter(Boolean);
      if (users.length > 0) {
        const userMatched = users.some(u => {
          if (u.includes('*')) return matchesPattern(r.userId, u);
          return r.userId.toLowerCase().includes(u);
        });
        if (!userMatched) return false;
      }
    }

    // 3. Only External IPs
    if (scope.onlyExternalIps && isPrivateOrInternalIp(r.clientIp)) {
      return false;
    }

    // 4. Target IPs
    if (scope.targetIps && scope.targetIps.trim()) {
      const ips = scope.targetIps.split(/[\s,]+/).map(ip => ip.trim()).filter(Boolean);
      if (ips.length > 0) {
        const ipMatched = ips.some(ip => {
          if (ip.includes('*')) return matchesPattern(r.clientIp, ip);
          return r.clientIp.startsWith(ip) || r.clientIp.includes(ip);
        });
        if (!ipMatched) return false;
      }
    }

    // 5. Target Operations
    if (scope.targetOperations && scope.targetOperations.trim()) {
      const ops = scope.targetOperations.split(/[\s,]+/).map(op => op.trim()).filter(Boolean);
      if (ops.length > 0) {
        const opMatched = ops.some(op => matchesPattern(r.operation, op));
        if (!opMatched) return false;
      }
    }

    // 6. Target Workload
    if (scope.targetWorkload && scope.targetWorkload !== 'ALL') {
      if (r.workload.toLowerCase() !== scope.targetWorkload.toLowerCase()) return false;
    }

    // 7. Target Severity
    if (scope.targetSeverity && scope.targetSeverity !== 'ALL') {
      if (r.severity !== scope.targetSeverity) return false;
    }

    // 8. Result Status
    if (scope.resultStatus && scope.resultStatus !== 'ALL') {
      if (r.resultStatus.toLowerCase() !== scope.resultStatus.toLowerCase()) return false;
    }

    // 9. Time Range Start / End
    if (scope.timeRangeStart && scope.timeRangeStart.trim()) {
      const startTime = new Date(scope.timeRangeStart).getTime();
      const recordTime = new Date(r.creationTime).getTime();
      if (!isNaN(startTime) && !isNaN(recordTime) && recordTime < startTime) return false;
    }
    if (scope.timeRangeEnd && scope.timeRangeEnd.trim()) {
      const endTime = new Date(scope.timeRangeEnd).getTime();
      const recordTime = new Date(r.creationTime).getTime();
      if (!isNaN(endTime) && !isNaN(recordTime) && recordTime > endTime) return false;
    }

    // 10. Matched Rule Filter
    if (scope.matchedRuleOnly && scope.matchedRuleOnly !== 'ALL') {
      if (r.matchedRuleId !== scope.matchedRuleOnly) return false;
    }

    return true;
  });
}

export interface ThreatGroups {
  accountDeletions: ParsedAuditRecord[];
  accountRenamings: ParsedAuditRecord[];
  privilegeEscalations: ParsedAuditRecord[];
  emailForwardings: ParsedAuditRecord[];
  oauthConsents: ParsedAuditRecord[];
  massDownloads: ParsedAuditRecord[];
  failedLogins: ParsedAuditRecord[];
  sessionHijackings: ParsedAuditRecord[];
}

export interface AuditAnalysisSummary {
  totalRecords: number;
  timeRange: { start: string; end: string };
  uniqueUsers: string[];
  uniqueIps: string[];
  uniqueWorkloads: string[];
  threatsDetected: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  threatGroups: ThreatGroups;
  highRiskEvents: ParsedAuditRecord[];
  topActors: { user: string; count: number }[];
  topOperations: { operation: string; count: number }[];
  matchedCustomRules?: { ruleId: string; ruleName: string; count: number }[];
}

// 1. High-Performance Chunked / Safe Parsing Functions
export const DEFAULT_MAX_RECORDS = 100000;

export function parsePurviewLogs(
  rawInput: string,
  customRules?: CustomAuditRule[],
  maxRecords: number = DEFAULT_MAX_RECORDS
): { records: ParsedAuditRecord[]; truncated: boolean } {
  const trimmed = rawInput.trim();
  if (!trimmed) return { records: [], truncated: false };

  let parsed: { records: ParsedAuditRecord[]; truncated: boolean };
  // Try JSON parsing first
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    parsed = parseJsonAuditLogs(trimmed, customRules, maxRecords);
  } else {
    // Otherwise CSV parsing
    parsed = parseCsvAuditLogs(trimmed, customRules, maxRecords);
  }

  // Cross-log correlation pass: Detect Session ID Hijacking & Token Replay Injection
  const correlatedRecords = correlateSessionHijacking(parsed.records);

  return {
    records: correlatedRecords,
    truncated: parsed.truncated,
  };
}

function parseJsonAuditLogs(
  rawJson: string,
  customRules?: CustomAuditRule[],
  maxRecords: number = DEFAULT_MAX_RECORDS
): { records: ParsedAuditRecord[]; truncated: boolean } {
  try {
    let items: any[] = [];
    let truncated = false;

    if (rawJson.startsWith('[')) {
      let parsedArray: any;
      try {
        parsedArray = JSON.parse(rawJson);
      } catch (err: any) {
        throw new Error('Invalid JSON array in audit logs: ' + (err.message || 'Syntax error'));
      }

      if (Array.isArray(parsedArray)) {
        if (parsedArray.length > maxRecords) {
          items = parsedArray.slice(0, maxRecords);
          truncated = true;
        } else {
          items = parsedArray;
        }
      } else {
        items = [parsedArray];
      }
    } else {
      // Single JSON object or Newline-Delimited JSON (NDJSON)
      // High-performance NDJSON scanner: find newlines without split('\n') which duplicates strings in memory
      let searchPos = 0;
      const len = rawJson.length;

      while (searchPos < len && items.length < maxRecords) {
        let nextNewline = rawJson.indexOf('\n', searchPos);
        if (nextNewline === -1) nextNewline = len;

        const line = rawJson.substring(searchPos, nextNewline).trim();
        searchPos = nextNewline + 1;

        if (line.startsWith('{')) {
          try {
            items.push(JSON.parse(line));
          } catch {
            // Ignore malformed individual lines in NDJSON streams
          }
        }
      }

      if (searchPos < len || items.length >= maxRecords) {
        if (searchPos < len && rawJson.indexOf('{', searchPos) !== -1) {
          truncated = true;
        }
      }

      if (items.length === 0 && rawJson.startsWith('{')) {
        try {
          items = [JSON.parse(rawJson)];
        } catch {
          // Fall through
        }
      }
    }

    const records = items.map((item, idx) => normalizeAuditRecord(item, idx, customRules));
    return { records, truncated };
  } catch (e: any) {
    console.error('Failed to parse JSON audit log', e);
    throw new Error(e.message || 'Invalid JSON format in audit logs. Please check your JSON syntax or use CSV export.');
  }
}

function parseCsvAuditLogs(
  rawCsv: string,
  customRules?: CustomAuditRule[],
  maxRecords: number = DEFAULT_MAX_RECORDS
): { records: ParsedAuditRecord[]; truncated: boolean } {
  let pos = 0;
  const len = rawCsv.length;

  // 1. Scan for the first real CSV header line (skipping leading blank lines and comments starting with // or #)
  let headerLine = '';
  let lineStart = 0;
  let inQuotes = false;

  for (let i = 0; i < len; i++) {
    const c = rawCsv.charCodeAt(i);
    if (c === 34) {
      // '"'
      inQuotes = !inQuotes;
    } else if ((c === 10 || c === 13) && !inQuotes) {
      // \n or \r
      const lineStr = rawCsv.substring(lineStart, i).trim();
      if (c === 13 && i + 1 < len && rawCsv.charCodeAt(i + 1) === 10) {
        i++;
      }
      lineStart = i + 1;

      if (lineStr.length > 0 && !lineStr.startsWith('//') && !lineStr.startsWith('#')) {
        headerLine = lineStr;
        pos = lineStart;
        break;
      }
    }
  }

  // Handle single-line CSV without trailing newline
  if (!headerLine && lineStart < len) {
    const lineStr = rawCsv.substring(lineStart).trim();
    if (lineStr.length > 0 && !lineStr.startsWith('//') && !lineStr.startsWith('#')) {
      headerLine = lineStr;
      pos = len;
    }
  }

  if (!headerLine) {
    return { records: [], truncated: false };
  }

  const headers = parseCsvRow(headerLine).map(h => h.trim().toLowerCase().replace(/\s*\[utc\]$/, ''));
  if (headers.length === 0) return { records: [], truncated: false };

  const records: ParsedAuditRecord[] = [];
  let truncated = false;
  let rowCount = 0;

  // 2. Scan rows up to maxRecords and halt immediately
  let rowStart = pos;
  inQuotes = false;

  for (let i = pos; i < len; i++) {
    const c = rawCsv.charCodeAt(i);
    if (c === 34) {
      inQuotes = !inQuotes;
    } else if ((c === 10 || c === 13) && !inQuotes) {
      const rowStr = rawCsv.substring(rowStart, i).trim();
      if (c === 13 && i + 1 < len && rawCsv.charCodeAt(i + 1) === 10) {
        i++;
      }
      rowStart = i + 1;

      if (rowStr.length > 0) {
        // Skip comment lines in data
        if (rowStr.startsWith('//') || rowStr.startsWith('#')) {
          continue;
        }

        rowCount++;
        if (records.length < maxRecords) {
          const rowFields = parseCsvRow(rowStr);
          if (rowFields.length > 0) {
            const rowObj: Record<string, any> = {};
            const limit = Math.min(headers.length, rowFields.length);
            for (let j = 0; j < limit; j++) {
              rowObj[headers[j]] = rowFields[j];
            }
            records.push(normalizeAuditRecord(rowObj, rowCount, customRules));
          }
        } else {
          // Reached maxRecords! Halt immediately to prevent memory exhaustion
          truncated = true;
          break;
        }
      }
    }
  }

  // Check trailing row if file doesn't end with newline
  if (!truncated && rowStart < len && records.length < maxRecords) {
    const rowStr = rawCsv.substring(rowStart).trim();
    if (rowStr.length > 0) {
      rowCount++;
      const rowFields = parseCsvRow(rowStr);
      if (rowFields.length > 0) {
        const rowObj: Record<string, any> = {};
        const limit = Math.min(headers.length, rowFields.length);
        for (let j = 0; j < limit; j++) {
          rowObj[headers[j]] = rowFields[j];
        }
        records.push(normalizeAuditRecord(rowObj, rowCount, customRules));
      }
    }
  } else if (rowStart < len) {
    truncated = true;
  }

  return { records, truncated };
}

// Fast zero-allocation CSV row parser using substring slices instead of character concatenation
function parseCsvRow(rowStr: string): string[] {
  const result: string[] = [];
  const len = rowStr.length;
  let fieldStart = 0;
  let inQuotes = false;
  let hasEscapedQuotes = false;

  for (let i = 0; i < len; i++) {
    const c = rowStr.charCodeAt(i);
    if (c === 34) {
      // '"'
      if (inQuotes && i + 1 < len && rowStr.charCodeAt(i + 1) === 34) {
        hasEscapedQuotes = true;
        i++; // skip escaped quote ""
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c === 44 && !inQuotes) {
      // ','
      let field = rowStr.substring(fieldStart, i).trim();
      if (field.charCodeAt(0) === 34 && field.charCodeAt(field.length - 1) === 34 && field.length >= 2) {
        field = field.substring(1, field.length - 1);
      }
      if (hasEscapedQuotes) {
        field = field.replace(/""/g, '"');
        hasEscapedQuotes = false;
      }
      result.push(field);
      fieldStart = i + 1;
    }
  }

  let field = rowStr.substring(fieldStart).trim();
  if (field.charCodeAt(0) === 34 && field.charCodeAt(field.length - 1) === 34 && field.length >= 2) {
    field = field.substring(1, field.length - 1);
  }
  if (hasEscapedQuotes) {
    field = field.replace(/""/g, '"');
  }
  result.push(field);

  return result;
}

// Normalize record properties and extract nested AuditData
function normalizeAuditRecord(raw: any, index: number, customRules?: CustomAuditRule[]): ParsedAuditRecord {
  let auditData: any = {};

  // Extract nested AuditData JSON string if present (M365 UAL export).
  // Defender Advanced Hunting (CloudAppEvents) carries the same UAL record as RawEventData.
  const auditDataStr = raw.AuditData || raw.auditdata || raw.RawEventData || raw.raweventdata;
  if (auditDataStr) {
    if (typeof auditDataStr === 'string') {
      try {
        auditData = JSON.parse(auditDataStr);
      } catch {
        auditData = { rawString: auditDataStr };
      }
    } else if (typeof auditDataStr === 'object') {
      auditData = auditDataStr;
    }
  }

  const creationTime = normalizeTimestamp(
    auditData.CreationTime ||
    raw.CreationDate ||
    raw.creationdate ||
    raw.CreationTime ||
    raw.creationtime ||
    raw.Timestamp ||
    raw.timestamp
  );

  const userId =
    auditData.UserId ||
    raw.UserIds ||
    raw.userids ||
    raw.UserId ||
    raw.userid ||
    raw.Actor ||
    auditData.Actor ||
    raw.AccountUpn ||
    raw.accountupn ||
    raw.AccountDisplayName ||
    raw.accountdisplayname ||
    raw.AccountObjectId ||
    raw.accountobjectid ||
    'Unknown User';

  const operation =
    auditData.Operation ||
    raw.Operations ||
    raw.operations ||
    raw.Operation ||
    raw.operation ||
    raw.Action ||
    raw.ActionType ||
    raw.actiontype ||
    'Unknown Operation';

  const workload =
    auditData.Workload ||
    raw.Workload ||
    raw.workload ||
    auditData.RecordType ||
    raw.Application ||
    raw.application ||
    'Microsoft 365';

  const clientIp = extractClientIp(auditData, raw);

  // Extract Session ID & User Agent for Session Hijacking / Token Replay Detection
  const sessionId = extractSessionId(auditData, raw);
  const userAgent = extractUserAgent(auditData, raw);

  const resultStatus = determineResultStatus(
    auditData.ResultStatus || raw.ResultStatus || raw.resultstatus || raw.Status || raw.status,
    operation
  );

  // Extract Modified Properties
  const modifiedProperties = extractModifiedProperties(auditData, raw);

  // Extract Target Object / User
  const target = extractTarget(auditData, raw, modifiedProperties);

  // Evaluate Forensic Threat Heuristics (custom rules prioritized)
  const threatInfo = evaluateThreatHeuristics(
    operation,
    workload,
    userId,
    target,
    modifiedProperties,
    auditData,
    resultStatus,
    clientIp,
    customRules
  );

  return {
    id: `audit_rec_${Date.now()}_${index}`,
    creationTime,
    userId,
    operation,
    workload,
    clientIp,
    sessionId: sessionId || undefined,
    userAgent: userAgent || undefined,
    resultStatus,
    target,
    severity: threatInfo.severity,
    threatCategory: threatInfo.threatCategory,
    threatDescription: threatInfo.threatDescription,
    mitreTactic: threatInfo.mitreTactic,
    matchedRuleId: threatInfo.matchedRuleId,
    matchedRuleName: threatInfo.matchedRuleName,
    modifiedProperties,
    rawDetails: (() => {
      const leanRaw: Record<string, any> = {};
      const hasParsed = Object.keys(auditData).length > 0;
      for (const k in raw) {
        if (hasParsed && (k === 'AuditData' || k === 'auditdata') && typeof raw[k] === 'string') {
          continue; // Avoid duplicating large unparsed string
        }
        leanRaw[k] = raw[k];
      }
      if (hasParsed) {
        leanRaw.parsedAuditData = auditData;
      }
      return leanRaw;
    })(),
  };
}

// UAL CreationTime is UTC but has no zone suffix, so the browser would read it as local time.
// Records with no timestamp stay empty rather than getting the time of the analysis.
function normalizeTimestamp(value: unknown): string {
  if (value === undefined || value === null || value === '') return '';
  const str = String(value).trim();
  const msDate = str.match(/^\/Date\((-?\d+)\)\/$/); // PowerShell ConvertTo-Json
  if (msDate) return new Date(Number(msDate[1])).toISOString();
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(str)) return str.replace(' ', 'T') + 'Z';
  return str;
}

// Many records (and Defender ActionTypes such as LogonFailed) carry no status field,
// so only the operation name can say it failed; otherwise the outcome is unknown.
function determineResultStatus(statusStr: string | undefined, operation: string): ParsedAuditRecord['resultStatus'] {
  if (!statusStr) return /fail/i.test(operation) ? 'Failed' : 'Unknown';
  const s = String(statusStr).toLowerCase();
  if (s.includes('fail') || s === '0' || s.includes('denied') || s.includes('error')) return 'Failed';
  if (s.includes('block')) return 'Blocked';
  if (s.includes('partial')) return 'PartiallySucceeded';
  if (s.includes('success') || s === '1' || s.includes('true') || s.includes('succeeded')) return 'Succeeded';
  return 'Unknown';
}

function extractModifiedProperties(auditData: any, raw: any): { name: string; oldValue?: string; newValue?: string }[] {
  const result: { name: string; oldValue?: string; newValue?: string }[] = [];

  const modProps = auditData.ModifiedProperties || raw.ModifiedProperties || raw.modifiedproperties;
  if (Array.isArray(modProps)) {
    modProps.forEach((p: any) => {
      result.push({
        name: p.Name || p.PropertyName || p.name || 'Property',
        oldValue: p.OldValue !== undefined ? String(p.OldValue) : undefined,
        newValue: p.NewValue !== undefined ? String(p.NewValue) : undefined,
      });
    });
  }

  // Parameters (Exchange admin actions)
  const params = auditData.Parameters || raw.Parameters;
  if (Array.isArray(params)) {
    params.forEach((p: any) => {
      result.push({
        name: p.Name || p.name || 'Param',
        newValue: p.Value !== undefined ? String(p.Value) : undefined,
      });
    });
  }

  return result;
}

function extractTarget(auditData: any, raw: any, modifiedProperties: any[]): string {
  if (auditData.Target && typeof auditData.Target === 'string') return auditData.Target;
  if (auditData.ObjectId) return auditData.ObjectId;
  if (auditData.TargetUserOrGroupName) return auditData.TargetUserOrGroupName;
  if (raw.ObjectId || raw.objectid) return raw.ObjectId || raw.objectid;
  if (raw.ItemName || raw.itemname) return raw.ItemName || raw.itemname;
  if (raw.Target || raw.target) return raw.Target || raw.target;
  if (raw.ObjectName || raw.objectname) return raw.ObjectName || raw.objectname;

  // Look for target in modified properties (e.g. UserPrincipalName, DisplayName)
  const upnProp = modifiedProperties.find(p => p.name.toLowerCase().includes('userprincipalname') || p.name.toLowerCase().includes('displayname'));
  if (upnProp) {
    return upnProp.oldValue ? `${upnProp.oldValue} ➔ ${upnProp.newValue}` : upnProp.newValue || 'N/A';
  }

  return 'N/A';
}

function extractSessionId(auditData: any, raw: any): string {
  if (auditData.SessionId) return String(auditData.SessionId);
  if (auditData.SessionID) return String(auditData.SessionID);
  if (auditData.sessionId) return String(auditData.sessionId);
  if (auditData.AADSessionId) return String(auditData.AADSessionId);
  if (auditData.LogonId) return String(auditData.LogonId);
  if (auditData.UniqueTokenIdentifier) return String(auditData.UniqueTokenIdentifier);

  if (auditData.AppAccessContext) {
    const ctx = auditData.AppAccessContext;
    if (ctx.AADSessionId) return String(ctx.AADSessionId);
    if (ctx.SessionId) return String(ctx.SessionId);
    if (ctx.UniqueTokenIdentifier) return String(ctx.UniqueTokenIdentifier);
  }

  const extProps = auditData.ExtendedProperties || raw.ExtendedProperties;
  if (Array.isArray(extProps)) {
    const found = extProps.find((p: any) => {
      const name = String(p?.Name || p?.name || '').toLowerCase();
      return name === 'sessionid' || name === 'aadsessionid' || name === 'uniquetokenidentifier';
    });
    if (found && (found.Value || found.value)) return String(found.Value || found.value);
  }

  if (raw.SessionId) return String(raw.SessionId);
  if (raw.SessionID) return String(raw.SessionID);
  if (raw.sessionid) return String(raw.sessionid);
  if (raw['session id'] || raw['Session ID']) return String(raw['session id'] || raw['Session ID']);

  return '';
}

function extractUserAgent(auditData: any, raw: any): string {
  if (auditData.UserAgent) return String(auditData.UserAgent);
  if (auditData.userAgent) return String(auditData.userAgent);
  if (auditData.ClientInfoString) return String(auditData.ClientInfoString);
  if (auditData.AppAccessContext?.UserAgent) return String(auditData.AppAccessContext.UserAgent);
  if (auditData.AppAccessContext?.ClientAppName) return String(auditData.AppAccessContext.ClientAppName);

  const extProps = auditData.ExtendedProperties || raw.ExtendedProperties;
  if (Array.isArray(extProps)) {
    const found = extProps.find((p: any) => {
      const name = String(p?.Name || p?.name || '').toLowerCase();
      return name === 'useragent' || name === 'clientinfostring';
    });
    if (found && (found.Value || found.value)) return String(found.Value || found.value);
  }

  if (raw.UserAgent || raw.useragent || raw['User Agent'] || raw['user agent']) {
    return String(raw.UserAgent || raw.useragent || raw['User Agent'] || raw['user agent']);
  }

  return '';
}

function extractClientIp(auditData: any, raw: any): string {
  let ip: any =
    auditData.ClientIP ||
    auditData.ClientIpAddress ||
    auditData.ClientIPAddress ||
    auditData.IPAddress ||
    auditData.ipAddress ||
    auditData.ActorIpAddress ||
    auditData.AppAccessContext?.ClientIP ||
    auditData.AppAccessContext?.ClientIPAddress ||
    auditData.NetworkInfo?.ClientIP ||
    raw.ClientIP ||
    raw.clientip ||
    raw['Client IP'] ||
    raw['client ip'] ||
    raw.Client_IP ||
    raw.client_ip ||
    raw.ClientIpAddress ||
    raw.clientipaddress ||
    raw.IPAddress ||
    raw.ipaddress ||
    raw['IP Address'] ||
    raw['ip address'] ||
    '';

  if (!ip && auditData.ExtendedProperties && Array.isArray(auditData.ExtendedProperties)) {
    const found = auditData.ExtendedProperties.find((p: any) => {
      const name = String(p?.Name || p?.name || '').toLowerCase();
      return name === 'clientip' || name === 'clientipaddress' || name === 'requestip' || name === 'client_ip';
    });
    if (found && (found.Value || found.value)) {
      ip = found.Value || found.value;
    }
  }

  if (ip && typeof ip === 'string') {
    ip = ip.trim();
    // Strip port if present on IPv4 e.g. 1.2.3.4:54321
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(ip)) {
      ip = ip.split(':')[0];
    }
    const lower = ip.toLowerCase();
    if (ip && lower !== 'n/a' && lower !== 'unknown' && lower !== 'null' && lower !== 'undefined' && ip !== '-') {
      return ip;
    }
  }

  return 'N/A';
}

// 2. Forensic Threat Evaluation Rules
function evaluateThreatHeuristics(
  operation: string,
  workload: string,
  actor: string,
  target: string,
  modifiedProps: any[],
  auditData: any,
  resultStatus: string,
  clientIp?: string,
  customRules?: CustomAuditRule[]
): {
  severity: ParsedAuditRecord['severity'];
  threatCategory?: string;
  threatDescription?: string;
  mitreTactic?: string;
  matchedRuleId?: string;
  matchedRuleName?: string;
} {
  const op = operation.toLowerCase();

  // Evaluate Custom Rules First (User-Defined Specifications)
  if (customRules && customRules.length > 0) {
    for (const rule of customRules) {
      if (!rule.enabled) continue;
      const m = rule.match;
      let matched = true;
      let hasCriteria = false;

      if (m.operation) {
        hasCriteria = true;
        if (!operation || !matchesPattern(operation, m.operation)) matched = false;
      }
      if (matched && m.actor) {
        hasCriteria = true;
        if (!actor || !matchesPattern(actor, m.actor)) matched = false;
      }
      if (matched && m.clientIp) {
        hasCriteria = true;
        if (!clientIp || clientIp === 'N/A' || clientIp.toLowerCase() === 'unknown' || !matchesPattern(clientIp, m.clientIp)) {
          matched = false;
        }
      }
      if (matched && m.workload) {
        hasCriteria = true;
        if (!workload || !matchesPattern(workload, m.workload)) matched = false;
      }
      if (matched && m.target) {
        hasCriteria = true;
        if (!target || !matchesPattern(target, m.target)) matched = false;
      }
      if (matched && m.resultStatus && m.resultStatus !== 'ALL') {
        hasCriteria = true;
        if (!resultStatus || m.resultStatus.toLowerCase() !== resultStatus.toLowerCase()) matched = false;
      }

      if (matched && hasCriteria) {
        return {
          severity: rule.severity,
          threatCategory: rule.threatCategory || rule.name,
          threatDescription: rule.threatDescription || `Matched custom detection rule '${rule.name}' for operation '${operation}' by '${actor}'.`,
          mitreTactic: rule.mitreTactic,
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
        };
      }
    }
  }

  // Rule 1: Account Deletion (Global Admin / User Access Removal)
  if (op.includes('delete user') || op.includes('hard delete user') || op.includes('remove-user') || op === 'delete user.') {
    return {
      severity: 'CRITICAL',
      threatCategory: 'Account Deletion / Destruction',
      threatDescription: `User account deleted by actor '${actor}'. Target: ${target}. Immediate verification required to confirm authorized deprovisioning vs unauthorized account destruction.`,
      mitreTactic: 'Impact (T1531 - Account Access Removal)',
    };
  }

  // Rule 2: Account Renaming & Identity Modification
  if (op.includes('update user') || op.includes('set-user') || op.includes('set-mailbox')) {
    const upnChange = modifiedProps.find(p => p.name.toLowerCase().includes('userprincipalname'));
    const pwdChange = modifiedProps.find(p => p.name.toLowerCase().includes('password') || p.name.toLowerCase().includes('accountenabled'));

    // Check if UPN was genuinely changed to a different value and not done by automated sync
    const isTrueUpnRename =
      upnChange &&
      upnChange.oldValue &&
      upnChange.newValue &&
      upnChange.oldValue.trim().toLowerCase() !== upnChange.newValue.trim().toLowerCase() &&
      !isServiceAccount(actor);

    if (isTrueUpnRename) {
      return {
        severity: 'HIGH',
        threatCategory: 'Account Renaming & Identity Tampering',
        threatDescription: `UserPrincipalName modified by '${actor}'. Old: '${upnChange.oldValue}' ➔ New: '${upnChange.newValue}'. Investigate for persistence or account takeover disguised as renaming.`,
        mitreTactic: 'Persistence / Defense Evasion (T1098 - Account Manipulation)',
      };
    }

    if (pwdChange && !isServiceAccount(actor)) {
      return {
        severity: 'HIGH',
        threatCategory: 'Account Credential / Status Modification',
        threatDescription: `User account state or password reset by '${actor}' for target ${target}.`,
        mitreTactic: 'Credential Access (T1098 - Account Manipulation)',
      };
    }

    // Routine attribute updates (DisplayName, Department, License assignment, DirSync)
    return {
      severity: 'INFO',
      threatCategory: 'Routine Directory Update',
      threatDescription: `Standard directory or user attribute update for ${target} by '${actor}'.`,
    };
  }

  // Rule 3: Privilege Escalation (Global Admin / Role Assignment)
  if (op.includes('roleassignmentadded') || op.includes('add member to role') || op.includes('add-rolegroupmember') || op.includes('elevateaccess')) {
    return {
      severity: 'CRITICAL',
      threatCategory: 'Privilege Escalation',
      threatDescription: `Privileged administrative role assigned by '${actor}' to target '${target}'. Verify if Global Admin or directory role promotion was authorized.`,
      mitreTactic: 'Privilege Escalation (T1078 - Valid Accounts)',
    };
  }

  // Rule 4: Email Forwarding & Inbox Rule Tampering (BEC)
  if (op.includes('new-inboxrule') || op.includes('set-inboxrule') || op.includes('enable-inboxrule') || op.includes('updateinboxrules')) {
    const forwardParam = modifiedProps.find(p => p.name.toLowerCase().includes('forward') || p.name.toLowerCase().includes('redirect'));
    return {
      severity: 'HIGH',
      threatCategory: 'Email Forwarding Rule (BEC Indicator)',
      threatDescription: `Mailbox forwarding rule created by '${actor}'. Potential Business Email Compromise (BEC) exfiltration or hiding alerts. Target: ${forwardParam ? forwardParam.newValue : target}`,
      mitreTactic: 'Collection / Exfiltration (T1114.003 - Email Forwarding Rule)',
    };
  }

  // Rule 5: OAuth App Consent & Service Principal Credentials
  if (op.includes('consenttoapplication') || op.includes('add service principal credentials') || op.includes('add-serviceprincipal') || op.includes('add app role assignment')) {
    return {
      severity: 'HIGH',
      threatCategory: 'Illicit OAuth Consent / Rogue App',
      threatDescription: `OAuth application consent or API credentials added by '${actor}'. Frequently used in OAuth phishing attacks for persistent API access.`,
      mitreTactic: 'Persistence / Credential Access (T1528 - Steal Application Access Token)',
    };
  }

  // Rule 6: Mass File Download / Exfiltration
  if (op.includes('sharinglinkcreated')) {
    return {
      severity: 'MEDIUM',
      threatCategory: 'External Sharing Link Created',
      threatDescription: `File sharing link created for '${target}' by '${actor}'. Review sharing permissions and external recipient scope.`,
      mitreTactic: 'Exfiltration (T1567 - Exfiltration Over Web Service)',
    };
  }

  if (op.includes('filedownloaded') || op.includes('filedownloadedextended')) {
    // Routine single file download is normal user activity in M365
    return {
      severity: 'INFO',
      threatCategory: 'Document Access / Download',
      threatDescription: `Standard file access or download: ${target} by '${actor}'.`,
    };
  }

  // Rule 7: Failed Authentication / Password Spray
  if (resultStatus === 'Failed' || resultStatus === 'Blocked' || op.includes('userloginfailed')) {
    return {
      severity: 'LOW',
      threatCategory: 'Authentication Failure',
      threatDescription: `Failed authentication attempt for '${actor}' from IP ${auditData.ClientIP || 'N/A'}.`,
      mitreTactic: 'Credential Access (T1110 - Brute Force)',
    };
  }

  // Default clean / info
  return {
    severity: 'INFO',
  };
}

// IPv6 clients rotate privacy addresses inside their /64, so session IPs are compared per /64.
function ipNetworkKey(ip: string): string {
  const lower = ip.toLowerCase();
  if (!lower.includes(':')) return lower;
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  const [head, tail] = lower.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];
  const groups = tail === undefined
    ? headGroups
    : [...headGroups, ...Array(Math.max(0, 8 - headGroups.length - tailGroups.length)).fill('0'), ...tailGroups];
  return groups.slice(0, 4).map(g => parseInt(g || '0', 16).toString(16)).join(':') + '::/64';
}

// 2.5 Multi-Log Session Correlation & Token Theft / Replay Detector
export function correlateSessionHijacking(records: ParsedAuditRecord[]): ParsedAuditRecord[] {
  // Map of sessionId -> session tracking metadata
  const sessionMap = new Map<string, {
    userId: string;
    ips: Set<string>;
    networks: Set<string>;
    userAgents: Set<string>;
    records: ParsedAuditRecord[];
    firstEventTime: number;
    lastEventTime: number;
    firstIp: string;
    firstIpTime: number;
  }>();

  records.forEach(r => {
    const sid = r.sessionId?.trim();
    if (!sid || sid.length < 5 || sid.toLowerCase() === 'n/a' || sid.toLowerCase() === 'undefined' || sid.toLowerCase() === 'null') {
      return;
    }

    const cleanIp = r.clientIp && r.clientIp !== 'N/A' && r.clientIp.toLowerCase() !== 'unknown' ? r.clientIp.trim() : '';
    const eventTime = new Date(r.creationTime).getTime(); // NaN when the record has no timestamp

    let entry = sessionMap.get(sid);
    if (!entry) {
      entry = {
        userId: r.userId,
        ips: new Set(),
        networks: new Set(),
        userAgents: new Set(),
        records: [],
        firstEventTime: NaN,
        lastEventTime: NaN,
        firstIp: '',
        firstIpTime: NaN,
      };
      sessionMap.set(sid, entry);
    }

    if (cleanIp) {
      entry.ips.add(cleanIp);
      entry.networks.add(ipNetworkKey(cleanIp));
    }
    if (r.userAgent) entry.userAgents.add(r.userAgent);
    entry.records.push(r);

    if (!isNaN(eventTime)) {
      if (isNaN(entry.firstEventTime) || eventTime < entry.firstEventTime) entry.firstEventTime = eventTime;
      if (isNaN(entry.lastEventTime) || eventTime > entry.lastEventTime) entry.lastEventTime = eventTime;
    }
    // Origin = earliest event that recorded an IP (first seen, if timestamps are missing)
    if (cleanIp && (!entry.firstIp || (!isNaN(eventTime) && (isNaN(entry.firstIpTime) || eventTime < entry.firstIpTime)))) {
      entry.firstIp = cleanIp;
      entry.firstIpTime = eventTime;
    }
  });

  // Evaluate Session ID Anomaly / Injection Heuristics
  sessionMap.forEach((session, sid) => {
    // Exclude automated sync / system service accounts
    if (isServiceAccount(session.userId)) {
      return;
    }

    const uniqueIps = Array.from(session.ips);
    const uniqueUserAgents = Array.from(session.userAgents);
    const durationDays = Math.max(0, Math.round((session.lastEventTime - session.firstEventTime) / (1000 * 60 * 60 * 24))) || 0;

    // Anomaly 1: Same Session ID replayed across 2 or more distinct networks (AiTM / Token Theft)
    if (session.networks.size >= 2) {
      // Check if all unique IPs are private or loopback (e.g. 10.x, 192.168.x). If so, it's internal office/VPN DHCP roaming
      const externalIps = uniqueIps.filter(ip => !isPrivateOrInternalIp(ip));
      if (externalIps.length < 2 && uniqueIps.every(ip => isPrivateOrInternalIp(ip))) {
        return;
      }

      const originIp = session.firstIp || uniqueIps[0] || 'Unknown Origin';
      const secondaryIps = uniqueIps.filter(ip => ip !== originIp);

      session.records.forEach(r => {
        const currentIp = r.clientIp && r.clientIp !== 'N/A' && r.clientIp.toLowerCase() !== 'unknown' ? r.clientIp.trim() : '';

        r.severity = 'CRITICAL';
        r.mitreTactic = 'Defense Evasion / Credential Access (T1550.004 / T1539)';

        if (currentIp && currentIp === originIp) {
          // 1. Event from the original victim origin IP
          r.threatCategory = '🚨 Stolen Session Source (Victim Origin)';
          r.threatDescription = `VICTIM SESSION ACTIVITY: Session ID "${sid}" belonging to "${session.userId}" was originally established from origin IP "${originIp}". However, this session token was subsequently observed active from secondary IP(s): [${secondaryIps.join(', ')}]. Session active across ${uniqueIps.length} distinct IPs spanning ${durationDays > 0 ? durationDays + ' days' : 'multiple sessions'}. Verify if user was traveling/hotspotting or if session was compromised via AiTM.`;
        } else if (currentIp && currentIp !== originIp) {
          // 2. Event from a confirmed secondary attacker IP
          r.threatCategory = '🚨 Stolen Session Injection (Attacker IP)';
          r.threatDescription = `POTENTIAL TOKEN INJECTION: Session ID "${sid}" was observed active from secondary IP "${currentIp}", while originally established from origin IP "${originIp}". Active across ${uniqueIps.length} distinct IPs (${uniqueIps.join(', ')}). Correlate with travel schedule or investigate potential AiTM token replay.`;
        } else {
          // 3. Event where client IP is 'N/A' or omitted in the audit log (e.g. backend cloud processing or internal sync)
          r.threatCategory = '🚨 Multi-IP Session Activity';
          r.threatDescription = `MULTI-IP SESSION ACTIVITY: This action occurred within Session ID "${sid}" (origin IP "${originIp}"). While this specific event did not record an external client IP (internal backend cloud action), the session was observed active from secondary IP(s): [${secondaryIps.join(', ')}].`;
        }
      });
    } else if (durationDays >= 7 && session.records.length >= 2) {
      // Anomaly 2: Extended Multi-Week/Month Session Reuse (Desktop Client / PRT)
      session.records.forEach(r => {
        if (r.severity === 'INFO' || r.severity === 'LOW' || !r.threatCategory) {
          r.severity = 'INFO';
          r.threatCategory = 'ℹ️ Long-Duration Session (PRT / Desktop Client)';
          r.mitreTactic = 'Persistence / Defense Evasion (T1550.004)';
          r.threatDescription = `Session ID "${sid}" has been active over a span of ${durationDays} days. This is normal for desktop M365 clients (Teams/Outlook) with Primary Refresh Tokens (PRT).`;
        }
      });
    }
  });

  return records;
}

// 3. Analytics Aggregation Function
export function summarizeAuditData(records: ParsedAuditRecord[]): AuditAnalysisSummary {
  if (records.length === 0) {
    return {
      totalRecords: 0,
      timeRange: { start: 'N/A', end: 'N/A' },
      uniqueUsers: [],
      uniqueIps: [],
      uniqueWorkloads: [],
      threatsDetected: { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 },
      threatGroups: {
        accountDeletions: [],
        accountRenamings: [],
        privilegeEscalations: [],
        emailForwardings: [],
        oauthConsents: [],
        massDownloads: [],
        failedLogins: [],
        sessionHijackings: [],
      },
      highRiskEvents: [],
      topActors: [],
      topOperations: [],
      matchedCustomRules: [],
    };
  }

  const userMap: Record<string, number> = {};
  const ipSet = new Set<string>();
  const workloadSet = new Set<string>();
  const opMap: Record<string, number> = {};
  const ruleCountMap: Record<string, { ruleName: string; count: number }> = {};

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  const highRiskEvents: ParsedAuditRecord[] = [];

  const threatGroups: ThreatGroups = {
    accountDeletions: [],
    accountRenamings: [],
    privilegeEscalations: [],
    emailForwardings: [],
    oauthConsents: [],
    massDownloads: [],
    failedLogins: [],
    sessionHijackings: [],
  };

  records.forEach(r => {
    userMap[r.userId] = (userMap[r.userId] || 0) + 1;
    if (r.clientIp && r.clientIp !== 'N/A') ipSet.add(r.clientIp);
    if (r.workload) workloadSet.add(r.workload);
    opMap[r.operation] = (opMap[r.operation] || 0) + 1;

    // Track matched custom rules
    if (r.matchedRuleId && r.matchedRuleName) {
      if (!ruleCountMap[r.matchedRuleId]) {
        ruleCountMap[r.matchedRuleId] = { ruleName: r.matchedRuleName, count: 0 };
      }
      ruleCountMap[r.matchedRuleId].count++;
    }

    // Severity counts
    if (r.severity === 'CRITICAL') {
      criticalCount++;
      highRiskEvents.push(r);
    } else if (r.severity === 'HIGH') {
      highCount++;
      highRiskEvents.push(r);
    } else if (r.severity === 'MEDIUM') {
      mediumCount++;
    } else if (r.severity === 'LOW') {
      lowCount++;
    }

    // Categorized threat groups
    const cat = r.threatCategory || '';
    if (cat.includes('Account Deletion')) threatGroups.accountDeletions.push(r);
    else if (cat.includes('Account Renaming') || cat.includes('Credential / Status')) threatGroups.accountRenamings.push(r);
    else if (cat.includes('Privilege Escalation')) threatGroups.privilegeEscalations.push(r);
    else if (cat.includes('Email Forwarding')) threatGroups.emailForwardings.push(r);
    else if (cat.includes('OAuth Consent')) threatGroups.oauthConsents.push(r);
    else if ((cat.includes('Data Access') || cat.includes('Sharing Link')) && r.severity !== 'INFO') threatGroups.massDownloads.push(r);
    else if (cat.includes('Authentication Failure')) threatGroups.failedLogins.push(r);
    
    // Stolen Session & Token Injection (only actual critical alerts)
    if ((cat.includes('Stolen Session') || cat.includes('Token Injection') || cat.includes('Token Theft') || cat.includes('Multi-IP Session')) && r.severity === 'CRITICAL') {
      threatGroups.sessionHijackings.push(r);
    }
  });

  const sortedTimestamps = records
    .map(r => new Date(r.creationTime).getTime())
    .filter(t => !isNaN(t))
    .sort((a, b) => a - b);

  const start = sortedTimestamps.length > 0 ? new Date(sortedTimestamps[0]).toISOString() : 'N/A';
  const end = sortedTimestamps.length > 0 ? new Date(sortedTimestamps[sortedTimestamps.length - 1]).toISOString() : 'N/A';

  const topActors = Object.entries(userMap)
    .map(([user, count]) => ({ user, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const topOperations = Object.entries(opMap)
    .map(([operation, count]) => ({ operation, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const matchedCustomRules = Object.entries(ruleCountMap).map(([ruleId, data]) => ({
    ruleId,
    ruleName: data.ruleName,
    count: data.count,
  }));

  return {
    totalRecords: records.length,
    timeRange: { start, end },
    uniqueUsers: Object.keys(userMap),
    uniqueIps: Array.from(ipSet),
    uniqueWorkloads: Array.from(workloadSet),
    threatsDetected: { criticalCount, highCount, mediumCount, lowCount },
    threatGroups,
    highRiskEvents,
    topActors,
    topOperations,
    matchedCustomRules,
  };
}

// 4. Incident reports are built in purview-report.ts

// 5. Pre-Built Sample Scenarios
export const SAMPLE_SCENARIO_ACCOUNT_TAMPERING = JSON.stringify(
  [
    {
      CreationTime: '2026-09-02T09:15:22Z',
      UserId: 'globaladmin_compromised@contoso.com',
      Operation: 'UserLoggedIn',
      Workload: 'AzureActiveDirectory',
      ClientIP: '185.220.101.45',
      ResultStatus: 'Success',
      Actor: 'globaladmin_compromised@contoso.com',
    },
    {
      CreationTime: '2026-09-02T09:18:40Z',
      UserId: 'globaladmin_compromised@contoso.com',
      Operation: 'Update user.',
      Workload: 'AzureActiveDirectory',
      ClientIP: '185.220.101.45',
      ResultStatus: 'Success',
      Target: 'it_support@contoso.com ➔ shadow_svc@contoso.com',
      ModifiedProperties: [
        { Name: 'UserPrincipalName', OldValue: 'it_support@contoso.com', NewValue: 'shadow_svc@contoso.com' },
        { Name: 'DisplayName', OldValue: 'IT Support Service', NewValue: 'System Backup Account' },
      ],
    },
    {
      CreationTime: '2026-09-02T09:22:15Z',
      UserId: 'globaladmin_compromised@contoso.com',
      Operation: 'Delete user.',
      Workload: 'AzureActiveDirectory',
      ClientIP: '185.220.101.45',
      ResultStatus: 'Success',
      Target: 'cfo_executive@contoso.com',
      Actor: 'globaladmin_compromised@contoso.com',
    },
    {
      CreationTime: '2026-09-02T09:25:30Z',
      UserId: 'globaladmin_compromised@contoso.com',
      Operation: 'RoleAssignmentAdded',
      Workload: 'AzureActiveDirectory',
      ClientIP: '185.220.101.45',
      ResultStatus: 'Success',
      Target: 'shadow_svc@contoso.com (Assigned: Global Administrator)',
    },
    {
      CreationTime: '2026-09-02T09:30:10Z',
      UserId: 'shadow_svc@contoso.com',
      Operation: 'New-InboxRule',
      Workload: 'Exchange',
      ClientIP: '185.220.101.45',
      ResultStatus: 'Success',
      Target: 'finance_mailbox@contoso.com',
      ModifiedProperties: [
        { Name: 'ForwardTo', NewValue: 'exfiltrate@malicious-c2-server.top' },
        { Name: 'Name', NewValue: 'Invoice Archive' },
      ],
    },
  ],
  null,
  2
);

export const SAMPLE_SCENARIO_BEC_FORWARDING = `CreationDate,UserIds,Operations,Workload,ClientIP,ResultStatus,AuditData
"2026-09-02T10:12:00Z","executive_assistant@contoso.com","UserLoggedIn","AzureActiveDirectory","194.26.29.112","Success","{""UserId"":""executive_assistant@contoso.com"",""Operation"":""UserLoggedIn"",""ClientIP"":""194.26.29.112""}"
"2026-09-02T10:14:22Z","executive_assistant@contoso.com","MailItemsAccessed","Exchange","194.26.29.112","Success","{""UserId"":""executive_assistant@contoso.com"",""Operation"":""MailItemsAccessed"",""ItemCount"":142,""ClientIP"":""194.26.29.112""}"
"2026-09-02T10:18:05Z","executive_assistant@contoso.com","New-InboxRule","Exchange","194.26.29.112","Success","{""UserId"":""executive_assistant@contoso.com"",""Operation"":""New-InboxRule"",""Parameters"":[{""Name"":""ForwardTo"",""Value"":""dropzone@darkweb-stealth.xyz""},{""Name"":""DeleteMessage"",""Value"":""True""}],""ClientIP"":""194.26.29.112""}"
"2026-09-02T10:25:40Z","executive_assistant@contoso.com","ConsentToApplication","AzureActiveDirectory","194.26.29.112","Success","{""UserId"":""executive_assistant@contoso.com"",""Operation"":""ConsentToApplication"",""Target"":""Office365 Security Mail Sync App"",""ClientIP"":""194.26.29.112""}"
`;

// 2-Month Multi-IP Stolen Session ID & Token Injection Attack Scenario
export const SAMPLE_SCENARIO_SESSION_HIJACKING = JSON.stringify(
  [
    {
      CreationTime: '2026-07-02T08:14:10Z',
      UserId: 'cfo_finance@contoso.com',
      Operation: 'UserLoggedIn',
      Workload: 'AzureActiveDirectory',
      ClientIP: '105.22.14.88',
      SessionId: 'f8a31b29-4d9a-4c22-8f15-token1234567',
      UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0',
      ResultStatus: 'Success',
      Actor: 'cfo_finance@contoso.com',
    },
    {
      CreationTime: '2026-07-02T08:18:25Z',
      UserId: 'cfo_finance@contoso.com',
      Operation: 'MailItemsAccessed',
      Workload: 'Exchange',
      ClientIP: '105.22.14.88',
      SessionId: 'f8a31b29-4d9a-4c22-8f15-token1234567',
      UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0',
      ResultStatus: 'Success',
    },
    {
      CreationTime: '2026-07-19T14:40:02Z',
      UserId: 'cfo_finance@contoso.com',
      Operation: 'MailItemsAccessed',
      Workload: 'Exchange',
      ClientIP: '185.220.101.45',
      SessionId: 'f8a31b29-4d9a-4c22-8f15-token1234567',
      UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0',
      ResultStatus: 'Success',
      Target: 'cfo_finance@contoso.com/Inbox (Items: 240)',
    },
    {
      CreationTime: '2026-08-04T11:22:15Z',
      UserId: 'cfo_finance@contoso.com',
      Operation: 'New-InboxRule',
      Workload: 'Exchange',
      ClientIP: '194.26.29.112',
      SessionId: 'f8a31b29-4d9a-4c22-8f15-token1234567',
      UserAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
      ResultStatus: 'Success',
      Target: 'cfo_finance@contoso.com',
      ModifiedProperties: [
        { Name: 'ForwardTo', NewValue: 'stealth-drop@bulletproof-relay.cc' },
        { Name: 'Name', NewValue: 'Wire Transfer Audit' },
      ],
    },
    {
      CreationTime: '2026-08-28T09:05:40Z',
      UserId: 'cfo_finance@contoso.com',
      Operation: 'FileDownloaded',
      Workload: 'SharePoint',
      ClientIP: '185.220.101.45',
      SessionId: 'f8a31b29-4d9a-4c22-8f15-token1234567',
      UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0',
      ResultStatus: 'Success',
      Target: 'Q3_Financial_Projections_CONFIDENTIAL.xlsx',
    },
  ],
  null,
  2
);
