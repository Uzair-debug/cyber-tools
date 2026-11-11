// Incident report builder for the Purview & Defender analyzer.
// One model feeds two renderers: Markdown (copy / .md download) and a print-ready HTML page
// that the browser saves as PDF. Both run locally; nothing is uploaded.

import {
  ParsedAuditRecord,
  AuditAnalysisSummary,
  AuditTargetScope,
  PurviewReportOptions,
  DEFAULT_REPORT_OPTIONS,
} from './purview-parser';

type Severity = ParsedAuditRecord['severity'];

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const MIN_RANK: Record<PurviewReportOptions['minSeverity'], number> = {
  CRITICAL_ONLY: 4,
  HIGH_CRITICAL: 3,
  MEDIUM_PLUS: 2,
  ALL: 1,
};

// Long logs stay readable: full write-ups for the worst findings, a compact table for the rest
export const NARRATIVE_LIMIT = 25;
export const APPENDIX_LIMIT = 500;
const TIMELINE_LIMIT = 50;
const ACTORS_PER_GROUP = 10;
const SESSION_LIMIT = 20;

interface ActorActivity {
  user: string;
  count: number;
  ips: string[];
  operations: string[];
  first: string;
  last: string;
}

interface FindingGroup {
  category: string;
  severity: Severity;
  count: number;
  actors: ActorActivity[];
  hiddenActors: number;
}

interface SessionGroup {
  sessionId: string;
  user: string;
  ips: string[];
  count: number;
  first: string;
  last: string;
}

interface PlaybookStep {
  title: string;
  detail: string;
  command?: string;
}

export interface PurviewReportModel {
  title: string;
  classification: string;
  organization: string;
  investigator: string;
  generatedAt: string;
  windowStart: string;
  windowEnd: string;
  totalRecords: number;
  recordsWithoutTime: number;
  counts: AuditAnalysisSummary['threatsDetected'];
  uniqueUsers: number;
  uniqueIps: string[];
  workloads: string[];
  analystNotes: string;
  scopeRows: { label: string; value: string }[];
  minSeverityLabel: string;
  eligibleCount: number;
  groups: FindingGroup[];
  matchedRules: NonNullable<AuditAnalysisSummary['matchedCustomRules']>;
  timeline: ParsedAuditRecord[];
  timelineTotal: number;
  narratives: ParsedAuditRecord[];
  appendix: ParsedAuditRecord[];
  appendixTotal: number;
  sessions: SessionGroup[];
  sessionTotal: number;
  playbook: PlaybookStep[];
  sections: Pick<
    PurviewReportOptions,
    | 'includeExecutiveSummary'
    | 'includeScopeSection'
    | 'includeCustomRulesSummary'
    | 'includeFindingsTable'
    | 'includeThreatNarratives'
    | 'includeSessionHijacking'
    | 'includeRemediationPlaybook'
  >;
}

const MIN_SEVERITY_LABEL: Record<PurviewReportOptions['minSeverity'], string> = {
  CRITICAL_ONLY: 'Critical only',
  HIGH_CRITICAL: 'High and Critical',
  MEDIUM_PLUS: 'Medium and above',
  ALL: 'Low and above',
};

// Detection categories carry emoji for the on-screen table; reports use plain text
function cleanCategory(category: string | undefined, fallback: string): string {
  const text = (category || '').replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}️]/gu, '').trim();
  return text || fallback;
}

function timeValue(t: string): number {
  const ms = new Date(t).getTime();
  return isNaN(ms) ? NaN : ms;
}

export function formatReportTime(t: string): string {
  if (!t) return 'No timestamp';
  const ms = timeValue(t);
  if (isNaN(ms)) return t;
  return new Date(ms).toISOString().replace('T', ' ').replace(/(\.\d+)?Z$/, ' UTC');
}

function earlier(a: string, b: string): string {
  if (!a) return b;
  if (!b) return a;
  return timeValue(b) < timeValue(a) ? b : a;
}

function later(a: string, b: string): string {
  if (!a) return b;
  if (!b) return a;
  return timeValue(b) > timeValue(a) ? b : a;
}

function byTime(a: ParsedAuditRecord, b: ParsedAuditRecord): number {
  const ta = timeValue(a.creationTime);
  const tb = timeValue(b.creationTime);
  if (isNaN(ta) && isNaN(tb)) return 0;
  if (isNaN(ta)) return 1;
  if (isNaN(tb)) return -1;
  return ta - tb;
}

function hasIp(ip: string): boolean {
  return !!ip && ip !== 'N/A' && ip.toLowerCase() !== 'unknown';
}

function buildGroups(events: ParsedAuditRecord[]): FindingGroup[] {
  const groups = new Map<string, { severity: Severity; count: number; actors: Map<string, { count: number; ips: Set<string>; ops: Set<string>; first: string; last: string }> }>();

  for (const evt of events) {
    const category = cleanCategory(evt.threatCategory, evt.operation);
    let group = groups.get(category);
    if (!group) {
      group = { severity: evt.severity, count: 0, actors: new Map() };
      groups.set(category, group);
    }
    group.count++;
    if (SEVERITY_RANK[evt.severity] > SEVERITY_RANK[group.severity]) group.severity = evt.severity;

    let actor = group.actors.get(evt.userId);
    if (!actor) {
      actor = { count: 0, ips: new Set(), ops: new Set(), first: '', last: '' };
      group.actors.set(evt.userId, actor);
    }
    actor.count++;
    if (hasIp(evt.clientIp)) actor.ips.add(evt.clientIp);
    actor.ops.add(evt.operation);
    if (evt.creationTime) {
      actor.first = earlier(actor.first, evt.creationTime);
      actor.last = later(actor.last, evt.creationTime);
    }
  }

  return Array.from(groups.entries())
    .map(([category, g]) => {
      const actors = Array.from(g.actors.entries())
        .map(([user, a]) => ({
          user,
          count: a.count,
          ips: Array.from(a.ips),
          operations: Array.from(a.ops),
          first: a.first,
          last: a.last,
        }))
        .sort((a, b) => b.count - a.count);
      return {
        category,
        severity: g.severity,
        count: g.count,
        actors: actors.slice(0, ACTORS_PER_GROUP),
        hiddenActors: Math.max(0, actors.length - ACTORS_PER_GROUP),
      };
    })
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count);
}

function buildSessions(events: ParsedAuditRecord[]): SessionGroup[] {
  const sessions = new Map<string, SessionGroup & { ipSet: Set<string> }>();
  for (const evt of events) {
    const sid = evt.sessionId || 'Not recorded';
    let s = sessions.get(sid);
    if (!s) {
      s = { sessionId: sid, user: evt.userId, ips: [], ipSet: new Set(), count: 0, first: '', last: '' };
      sessions.set(sid, s);
    }
    s.count++;
    if (hasIp(evt.clientIp)) s.ipSet.add(evt.clientIp);
    if (evt.creationTime) {
      s.first = earlier(s.first, evt.creationTime);
      s.last = later(s.last, evt.creationTime);
    }
  }
  return Array.from(sessions.values())
    .map(({ ipSet, ...s }) => ({ ...s, ips: Array.from(ipSet) }))
    .sort((a, b) => b.ips.length - a.ips.length || b.count - a.count);
}

// Steps are only listed when the matching activity was seen, and numbered in order
function buildPlaybook(summary: AuditAnalysisSummary, eligible: ParsedAuditRecord[]): PlaybookStep[] {
  const steps: PlaybookStep[] = [];
  const g = summary.threatGroups;
  const riskyActors = Array.from(
    new Set(eligible.filter(e => SEVERITY_RANK[e.severity] >= 3).map(e => e.userId).filter(u => u && u !== 'Unknown User'))
  );

  if (g.sessionHijackings.length > 0) {
    steps.push({
      title: 'Revoke sessions for the affected users',
      detail: 'Sign the users out everywhere so stolen session cookies and refresh tokens stop working, then reset their credentials.',
      command: 'Revoke-MgUserSignInSession -UserId "<user@domain>"',
    });
    steps.push({
      title: 'Require phishing-resistant sign-in',
      detail: 'Move the affected users to FIDO2 keys, Windows Hello for Business or certificate-based authentication, which adversary-in-the-middle proxies cannot replay.',
    });
  }
  if (riskyActors.length > 0) {
    const shown = riskyActors.slice(0, 5).join(', ');
    steps.push({
      title: 'Contain the accounts behind High and Critical findings',
      detail: `Confirm with the owners whether this activity was theirs. If not, block sign-in, reset the password and revoke sessions. Accounts: ${shown}${riskyActors.length > 5 ? ` and ${riskyActors.length - 5} more` : ''}.`,
      command: 'Update-MgUser -UserId "<user@domain>" -AccountEnabled:$false',
    });
  }
  if (g.accountDeletions.length > 0) {
    steps.push({
      title: 'Check deleted accounts',
      detail: 'Deleted users can be restored for 30 days. List them and restore any that should not have been removed.',
      command: 'Get-MgDirectoryDeletedItemAsUser -All | Select-Object Id, UserPrincipalName, DeletedDateTime\nRestore-MgDirectoryDeletedItem -DirectoryObjectId "<id>"',
    });
  }
  if (g.privilegeEscalations.length > 0) {
    steps.push({
      title: 'Review new admin role assignments',
      detail: 'Remove any role assignment that was not approved, and check who else holds privileged roles.',
      command: 'Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq \'<object-id>\'"',
    });
  }
  if (g.emailForwardings.length > 0) {
    steps.push({
      title: 'Review mailbox forwarding',
      detail: 'List forwarding and redirect rules first, confirm which are unauthorised, then remove only those. Also check mailbox-level forwarding.',
      command:
        'Get-InboxRule -Mailbox "<mailbox>" | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo } | Format-List Name, ForwardTo, RedirectTo\n' +
        'Remove-InboxRule -Mailbox "<mailbox>" -Identity "<rule name>"\n' +
        'Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress } | Select-Object UserPrincipalName, ForwardingSmtpAddress',
    });
  }
  if (g.oauthConsents.length > 0) {
    steps.push({
      title: 'Review OAuth app consents',
      detail: 'Remove consent grants for apps the organisation does not recognise, and restrict user consent if it is still allowed.',
      command: 'Get-MgOauth2PermissionGrant -All | Select-Object ClientId, ConsentType, PrincipalId, Scope\nRemove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<id>"',
    });
  }
  if (g.massDownloads.length > 0) {
    steps.push({
      title: 'Review file access and sharing',
      detail: 'Check what was downloaded or shared, remove anonymous or external links that should not exist, and notify data owners.',
    });
  }
  if (g.failedLogins.length > 0) {
    steps.push({
      title: 'Check the failed sign-ins',
      detail: 'Look for password spraying (one IP, many accounts) or brute force (one account, many attempts) in the Entra sign-in logs, and block the source IPs with Conditional Access if needed.',
    });
  }
  return steps;
}

export function buildPurviewReportModel(
  summary: AuditAnalysisSummary,
  records: ParsedAuditRecord[],
  options?: Partial<PurviewReportOptions>,
  scope?: Partial<AuditTargetScope>
): PurviewReportModel {
  const opts: PurviewReportOptions = { ...DEFAULT_REPORT_OPTIONS, ...(options || {}) };
  const minRank = MIN_RANK[opts.minSeverity] ?? 1;

  const eligible = records.filter(r => SEVERITY_RANK[r.severity] >= minRank);
  const worstFirst = [...eligible].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || byTime(a, b));
  const highPlus = eligible.filter(r => SEVERITY_RANK[r.severity] >= 3).sort(byTime);
  const rest = worstFirst.slice(NARRATIVE_LIMIT);
  const sessions = buildSessions(summary.threatGroups.sessionHijackings);

  const scopeRows: { label: string; value: string }[] = [];
  if (scope) {
    if (scope.targetUsers) scopeRows.push({ label: 'Users', value: scope.targetUsers });
    if (scope.excludeServiceAccounts) scopeRows.push({ label: 'Service accounts', value: 'Excluded (sync_*, msol_*, app@*)' });
    if (scope.targetIps) scopeRows.push({ label: 'Client IPs', value: scope.targetIps });
    if (scope.onlyExternalIps) scopeRows.push({ label: 'IP range', value: 'Public IPs only (private and internal removed)' });
    if (scope.targetOperations) scopeRows.push({ label: 'Operations', value: scope.targetOperations });
    if (scope.targetWorkload && scope.targetWorkload !== 'ALL') scopeRows.push({ label: 'Workload', value: scope.targetWorkload });
    if (scope.targetSeverity && scope.targetSeverity !== 'ALL') scopeRows.push({ label: 'Severity', value: scope.targetSeverity });
    if (scope.resultStatus && scope.resultStatus !== 'ALL') scopeRows.push({ label: 'Result', value: scope.resultStatus === 'Unknown' ? 'Not recorded' : scope.resultStatus });
    if (scope.timeRangeStart || scope.timeRangeEnd) scopeRows.push({ label: 'Time range', value: `${scope.timeRangeStart || 'start'} to ${scope.timeRangeEnd || 'end'}` });
    if (scope.matchedRuleOnly && scope.matchedRuleOnly !== 'ALL') scopeRows.push({ label: 'Rule', value: scope.matchedRuleOnly });
  }

  return {
    title: opts.caseTitle.trim() || 'Microsoft Purview & Defender Audit Report',
    classification: opts.classification || 'RESTRICTED',
    organization: opts.organization.trim(),
    investigator: opts.investigator.trim(),
    generatedAt: formatReportTime(new Date().toISOString()),
    windowStart: summary.timeRange.start === 'N/A' ? 'Not recorded' : formatReportTime(summary.timeRange.start),
    windowEnd: summary.timeRange.end === 'N/A' ? 'Not recorded' : formatReportTime(summary.timeRange.end),
    totalRecords: summary.totalRecords,
    recordsWithoutTime: records.filter(r => isNaN(timeValue(r.creationTime))).length,
    counts: summary.threatsDetected,
    uniqueUsers: summary.uniqueUsers.length,
    uniqueIps: summary.uniqueIps,
    workloads: summary.uniqueWorkloads,
    analystNotes: opts.analystNotes.trim(),
    scopeRows,
    minSeverityLabel: MIN_SEVERITY_LABEL[opts.minSeverity] ?? MIN_SEVERITY_LABEL.ALL,
    eligibleCount: eligible.length,
    groups: buildGroups(eligible),
    matchedRules: summary.matchedCustomRules ?? [],
    timeline: highPlus.slice(0, TIMELINE_LIMIT),
    timelineTotal: highPlus.length,
    narratives: worstFirst.slice(0, NARRATIVE_LIMIT),
    appendix: rest.slice(0, APPENDIX_LIMIT),
    appendixTotal: rest.length,
    sessions: sessions.slice(0, SESSION_LIMIT),
    sessionTotal: sessions.length,
    playbook: buildPlaybook(summary, eligible),
    sections: {
      includeExecutiveSummary: opts.includeExecutiveSummary,
      includeScopeSection: opts.includeScopeSection,
      includeCustomRulesSummary: opts.includeCustomRulesSummary,
      includeFindingsTable: opts.includeFindingsTable,
      includeThreatNarratives: opts.includeThreatNarratives,
      includeSessionHijacking: opts.includeSessionHijacking,
      includeRemediationPlaybook: opts.includeRemediationPlaybook,
    },
  };
}

const METHOD_NOTE = [
  'Findings come from built-in detection heuristics and the custom rules listed in this report, applied to the exported audit records. They flag activity for an analyst to review; on their own they do not prove a compromise.',
  'All times are UTC. A value the source log did not contain is shown as "Not recorded" rather than guessed.',
  'The analysis ran in the browser. The audit log was not uploaded to any server.',
];

function listOrDash(values: string[], max = 3): string {
  if (values.length === 0) return 'Not recorded';
  return values.slice(0, max).join(', ') + (values.length > max ? ` +${values.length - max}` : '');
}

function timeSpan(first: string, last: string): string {
  if (!first) return 'No timestamp';
  return first === last ? formatReportTime(first) : `${formatReportTime(first)} to ${formatReportTime(last)}`;
}

function plural(n: number, word: string): string {
  return `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;
}

function displayStatus(status: ParsedAuditRecord['resultStatus']): string {
  return status === 'Unknown' ? 'Not recorded' : status;
}

function displayIp(ip: string): string {
  return hasIp(ip) ? ip : 'Not recorded';
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

// Log values are untrusted: keep them on one line and escape Markdown syntax (a "|" would split a table)
function md(value: unknown): string {
  return String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/([\\`*_[\]<>|#~])/g, '\\$1');
}

export function renderPurviewReportMarkdown(m: PurviewReportModel): string {
  const lines: string[] = [];
  let section = 0;
  const heading = (title: string) => {
    section++;
    lines.push(`## ${section}. ${title}`, '');
  };

  lines.push(`# ${md(m.title)}`, '');
  lines.push(`> **Classification: ${m.classification}**`, '');
  if (m.organization) lines.push(`- **Organisation:** ${md(m.organization)}`);
  if (m.investigator) lines.push(`- **Investigator:** ${md(m.investigator)}`);
  lines.push(`- **Generated:** ${m.generatedAt}`);
  lines.push(`- **Activity window:** ${m.windowStart} to ${m.windowEnd}`);
  lines.push(`- **Records in scope:** ${m.totalRecords.toLocaleString()}`);
  lines.push(`- **Findings included:** ${m.eligibleCount.toLocaleString()} (${m.minSeverityLabel})`, '');

  if (m.analystNotes) {
    heading('Analyst Notes');
    lines.push(m.analystNotes, '');
  }

  if (m.sections.includeExecutiveSummary) {
    heading('Summary');
    const high = m.counts.criticalCount + m.counts.highCount;
    lines.push(
      high > 0
        ? `**${m.counts.criticalCount} Critical** and **${m.counts.highCount} High** findings need review.`
        : 'No Critical or High findings in this scope.',
      ''
    );
    lines.push('| Critical | High | Medium | Low | Accounts | Client IPs |');
    lines.push('|---|---|---|---|---|---|');
    lines.push(`| ${m.counts.criticalCount} | ${m.counts.highCount} | ${m.counts.mediumCount} | ${m.counts.lowCount} | ${m.uniqueUsers} | ${m.uniqueIps.length} |`, '');
    lines.push(`- **Workloads:** ${md(m.workloads.join(', ') || 'Not recorded')}`);
    if (m.recordsWithoutTime > 0) lines.push(`- **Records with no timestamp:** ${m.recordsWithoutTime}`);
    lines.push('');
  }

  if (m.sections.includeScopeSection && m.scopeRows.length > 0) {
    heading('Scope');
    lines.push('| Filter | Value |', '|---|---|');
    m.scopeRows.forEach(r => lines.push(`| ${r.label} | ${md(r.value)} |`));
    lines.push('');
  }

  if (m.sections.includeFindingsTable && m.groups.length > 0) {
    heading('Findings by Type');
    lines.push('| Finding | Severity | Events | Accounts |', '|---|---|---|---|');
    m.groups.forEach(g => lines.push(`| ${md(g.category)} | ${g.severity} | ${g.count} | ${g.actors.length + g.hiddenActors} |`));
    lines.push('');
    m.groups.forEach(g => {
      lines.push(`### ${md(g.category)} (${g.severity}, ${plural(g.count, 'event')})`, '');
      lines.push('| Account | Events | Client IPs | Operations | When |', '|---|---|---|---|---|');
      g.actors.forEach(a =>
        lines.push(`| ${md(a.user)} | ${a.count} | ${md(listOrDash(a.ips))} | ${md(listOrDash(a.operations))} | ${timeSpan(a.first, a.last)} |`)
      );
      if (g.hiddenActors > 0) lines.push(`| ...and ${g.hiddenActors} more accounts | | | | |`);
      lines.push('');
    });

    if (m.timeline.length > 0) {
      lines.push('### Timeline of High and Critical Findings', '');
      if (m.timelineTotal > m.timeline.length) lines.push(`First ${m.timeline.length} of ${m.timelineTotal}, oldest first.`, '');
      lines.push('| Time (UTC) | Severity | Account | Operation | Target |', '|---|---|---|---|---|');
      m.timeline.forEach(e =>
        lines.push(`| ${formatReportTime(e.creationTime)} | ${e.severity} | ${md(e.userId)} | ${md(e.operation)} | ${md(e.target)} |`)
      );
      lines.push('');
    }
  }

  if (m.sections.includeCustomRulesSummary && m.matchedRules.length > 0) {
    heading('Custom Rules Matched');
    lines.push('| Rule | Events |', '|---|---|');
    m.matchedRules.forEach(r => lines.push(`| ${md(r.ruleName)} | ${r.count} |`));
    lines.push('');
  }

  if (m.sections.includeThreatNarratives && m.narratives.length > 0) {
    heading('Finding Details');
    if (m.appendixTotal > 0) lines.push(`The ${m.narratives.length} most severe findings. The remaining ${m.appendixTotal} are listed in the appendix.`, '');
    m.narratives.forEach((e, i) => {
      lines.push(`### ${i + 1}. ${md(cleanCategory(e.threatCategory, e.operation))} (${e.severity})`, '');
      lines.push(`- **Time:** ${formatReportTime(e.creationTime)}`);
      lines.push(`- **Account:** ${md(e.userId)}`);
      lines.push(`- **Operation:** ${md(e.operation)} (${md(e.workload)}, result: ${displayStatus(e.resultStatus)})`);
      lines.push(`- **Client IP:** ${md(displayIp(e.clientIp))}`);
      lines.push(`- **Target:** ${md(e.target)}`);
      if (e.mitreTactic) lines.push(`- **MITRE ATT&CK:** ${md(e.mitreTactic)}`);
      if (e.matchedRuleName) lines.push(`- **Rule:** ${md(e.matchedRuleName)}`);
      if (e.threatDescription) lines.push(`- **Why it was flagged:** ${md(e.threatDescription)}`);
      if (e.modifiedProperties && e.modifiedProperties.length > 0) {
        lines.push('- **Changed values:**');
        e.modifiedProperties.slice(0, 10).forEach(p =>
          lines.push(`  - ${md(p.name)}: ${md(p.oldValue ?? 'none')} → ${md(p.newValue ?? 'none')}`)
        );
      }
      lines.push('');
    });
  }

  if (m.sections.includeSessionHijacking && m.sessions.length > 0) {
    heading('Sessions Used From More Than One Network');
    lines.push('The same session ID was seen from different networks. Confirm with the user (travel, VPN, mobile data) before treating it as token theft.', '');
    lines.push('| Session ID | Account | Client IPs | Events | When |', '|---|---|---|---|---|');
    m.sessions.forEach(s =>
      lines.push(`| ${md(s.sessionId)} | ${md(s.user)} | ${md(listOrDash(s.ips, 5))} | ${s.count} | ${timeSpan(s.first, s.last)} |`)
    );
    if (m.sessionTotal > m.sessions.length) lines.push('', `${m.sessionTotal - m.sessions.length} more sessions not shown.`);
    lines.push('');
  }

  if (m.sections.includeRemediationPlaybook) {
    heading('Recommended Response');
    if (m.playbook.length === 0) {
      lines.push('No response steps were triggered by the findings in this scope.', '');
    } else {
      m.playbook.forEach((s, i) => {
        lines.push(`${i + 1}. **${s.title}.** ${md(s.detail)}`);
        if (s.command) lines.push('   ```powershell', ...s.command.split('\n').map(c => `   ${c}`), '   ```');
      });
      lines.push('');
    }
  }

  if (m.sections.includeThreatNarratives && m.appendix.length > 0) {
    heading('Appendix: Other Findings');
    if (m.appendixTotal > m.appendix.length) lines.push(`First ${m.appendix.length} of ${m.appendixTotal}. Export the CSV for the full list.`, '');
    lines.push('| Time (UTC) | Severity | Finding | Account | Operation | Client IP |', '|---|---|---|---|---|---|');
    m.appendix.forEach(e =>
      lines.push(
        `| ${formatReportTime(e.creationTime)} | ${e.severity} | ${md(cleanCategory(e.threatCategory, e.operation))} | ${md(e.userId)} | ${md(e.operation)} | ${md(displayIp(e.clientIp))} |`
      )
    );
    lines.push('');
  }

  lines.push('---', '', '**How to read this report**', '');
  METHOD_NOTE.forEach(n => lines.push(`- ${n}`));
  lines.push('', '*Generated by Cyber Tools Portal: Purview & Defender Audit Analyzer.*');
  return lines.join('\n');
}

export function generatePurviewIncidentReport(
  summary: AuditAnalysisSummary,
  records: ParsedAuditRecord[],
  options?: Partial<PurviewReportOptions>,
  scope?: Partial<AuditTargetScope>
): string {
  return renderPurviewReportMarkdown(buildPurviewReportModel(summary, records, options, scope));
}

// ---------------------------------------------------------------------------
// Print-ready HTML (saved as PDF through the browser's print dialog)
// ---------------------------------------------------------------------------

function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function badge(sev: Severity): string {
  return `<span class="sev sev-${sev.toLowerCase()}">${sev}</span>`;
}

const REPORT_CSS = `
  @page {
    size: A4;
    margin: 18mm 14mm 18mm 14mm;
    @bottom-left { content: "Cyber Tools Portal: Purview & Defender Audit"; font: 8pt system-ui, sans-serif; color: #6b7280; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt system-ui, sans-serif; color: #6b7280; }
  }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0; background: #e5e7eb; color: #111827; font: 10pt/1.45 "Segoe UI", system-ui, -apple-system, Arial, sans-serif; }
  .page { background: #fff; max-width: 210mm; margin: 16px auto; padding: 14mm 14mm 10mm; box-shadow: 0 1px 4px rgba(0,0,0,.15); }
  @media print { body { background: #fff; } .page { margin: 0; padding: 0; max-width: none; box-shadow: none; } }
  .classification { text-align: center; font-weight: 700; letter-spacing: .08em; font-size: 9pt; color: #fff; background: #991b1b; padding: 4px 0; border-radius: 3px; }
  header { border-bottom: 2px solid #991b1b; padding: 10px 0 12px; margin-bottom: 14px; }
  h1 { font-size: 18pt; margin: 8px 0 8px; line-height: 1.2; }
  h2 { font-size: 12.5pt; margin: 20px 0 8px; padding-bottom: 3px; border-bottom: 1px solid #d1d5db; break-after: avoid; }
  h3 { font-size: 10.5pt; margin: 14px 0 6px; break-after: avoid; }
  .meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; font-size: 9pt; }
  .meta dt { color: #6b7280; } .meta dd { margin: 0; }
  .tiles { display: grid; grid-template-columns: repeat(6, 1fr); gap: 6px; margin: 8px 0 10px; }
  .tile { border: 1px solid #e5e7eb; border-radius: 6px; padding: 6px 8px; break-inside: avoid; }
  .tile b { display: block; font-size: 15pt; line-height: 1.1; }
  .tile span { font-size: 7.5pt; color: #6b7280; text-transform: uppercase; letter-spacing: .04em; }
  .tile.crit b { color: #b91c1c; } .tile.high b { color: #c2410c; }
  .lead { font-size: 10.5pt; margin: 4px 0 8px; }
  table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 8.5pt; margin: 4px 0 10px; }
  thead { display: table-header-group; }
  th { text-align: left; background: #f3f4f6; color: #374151; font-weight: 600; }
  th, td { border: 1px solid #e5e7eb; padding: 4px 6px; vertical-align: top; overflow-wrap: anywhere; }
  tr { break-inside: avoid; }
  .num { text-align: right; width: 9%; }
  .sev { display: inline-block; font-size: 7pt; font-weight: 700; padding: 1px 5px; border-radius: 3px; letter-spacing: .03em; }
  .sev-critical { background: #fee2e2; color: #991b1b; } .sev-high { background: #ffedd5; color: #9a3412; }
  .sev-medium { background: #fef9c3; color: #854d0e; } .sev-low { background: #dcfce7; color: #166534; } .sev-info { background: #f1f5f9; color: #475569; }
  .finding { border: 1px solid #e5e7eb; border-left: 4px solid #9ca3af; border-radius: 4px; padding: 8px 10px; margin: 0 0 8px; break-inside: avoid; }
  .finding.critical { border-left-color: #b91c1c; } .finding.high { border-left-color: #ea580c; } .finding.medium { border-left-color: #ca8a04; } .finding.low { border-left-color: #16a34a; }
  .finding h3 { margin: 0 0 4px; }
  .finding dl { display: grid; grid-template-columns: 88px 1fr; gap: 1px 10px; margin: 0; font-size: 8.5pt; }
  .finding dt { color: #6b7280; } .finding dd { margin: 0; overflow-wrap: anywhere; }
  .why { margin: 6px 0 0; font-size: 8.5pt; color: #374151; }
  .changes { margin: 4px 0 0 0; padding-left: 16px; font-size: 8pt; }
  .note { font-size: 8.5pt; color: #4b5563; }
  .notes-box { white-space: pre-wrap; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 4px; padding: 8px 10px; }
  ol.steps { padding-left: 18px; } ol.steps li { margin-bottom: 8px; break-inside: avoid; }
  pre { background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 4px; padding: 6px 8px; font: 7.5pt/1.4 Consolas, "Cascadia Mono", monospace; white-space: pre-wrap; overflow-wrap: anywhere; margin: 4px 0 0; }
  .method { margin-top: 18px; border-top: 1px solid #d1d5db; padding-top: 8px; font-size: 8pt; color: #4b5563; break-inside: avoid; }
  .method ul { margin: 4px 0; padding-left: 16px; }
`;

export function renderPurviewReportHtml(m: PurviewReportModel): string {
  const out: string[] = [];
  let section = 0;
  const heading = (title: string) => {
    section++;
    out.push(`<h2>${section}. ${esc(title)}</h2>`);
  };

  out.push(`<div class="classification">${esc(m.classification)}</div>`);
  out.push('<header>');
  out.push(`<h1>${esc(m.title)}</h1>`);
  out.push('<dl class="meta">');
  if (m.organization) out.push(`<dt>Organisation</dt><dd>${esc(m.organization)}</dd>`);
  if (m.investigator) out.push(`<dt>Investigator</dt><dd>${esc(m.investigator)}</dd>`);
  out.push(`<dt>Generated</dt><dd>${esc(m.generatedAt)}</dd>`);
  out.push(`<dt>Activity window</dt><dd>${esc(m.windowStart)} to ${esc(m.windowEnd)}</dd>`);
  out.push(`<dt>Records in scope</dt><dd>${m.totalRecords.toLocaleString()}</dd>`);
  out.push(`<dt>Findings included</dt><dd>${m.eligibleCount.toLocaleString()} (${esc(m.minSeverityLabel)})</dd>`);
  out.push('</dl></header>');

  if (m.analystNotes) {
    heading('Analyst Notes');
    out.push(`<div class="notes-box">${esc(m.analystNotes)}</div>`);
  }

  if (m.sections.includeExecutiveSummary) {
    heading('Summary');
    const high = m.counts.criticalCount + m.counts.highCount;
    out.push(
      `<p class="lead">${
        high > 0
          ? `<b>${m.counts.criticalCount} Critical</b> and <b>${m.counts.highCount} High</b> findings need review.`
          : 'No Critical or High findings in this scope.'
      }</p>`
    );
    out.push('<div class="tiles">');
    out.push(`<div class="tile crit"><b>${m.counts.criticalCount}</b><span>Critical</span></div>`);
    out.push(`<div class="tile high"><b>${m.counts.highCount}</b><span>High</span></div>`);
    out.push(`<div class="tile"><b>${m.counts.mediumCount}</b><span>Medium</span></div>`);
    out.push(`<div class="tile"><b>${m.counts.lowCount}</b><span>Low</span></div>`);
    out.push(`<div class="tile"><b>${m.uniqueUsers}</b><span>Accounts</span></div>`);
    out.push(`<div class="tile"><b>${m.uniqueIps.length}</b><span>Client IPs</span></div>`);
    out.push('</div>');
    out.push(`<p class="note">Workloads: ${esc(m.workloads.join(', ') || 'Not recorded')}${m.recordsWithoutTime > 0 ? ` · Records with no timestamp: ${m.recordsWithoutTime}` : ''}</p>`);
  }

  if (m.sections.includeScopeSection && m.scopeRows.length > 0) {
    heading('Scope');
    out.push('<table><thead><tr><th style="width:25%">Filter</th><th>Value</th></tr></thead><tbody>');
    m.scopeRows.forEach(r => out.push(`<tr><td>${esc(r.label)}</td><td>${esc(r.value)}</td></tr>`));
    out.push('</tbody></table>');
  }

  if (m.sections.includeFindingsTable && m.groups.length > 0) {
    heading('Findings by Type');
    out.push('<table><thead><tr><th>Finding</th><th style="width:12%">Severity</th><th class="num">Events</th><th class="num">Accounts</th></tr></thead><tbody>');
    m.groups.forEach(g =>
      out.push(`<tr><td>${esc(g.category)}</td><td>${badge(g.severity)}</td><td class="num">${g.count}</td><td class="num">${g.actors.length + g.hiddenActors}</td></tr>`)
    );
    out.push('</tbody></table>');

    m.groups.forEach(g => {
      out.push(`<h3>${badge(g.severity)} ${esc(g.category)} <span class="note">(${plural(g.count, 'event')})</span></h3>`);
      out.push('<table><thead><tr><th style="width:26%">Account</th><th class="num">Events</th><th style="width:20%">Client IPs</th><th>Operations</th><th style="width:22%">When (UTC)</th></tr></thead><tbody>');
      g.actors.forEach(a =>
        out.push(
          `<tr><td>${esc(a.user)}</td><td class="num">${a.count}</td><td>${esc(listOrDash(a.ips))}</td><td>${esc(listOrDash(a.operations))}</td><td>${esc(timeSpan(a.first, a.last))}</td></tr>`
        )
      );
      if (g.hiddenActors > 0) out.push(`<tr><td colspan="5" class="note">...and ${g.hiddenActors} more accounts</td></tr>`);
      out.push('</tbody></table>');
    });

    if (m.timeline.length > 0) {
      out.push('<h3>Timeline of High and Critical Findings</h3>');
      if (m.timelineTotal > m.timeline.length) out.push(`<p class="note">First ${m.timeline.length} of ${m.timelineTotal}, oldest first.</p>`);
      out.push('<table><thead><tr><th style="width:20%">Time (UTC)</th><th style="width:11%">Severity</th><th style="width:24%">Account</th><th style="width:20%">Operation</th><th>Target</th></tr></thead><tbody>');
      m.timeline.forEach(e =>
        out.push(
          `<tr><td>${esc(formatReportTime(e.creationTime))}</td><td>${badge(e.severity)}</td><td>${esc(e.userId)}</td><td>${esc(e.operation)}</td><td>${esc(e.target)}</td></tr>`
        )
      );
      out.push('</tbody></table>');
    }
  }

  if (m.sections.includeCustomRulesSummary && m.matchedRules.length > 0) {
    heading('Custom Rules Matched');
    out.push('<table><thead><tr><th>Rule</th><th class="num">Events</th></tr></thead><tbody>');
    m.matchedRules.forEach(r => out.push(`<tr><td>${esc(r.ruleName)}</td><td class="num">${r.count}</td></tr>`));
    out.push('</tbody></table>');
  }

  if (m.sections.includeThreatNarratives && m.narratives.length > 0) {
    heading('Finding Details');
    if (m.appendixTotal > 0) out.push(`<p class="note">The ${m.narratives.length} most severe findings. The remaining ${m.appendixTotal} are listed in the appendix.</p>`);
    m.narratives.forEach((e, i) => {
      out.push(`<div class="finding ${e.severity.toLowerCase()}">`);
      out.push(`<h3>${i + 1}. ${esc(cleanCategory(e.threatCategory, e.operation))} ${badge(e.severity)}</h3><dl>`);
      out.push(`<dt>Time</dt><dd>${esc(formatReportTime(e.creationTime))}</dd>`);
      out.push(`<dt>Account</dt><dd>${esc(e.userId)}</dd>`);
      out.push(`<dt>Operation</dt><dd>${esc(e.operation)} (${esc(e.workload)}, result: ${esc(displayStatus(e.resultStatus))})</dd>`);
      out.push(`<dt>Client IP</dt><dd>${esc(displayIp(e.clientIp))}</dd>`);
      out.push(`<dt>Target</dt><dd>${esc(e.target)}</dd>`);
      if (e.mitreTactic) out.push(`<dt>MITRE ATT&amp;CK</dt><dd>${esc(e.mitreTactic)}</dd>`);
      if (e.matchedRuleName) out.push(`<dt>Rule</dt><dd>${esc(e.matchedRuleName)}</dd>`);
      out.push('</dl>');
      if (e.threatDescription) out.push(`<p class="why"><b>Why it was flagged:</b> ${esc(e.threatDescription)}</p>`);
      if (e.modifiedProperties && e.modifiedProperties.length > 0) {
        out.push('<ul class="changes">');
        e.modifiedProperties.slice(0, 10).forEach(p =>
          out.push(`<li>${esc(p.name)}: ${esc(p.oldValue ?? 'none')} → ${esc(p.newValue ?? 'none')}</li>`)
        );
        out.push('</ul>');
      }
      out.push('</div>');
    });
  }

  if (m.sections.includeSessionHijacking && m.sessions.length > 0) {
    heading('Sessions Used From More Than One Network');
    out.push('<p class="note">The same session ID was seen from different networks. Confirm with the user (travel, VPN, mobile data) before treating it as token theft.</p>');
    out.push('<table><thead><tr><th style="width:24%">Session ID</th><th style="width:22%">Account</th><th>Client IPs</th><th class="num">Events</th><th style="width:22%">When (UTC)</th></tr></thead><tbody>');
    m.sessions.forEach(s =>
      out.push(`<tr><td>${esc(s.sessionId)}</td><td>${esc(s.user)}</td><td>${esc(listOrDash(s.ips, 5))}</td><td class="num">${s.count}</td><td>${esc(timeSpan(s.first, s.last))}</td></tr>`)
    );
    out.push('</tbody></table>');
    if (m.sessionTotal > m.sessions.length) out.push(`<p class="note">${m.sessionTotal - m.sessions.length} more sessions not shown.</p>`);
  }

  if (m.sections.includeRemediationPlaybook) {
    heading('Recommended Response');
    if (m.playbook.length === 0) {
      out.push('<p>No response steps were triggered by the findings in this scope.</p>');
    } else {
      out.push('<ol class="steps">');
      m.playbook.forEach(s =>
        out.push(`<li><b>${esc(s.title)}.</b> ${esc(s.detail)}${s.command ? `<pre>${esc(s.command)}</pre>` : ''}</li>`)
      );
      out.push('</ol>');
    }
  }

  if (m.sections.includeThreatNarratives && m.appendix.length > 0) {
    heading('Appendix: Other Findings');
    if (m.appendixTotal > m.appendix.length) out.push(`<p class="note">First ${m.appendix.length} of ${m.appendixTotal}. Export the CSV for the full list.</p>`);
    out.push('<table><thead><tr><th style="width:18%">Time (UTC)</th><th style="width:10%">Severity</th><th>Finding</th><th style="width:22%">Account</th><th style="width:17%">Operation</th><th style="width:13%">Client IP</th></tr></thead><tbody>');
    m.appendix.forEach(e =>
      out.push(
        `<tr><td>${esc(formatReportTime(e.creationTime))}</td><td>${badge(e.severity)}</td><td>${esc(cleanCategory(e.threatCategory, e.operation))}</td><td>${esc(e.userId)}</td><td>${esc(e.operation)}</td><td>${esc(displayIp(e.clientIp))}</td></tr>`
      )
    );
    out.push('</tbody></table>');
  }

  out.push('<div class="method"><b>How to read this report</b><ul>');
  METHOD_NOTE.forEach(n => out.push(`<li>${esc(n)}</li>`));
  out.push('</ul></div>');
  out.push(`<div class="classification" style="margin-top:12px">${esc(m.classification)}</div>`);

  // The classification is one of a fixed set of labels, so it is safe inside the CSS string
  const pageLabel = `"${m.classification.replace(/[^A-Z:]/g, '')}"`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(m.title)}</title>
<style>${REPORT_CSS}
@page { @top-center { content: ${pageLabel}; font: 700 8pt system-ui, sans-serif; color: #991b1b; letter-spacing: .08em; } }</style>
</head><body><div class="page">${out.join('\n')}</div></body></html>`;
}

export function generatePurviewReportHtml(
  summary: AuditAnalysisSummary,
  records: ParsedAuditRecord[],
  options?: Partial<PurviewReportOptions>,
  scope?: Partial<AuditTargetScope>
): string {
  return renderPurviewReportHtml(buildPurviewReportModel(summary, records, options, scope));
}
