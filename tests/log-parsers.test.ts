import { describe, expect, it } from 'vitest';
import {
  SAMPLE_WINDOWS_XML,
  generateWindowsIncidentReport,
  parseWindowsEvents,
  summarizeWindowsEvents,
} from '@/components/windows-events/windows-event-parser';
import {
  SAMPLE_SCENARIO_ACCOUNT_TAMPERING,
  SAMPLE_SCENARIO_BEC_FORWARDING,
  SAMPLE_SCENARIO_SESSION_HIJACKING,
  isPrivateOrInternalIp,
  isServiceAccount,
  matchesPattern,
  parsePurviewLogs,
  summarizeAuditData,
} from '@/components/purview-analyzer/purview-parser';

const xmlEvent = (id: number, data: Record<string, string>, extra = '') => `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>${id}</EventID>
    <TimeCreated SystemTime="2026-10-30T10:00:00.000Z" />
    <Computer>WS01.corp.contoso.com</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    ${Object.entries(data)
      .map(([k, v]) => `<Data Name="${k}">${v}</Data>`)
      .join('\n    ')}
  </EventData>${extra}
</Event>`;

describe('Windows event triage', () => {
  const { events, truncated } = parseWindowsEvents(SAMPLE_WINDOWS_XML);
  const summary = summarizeWindowsEvents(events);

  it('parses every event in the sample', () => {
    expect(truncated).toBe(false);
    expect(summary.totalEvents).toBe(18);
    expect(summary.eventCounts).toEqual({ 1: 1, 1102: 1, 4624: 1, 4625: 12, 4720: 1, 4732: 1, 7045: 1 });
  });

  it('flags the password spray source', () => {
    expect(summary.bruteForceSources).toEqual([{ ip: '203.0.113.45', failures: 12, accounts: 6 }]);
  });

  it('finds the RDP logon (logon type 10)', () => {
    expect(summary.rdpLogons).toHaveLength(1);
    expect(summary.rdpLogons[0]).toMatchObject({ targetUser: 'helpdesk_svc', ipAddress: '203.0.113.45', logonType: 10 });
  });

  it('rates log clearing and admin-group additions CRITICAL', () => {
    const critical = events.filter(e => e.severity === 'CRITICAL').map(e => e.eventId).sort();
    expect(critical).toEqual([1, 1102, 4732]);
    expect(summary.logsCleared.map(e => e.eventId)).toEqual([1102]);
  });

  it('names the added member, not just the group, for 4732', () => {
    const add = events.find(e => e.eventId === 4732)!;
    expect(add.threatDescription).toBe("'backup_admin' was added to 'Administrators' by 'helpdesk_svc'.");
  });

  it('lists accounts, not group names, in the summary', () => {
    expect(summary.uniqueUsers).toContain('backup_admin');
    expect(summary.uniqueUsers).not.toContain('Administrators');
  });

  it('builds a report from the summary', () => {
    const report = generateWindowsIncidentReport(summary, events);
    expect(report).toMatch(/^# Windows Event Triage Report/);
    expect(report).toContain('203.0.113.45');
  });

  it('does not flag a handful of failures as brute force', () => {
    const few = Array.from({ length: 3 }, () =>
      xmlEvent(4625, { TargetUserName: 'bob', IpAddress: '198.51.100.9', LogonType: '3' })
    ).join('\n');
    expect(summarizeWindowsEvents(parseWindowsEvents(`<Events>${few}</Events>`).events).bruteForceSources).toEqual([]);
  });

  it('flags many failures against one account as brute force', () => {
    const many = Array.from({ length: 10 }, () =>
      xmlEvent(4625, { TargetUserName: 'bob', IpAddress: '198.51.100.9', LogonType: '3' })
    ).join('\n');
    const s = summarizeWindowsEvents(parseWindowsEvents(`<Events>${many}</Events>`).events);
    expect(s.bruteForceSources).toEqual([{ ip: '198.51.100.9', failures: 10, accounts: 1 }]);
  });

  it('accepts JSON arrays and JSON lines', () => {
    const one = { EventID: 4624, TimeCreated: '2026-10-30T10:00:00Z', Computer: 'WS01', TargetUserName: 'bob', IpAddress: '198.51.100.9', LogonType: 10 };
    expect(parseWindowsEvents(JSON.stringify([one, one])).events).toHaveLength(2);
    expect(parseWindowsEvents(`${JSON.stringify(one)}\n${JSON.stringify(one)}`).events).toHaveLength(2);
  });

  it('returns nothing for empty input and explains unusable input', () => {
    expect(parseWindowsEvents('   ')).toEqual({ events: [], truncated: false });
    expect(() => parseWindowsEvents('hello world')).toThrow(/No Windows events found/);
    expect(() => parseWindowsEvents('[{bad json')).toThrow(/Invalid JSON/);
  });
});

describe('Purview audit log analysis', () => {
  const ops = (input: string) =>
    parsePurviewLogs(input).records.map(r => [r.operation, r.severity, r.threatCategory ?? null]);

  it('detects account tampering and privilege escalation', () => {
    expect(ops(SAMPLE_SCENARIO_ACCOUNT_TAMPERING)).toEqual([
      ['UserLoggedIn', 'INFO', null],
      ['Update user.', 'HIGH', 'Account Renaming & Identity Tampering'],
      ['Delete user.', 'CRITICAL', 'Account Deletion / Destruction'],
      ['RoleAssignmentAdded', 'CRITICAL', 'Privilege Escalation'],
      ['New-InboxRule', 'HIGH', 'Email Forwarding Rule (BEC Indicator)'],
    ]);
  });

  it('detects BEC forwarding and OAuth consent from CSV exports', () => {
    expect(ops(SAMPLE_SCENARIO_BEC_FORWARDING)).toEqual([
      ['UserLoggedIn', 'INFO', null],
      ['MailItemsAccessed', 'INFO', null],
      ['New-InboxRule', 'HIGH', 'Email Forwarding Rule (BEC Indicator)'],
      ['ConsentToApplication', 'HIGH', 'Illicit OAuth Consent / Rogue App'],
    ]);
  });

  it('correlates one session ID used from several IPs as session hijacking', () => {
    const records = parsePurviewLogs(SAMPLE_SCENARIO_SESSION_HIJACKING).records;
    expect(records.every(r => r.severity === 'CRITICAL')).toBe(true);
    const attacker = records.filter(r => r.threatCategory?.includes('Attacker IP')).map(r => r.clientIp);
    expect(new Set(attacker)).toEqual(new Set(['185.220.101.45', '194.26.29.112']));
    expect(records.find(r => r.clientIp === '105.22.14.88')?.threatCategory).toMatch(/Victim Origin/);
  });

  it('summarises threats into groups', () => {
    const summary = summarizeAuditData(parsePurviewLogs(SAMPLE_SCENARIO_ACCOUNT_TAMPERING).records);
    expect(summary.totalRecords).toBe(5);
    expect(summary.threatGroups.accountDeletions).toHaveLength(1);
    expect(summary.threatGroups.privilegeEscalations).toHaveLength(1);
    expect(summary.threatGroups.emailForwardings).toHaveLength(1);
    expect(summary.uniqueIps).toEqual(['185.220.101.45']);
  });

  it('caps the number of records and reports truncation', () => {
    const many = JSON.stringify(
      Array.from({ length: 20 }, (_, i) => ({
        CreationTime: '2026-10-30T10:00:00Z',
        UserId: `u${i}@contoso.com`,
        Operation: 'FileAccessed',
        Workload: 'SharePoint',
        ClientIP: '198.51.100.1',
      }))
    );
    const { records, truncated } = parsePurviewLogs(many, undefined, 5);
    expect(records).toHaveLength(5);
    expect(truncated).toBe(true);
  });

  it('returns nothing for empty input', () => {
    expect(parsePurviewLogs('  ')).toEqual({ records: [], truncated: false });
  });
});

describe('Purview helpers', () => {
  it.each([
    '10.0.0.5',
    '127.0.0.1',
    '192.168.1.10',
    '172.16.0.1',
    '172.31.255.255',
    '169.254.10.1',
    '100.64.0.1',
    '100.127.255.255',
    '::ffff:10.0.0.5',
    '10.0.0.5:51234',
    '[fd12:3456::1]',
    'fd12:3456::1',
    'fc00::1',
    'fe80::1',
    '::1',
    '',
    'N/A',
    'unknown',
  ])('treats %j as internal', ip => {
    expect(isPrivateOrInternalIp(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '172.32.0.1', '100.128.0.1', '185.220.101.45', '2606:4700::1111', 'fd.example.com'])(
    'treats %s as external',
    ip => {
      expect(isPrivateOrInternalIp(ip)).toBe(false);
    }
  );

  it.each([
    'Sync_DC01_abc123@contoso.onmicrosoft.com',
    'MSOL_1234abcd',
    'app@sharepoint',
    'svc-backup@contoso.com',
    'NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)',
    'SYSTEM',
  ])('treats %s as a service account', user => {
    expect(isServiceAccount(user)).toBe(true);
  });

  // These used to match the old substring check on "system" and were exempt from detections
  it.each(['it.systems@contoso.com', 'systemadmin@contoso.com', 'ecosystem.team@contoso.com', 'alice@contoso.com', ''])(
    'does not treat %j as a service account',
    user => {
      expect(isServiceAccount(user)).toBe(false);
    }
  );

  it('still detects a password reset done by a user whose name contains "system"', () => {
    const log = JSON.stringify([
      {
        CreationTime: '2026-10-30T10:00:00Z',
        UserId: 'it.systems@contoso.com',
        Operation: 'Update user.',
        Workload: 'AzureActiveDirectory',
        ClientIP: '185.220.101.45',
        ObjectId: 'ceo@contoso.com',
        ModifiedProperties: [{ Name: 'PasswordProfile', OldValue: '', NewValue: '' }],
      },
    ]);
    const [record] = parsePurviewLogs(log).records;
    expect(record.severity).toBe('HIGH');
    expect(record.threatCategory).toBe('Account Credential / Status Modification');
  });

  it.each([
    ['admin@contoso.com', '', true],
    ['admin@contoso.com', 'ADMIN', true],
    ['admin@contoso.com', 'admin*', true],
    ['admin@contoso.com', '*@contoso.com', true],
    ['admin@contoso.com', '*@fabrikam.com', false],
    ['Delete user.', '^delete|^remove', true],
    ['Add member.', '^delete|^remove', false],
    ['', 'x', false],
    ['a(b', 'a(b', true], // invalid regex characters fall back to substring
  ])('matchesPattern(%j, %j) = %s', (value, pattern, expected) => {
    expect(matchesPattern(value, pattern)).toBe(expected);
  });
});
