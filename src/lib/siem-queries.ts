// Builds IOC hunting queries for each SIEM. Every indicator type present in the input
// is included in every query, so mixed input never drops indicators silently.

import { SiemPlatform } from '@/lib/types';

export interface ExtractedIocs {
  ips: string[];
  domains: string[];
  md5: string[];
  sha1: string[];
  sha256: string[];
  unrecognised: string[];
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// Labels of letters, digits and hyphens; the last label (TLD) must be alphabetic
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const HEX = /^[a-f0-9]+$/;

// Undo common defanging and strip URL parts so "hxxps://evil[.]com/path" becomes "evil.com"
function refang(token: string): string {
  let t = token.trim().replace(/^['"<(]+|['">),;]+$/g, '');
  t = t.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.').replace(/\[:\]/g, ':');
  t = t.replace(/^h[tx]{2}ps?(?:\[:\]|:)\/\//i, '').replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  t = t.split(/[/?#]/)[0];
  t = t.replace(/^[^@]*@/, ''); // user@host
  t = t.replace(/:\d+$/, ''); // host:port
  return t.replace(/\.$/, '');
}

export function extractIocs(input: string): ExtractedIocs {
  const out: ExtractedIocs = { ips: [], domains: [], md5: [], sha1: [], sha256: [], unrecognised: [] };
  for (const raw of input.split(/[\s,;]+/).filter(Boolean)) {
    const token = refang(raw);
    const lower = token.toLowerCase();
    if (IPV4.test(token)) out.ips.push(token);
    else if (HEX.test(lower) && lower.length === 32) out.md5.push(lower);
    else if (HEX.test(lower) && lower.length === 40) out.sha1.push(lower);
    else if (HEX.test(lower) && lower.length === 64) out.sha256.push(lower);
    else if (DOMAIN.test(lower)) out.domains.push(lower);
    else out.unrecognised.push(raw);
  }
  for (const k of Object.keys(out) as (keyof ExtractedIocs)[]) out[k] = Array.from(new Set(out[k]));
  return out;
}

const q = (v: string) => `"${v}"`;
const list = (vs: string[]) => vs.map(q).join(', ');
const oneLine = (s: string) => s.replace(/[\r\n]+/g, ' ').trim();

// Microsoft Defender XDR advanced hunting, or Sentinel with the Defender for Endpoint connector
function kql(i: ExtractedIocs, title: string): string {
  const lets: string[] = [`let lookback = 7d;`];
  const blocks: string[] = [];
  const hashes = i.md5.length + i.sha1.length + i.sha256.length > 0;
  if (i.ips.length) {
    lets.push(`let threat_ips = dynamic([${list(i.ips)}]);`);
    blocks.push(`DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteIP in (threat_ips)
    | extend IocType = "ip", MatchedIoc = RemoteIP`);
  }
  if (i.domains.length) {
    lets.push(`let threat_domains = dynamic([${list(i.domains)}]);`);
    // has_any matches whole terms, so it also finds subdomains (a.evil.com) but not notevil.com
    blocks.push(`DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has_any (threat_domains)
    | extend IocType = "domain", MatchedIoc = RemoteUrl`);
    blocks.push(`DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).DnsQueryString)
    | where QueryName has_any (threat_domains)
    | extend IocType = "domain", MatchedIoc = QueryName`);
  }
  if (hashes) {
    lets.push(`let threat_md5 = dynamic([${list(i.md5)}]);`);
    lets.push(`let threat_sha1 = dynamic([${list(i.sha1)}]);`);
    lets.push(`let threat_sha256 = dynamic([${list(i.sha256)}]);`);
    for (const table of ['DeviceProcessEvents', 'DeviceFileEvents']) {
      blocks.push(`${table}
    | where Timestamp > ago(lookback)
    | where SHA256 in~ (threat_sha256) or SHA1 in~ (threat_sha1) or MD5 in~ (threat_md5)
    | extend IocType = "hash", MatchedIoc = case(SHA256 in~ (threat_sha256), SHA256, SHA1 in~ (threat_sha1), SHA1, MD5)`);
    }
  }
  if (!blocks.length) return '// Add IP addresses, domains or hashes to build a query.';
  const body = blocks.length === 1 ? blocks[0].replace(/\n {4}/g, '\n') : `union isfuzzy=true\n  (${blocks.join('),\n  (')})`;
  return `// ${oneLine(title)}
${lets.join('\n')}
${body}
| project Timestamp, DeviceName, IocType, MatchedIoc, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc`;
}

// Splunk: CIM field names plus the Sysmon add-on's fields. Note Splunk gives OR higher
// precedence than the implicit AND, so every group is parenthesised explicitly.
function spl(i: ExtractedIocs, title: string): string {
  const terms: string[] = [];
  if (i.ips.length) {
    const ips = i.ips.join(', ');
    terms.push(`src IN (${ips}) OR src_ip IN (${ips}) OR dest IN (${ips}) OR dest_ip IN (${ips}) OR DestinationIp IN (${ips})`);
  }
  if (i.domains.length) {
    const doms = i.domains.flatMap(d => [q(d), q(`*.${d}`)]).join(', ');
    terms.push(`query IN (${doms}) OR QueryName IN (${doms}) OR url_domain IN (${doms}) OR dest IN (${doms})`);
  }
  const hashes = [...i.md5, ...i.sha1, ...i.sha256];
  if (hashes.length) {
    terms.push(`file_hash IN (${hashes.join(', ')}) OR Hashes IN (${hashes.map(h => q(`*${h}*`)).join(', ')})`);
  }
  if (!terms.length) return '``` Add IP addresses, domains or hashes to build a query. ```';
  return `\`\`\` ${oneLine(title).replace(/`/g, "'")} \`\`\`
index=* earliest=-7d (${terms.map(t => `(${t})`).join(' OR ')})
| table _time, index, sourcetype, host, user, src, src_ip, dest, dest_ip, query, QueryName, url_domain, file_hash, Hashes
| sort - _time`;
}

// Elastic Common Schema, Lucene syntax (Kibana: switch the query bar language to Lucene)
function elastic(i: ExtractedIocs): string {
  const terms: string[] = [];
  if (i.ips.length) {
    const ips = i.ips.map(q).join(' OR ');
    terms.push(`source.ip:(${ips})`, `destination.ip:(${ips})`);
  }
  if (i.domains.length) {
    const doms = i.domains.flatMap(d => [q(d), `*.${d.replace(/-/g, '\\-')}`]).join(' OR ');
    terms.push(`dns.question.name:(${doms})`, `url.domain:(${doms})`, `destination.domain:(${doms})`);
  }
  for (const [algo, vs] of [['md5', i.md5], ['sha1', i.sha1], ['sha256', i.sha256]] as const) {
    if (!vs.length) continue;
    const hs = vs.map(q).join(' OR ');
    terms.push(`file.hash.${algo}:(${hs})`, `process.hash.${algo}:(${hs})`);
  }
  return terms.length ? terms.join('\nOR ') : '';
}

// One Sigma rule per indicator type, because each needs a different log source
function sigma(i: ExtractedIocs, title: string, today: string, uuid: () => string): string {
  const rules: string[] = [];
  const t = oneLine(title) || 'IOC match';
  const yamlList = (vs: string[], indent: string) => vs.map(v => `${indent}- '${v}'`).join('\n');
  const header = (suffix: string, description: string, category: string) =>
    `title: ${JSON.stringify(`${t} (${suffix})`)}
id: ${uuid()}
status: experimental
description: ${JSON.stringify(description)}
author: Cyber Tools Portal
date: ${today}
logsource:
    category: ${category}
    product: windows`;
  if (i.ips.length) {
    rules.push(`${header('IP addresses', 'Detects network connections to listed IP addresses.', 'network_connection')}
detection:
    selection:
        DestinationIp:
${yamlList(i.ips, '            ')}
    condition: selection
falsepositives:
    - Shared hosting or CDN addresses
level: high`);
  }
  if (i.domains.length) {
    rules.push(`${header('domains', 'Detects DNS queries for listed domains and their subdomains.', 'dns_query')}
detection:
    selection_exact:
        QueryName:
${yamlList(i.domains, '            ')}
    selection_subdomain:
        QueryName|endswith:
${yamlList(i.domains.map(d => `.${d}`), '            ')}
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high`);
  }
  const hashes = [...i.md5, ...i.sha1, ...i.sha256];
  if (hashes.length) {
    rules.push(`${header('file hashes', 'Detects processes whose image hash matches a listed hash (Sysmon Hashes field).', 'process_creation')}
detection:
    selection:
        Hashes|contains:
${yamlList(hashes, '            ')}
    condition: selection
falsepositives:
    - Unknown
level: high`);
  }
  return rules.length ? rules.join('\n---\n') : '# Add IP addresses, domains or hashes to build a rule.';
}

// IBM QRadar AQL. Domains and hashes have no standard QRadar property, so they are matched
// against the raw payload, which works everywhere but is slow on large time ranges.
function qradar(i: ExtractedIocs): string {
  const conds: string[] = [];
  for (const ip of i.ips) conds.push(`sourceip = '${ip}' OR destinationip = '${ip}'`);
  for (const v of [...i.domains, ...i.md5, ...i.sha1, ...i.sha256]) conds.push(`UTF8(payload) ILIKE '%${v}%'`);
  if (!conds.length) return '';
  return `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Start Time", QIDNAME(qid) AS "Event Name", LOGSOURCENAME(logsourceid) AS "Log Source", sourceip, destinationip, destinationport, username
FROM events
WHERE ${conds.join('\n   OR ')}
ORDER BY starttime DESC
LAST 7 DAYS`;
}

export const PLATFORM_NOTES: Record<SiemPlatform, string> = {
  kql: 'Defender for Endpoint tables: works in Defender XDR advanced hunting, or in Sentinel with the Defender XDR connector. Looks back 7 days.',
  spl: 'Searches all indexes for 7 days using CIM and Sysmon add-on field names. Narrow index= to your data for speed.',
  elastic: 'Elastic Common Schema fields, Lucene syntax. In Kibana, switch the query language to Lucene and set the time range in the picker.',
  sigma: 'One rule per indicator type, separated by ---, because each needs a different log source. Convert with sigma-cli for your backend.',
  qradar: 'IPs use the standard properties. Domains and hashes are matched in the raw payload (no standard property exists), which is slow over long ranges.',
};

export function buildQueries(iocs: ExtractedIocs, title: string, now = new Date()): Record<SiemPlatform, string> {
  const uuid = () =>
    typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : '00000000-0000-4000-8000-000000000000';
  return {
    kql: kql(iocs, title),
    spl: spl(iocs, title),
    elastic: elastic(iocs) || 'Add IP addresses, domains or hashes to build a query.',
    sigma: sigma(iocs, title, now.toISOString().slice(0, 10), uuid),
    qradar: qradar(iocs) || 'Add IP addresses, domains or hashes to build a query.',
  };
}
