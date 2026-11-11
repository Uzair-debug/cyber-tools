// Threat Intelligence Pivot Engines & IOC Classifier

import { defangText, refangText } from '@/lib/defang';

export type IocType = 'IPV4' | 'IPV6' | 'DOMAIN' | 'URL' | 'MD5' | 'SHA1' | 'SHA256' | 'CVE' | 'UNKNOWN';

export interface IntelEngine {
  id: string;
  name: string;
  category: 'Reputation & Malware' | 'Infrastructure & Scanners' | 'Enterprise Threat Intel';
  description: string;
  supportedTypes: IocType[];
  badgeColor: string;
  buildUrl: (ioc: string, type: IocType) => string;
}

// 1. Classifier
export function classifyIoc(rawInput: string): IocType {
  const ioc = refangText(rawInput).trim();
  if (!ioc) return 'UNKNOWN';

  // IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(ioc)) return 'IPV4';

  // IPv6
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  if (ipv6Regex.test(ioc)) return 'IPV6';

  // Hashes
  if (/^[a-fA-F0-9]{32}$/.test(ioc)) return 'MD5';
  if (/^[a-fA-F0-9]{40}$/.test(ioc)) return 'SHA1';
  if (/^[a-fA-F0-9]{64}$/.test(ioc)) return 'SHA256';

  // CVE
  if (/^CVE-\d{4}-\d{4,7}$/i.test(ioc)) return 'CVE';

  // URL
  if (/^https?:\/\/\S+$/i.test(ioc) || /^[^\s/]+\.[a-z]{2,}\/\S*$/i.test(ioc)) return 'URL';

  // Domain
  if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(ioc)) return 'DOMAIN';

  return 'UNKNOWN';
}

// 2. Defanger
export function defangIoc(raw: string): string {
  const ioc = refangText(raw).trim();
  return classifyIoc(ioc) === 'IPV6' ? ioc.replace(/:/g, '[:]') : defangText(ioc);
}

// 3. Threat Intel Engines Matrix
export const INTEL_ENGINES: IntelEngine[] = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    category: 'Reputation & Malware',
    description: 'Crowdsourced multi-antivirus scanning, sandbox detonation & community comments.',
    supportedTypes: ['IPV4', 'IPV6', 'DOMAIN', 'URL', 'MD5', 'SHA1', 'SHA256'],
    badgeColor: 'bg-blue-950/80 border-blue-600 text-blue-300',
    buildUrl: (ioc, type) => {
      const clean = encodeURIComponent(ioc.trim());
      if (type === 'IPV4' || type === 'IPV6') return `https://www.virustotal.com/gui/ip-address/${clean}`;
      if (type === 'DOMAIN') return `https://www.virustotal.com/gui/domain/${clean}`;
      // Search rather than gui/url/<id>: report ids need VirusTotal's own URL canonicalisation.
      // Encoded twice so the URL's slashes survive as a single path segment.
      if (type === 'URL') return `https://www.virustotal.com/gui/search/${encodeURIComponent(clean)}`;
      return `https://www.virustotal.com/gui/file/${clean}`;
    },
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    category: 'Reputation & Malware',
    description: 'Community-reported malicious IP database tracking brute-force, spam & port scanning.',
    supportedTypes: ['IPV4', 'IPV6'],
    badgeColor: 'bg-red-950/80 border-red-600 text-red-300',
    buildUrl: (ioc) => `https://www.abuseipdb.com/check/${encodeURIComponent(ioc.trim())}`,
  },
  {
    id: 'alienvault',
    name: 'AlienVault OTX',
    category: 'Reputation & Malware',
    description: 'Open Threat Exchange pulses, adversary campaigns, and associated malware indicators.',
    supportedTypes: ['IPV4', 'IPV6', 'DOMAIN', 'URL', 'MD5', 'SHA1', 'SHA256', 'CVE'],
    badgeColor: 'bg-purple-950/80 border-purple-600 text-purple-300',
    buildUrl: (ioc, type) => {
      const clean = encodeURIComponent(ioc.trim());
      if (type === 'IPV4' || type === 'IPV6') return `https://otx.alienvault.com/indicator/ip/${clean}`;
      if (type === 'DOMAIN') return `https://otx.alienvault.com/indicator/domain/${clean}`;
      if (type === 'URL') return `https://otx.alienvault.com/indicator/url/${clean}`;
      if (type === 'CVE') return `https://otx.alienvault.com/indicator/cve/${clean}`;
      return `https://otx.alienvault.com/indicator/file/${clean}`;
    },
  },
  {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    category: 'Reputation & Malware',
    description: 'Database of active malicious URLs distributing malware and botnet loaders.',
    supportedTypes: ['URL', 'DOMAIN', 'IPV4', 'SHA256', 'MD5'],
    badgeColor: 'bg-amber-950/80 border-amber-600 text-amber-300',
    buildUrl: (ioc, type) => {
      const clean = encodeURIComponent(ioc.trim());
      if (type === 'URL') return `https://urlhaus.abuse.ch/browse.php?search=${clean}`;
      if (type === 'DOMAIN' || type === 'IPV4') return `https://urlhaus.abuse.ch/host/${clean}/`;
      return `https://urlhaus.abuse.ch/browse.php?search=${clean}`;
    },
  },
  {
    id: 'threatfox',
    name: 'ThreatFox (abuse.ch)',
    category: 'Reputation & Malware',
    description: 'Free platform for sharing indicators of compromise (IOCs) associated with malware.',
    supportedTypes: ['IPV4', 'DOMAIN', 'URL', 'SHA256', 'MD5'],
    badgeColor: 'bg-orange-950/80 border-orange-600 text-orange-300',
    buildUrl: (ioc) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(ioc.trim())}`,
  },
  {
    id: 'shodan',
    name: 'Shodan',
    category: 'Infrastructure & Scanners',
    description: 'Search engine for Internet-connected devices, open ports, banners & vulnerabilities.',
    supportedTypes: ['IPV4', 'IPV6', 'DOMAIN'],
    badgeColor: 'bg-red-950/80 border-red-500 text-red-300',
    buildUrl: (ioc) => `https://www.shodan.io/host/${encodeURIComponent(ioc.trim())}`,
  },
  {
    id: 'censys',
    name: 'Censys Search',
    category: 'Infrastructure & Scanners',
    description: 'Continuous Internet attack surface visibility, SSL certificates & host profiling.',
    supportedTypes: ['IPV4', 'IPV6', 'DOMAIN', 'SHA256'],
    badgeColor: 'bg-cyan-950/80 border-cyan-600 text-cyan-300',
    buildUrl: (ioc, type) => {
      const clean = encodeURIComponent(ioc.trim());
      if (type === 'IPV4' || type === 'IPV6') return `https://search.censys.io/hosts/${clean}`;
      if (type === 'DOMAIN') return `https://search.censys.io/certificates?q=${clean}`;
      return `https://search.censys.io/certificates/${clean}`;
    },
  },
  {
    id: 'greynoise',
    name: 'GreyNoise Visualizer',
    category: 'Infrastructure & Scanners',
    description: 'Analyzes Internet-wide scan noise, benign crawlers, and malicious opportunistic exploits.',
    supportedTypes: ['IPV4'],
    badgeColor: 'bg-slate-900 border-slate-600 text-slate-300',
    buildUrl: (ioc) => `https://viz.greynoise.io/ip/${encodeURIComponent(ioc.trim())}`,
  },
  {
    id: 'bgphe',
    name: 'Hurricane Electric BGP (he.net)',
    category: 'Infrastructure & Scanners',
    description: 'Autonomous System (ASN), BGP routing prefixes, IP WHOIS & peering graph.',
    supportedTypes: ['IPV4', 'IPV6', 'DOMAIN'],
    badgeColor: 'bg-emerald-950/80 border-emerald-600 text-emerald-300',
    buildUrl: (ioc) => `https://bgp.he.net/ip/${encodeURIComponent(ioc.trim())}`,
  },
  {
    id: 'talos',
    name: 'Cisco Talos Intelligence',
    category: 'Enterprise Threat Intel',
    description: 'Global threat intelligence, IP reputation score, email volume & DNS categorization.',
    supportedTypes: ['IPV4', 'IPV6', 'DOMAIN'],
    badgeColor: 'bg-blue-950/80 border-sky-600 text-sky-300',
    buildUrl: (ioc) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(ioc.trim())}`,
  },
  {
    id: 'nvd',
    name: 'NIST NVD (CVE Database)',
    category: 'Enterprise Threat Intel',
    description: 'National Vulnerability Database official vulnerability records and CVSS vectors.',
    supportedTypes: ['CVE'],
    badgeColor: 'bg-rose-950/80 border-rose-600 text-rose-300',
    buildUrl: (ioc) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(ioc.trim().toUpperCase())}`,
  },
  {
    id: 'malwarebazaar',
    name: 'MalwareBazaar (abuse.ch)',
    category: 'Reputation & Malware',
    description: 'Malware sample repository and hash analysis lookup.',
    supportedTypes: ['MD5', 'SHA1', 'SHA256'],
    badgeColor: 'bg-pink-950/80 border-pink-600 text-pink-300',
    buildUrl: (ioc) => `https://bazaar.abuse.ch/sample/${encodeURIComponent(ioc.trim())}/`,
  },
];

export const PRESET_IOCS = [
  { label: '🔴 Suspicious C2 IP', ioc: '185.220.101.45', type: 'IPV4' },
  { label: '✉️ Phishing Lookalike Domain', ioc: 'login-microsoft-security-auth.top', type: 'DOMAIN' },
  { label: '🦠 Ransomware Hash (SHA256)', ioc: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', type: 'SHA256' },
  { label: '🛡️ Critical RCE (Log4j)', ioc: 'CVE-2021-44228', type: 'CVE' },
];
