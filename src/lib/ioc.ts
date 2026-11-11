// Pulls indicators out of free text (logs, reports, incident notes), defanged or not.
// Used by the IOC Extractor.

import { refangText } from '@/lib/defang';
import { classifyIpv4 } from '@/lib/ip-class';

export interface ExtractedIocs {
  ips: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  cves: string[];
  md5s: string[];
  sha1s: string[];
  sha256s: string[];
}

export interface ExtractOptions {
  dedup?: boolean;
  publicIpsOnly?: boolean;
}

const IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\.?\d)/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const URL_TOKEN = /\b(?:https?|ftp):\/\/[^\s<>"'`]+/gi;
const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const MD5 = /\b[a-fA-F0-9]{32}\b/g;
const SHA1 = /\b[a-fA-F0-9]{40}\b/g;
const SHA256 = /\b[a-fA-F0-9]{64}\b/g;
const DOMAIN = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;

// File names look like domains. A few extensions are also real TLDs (.zip, .sh, .py), but in
// logs and reports they are far more often files.
const FILE_NAME = /\.(exe|dll|sys|msi|bat|cmd|ps1|psm1|vbs|lnk|jar|bin|dat|tmp|iso|img|zip|rar|tar|gz|sh|py|php|asp|aspx|html|htm|js|css|json|xml|yml|yaml|ini|cfg|conf|log|txt|csv|md|pdf|doc|docx|xls|xlsx|ppt|pptx|png|jpg|jpeg|gif|svg)$/i;

const CLOSERS: Record<string, string> = { ')': '(', ']': '[', '}': '{' };
const count = (s: string, ch: string) => s.split(ch).length - 1;

// Drops sentence punctuation and unmatched closing brackets picked up after a URL
function trimUrl(raw: string): string {
  let url = raw;
  for (;;) {
    const last = url[url.length - 1];
    if ('.,;:!?'.includes(last)) url = url.slice(0, -1);
    else if (CLOSERS[last] && count(url, last) > count(url, CLOSERS[last])) url = url.slice(0, -1);
    else return url;
  }
}

export function extractIocs(text: string, options: ExtractOptions = {}): ExtractedIocs {
  const { dedup = true, publicIpsOnly = false } = options;
  const normalized = refangText(text);
  const all = (re: RegExp, source = normalized) => source.match(re) || [];

  const urls = all(URL_TOKEN).map(trimUrl);
  const emails = all(EMAIL);

  // Hosts inside URLs and email addresses are already reported there, so only bare mentions count
  const remainder = normalized.replace(URL_TOKEN, ' ').replace(EMAIL, ' ');
  const domains = all(DOMAIN, remainder)
    .filter(d => !FILE_NAME.test(d))
    .map(d => d.toLowerCase());

  const ips = all(IPV4).filter(ip => !publicIpsOnly || classifyIpv4(ip) === 'public');

  const result: ExtractedIocs = {
    ips,
    domains,
    urls,
    emails,
    cves: all(CVE).map(c => c.toUpperCase()),
    md5s: all(MD5).map(h => h.toLowerCase()),
    sha1s: all(SHA1).map(h => h.toLowerCase()),
    sha256s: all(SHA256).map(h => h.toLowerCase()),
  };

  if (dedup) {
    for (const key of Object.keys(result) as (keyof ExtractedIocs)[]) {
      result[key] = Array.from(new Set(result[key]));
    }
  }
  return result;
}
