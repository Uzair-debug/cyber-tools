import PostalMime from 'postal-mime';
import { AuthVerdict, ExtractedAttachment, ExtractedUrl, ParsedEmailData, ReceivedHop } from './types';
import { computeHashes } from './crypto-utils';
import { defangText } from './defang';
import { calculatePhishingRisk } from './phishing-scorer';

const MAX_URLS = 200;

export async function parseEmailContent(rawInput: string | ArrayBuffer): Promise<ParsedEmailData> {
  if (typeof rawInput !== 'string' && isOleCompoundFile(rawInput)) {
    throw new Error(
      'This looks like an Outlook .msg file, which this tool cannot read. In Outlook, save the message as .eml, or copy the headers from File > Properties > Internet headers and paste them here.'
    );
  }

  const parser = new PostalMime();
  const parsed: any = await parser.parse(rawInput);

  // Raw header parsing and fallback
  const rawText = typeof rawInput === 'string' ? rawInput : new TextDecoder().decode(rawInput);
  const rawHeaders = parseRawHeaderLines(rawText);
  if (Object.keys(rawHeaders).length === 0) {
    throw new Error('No email headers were found. Paste the full message source or its internet headers, starting with lines such as "Received:" or "From:".');
  }

  // Extract from, to, cc, reply-to
  const from = {
    name: parsed.from?.name || '',
    address: parsed.from?.address || extractEmailFromHeader(rawHeaders['from'] || ''),
  };

  const to = (parsed.to || []).map((t: any) => ({
    name: t.name || '',
    address: t.address || '',
  }));

  const cc = (parsed.cc || []).map((c: any) => ({
    name: c.name || '',
    address: c.address || '',
  }));

  let replyTo: { name: string; address: string } | undefined = undefined;
  if (parsed.replyTo && parsed.replyTo.length > 0) {
    replyTo = {
      name: parsed.replyTo[0].name || '',
      address: parsed.replyTo[0].address || '',
    };
  } else if (rawHeaders['reply-to']) {
    replyTo = {
      name: '',
      address: extractEmailFromHeader(rawHeaders['reply-to']),
    };
  }

  const subject = parsed.subject || getHeaderValue(rawHeaders, 'subject') || '(No Subject)';
  // Left empty when the message has no Date header, never filled with the current time
  const date = parsed.date || getHeaderValue(rawHeaders, 'date') || '';
  const messageId = parsed.messageId || getHeaderValue(rawHeaders, 'message-id') || '';
  const returnPath = getHeaderValue(rawHeaders, 'return-path') || '';
  // The topmost Authentication-Results header is the one added by the final receiving server
  const authResults = getHeaderValue(rawHeaders, 'authentication-results') || '';

  // SPF, DKIM and DMARC are read from what the receiving server recorded, not re-checked here
  const spf = parseSpfVerdict(rawHeaders, authResults);
  const dkim = parseDkimVerdict(rawHeaders, authResults);
  const dmarc = parseDmarcVerdict(authResults);

  // Parse Received Hops
  const hops = parseReceivedHops(rawHeaders);

  // Extract URLs from body
  const bodyText = parsed.text || '';
  const bodyHtml = parsed.html || '';
  const { urls, total: urlTotal } = extractUrlsFromBody(bodyText, bodyHtml);

  // Extract attachments and compute MD5/SHA-256 hashes
  const attachments: ExtractedAttachment[] = [];
  if (parsed.attachments && Array.isArray(parsed.attachments)) {
    for (const att of parsed.attachments) {
      let hashes = { md5: '', sha1: '', sha256: '', sha512: '' };
      if (att.content) {
        hashes = await computeHashes(att.content);
      }
      const filename = att.filename || '(no filename)';

      attachments.push({
        filename,
        mimeType: att.mimeType || 'Not specified',
        size: att.content ? att.content.byteLength || att.content.length || 0 : 0,
        md5: hashes.md5,
        sha256: hashes.sha256,
        isDangerousExt: att.filename ? isDangerousFilename(att.filename) : false,
      });
    }
  }

  // Calculate Phishing Risk
  const riskAnalysis = calculatePhishingRisk({
    fromAddress: from.address,
    fromName: from.name,
    replyToAddress: replyTo?.address,
    returnPath,
    subject,
    bodyText,
    spf,
    dkim,
    dmarc,
    urls,
    attachments,
  });

  return {
    subject,
    from,
    to,
    cc,
    replyTo,
    date,
    messageId,
    returnPath,
    hops,
    spf,
    dkim,
    dmarc,
    authResults,
    phishingScore: riskAnalysis.score,
    phishingRiskLevel: riskAnalysis.riskLevel,
    phishingIndicators: riskAnalysis.indicators,
    urls,
    attachments,
    bodyText,
    bodyHtml,
    rawHeaders,
    urlTotal,
  };
}

// Outlook .msg files are OLE compound documents, which postal-mime cannot read
function isOleCompoundFile(buffer: ArrayBuffer): boolean {
  const sig = new Uint8Array(buffer.slice(0, 8));
  return [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((b, i) => sig[i] === b);
}

function parseRawHeaderLines(rawEmail: string): Record<string, string | string[]> {
  const headers: Record<string, string | string[]> = {};
  const headerSection = rawEmail.replace(/^\s+/, '').split(/\r?\n\r?\n/)[0] || '';
  const lines = headerSection.split(/\r?\n/);

  let currentKey = '';
  let currentValue = '';

  for (const line of lines) {
    if (/^\s+/.test(line)) {
      // Continuation line
      currentValue += ' ' + line.trim();
    } else {
      if (currentKey) {
        saveHeader(headers, currentKey.toLowerCase(), currentValue.trim());
      }
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0 && !/\s/.test(line.substring(0, colonIndex).trim())) {
        currentKey = line.substring(0, colonIndex).trim();
        currentValue = line.substring(colonIndex + 1).trim();
      } else {
        currentKey = '';
        currentValue = '';
      }
    }
  }

  if (currentKey) {
    saveHeader(headers, currentKey.toLowerCase(), currentValue.trim());
  }

  return headers;
}

function saveHeader(headers: Record<string, string | string[]>, key: string, value: string) {
  if (headers[key]) {
    if (Array.isArray(headers[key])) {
      (headers[key] as string[]).push(value);
    } else {
      headers[key] = [headers[key] as string, value];
    }
  } else {
    headers[key] = value;
  }
}

function getHeaderValue(headers: Record<string, string | string[]>, key: string): string {
  const val = headers[key.toLowerCase()];
  if (!val) return '';
  if (Array.isArray(val)) return val[0];
  return val;
}

function extractEmailFromHeader(header: string | string[]): string {
  const str = Array.isArray(header) ? header[0] : header;
  const match = str.match(/<([^>]+@[^>]+)>/) || str.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1] : '';
}

interface MethodResult {
  result: string;
  props: string;
}

// Every "method=result ..." clause for one method in an Authentication-Results value (RFC 8601)
function methodResults(authResults: string, method: string): MethodResult[] {
  const out: MethodResult[] = [];
  const re = new RegExp(`(?:^|[;\\s])${method}=([a-z]+)([^;]*)`, 'gi');
  let m: RegExpExecArray | null;
  while ((m = re.exec(authResults))) {
    out.push({ result: m[1].toLowerCase(), props: m[2] });
  }
  return out;
}

function propValue(props: string, name: string): string {
  const m = props.match(new RegExp(`\\b${name.replace('.', '\\.')}=([^\\s;()]+)`, 'i'));
  return m ? m[1].replace(/^<|>$/g, '') : '';
}

function domainOf(value: string): string {
  const d = value.includes('@') ? value.split('@').pop() || '' : value;
  return d.toLowerCase() === 'none' ? '' : d;
}

function parseSpfVerdict(headers: Record<string, string | string[]>, authResults: string): AuthVerdict {
  const receivedSpf = getHeaderValue(headers, 'received-spf');
  const fromAuth = methodResults(authResults, 'spf')[0];

  let result = '';
  let domain = '';
  let rawHeader = '';
  if (fromAuth) {
    result = fromAuth.result;
    domain = domainOf(propValue(fromAuth.props, 'smtp.mailfrom') || propValue(fromAuth.props, 'smtp.helo'));
    rawHeader = authResults;
  } else if (receivedSpf) {
    result = (receivedSpf.match(/^\s*([a-z]+)/i)?.[1] || '').toLowerCase();
    domain = domainOf(propValue(receivedSpf, 'envelope-from'));
    rawHeader = receivedSpf;
  }

  if (!result) {
    return { status: 'missing', details: 'No SPF result found in the headers.' };
  }

  const record = domain ? `the SPF record for ${domain}` : 'the SPF record';
  switch (result) {
    case 'pass':
      return { status: 'pass', details: `The receiving server reports the sending IP is authorised by ${record}.`, rawHeader };
    case 'fail':
      return { status: 'fail', details: `The receiving server reports the sending IP is not authorised by ${record} (hard fail, -all).`, rawHeader };
    case 'softfail':
      return { status: 'softfail', details: `The receiving server reports ${record} marks the sending IP as probably not authorised (soft fail, ~all).`, rawHeader };
    case 'neutral':
      return { status: 'neutral', details: `${capitalise(record)} makes no statement about the sending IP (neutral, ?all).`, rawHeader };
    case 'none':
      return { status: 'none', details: domain ? `${domain} has no SPF record.` : 'No SPF record was found for the sending domain.', rawHeader };
    case 'temperror':
      return { status: 'temperror', details: `The receiving server hit a temporary DNS error checking ${record}.`, rawHeader };
    case 'permerror':
      return { status: 'permerror', details: `${capitalise(record)} could not be evaluated (permanent error, usually a broken record).`, rawHeader };
    default:
      return { status: 'neutral', details: `Unrecognised SPF result "${result}".`, rawHeader };
  }
}

function parseDkimVerdict(headers: Record<string, string | string[]>, authResults: string): AuthVerdict {
  const results = methodResults(authResults, 'dkim');
  const dkimSig = getHeaderValue(headers, 'dkim-signature');

  if (results.length === 0) {
    if (dkimSig) {
      const d = dkimSig.match(/(?:^|[;\s])d=([^;\s]+)/)?.[1];
      return {
        status: 'missing',
        details: `A DKIM-Signature${d ? ` for ${d}` : ''} is present, but the headers hold no verification result. This tool does not verify signatures itself.`,
        rawHeader: dkimSig,
      };
    }
    return { status: 'missing', details: 'No DKIM result or DKIM-Signature found in the headers.' };
  }

  const signer = (r: MethodResult) => domainOf(propValue(r.props, 'header.d') || propValue(r.props, 'header.i'));
  const signers = (rs: MethodResult[]) => Array.from(new Set(rs.map(signer).filter(Boolean))).join(', ');

  const passed = results.filter(r => r.result === 'pass');
  if (passed.length > 0) {
    const others = results.length - passed.length;
    const by = signers(passed);
    return {
      status: 'pass',
      details: `Signature verified${by ? ` for ${by}` : ''}.${others > 0 ? ` ${others} other signature${others === 1 ? '' : 's'} did not verify.` : ''}`,
      rawHeader: authResults,
    };
  }

  // No signature passed, so report the most serious result
  const order = ['fail', 'permerror', 'policy', 'temperror', 'neutral', 'none'];
  const worst = [...results].sort((a, b) => rank(order, a.result) - rank(order, b.result))[0];
  const by = signer(worst);
  const sig = by ? `The signature for ${by}` : 'The signature';
  switch (worst.result) {
    case 'fail':
      return { status: 'fail', details: `${sig} did not verify. The message may have been changed after signing, or the signature is not valid.`, rawHeader: authResults };
    case 'permerror':
      return { status: 'permerror', details: `${sig} could not be verified (permanent error, such as a missing or malformed key).`, rawHeader: authResults };
    case 'policy':
      return { status: 'policy', details: `${sig} was rejected by the receiving server's policy (for example a weak key).`, rawHeader: authResults };
    case 'temperror':
      return { status: 'temperror', details: `${sig} could not be checked because of a temporary error fetching the key.`, rawHeader: authResults };
    case 'neutral':
      return { status: 'neutral', details: `${sig} could not be verified (neutral).`, rawHeader: authResults };
    case 'none':
      return { status: 'none', details: 'The receiving server reports the message was not DKIM-signed.', rawHeader: authResults };
    default:
      return { status: 'neutral', details: `Unrecognised DKIM result "${worst.result}".`, rawHeader: authResults };
  }
}

function parseDmarcVerdict(authResults: string): AuthVerdict {
  const r = methodResults(authResults, 'dmarc')[0];
  if (!r) {
    return { status: 'missing', details: 'No DMARC result found in the headers.' };
  }

  const fromDomain = propValue(r.props, 'header.from');
  const subject = fromDomain ? `The From domain ${fromDomain}` : 'The From domain';
  const policy = propValue(r.props, 'p');
  const action = propValue(r.props, 'action') || propValue(r.props, 'dis');
  const compauth = methodResults(authResults, 'compauth')[0];
  const reason = compauth ? propValue(compauth.props, 'reason') : '';

  const extra =
    (policy ? ` Published policy: p=${policy.toLowerCase()}.` : '') +
    (action ? ` Receiver action: ${action.toLowerCase()}.` : '') +
    (compauth ? ` Microsoft composite authentication: ${compauth.result}${reason ? ` (reason ${reason})` : ''}.` : '');

  switch (r.result) {
    case 'pass':
      return { status: 'pass', details: `${subject} passed DMARC: SPF or DKIM passed for a domain aligned with the From address.${extra}`, rawHeader: authResults };
    case 'fail':
      return { status: 'fail', details: `${subject} failed DMARC: neither SPF nor DKIM passed for a domain aligned with the From address.${extra}`, rawHeader: authResults };
    case 'none':
      return { status: 'none', details: `${subject} publishes no DMARC record.${extra}`, rawHeader: authResults };
    case 'bestguesspass':
      return {
        status: 'none',
        details: `${subject} publishes no DMARC record. Microsoft reports the message would have passed if it did (bestguesspass).${extra}`,
        rawHeader: authResults,
      };
    case 'temperror':
      return { status: 'temperror', details: `The receiving server hit a temporary error checking DMARC.${extra}`, rawHeader: authResults };
    case 'permerror':
      return { status: 'permerror', details: `The DMARC record could not be evaluated (permanent error).${extra}`, rawHeader: authResults };
    default:
      return { status: 'neutral', details: `Unrecognised DMARC result "${r.result}".${extra}`, rawHeader: authResults };
  }
}

function rank(order: string[], value: string): number {
  const i = order.indexOf(value);
  return i === -1 ? order.length : i;
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function parseReceivedHops(headers: Record<string, string | string[]>): ReceivedHop[] {
  const receivedRaw = headers['received'];
  if (!receivedRaw) return [];

  const hopLines = Array.isArray(receivedRaw) ? receivedRaw : [receivedRaw];
  // Hops are listed from newest (destination) to oldest (originator). We reverse them so hop 1 is the sender
  const chronological = [...hopLines].reverse();
  const hops: ReceivedHop[] = [];

  let prevTime: number | null = null;

  chronological.forEach((raw, index) => {
    // The date always follows the last semicolon (RFC 5322)
    const semi = raw.lastIndexOf(';');
    const clauses = semi >= 0 ? raw.slice(0, semi) : raw;
    const dateStr = semi >= 0 ? raw.slice(semi + 1).trim() : '';

    const fromMatch = clauses.match(/^\s*from\s+(\S+(?:\s*\([^)]*\))?)/i);
    const fromSection = clauses.match(/^\s*from\s+([\s\S]*?)(?:\s+by\s|$)/i)?.[1] || '';
    const byMatch = clauses.match(/\bby\s+([^\s;()]+)/i);
    // Protocol can be several words ("Microsoft SMTP Server"), so read up to the next clause or comment
    const withMatch = clauses.match(/\bwith\s+([^;()]+?)(?=\s*\(|\s+id\s|\s+via\s|\s+for\s|$)/i);

    // Only the "from" part names the sending side's IP; the "by" part is the receiving server
    const ip = extractIp(fromSection);

    let timestamp = dateStr;
    let delaySec: number | null = null;

    if (dateStr) {
      const parsedDate = new Date(dateStr.replace(/\s*\([^)]*\)\s*$/, ''));
      if (!isNaN(parsedDate.getTime())) {
        timestamp = parsedDate.toUTCString();
        if (prevTime !== null) {
          delaySec = Math.round((parsedDate.getTime() - prevTime) / 1000);
        }
        prevTime = parsedDate.getTime();
      }
    }

    hops.push({
      hopNumber: index + 1,
      from: fromMatch ? fromMatch[1].trim() : '',
      by: byMatch ? byMatch[1].trim() : '',
      with: withMatch ? withMatch[1].trim() : '',
      timestamp,
      delaySec,
      ip,
      isPrivateIp: ip ? isPrivateIp(ip) : false,
      raw,
    });
  });

  return hops;
}

function extractIp(section: string): string {
  const bracketed = section.match(/\[(?:IPv6:)?([0-9a-fA-F:.]+)\]/);
  if (bracketed && isIpLiteral(bracketed[1])) return bracketed[1];
  const v4 = section.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  if (v4 && isIpLiteral(v4[1])) return v4[1];
  const v6 = section.match(/(?:^|[\s(])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?=[\s)\]]|$)/);
  if (v6 && isIpLiteral(v6[1])) return v6[1];
  return '';
}

function isIpLiteral(value: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every(p => Number(p) <= 255);
  }
  return value.includes(':') && /^[0-9a-fA-F:.]+$/.test(value) && /[0-9a-fA-F]/.test(value);
}

function extractUrlsFromBody(text: string, html: string): { urls: ExtractedUrl[]; total: number } {
  const combined = `${text}\n${html.replace(/&amp;/gi, '&')}`;
  const urlRegex = /\bhttps?:\/\/[^\s<>"'`)]+[^\s<>"'`).,;]/gi;
  const matches = Array.from(new Set(combined.match(urlRegex) || []));

  const urls = matches.slice(0, MAX_URLS).map(url => {
    let domain = '';
    let hasUserInfo = false;
    try {
      const parsedUrl = new URL(url);
      domain = parsedUrl.hostname;
      hasUserInfo = Boolean(parsedUrl.username || parsedUrl.password);
    } catch {
      domain = url;
    }

    const host = domain.toLowerCase();
    const reasons: string[] = [];
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
      reasons.push('IP address instead of a domain name');
    }
    const shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'rb.gy', 'cutt.ly', 'buff.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly'];
    if (shorteners.includes(host)) {
      reasons.push('URL shortener hides the real destination');
    }
    const suspiciousTlds = ['.xyz', '.top', '.buzz', '.work', '.click', '.loan', '.icu', '.monster'];
    const tld = suspiciousTlds.find(t => host.endsWith(t));
    if (tld) {
      reasons.push(`Top-level domain often seen in abuse (${tld})`);
    }
    if (host.split('.').some(label => label.startsWith('xn--'))) {
      reasons.push('Punycode domain, check for lookalike characters');
    }
    if (hasUserInfo) {
      reasons.push('Text before "@" in the link disguises the real host');
    }

    return {
      original: url,
      defanged: defangText(url),
      domain,
      isSuspicious: reasons.length > 0,
      reasons,
    };
  });

  return { urls, total: matches.length };
}

function isDangerousFilename(filename: string): boolean {
  const dangerousExtensions = [
    '.exe', '.bat', '.scr', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.cmd', '.com', '.pif', '.ps1', '.jar', '.msi', '.dll', '.cpl', '.lnk',
    '.iso', '.img', '.vhd', '.vhdx', '.one', '.chm', '.xll', '.docm', '.xlsm', '.pptm', '.htm', '.html', '.svg',
  ];
  return dangerousExtensions.some(ext => filename.toLowerCase().trim().endsWith(ext));
}

function isPrivateIp(ip: string): boolean {
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    return lower === '::1' || /^fe[89ab]/.test(lower) || /^f[cd]/.test(lower);
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    parts[0] === 0 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
  );
}
