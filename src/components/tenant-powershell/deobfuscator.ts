// PowerShell Deobfuscator & Security Inspector Engine

export interface DeobfuscationResult {
  originalScript: string;
  deobfuscatedScript: string;
  decodedBase64Payloads: string[];
  // NO_INDICATORS means no heuristic matched, not that the script is safe
  threatSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NO_INDICATORS';
  detectedIndicators: {
    title: string;
    description: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  }[];
  extractedIocs: {
    urls: string[];
    ips: string[];
    domains: string[];
    filePaths: string[];
  };
}

export function deobfuscatePowerShell(script: string): DeobfuscationResult {
  if (!script.trim()) {
    return {
      originalScript: '',
      deobfuscatedScript: '',
      decodedBase64Payloads: [],
      threatSeverity: 'NO_INDICATORS',
      detectedIndicators: [],
      extractedIocs: { urls: [], ips: [], domains: [], filePaths: [] },
    };
  }

  let working = script;
  const decodedBase64Payloads: string[] = [];
  const detectedIndicators: DeobfuscationResult['detectedIndicators'] = [];

  // 1. Detect & Decode Base64 Encoded Commands (-EncodedCommand, -enc, -e)
  const encRegex = /(?:-(?:encodedcommand|encode|enc|ec|e))\s+([A-Za-z0-9+/=]{8,})/gi;
  let match;
  while ((match = encRegex.exec(script)) !== null) {
    const rawB64 = match[1];
    try {
      const decoded = decodePowerShellBase64(rawB64);
      if (decoded && decoded.trim()) {
        decodedBase64Payloads.push(decoded);
        working = working.replace(match[0], () => `\n# --- DECODED BASE64 PAYLOAD ---\n${decoded}\n# ------------------------------\n`);
        detectedIndicators.push({
          title: 'Hidden Base64 Execution (-EncodedCommand)',
          description: 'Obfuscated command passed via Base64 to bypass command-line visibility and AMSI inspection.',
          severity: 'HIGH',
        });
      }
    } catch {
      // Ignore malformed base64
    }
  }

  // Also search for standalone base64 strings in FromBase64String(...)
  const fromB64Regex = /\[(?:System\.)?Convert\]::FromBase64String\(['"]([A-Za-z0-9+/=]{12,})['"]\)/gi;
  while ((match = fromB64Regex.exec(working)) !== null) {
    try {
      const decoded = decodePowerShellBase64(match[1]) || decodeAsciiBase64(match[1]);
      if (decoded) {
        decodedBase64Payloads.push(decoded);
        detectedIndicators.push({
          title: 'Inline Convert::FromBase64String Call',
          description: 'Script explicitly converts inline Base64 payload in memory.',
          severity: 'HIGH',
        });
      }
    } catch {}
  }

  // 2. Remove Backtick Obfuscation (`i`e`x -> iex)
  const backtickCount = (working.match(/`[a-zA-Z]/g) || []).length;
  if (backtickCount > 3) {
    detectedIndicators.push({
      title: 'Backtick Character Obfuscation',
      description: `Detected ${backtickCount} backtick escape characters used to disrupt static string detection.`,
      severity: 'MEDIUM',
    });
  }
  working = working.replace(/`([a-zA-Z0-9_\-$])/g, '$1');

  // 3. Resolve Character Codes: [char]0x41 or [char]65. Runs before concatenation so that
  // [char]73+[char]69+[char]88 can be joined into one string below.
  const charCodeRegex = /\[char\](?:0x([0-9a-fA-F]+)|([0-9]{1,5}))/gi;
  working = working.replace(charCodeRegex, (original, hex, dec) => {
    const code = hex ? parseInt(hex, 16) : parseInt(dec, 10);
    if (code > 0xffff) return original;
    const ch = String.fromCharCode(code);
    return ch === "'" ? `"'"` : `'${ch}'`;
  });

  // 4. Resolve String Concatenations ('d'+'o'+'w'+'n' -> download)
  const concatRegex = /['"]([^'"]*)['"]\s*\+\s*['"]([^'"]*)['"]/g;
  const resolveConcats = () => {
    let prev;
    let loopCount = 0;
    do {
      prev = working;
      working = working.replace(concatRegex, "'$1$2'");
      loopCount++;
    } while (working !== prev && loopCount < 10);
  };
  resolveConcats();

  // 5. Resolve Format Operators ("{1}{0}" -f 'EX','I' -> 'IEX')
  const formatRegex = /\(?\s*['"]((?:\{\d+\}|[^'"{}])*)['"]\s+-f\s+((?:['"][^'"]*['"]\s*,?\s*)+)\)?/gi;
  working = working.replace(formatRegex, (original, template: string, rawArgs: string) => {
    const args = Array.from(rawArgs.matchAll(/['"]([^'"]*)['"]/g), m => m[1]);
    const indexes = Array.from(template.matchAll(/\{(\d+)\}/g), m => Number(m[1]));
    if (indexes.some(i => i >= args.length)) return original;
    return `'${template.replace(/\{(\d+)\}/g, (_, i) => args[Number(i)])}'`;
  });
  resolveConcats();

  // 6. Threat Indicator Heuristics
  const lower = working.toLowerCase();

  // Invoke-Expression / IEX
  if (/\b(?:iex|invoke-expression)\b/i.test(working)) {
    detectedIndicators.push({
      title: 'Dynamic Code Execution (Invoke-Expression / IEX)',
      description: 'Executes arbitrary string commands dynamically in memory, a classic malware delivery mechanism.',
      severity: 'CRITICAL',
    });
  }

  // Web Downloaders
  if (lower.includes('downloadstring') || lower.includes('downloadfile') || lower.includes('webclient')) {
    detectedIndicators.push({
      title: 'Remote Stage Download (Net.WebClient)',
      description: 'Attempts to fetch external payloads from remote servers in memory.',
      severity: 'CRITICAL',
    });
  }

  // Hidden Window Execution
  if (lower.includes('-windowstyle hidden') || lower.includes('-w hidden') || lower.includes('-win 1')) {
    detectedIndicators.push({
      title: 'Hidden Console Execution (-WindowStyle Hidden)',
      description: 'Attempts to hide PowerShell console window from the logged-in victim.',
      severity: 'HIGH',
    });
  }

  // Execution Policy Bypass
  if (/-(?:ep|ex[a-z]*)\s+['"]?bypass\b/i.test(working) || /set-executionpolicy\s+['"]?bypass\b/i.test(working)) {
    detectedIndicators.push({
      title: 'Execution Policy Bypass',
      description: 'Disables script signing checks to execute unverified local and remote scripts.',
      severity: 'MEDIUM',
    });
  }

  // Windows Defender Tampering
  if (lower.includes('add-mppreference') || lower.includes('set-mppreference') || lower.includes('exclusionpath') || lower.includes('disablerealtimemonitoring')) {
    detectedIndicators.push({
      title: 'Antivirus Evasion (Defender Exclusion Tampering)',
      description: 'Manipulates Microsoft Defender preferences, adding exclusion folders or disabling real-time protection.',
      severity: 'CRITICAL',
    });
  }

  // Memory Reflection / Assembly Load
  if (lower.includes('[reflection.assembly]::load') || lower.includes('virtualalloc') || lower.includes('createremotethread')) {
    detectedIndicators.push({
      title: 'In-Memory Reflection / Process Injection',
      description: 'Loads compiled assemblies directly into memory or allocates memory pages for shellcode injection.',
      severity: 'CRITICAL',
    });
  }

  // 7. Extract IOCs
  const urlRegex = /\b(?:https?|ftp):\/\/[^\s/$.?#].[^\s'"]*/gi;
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|cc|info|biz|site)\b/gi;
  const filePathRegex = /[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g;

  const urls = Array.from(new Set(working.match(urlRegex) || []));
  const ips = Array.from(new Set(working.match(ipv4Regex) || []));
  const domains = Array.from(new Set(working.match(domainRegex) || []));
  const filePaths = Array.from(new Set(working.match(filePathRegex) || []));

  // Determine overall severity
  let threatSeverity: DeobfuscationResult['threatSeverity'] = 'NO_INDICATORS';
  if (detectedIndicators.some(i => i.severity === 'CRITICAL')) {
    threatSeverity = 'CRITICAL';
  } else if (detectedIndicators.some(i => i.severity === 'HIGH')) {
    threatSeverity = 'HIGH';
  } else if (detectedIndicators.length > 0) {
    threatSeverity = 'MEDIUM';
  }

  return {
    originalScript: script,
    deobfuscatedScript: working,
    decodedBase64Payloads,
    threatSeverity,
    detectedIndicators,
    extractedIocs: { urls, ips, domains, filePaths },
  };
}

// Decode PowerShell UTF-16LE Base64 (standard for -EncodedCommand)
function decodePowerShellBase64(base64Str: string): string {
  try {
    const rawBinary = atob(base64Str.trim());
    const bytes = new Uint8Array(rawBinary.length);
    for (let i = 0; i < rawBinary.length; i++) {
      bytes[i] = rawBinary.charCodeAt(i);
    }
    // Attempt UTF-16LE decoding
    const decoder = new TextDecoder('utf-16le', { fatal: false });
    const decoded = decoder.decode(bytes);
    if (decoded && decoded.replace(/[\x00-\x1F\x7F-\x9F]/g, '').length > 3) {
      return decoded;
    }
  } catch {}
  return decodeAsciiBase64(base64Str);
}

// Fallback ASCII Base64 decoding
function decodeAsciiBase64(base64Str: string): string {
  try {
    return atob(base64Str.trim());
  } catch {
    return '';
  }
}
