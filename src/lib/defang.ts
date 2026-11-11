/**
 * Utility functions for Defanging and Refanging IoCs (URLs, Domains, IPs, Emails)
 */

export function defangText(input: string): string {
  if (!input) return '';

  let text = input;

  // 1. Defang protocols
  text = text.replace(/https:\/\//gi, 'hxxps://');
  text = text.replace(/http:\/\//gi, 'hxxp://');
  text = text.replace(/ftp:\/\//gi, 'fxp://');

  // 2. Defang email @ signs while the domain still has plain dots: user@evil.com -> user[@]evil.com
  text = text.replace(/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, '$1[@]$2');

  // 3. Defang IPv4 addresses: e.g. 192.168.1.1 -> 192[.]168[.]1[.]1
  // We use regex that matches standard IPv4 patterns
  text = text.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1[.]$2[.]$3[.]$4');

  // 4. Defang domain dots if not already defanged
  // Matches domain names like evil.example.com -> evil[.]example[.]com
  // Avoid already bracketed dots
  text = text.replace(/(?<!\[)\.(?!\])/g, (match, offset, str) => {
    // Check if within a word or URL
    const prevChar = str[offset - 1] || '';
    const nextChar = str[offset + 1] || '';
    if (/[a-zA-Z0-9_-]/.test(prevChar) && /[a-zA-Z0-9_-]/.test(nextChar)) {
      return '[.]';
    }
    return match;
  });

  return text;
}

export function refangText(input: string): string {
  if (!input) return '';

  let text = input;

  // 1. Refang colons first, so the protocol patterns below see "hxxps://"
  text = text.replace(/\[:\/\/\]/g, '://');
  text = text.replace(/\[:\]/g, ':');

  // 2. Refang protocols
  text = text.replace(/hxxps:\/\//gi, 'https://');
  text = text.replace(/hxxp:\/\//gi, 'http://');
  text = text.replace(/fxp:\/\//gi, 'ftp://');

  // 3. Refang brackets around dots
  text = text.replace(/\[\.\]/g, '.');
  text = text.replace(/\(\.\)/g, '.');
  text = text.replace(/\{ \. \}/g, '.');
  text = text.replace(/\{\.\}/g, '.');
  text = text.replace(/\[dot\]/gi, '.');
  text = text.replace(/\(dot\)/gi, '.');

  // 4. Refang email at
  text = text.replace(/\[@\]/g, '@');
  text = text.replace(/\(@\)/g, '@');
  text = text.replace(/\[at\]/gi, '@');
  text = text.replace(/\(at\)/gi, '@');

  return text;
}
