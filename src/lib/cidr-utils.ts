import { classifyIpv4 } from './ip-class';
import { CidrCalculation } from './types';

export function ipToLong(ip: string): number {
  const octets = ip.split('.');
  if (octets.length !== 4 || octets.some(o => !/^\d{1,3}$/.test(o) || Number(o) > 255)) {
    throw new Error('Invalid IPv4 address');
  }
  const parts = octets.map(Number);
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

export function longToIp(long: number): string {
  return [
    (long >>> 24) & 255,
    (long >>> 16) & 255,
    (long >>> 8) & 255,
    long & 255
  ].join('.');
}

export function toBinary(long: number): string {
  const binary = (long >>> 0).toString(2).padStart(32, '0');
  return `${binary.substring(0, 8)}.${binary.substring(8, 16)}.${binary.substring(16, 24)}.${binary.substring(24, 32)}`;
}

function addressScope(ip: string): string {
  const [first, second] = ip.split('.').map(Number);
  if (first === 127) return 'Loopback';
  if (first === 169 && second === 254) return 'Link-local';
  if (first === 100 && second >= 64 && second <= 127) return 'CGNAT (RFC 6598)';
  if (first >= 224 && first <= 239) return 'Multicast';

  const cls = classifyIpv4(ip);
  if (cls === 'private') return 'RFC 1918 Private';
  return cls === 'bogon' ? 'Reserved' : 'Public IP';
}

export function calculateCidr(input: string): CidrCalculation {
  let ipStr = input.trim();
  let prefix = 24;

  if (ipStr.includes('/')) {
    const parts = ipStr.split('/');
    const rawPrefix = parts[1].trim();
    // A typo like /33 or /2x must be reported, not silently replaced with /24 (which gives a confident wrong answer)
    if (parts.length !== 2 || !/^\d{1,2}$/.test(rawPrefix) || Number(rawPrefix) > 32) {
      throw new Error('Invalid prefix length: use a number from 0 to 32, e.g. 10.0.0.0/16');
    }
    ipStr = parts[0].trim();
    prefix = Number(rawPrefix);
  }

  const ipNum = ipToLong(ipStr);
  const maskNum = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const wildcardNum = (~maskNum) >>> 0;
  const networkNum = (ipNum & maskNum) >>> 0;
  const broadcastNum = (networkNum | wildcardNum) >>> 0;

  const totalHosts = Math.pow(2, 32 - prefix);
  let usableHosts = 0;
  let firstUsableNum = networkNum;
  let lastUsableNum = broadcastNum;

  if (prefix === 32) {
    usableHosts = 1;
    firstUsableNum = networkNum;
    lastUsableNum = networkNum;
  } else if (prefix === 31) {
    usableHosts = 2; // RFC 3021 point-to-point links
    firstUsableNum = networkNum;
    lastUsableNum = broadcastNum;
  } else {
    usableHosts = Math.max(0, totalHosts - 2);
    firstUsableNum = networkNum + 1;
    lastUsableNum = broadcastNum - 1;
  }

  // Determine IP Class
  const firstOctet = (ipNum >>> 24) & 255;
  let ipClass = 'Class E';
  if (firstOctet <= 127) ipClass = 'Class A';
  else if (firstOctet <= 191) ipClass = 'Class B';
  else if (firstOctet <= 223) ipClass = 'Class C';
  else if (firstOctet <= 239) ipClass = 'Class D';

  // Subnet split breakdowns (next 4 subnets with prefix+2 if prefix <= 30)
  const subnetsBreakdown: CidrCalculation['subnetsBreakdown'] = [];
  if (prefix <= 28) {
    const subPrefix = prefix + 2;
    const subHostCount = Math.pow(2, 32 - subPrefix);
    for (let i = 0; i < 4; i++) {
      const subNet = (networkNum + i * subHostCount) >>> 0;
      const subBrd = (subNet + subHostCount - 1) >>> 0;
      const fst = subNet + 1;
      const lst = subBrd - 1;
      subnetsBreakdown.push({
        cidr: `${longToIp(subNet)}/${subPrefix}`,
        network: longToIp(subNet),
        usableRange: `${longToIp(fst)} - ${longToIp(lst)}`,
        hosts: Math.max(0, subHostCount - 2),
      });
    }
  }

  return {
    cidr: `${longToIp(networkNum)}/${prefix}`,
    ip: longToIp(ipNum),
    prefix,
    netmask: longToIp(maskNum),
    wildcard: longToIp(wildcardNum),
    networkAddress: longToIp(networkNum),
    broadcastAddress: longToIp(broadcastNum),
    firstUsableIp: longToIp(firstUsableNum),
    lastUsableIp: longToIp(lastUsableNum),
    totalHosts,
    usableHosts,
    ipClass,
    scope: addressScope(ipStr),
    binaryIp: toBinary(ipNum),
    binaryNetmask: toBinary(maskNum),
    subnetsBreakdown,
  };
}
