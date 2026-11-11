// IPv4 classification with no Node dependencies, so browser tools and API routes share it.

export type IpClass = 'public' | 'private' | 'bogon' | 'invalid';

export function classifyIpv4(ip: string): IpClass {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) return 'invalid';

  if (
    p[0] === 10 ||
    p[0] === 127 || // loopback
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) // link-local
  ) {
    return 'private';
  }

  if (
    p[0] === 0 ||
    p[0] >= 224 || // multicast (224-239) and reserved (240-255)
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || // CGNAT (RFC 6598)
    (p[0] === 192 && p[1] === 0 && p[2] === 0) || // IETF protocol assignments
    (p[0] === 192 && p[1] === 0 && p[2] === 2) || // TEST-NET-1
    (p[0] === 198 && (p[1] === 18 || p[1] === 19)) || // benchmarking
    (p[0] === 198 && p[1] === 51 && p[2] === 100) || // TEST-NET-2
    (p[0] === 203 && p[1] === 0 && p[2] === 113) // TEST-NET-3
  ) {
    return 'bogon';
  }

  return 'public';
}
