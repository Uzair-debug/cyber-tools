export interface ReceivedHop {
  hopNumber: number;
  from: string;
  by: string;
  with: string;
  timestamp: string;
  // Seconds since the previous hop; null when either timestamp is missing or unreadable
  delaySec: number | null;
  ip: string;
  isPrivateIp: boolean;
  reverseDns?: string;
  raw: string;
}

export interface AuthVerdict {
  // 'none' is a result the receiving server reported; 'missing' means the headers hold no result at all
  status: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'policy' | 'missing';
  details: string;
  rawHeader?: string;
}

export interface ExtractedAttachment {
  filename: string;
  mimeType: string;
  size: number;
  md5: string;
  sha256: string;
  isDangerousExt: boolean;
  suspiciousNote?: string;
}

export interface ExtractedUrl {
  original: string;
  defanged: string;
  domain: string;
  isSuspicious: boolean;
  reasons: string[];
}

export interface PhishingIndicator {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';
  points: number;
}

export interface ParsedEmailData {
  subject: string;
  from: { name: string; address: string };
  to: Array<{ name: string; address: string }>;
  cc: Array<{ name: string; address: string }>;
  replyTo?: { name: string; address: string };
  date: string;
  messageId: string;
  returnPath: string;
  hops: ReceivedHop[];
  spf: AuthVerdict;
  dkim: AuthVerdict;
  dmarc: AuthVerdict;
  authResults: string;
  phishingScore: number;
  phishingRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  phishingIndicators: PhishingIndicator[];
  urls: ExtractedUrl[];
  attachments: ExtractedAttachment[];
  bodyText: string;
  bodyHtml: string;
  rawHeaders: Record<string, string | string[]>;
  urlTotal: number;
}

export type DnsErrorCode =
  | 'INVALID_DOMAIN'
  | 'NXDOMAIN'
  | 'DNS_TIMEOUT'
  | 'SERVFAIL'
  | 'REFUSED'
  | 'RESOLVER_ERROR'
  | 'NETWORK_ERROR';

export interface DnsErrorResponse {
  error: string;
  code: DnsErrorCode;
  details?: string;
  domain?: string;
  suggestion?: string;
  recordErrors?: Record<string, string>;
}

export interface DnsRecordResult {
  type: string;
  records: Array<{
    value: string;
    priority?: number;
    ttl?: number;
    target?: string;
    port?: number;
    flags?: string;
    tag?: string;
    resolvedIp?: string;
    countryCode?: string;
    orgProvider?: string;
  }>;
  status: 'found' | 'not_found' | 'error';
  rawText?: string;
  errorMessage?: string;
}


export interface PolicyEvaluation {
  protocol: 'SPF' | 'DMARC' | 'BIMI' | 'MTA-STS';
  status: 'valid' | 'warning' | 'invalid' | 'missing';
  policy: string;
  parsedTags: Record<string, string>;
  issues: string[];
  recommendations: string[];
  strictness: 'Strong / Enforcing' | 'Moderate' | 'Permissive / Testing' | 'Unprotected';
}

export interface WhoisData {
  domain: string;
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  updatedDate?: string;
  nameservers: string[];
  status: string[];
  dnssec: boolean;
  organization?: string;
  registrantOrg?: string;
  country?: string;
  abuseEmail?: string;
  abusePhone?: string;
  asn?: string;
  ipAddresses?: string[];
  rawWhois?: string;
}

export interface SubdomainResult {
  subdomain: string;
  issuer?: string;
  loggedAt?: string;
  ip?: string;
}

export interface DkimSelectorResult {
  selector: string;
  fqdn: string;
  status: 'found' | 'not_found' | 'delegated';
  recordType?: 'TXT' | 'CNAME';
  cnameTarget?: string;
  publicKey?: string;
  keyType?: string;
  keyLengthBits?: number;
  isKeySecure?: boolean; // >= 2048-bit
  rawRecord?: string;
}

export interface HostingProviders {
  webHost: {
    company: string;
    asn?: string;
    org?: string;
    country?: string;
    city?: string;
    ip: string;
  };
  mailHost: {
    provider: string;
    mxHost?: string;
  };
  dnsHost: {
    provider: string;
    nameservers: string[];
  };
}

export interface DomainReconData {
  domain: string;
  resolvedIp?: string;
  hosting?: HostingProviders;
  records: Record<string, DnsRecordResult>;
  policies: {
    spf: PolicyEvaluation;
    dmarc: PolicyEvaluation;
    bimi: PolicyEvaluation;
    mtaSts: PolicyEvaluation;
  };
  dkimSelectors: DkimSelectorResult[];
  whois: WhoisData;
  subdomains: SubdomainResult[];
  dnssec: {
    enabled: boolean;
    details: string;
  };
  queriedAt: string;
}

export interface IpThreatData {
  ip: string;
  hostname?: string;
  asn?: {
    asn: string;
    name: string;
    route: string;
    domain?: string;
    type?: string;
  };
  geo?: {
    country: string;
    countryCode: string;
    city: string;
    region: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
  };
  isPrivate: boolean;
  isBogon: boolean;
  reverseDns?: string;
  threatScore: number;
  threatLevel: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  abuseConfidenceScore?: number;
  totalReports?: number;
  lastReportedAt?: string;
  openPortsSimulated?: Array<{ port: number; service: string; state: 'open' | 'filtered' | 'closed' }>;
  portProbeNote?: string; // why ports weren't probed, when the reason is known
  categories?: string[];
}

export interface HashResult {
  algorithm: 'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512';
  hash: string;
}

export interface AttackScenario {
  name: string;
  hashSpeed: string;
  timeEstimate: string;
  technique: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
  explanation: string;
}

export interface DetectedPattern {
  type: 'DICTIONARY_WORD' | 'YEAR' | 'DELIMITER' | 'LEET_SUBSTITUTION' | 'SEQUENCE' | 'REPEAT' | 'RANDOM_SEGMENT';
  token: string;
  entropyCostBits: number;
  description: string;
}

export interface PasswordAnalysis {
  passwordLength: number;
  entropy: number; // Effective realistic entropy (accounting for dictionary, rules, years, patterns)
  theoreticalEntropy: number; // Raw theoretical uniform entropy (assuming pure random coin flips)
  score: 0 | 1 | 2 | 3 | 4; // 0=Very Weak, 4=Very Strong
  label: string;
  crackTimeOfflineBruteForce: string; // Fast hash attack (NTLM/MD5 with dictionary+rules, 100 GH/s)
  crackTimeOnlineSlow: string; // Throttled web login (100 req/s with lockout)
  crackTimeSlowHash: string; // Memory-hard hash (bcrypt/Argon2id, 10 kH/s)
  crackTimePureBruteForce: string; // Theoretical unguided brute force (pure keyspace)
  detectedPatterns: DetectedPattern[];
  attackScenarios: AttackScenario[];
  charDistribution: {
    lowercase: number;
    uppercase: number;
    digits: number;
    special: number;
  };
  warnings: string[];
  suggestions: string[];
}

export interface CidrCalculation {
  cidr: string;
  ip: string;
  prefix: number;
  netmask: string;
  wildcard: string;
  networkAddress: string;
  broadcastAddress: string;
  firstUsableIp: string;
  lastUsableIp: string;
  totalHosts: number;
  usableHosts: number;
  ipClass: string;
  scope: string;
  binaryIp: string;
  binaryNetmask: string;
  subnetsBreakdown?: Array<{
    cidr: string;
    network: string;
    usableRange: string;
    hosts: number;
  }>;
}

// 1. SSL/TLS Certificate Inspector Types
export interface SslCertificateData {
  host: string;
  port: number;
  // 'live-handshake' = observed directly from the server; 'certificate-transparency' = most recent
  // logged certificate, with handshake properties (protocol, cipher, OCSP, chain) unknown
  source: 'live-handshake' | 'certificate-transparency';
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  gradeReason: string;
  isValid: boolean;
  isTrusted: boolean | null; // null = not verifiable (no live handshake)
  trustError?: string;
  hostnameMatches: boolean | null;
  isExpired: boolean;
  isSelfSigned: boolean;
  daysRemaining: number;
  validFrom: string;
  validTo: string;
  subject: {
    commonName: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    state?: string;
    locality?: string;
  };
  issuer: {
    commonName: string;
    organization?: string;
    country?: string;
  };
  sanList: string[];
  // null = unknown (not observed)
  protocol: string | null;
  cipherSuite: {
    name: string;
    standardName?: string;
    version?: string;
    isPfs: boolean; // Perfect Forward Secrecy
    isAead: boolean; // Authenticated Encryption
    strength: 'STRONG' | 'MODERATE' | 'WEAK';
  } | null;
  publicKey: {
    type: string;
    bits: number | null;
    strength: 'STRONG' | 'MODERATE' | 'WEAK' | null;
  } | null;
  fingerprints: {
    sha256: string | null;
    sha1: string | null;
  };
  serialNumber: string | null;
  ocspStapling: boolean | null;
  certChainCount: number;
  certificateChain: Array<{
    subject: string;
    issuer: string;
    validTo: string;
  }>;
}

// 2. HTTP Security Headers Types
export interface SecurityHeaderItem {
  name: string;
  value: string | null;
  status: 'PASS' | 'WARN' | 'FAIL' | 'OPTIONAL';
  scoreImpact: number; // e.g. +15, -20
  summary: string;
  recommendation?: string;
  details?: Record<string, any>;
}

export interface SecurityHeadersData {
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  score: number; // 0 to 100
  headersEvaluated: SecurityHeaderItem[];
  cookies: Array<{
    name: string;
    hasSecure: boolean;
    hasHttpOnly: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None' | 'Missing';
    status: 'SECURE' | 'WARNING' | 'INSECURE';
  }>;
  rawHeaders: Record<string, string>;
  remediationSnippets: {
    nginx: string;
    apache: string;
    cloudflare: string;
    nextjs: string;
  };
}

// 3. JWT Auditor Types
export interface JwtAuditData {
  header: Record<string, any>;
  payload: Record<string, any>;
  signatureHex: string;
  algorithm: string;
  isValidStructure: boolean;
  isExpired: boolean;
  expirationDate?: string;
  issuedAtDate?: string;
  notBeforeDate?: string;
  claimsSummary: {
    issuer?: string;
    subject?: string;
    audience?: string;
    roles?: string[];
  };
  vulnerabilities: Array<{
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    title: string;
    description: string;
    recommendation: string;
  }>;
  secretCheckStatus?: 'UNCHECKED' | 'VERIFIED' | 'FAILED' | 'WEAK_CRACKED';
  crackedSecret?: string;
}

// 4. SIEM Query Translation Types
export type SiemPlatform = 'kql' | 'spl' | 'elastic' | 'sigma' | 'qradar';

export interface SiemQueryTranslation {
  kql: string;
  spl: string;
  elastic: string;
  sigma: string;
  qradar: string;
  iocsFound: {
    ips: string[];
    domains: string[];
    hashes: string[];
  };
}

// 5. MITRE ATT&CK Matrix Types
export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
  description: string;
  detection: string;
  mitigation: string;
  platforms: string[];
  dataSources: string[];
  sampleKqlQuery?: string;
  sampleSplQuery?: string;
}

// 6. Link & Redirection Security Checker Types
export interface LinkHopInfo {
  hopNumber: number;
  url: string;
  statusCode: number;
  statusText: string;
  durationMs: number;
  ip?: string;
  protocol: 'HTTP' | 'HTTPS';
  headers: Record<string, string>;
  location?: string;
  isTls: boolean;
  securityHeadersPresent: string[];
}

export interface UrlRiskFinding {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SAFE';
  points: number;
}

export interface ParsedUrlBreakdown {
  original: string;
  defanged: string;
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  tld: string;
  subdomain: string;
  isPunycode: boolean;
  decodedHostname: string;
  queryParams: Array<{ key: string; value: string; isSuspicious: boolean; reason?: string }>;
}

export interface SingleLinkCheckResult {
  inputUrl: string;
  finalUrl: string;
  finalStatusCode: number;
  finalStatusText: string;
  totalDurationMs: number;
  hopCount: number;
  isRedirected: boolean;
  hasRedirectLoop: boolean;
  hasProtocolDowngrade: boolean;
  riskScore: number; // 0 to 100
  riskLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  findings: UrlRiskFinding[];
  hops: LinkHopInfo[];
  urlBreakdown: ParsedUrlBreakdown;
  dnsResolvedIps: string[];
  scanTimestamp: string;
}

export interface BatchLinkItemResult {
  id: string;
  inputUrl: string;
  finalUrl: string;
  statusCode: number;
  statusText: string;
  durationMs: number;
  hopCount: number;
  riskLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  statusGroup: '2xx' | '3xx' | '4xx' | '5xx' | 'error';
  errorMessage?: string;
  hasRedirect: boolean;
}

export interface BatchLinkCheckResponse {
  total: number;
  summary: {
    successCount: number;
    redirectCount: number;
    clientErrorCount: number;
    serverErrorCount: number;
    errorCount: number;
    highRiskCount: number;
  };
  results: BatchLinkItemResult[];
}

