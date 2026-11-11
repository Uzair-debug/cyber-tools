'use client';

import React, { useState, useMemo } from 'react';
import {
  Radio,
  Search,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Filter,
  FolderPlus,
  Sparkles,
  Layers,
  Info,
  Sliders,
  AlertTriangle,
  Zap,
  EyeOff,
  Eye,
  Activity,
  ChevronDown,
  ChevronUp,
  LayoutGrid,
  List,
  Plus,
  Trash2,
  RotateCcw,
  CheckSquare,
  Square,
  Network,
  ShieldAlert as ShieldAlertIcon,
} from 'lucide-react';
import { useCase } from '@/components/shared/CaseContext';
import { useToolHistory } from '@/lib/useToolHistory';
import { ToolHistoryDropdown } from '@/components/shared/ToolHistoryDropdown';

interface PortData {
  port: number;
  protocol: 'TCP' | 'UDP' | 'TCP/UDP';
  service: string;
  category: 'Remote Access' | 'Web' | 'Database' | 'Active Directory' | 'Email' | 'Core Network' | 'Other';
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  defaultCreds?: string;
  exploitVectors: string;
  hardening: string;
}

const COMMON_PORTS: PortData[] = [
  {
    port: 21,
    protocol: 'TCP',
    service: 'FTP (File Transfer Protocol)',
    category: 'Other',
    risk: 'HIGH',
    description: 'Cleartext file transfer service vulnerable to sniffing and brute force.',
    defaultCreds: 'anonymous:anonymous, admin:admin',
    exploitVectors: 'Anonymous login, cleartext credential sniffing, vsftpd 2.3.4 backdoor.',
    hardening: 'Enforce SFTP/FTPS, disable anonymous access, use rate limiting.',
  },
  {
    port: 22,
    protocol: 'TCP',
    service: 'SSH (Secure Shell)',
    category: 'Remote Access',
    risk: 'MEDIUM',
    description: 'Encrypted administrative remote terminal access.',
    defaultCreds: 'root:root, admin:admin, pi:raspberry',
    exploitVectors: 'SSH brute force, leaked private keys, OpenSSH vulnerabilities (RegreSSHion CVE-2024-6387).',
    hardening: 'Disable root password login, enforce SSH keys + MFA, change default port.',
  },
  {
    port: 23,
    protocol: 'TCP',
    service: 'Telnet',
    category: 'Remote Access',
    risk: 'CRITICAL',
    description: 'Legacy unencrypted terminal access transmitting all keystrokes in plaintext.',
    defaultCreds: 'admin:password, root:root, cisco:cisco',
    exploitVectors: 'Plaintext credential interception via network sniffing (MITM).',
    hardening: 'Disable immediately and replace with SSHv2.',
  },
  {
    port: 25,
    protocol: 'TCP',
    service: 'SMTP (Simple Mail Transfer Protocol)',
    category: 'Email',
    risk: 'MEDIUM',
    description: 'Mail relay and transmission server.',
    exploitVectors: 'Open mail relay abuse for spam, email spoofing without SPF/DKIM/DMARC.',
    hardening: 'Enforce STARTTLS, restrict open relays, implement SPF/DKIM/DMARC.',
  },
  {
    port: 53,
    protocol: 'TCP/UDP',
    service: 'DNS (Domain Name System)',
    category: 'Core Network',
    risk: 'MEDIUM',
    description: 'Resolves hostnames to IP addresses.',
    exploitVectors: 'DNS amplification DDoS, DNS cache poisoning, zone transfer leaks (AXFR).',
    hardening: 'Restrict AXFR zone transfers, enable DNSSEC, implement response rate limiting.',
  },
  {
    port: 80,
    protocol: 'TCP',
    service: 'HTTP (Hypertext Transfer Protocol)',
    category: 'Web',
    risk: 'MEDIUM',
    description: 'Unencrypted web server traffic.',
    exploitVectors: 'Cleartext interception, SQLi, XSS, web application vulnerabilities.',
    hardening: 'Redirect 100% of HTTP traffic to HTTPS (port 443) with HSTS headers.',
  },
  {
    port: 88,
    protocol: 'TCP/UDP',
    service: 'Kerberos Authentication',
    category: 'Active Directory',
    risk: 'CRITICAL',
    description: 'Key authentication mechanism for Windows Active Directory domains.',
    exploitVectors: 'Kerberoasting (TGS ticket offline cracking), AS-REP Roasting, Golden/Silver Tickets.',
    hardening: 'Use AES-256 encryption, long complex service account passwords (25+ chars), gMSAs.',
  },
  {
    port: 135,
    protocol: 'TCP',
    service: 'MSRPC (Microsoft RPC Endpoint Mapper)',
    category: 'Active Directory',
    risk: 'HIGH',
    description: 'Locates RPC services on Windows hosts.',
    exploitVectors: 'RPC user enumeration, PetitPotam NTLM relay, remote code execution.',
    hardening: 'Block from perimeter firewall, enforce RPC packet signing.',
  },
  {
    port: 139,
    protocol: 'TCP',
    service: 'NetBIOS Session Service',
    category: 'Active Directory',
    risk: 'HIGH',
    description: 'Legacy Windows file and printer sharing over NetBIOS.',
    exploitVectors: 'Null session user/share enumeration, NTLM relay attacks.',
    hardening: 'Disable NetBIOS over TCP/IP across Windows environments.',
  },
  {
    port: 389,
    protocol: 'TCP/UDP',
    service: 'LDAP (Lightweight Directory Access Protocol)',
    category: 'Active Directory',
    risk: 'HIGH',
    description: 'Directory services query protocol for domain objects.',
    exploitVectors: 'Cleartext credential queries, anonymous bind enumeration, LDAP injection.',
    hardening: 'Enforce LDAPS (port 636) and LDAP channel binding + signing.',
  },
  {
    port: 443,
    protocol: 'TCP',
    service: 'HTTPS (HTTP over TLS/SSL)',
    category: 'Web',
    risk: 'LOW',
    description: 'Encrypted modern web server communication.',
    exploitVectors: 'Web application exploits (OWASP Top 10), weak TLS ciphers (TLS 1.0/1.1), expired certs.',
    hardening: 'Enforce TLS 1.3/1.2 only, strong cipher suites, HSTS, WAF.',
  },
  {
    port: 445,
    protocol: 'TCP',
    service: 'SMB (Server Message Block)',
    category: 'Active Directory',
    risk: 'CRITICAL',
    description: 'Windows file sharing, named pipes, and remote administration.',
    exploitVectors: 'EternalBlue (MS17-010), SMBGhost (CVE-2020-0796), PsExec lateral movement, NTLM Relay.',
    hardening: 'Block port 445 on all internet firewalls, disable SMBv1, enforce SMB signing & encryption.',
  },
  {
    port: 1433,
    protocol: 'TCP',
    service: 'Microsoft SQL Server (MSSQL)',
    category: 'Database',
    risk: 'CRITICAL',
    description: 'Enterprise relational database management system.',
    defaultCreds: 'sa:blank, sa:Password123, sa:sa',
    exploitVectors: 'xp_cmdshell arbitrary command execution, SQL injection, sa password brute forcing.',
    hardening: 'Never expose to internet, disable xp_cmdshell, enforce Windows Authentication only.',
  },
  {
    port: 3306,
    protocol: 'TCP',
    service: 'MySQL Database',
    category: 'Database',
    risk: 'CRITICAL',
    description: 'Open-source relational database server.',
    defaultCreds: 'root:blank, root:root, admin:admin',
    exploitVectors: 'User brute force, UDF shared library command execution, CVE-2012-2122 auth bypass.',
    hardening: 'Bind to 127.0.0.1, restrict remote root logins, enforce TLS.',
  },
  {
    port: 3389,
    protocol: 'TCP/UDP',
    service: 'RDP (Remote Desktop Protocol)',
    category: 'Remote Access',
    risk: 'CRITICAL',
    description: 'Microsoft Remote Desktop graphical interface.',
    exploitVectors: 'BlueKeep (CVE-2019-0708), brute-force password spraying, initial access for Ransomware.',
    hardening: 'Never expose directly to WAN; require VPN + MFA, enable NLA (Network Level Auth).',
  },
  {
    port: 5432,
    protocol: 'TCP',
    service: 'PostgreSQL Database',
    category: 'Database',
    risk: 'HIGH',
    description: 'Object-relational database management system.',
    defaultCreds: 'postgres:postgres, postgres:blank',
    exploitVectors: 'COPY PROGRAM command execution, misconfigured pg_hba.conf trust authentication.',
    hardening: 'Bind locally, enforce md5/scram-sha-256 password hashing.',
  },
  {
    port: 5985,
    protocol: 'TCP',
    service: 'WinRM (Windows Remote Management HTTP)',
    category: 'Remote Access',
    risk: 'HIGH',
    description: 'PowerShell remoting and Windows CLI management.',
    exploitVectors: 'Pass-the-Hash (PtH) execution, evil-winrm exploitation, lateral movement.',
    hardening: 'Enforce WinRM over HTTPS (5986), restrict IP access via GPO.',
  },
  {
    port: 6379,
    protocol: 'TCP',
    service: 'Redis In-Memory Data Store',
    category: 'Database',
    risk: 'CRITICAL',
    description: 'In-memory key-value database cache.',
    defaultCreds: 'No auth required by default',
    exploitVectors: 'Unauthenticated RCE via SSH authorized_keys write, cron job injection, rogue module load.',
    hardening: 'Require strong requirepass, bind to localhost, rename dangerous commands (FLUSHALL, CONFIG).',
  },
  {
    port: 8080,
    protocol: 'TCP',
    service: 'HTTP Alternate / Tomcat / Jenkins',
    category: 'Web',
    risk: 'HIGH',
    description: 'Alternate web port frequently running administrative dashboards.',
    defaultCreds: 'tomcat:tomcat, admin:admin',
    exploitVectors: 'Tomcat WAR file upload RCE, Jenkins script console RCE, unauthenticated proxy abuse.',
    hardening: 'Place behind reverse proxy with authentication and TLS.',
  },
  {
    port: 27017,
    protocol: 'TCP',
    service: 'MongoDB NoSQL Database',
    category: 'Database',
    risk: 'CRITICAL',
    description: 'NoSQL document-oriented database.',
    defaultCreds: 'No auth enabled by default in legacy versions',
    exploitVectors: 'Unauthenticated database wipe/ransomware, NoSQL injection, cleartext data theft.',
    hardening: 'Enable authorization (auth = true), bind to 127.0.0.1, enforce TLS.',
  },
  {
    port: 636,
    protocol: 'TCP',
    service: 'LDAPS (LDAP over SSL/TLS)',
    category: 'Active Directory',
    risk: 'MEDIUM',
    description: 'Encrypted directory service query channel.',
    exploitVectors: 'Credential enumeration if anonymous bind is enabled, certificate spoofing.',
    hardening: 'Enforce channel binding tokens and strict TLS certificate validation.',
  },
  {
    port: 1521,
    protocol: 'TCP',
    service: 'Oracle Database TNS Listener',
    category: 'Database',
    risk: 'HIGH',
    description: 'Oracle database client connection listener.',
    defaultCreds: 'system:manager, scott:tiger, dbsnmp:dbsnmp',
    exploitVectors: 'TNS poisoning, SID brute force, unauthenticated PL/SQL execution.',
    hardening: 'Enforce valid node checking (VALID_NODE_CHECKING_REGISTRATION), disable default accounts.',
  },
  {
    port: 3268,
    protocol: 'TCP',
    service: 'Active Directory Global Catalog',
    category: 'Active Directory',
    risk: 'MEDIUM',
    description: 'Forest-wide directory search database containing partial attribute sets.',
    exploitVectors: 'Reconnaissance and rapid enumeration of domain users across forests.',
    hardening: 'Restrict access to trusted internal subnets and domain member servers only.',
  },
  {
    port: 5986,
    protocol: 'TCP',
    service: 'WinRM over HTTPS',
    category: 'Remote Access',
    risk: 'MEDIUM',
    description: 'Encrypted PowerShell Remoting endpoint for Windows host administration.',
    exploitVectors: 'Pass-the-Hash (PtH) execution, remote command injection.',
    hardening: 'Require Kerberos / certificate authentication, restrict via GPO firewall rules.',
  },
  {
    port: 8443,
    protocol: 'TCP',
    service: 'HTTPS Alternate / Admin Consoles',
    category: 'Web',
    risk: 'MEDIUM',
    description: 'Secondary encrypted web port frequently used by management interfaces (Plesk, UniFi, Tomcat).',
    exploitVectors: 'Administrative interface credential spraying, unpatched web application flaws.',
    hardening: 'Enforce IP whitelisting, multi-factor authentication, and TLS 1.3.',
  },
];

export interface PresetBundle {
  id: string;
  name: string;
  icon: string;
  ports: number[];
  description: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export const PRESET_BUNDLES: PresetBundle[] = [
  {
    id: 'web',
    name: 'Web Perimeter',
    icon: '🌐',
    ports: [80, 443, 8080, 8443],
    description: 'HTTP/S web servers and application proxies',
    risk: 'MEDIUM',
  },
  {
    id: 'ad',
    name: 'Active Directory / DC',
    icon: '🏰',
    ports: [53, 88, 135, 139, 389, 445, 636, 3268],
    description: 'Core Windows Domain Controller services',
    risk: 'CRITICAL',
  },
  {
    id: 'remote',
    name: 'Remote Administration',
    icon: '🔑',
    ports: [22, 23, 3389, 5985, 5986],
    description: 'SSH, RDP, Telnet and WinRM management',
    risk: 'HIGH',
  },
  {
    id: 'db',
    name: 'Database Clusters',
    icon: '💾',
    ports: [1433, 1521, 3306, 5432, 6379, 27017],
    description: 'Relational, NoSQL, and cache stores',
    risk: 'CRITICAL',
  },
  {
    id: 'mail',
    name: 'Mail Infrastructure',
    icon: '📬',
    ports: [25, 110, 143, 465, 587, 993, 995],
    description: 'SMTP, IMAP, and POP3 mail relays',
    risk: 'MEDIUM',
  },
  {
    id: 'top10',
    name: 'Top 10 High-Risk',
    icon: '⚡',
    ports: [21, 22, 23, 80, 88, 135, 445, 1433, 3389, 8080],
    description: 'Most frequently exploited enterprise ports',
    risk: 'CRITICAL',
  },
];

export function PortIntelGuide() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedRisk, setSelectedRisk] = useState<string>('ALL');
  const [selectedPorts, setSelectedPorts] = useState<number[]>([22, 80, 443, 445, 3389]);
  const [nmapTarget, setNmapTarget] = useState('192.168.1.1/24');
  const [copiedNmap, setCopiedNmap] = useState(false);
  const [customPortInput, setCustomPortInput] = useState('');
  const [addedToCase, setAddedToCase] = useState(false);
  const [recentlyAddedPort, setRecentlyAddedPort] = useState<number | null>(null);
  const [addedScanToCase, setAddedScanToCase] = useState(false);
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');

  const { addItem } = useCase();
  const {
    history: targetHistory,
    addEntry: addTargetEntry,
    removeEntry: removeTargetEntry,
    clearHistory: clearTargetHistory,
  } = useToolHistory('port_intel_target');

  // Filter ports
  const filteredPorts = useMemo(() => {
    return COMMON_PORTS.filter(p => {
      const matchSearch =
        p.port.toString().includes(searchTerm) ||
        p.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.exploitVectors.toLowerCase().includes(searchTerm.toLowerCase());

      const matchCategory = selectedCategory === 'ALL' || p.category === selectedCategory;
      const matchRisk = selectedRisk === 'ALL' || p.risk === selectedRisk;

      return matchSearch && matchCategory && matchRisk;
    });
  }, [searchTerm, selectedCategory, selectedRisk]);

  // Evasion & Profile State
  const [scanProfile, setScanProfile] = useState<'evasion' | 'stealth' | 'low_slow' | 'discovery' | 'aggressive' | 'custom'>('evasion');
  const [timing, setTiming] = useState<'-T1' | '-T2' | '-T3' | '-T4'>('-T2');
  const [scanType, setScanType] = useState<'-sS' | '-sT' | '-sU' | '-sn'>('-sS');
  const [serviceDetection, setServiceDetection] = useState<'none' | 'version' | 'version_light' | 'scripts' | 'safe_scripts'>('none');
  const [enablePn, setEnablePn] = useState(true);
  const [enableFragment, setEnableFragment] = useState(true);
  const [enableDecoys, setEnableDecoys] = useState(true);
  const [enableSourcePort, setEnableSourcePort] = useState(true);
  const [enableRandomizeHosts, setEnableRandomizeHosts] = useState(true);
  const [enableDataPadding, setEnableDataPadding] = useState(true);
  const [enableCustomUa, setEnableCustomUa] = useState(false);
  const [showAdvancedEvasion, setShowAdvancedEvasion] = useState(false);

  // Apply Scan Profile Preset
  const applyScanProfile = (profile: 'evasion' | 'stealth' | 'low_slow' | 'discovery' | 'aggressive') => {
    setScanProfile(profile);
    if (profile === 'evasion') {
      setScanType('-sS');
      setTiming('-T2');
      setServiceDetection('none');
      setEnablePn(true);
      setEnableFragment(true);
      setEnableDecoys(true);
      setEnableSourcePort(true);
      setEnableRandomizeHosts(true);
      setEnableDataPadding(true);
      setEnableCustomUa(false);
    } else if (profile === 'stealth') {
      setScanType('-sS');
      setTiming('-T2');
      setServiceDetection('none');
      setEnablePn(true);
      setEnableFragment(false);
      setEnableDecoys(false);
      setEnableSourcePort(false);
      setEnableRandomizeHosts(true);
      setEnableDataPadding(false);
      setEnableCustomUa(false);
    } else if (profile === 'low_slow') {
      setScanType('-sS');
      setTiming('-T1');
      setServiceDetection('none');
      setEnablePn(true);
      setEnableFragment(false);
      setEnableDecoys(true);
      setEnableSourcePort(true);
      setEnableRandomizeHosts(true);
      setEnableDataPadding(true);
      setEnableCustomUa(false);
    } else if (profile === 'discovery') {
      setScanType('-sn');
      setTiming('-T3');
      setServiceDetection('none');
      setEnablePn(false);
      setEnableFragment(false);
      setEnableDecoys(false);
      setEnableSourcePort(false);
      setEnableRandomizeHosts(true);
      setEnableDataPadding(false);
      setEnableCustomUa(false);
    } else if (profile === 'aggressive') {
      setScanType('-sS');
      setTiming('-T3');
      setServiceDetection('scripts');
      setEnablePn(false);
      setEnableFragment(false);
      setEnableDecoys(false);
      setEnableSourcePort(false);
      setEnableRandomizeHosts(false);
      setEnableDataPadding(false);
      setEnableCustomUa(false);
    }
  };

  // Generated Nmap Command
  const nmapCommand = useMemo(() => {
    const parts: string[] = ['nmap'];

    // Scan Type
    if (scanType === '-sn') {
      parts.push('-sn');
    } else {
      parts.push(scanType);
    }

    // Skip Host Discovery Ping
    if (enablePn && scanType !== '-sn') {
      parts.push('-Pn');
    }

    // Timing
    parts.push(timing);

    // Service Detection & Scripts
    if (scanType !== '-sn') {
      if (serviceDetection === 'version') parts.push('-sV');
      else if (serviceDetection === 'version_light') parts.push('-sV --version-light');
      else if (serviceDetection === 'scripts') parts.push('-sV -sC');
      else if (serviceDetection === 'safe_scripts') parts.push('-sV --script "safe and not intrusive"');
    }

    // Evasion Flags
    if (enableFragment && scanType !== '-sn') parts.push('-f');
    if (enableDecoys) parts.push('-D RND:5,ME');
    if (enableSourcePort) parts.push('-g 53');
    if (enableRandomizeHosts) parts.push('--randomize-hosts');
    if (enableDataPadding && scanType !== '-sn') parts.push('--data-length 16');
    if (enableCustomUa && (serviceDetection === 'scripts' || serviceDetection === 'safe_scripts')) {
      parts.push('--script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"');
    }

    // Ports
    if (scanType !== '-sn') {
      if (selectedPorts.length > 0) {
        const portList = [...selectedPorts].sort((a, b) => a - b).join(',');
        parts.push(`-p ${portList}`);
      }
    } else {
      if (selectedPorts.length > 0) {
        const probePorts = [...selectedPorts].slice(0, 4).sort((a, b) => a - b).join(',');
        parts.push(`-PS${probePorts} -PE`);
      }
    }

    // Target
    parts.push(nmapTarget.trim() || '192.168.1.1/24');

    return parts.join(' ');
  }, [
    selectedPorts,
    nmapTarget,
    scanType,
    timing,
    serviceDetection,
    enablePn,
    enableFragment,
    enableDecoys,
    enableSourcePort,
    enableRandomizeHosts,
    enableDataPadding,
    enableCustomUa,
  ]);

  // Detection Risk Assessment
  const detectionRisk = useMemo(() => {
    if (scanType === '-sn') {
      return {
        level: 'MINIMAL' as const,
        color: 'text-cyan-400 bg-cyan-950/40 border-cyan-500/30',
        badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
        title: 'Minimal Detection Risk (Host Discovery Only)',
        explanation: 'Sends basic ICMP echo and TCP SYN probes without touching application services or transmitting vulnerability scripts.',
        alerts: ['No service banners or exploit payloads transmitted.', 'Safe for network perimeter asset sweeps.'],
      };
    }

    let score = 0;
    const reasons: string[] = [];

    if (serviceDetection === 'scripts') {
      score += 50;
      reasons.push('Default NSE scripts (-sC) transmit known exploit payloads and hardcoded Nmap user-agents.');
    } else if (serviceDetection === 'safe_scripts') {
      score += 25;
      reasons.push('Safe scripts generate application-level HTTP/SMB query traffic logged by L7 firewalls.');
    } else if (serviceDetection === 'version') {
      score += 20;
      reasons.push('Version probes (-sV) send malformed protocol handshakes to force banner releases.');
    }

    if (timing === '-T4') {
      score += 30;
      reasons.push('Aggressive timing (-T4) fires high-frequency bursts exceeding common IDS port-scan thresholds.');
    } else if (timing === '-T3') {
      score += 15;
    } else if (timing === '-T2') {
      score -= 10;
    } else if (timing === '-T1') {
      score -= 25;
    }

    if (nmapTarget.includes('/24') || nmapTarget.includes('/16')) {
      score += 20;
      reasons.push('Sweeping an entire subnet (/24 = 256 hosts) multiplies alert volume exponentially for network switches and SIEMs.');
    }

    if (enableDecoys) score -= 15;
    if (enableSourcePort) score -= 10;
    if (enableFragment) score -= 10;
    if (enableRandomizeHosts) score -= 10;
    if (enablePn) score -= 5;

    if (score >= 50) {
      return {
        level: 'CRITICAL' as const,
        color: 'text-rose-400 bg-rose-950/40 border-rose-500/30',
        badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
        title: 'Critical Detection Risk (Guaranteed Immediate Block)',
        explanation: 'This command will trigger immediate threshold and signature alarms in Palo Alto, Fortinet, Snort/Suricata, and Defender for Endpoint.',
        alerts: reasons.length > 0 ? reasons : ['High packet frequency across multiple hosts without evasion protections.'],
      };
    } else if (score >= 25) {
      return {
        level: 'MODERATE' as const,
        color: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
        badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        title: 'Moderate Detection Risk (Likely Logged by SIEM)',
        explanation: 'Traffic avoids immediate heuristic drops but may trigger correlation rules or threshold alerts on enterprise sensors.',
        alerts: reasons.length > 0 ? reasons : ['Detectible by stateful firewalls tracking connection frequencies.'],
      };
    } else {
      return {
        level: 'LOW' as const,
        color: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
        badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        title: 'Low Detection Risk (Stealth & Evasion Optimized)',
        explanation: 'Masked origin, packet fragmentation, and polite timing keep packet volume below standard IDS/IPS detection limits.',
        alerts: [
          'Decoys spoof 5 random IP sources to confuse SOC correlation.',
          'DNS source port 53 bypasses many stateless inbound packet filters.',
          'Packet fragmentation and randomized host order prevent sequential port-scan triggers.',
        ],
      };
    }
  }, [
    scanType,
    serviceDetection,
    timing,
    nmapTarget,
    enableDecoys,
    enableSourcePort,
    enableFragment,
    enableRandomizeHosts,
    enablePn,
  ]);

  const togglePortSelect = (port: number) => {
    setSelectedPorts(prev =>
      prev.includes(port) ? prev.filter(p => p !== port) : [...prev, port]
    );
  };

  const handleCopyNmap = () => {
    if (nmapTarget.trim()) addTargetEntry(nmapTarget.trim());
    navigator.clipboard.writeText(nmapCommand);
    setCopiedNmap(true);
    setTimeout(() => setCopiedNmap(false), 2000);
  };

  const handleAddToCase = (portItem: PortData) => {
    addItem({
      tool: 'Port Intelligence',
      title: `Port ${portItem.port}/${portItem.protocol} - ${portItem.service}`,
      category: 'RECON',
      severity: portItem.risk as any,
      summary: `Identified ${portItem.service} (${portItem.risk} Risk). Exploit Vectors: ${portItem.exploitVectors}`,
      details: portItem,
    });
    setRecentlyAddedPort(portItem.port);
    setTimeout(() => setRecentlyAddedPort(null), 2000);
  };

  const handleAddScanPlanToCase = () => {
    if (nmapTarget.trim()) addTargetEntry(nmapTarget.trim());
    addItem({
      tool: 'Port Intelligence Recon',
      title: `Nmap Evasion Plan: ${nmapTarget} (${selectedPorts.length} Ports)`,
      category: 'RECON',
      severity: detectionRisk.level === 'CRITICAL' ? 'CRITICAL' : detectionRisk.level === 'MODERATE' ? 'MEDIUM' : 'LOW',
      summary: `Synthesized Nmap tactical command for ${nmapTarget} with ${scanProfile.toUpperCase()} profile. Risk rating: ${detectionRisk.level}. Ports: ${selectedPorts.join(', ')}`,
      details: {
        command: nmapCommand,
        target: nmapTarget,
        profile: scanProfile,
        timing,
        scanType,
        detectionRisk: detectionRisk.level,
        portsCount: selectedPorts.length,
        ports: selectedPorts,
      },
    });
    setAddedScanToCase(true);
    setTimeout(() => setAddedScanToCase(false), 2000);
  };

  const handleAddCustomPort = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const parsed = parseInt(customPortInput.trim(), 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      if (!selectedPorts.includes(parsed)) {
        setSelectedPorts(prev => [...prev, parsed]);
      }
      setCustomPortInput('');
    }
  };

  const handleRemovePort = (port: number) => {
    setSelectedPorts(prev => prev.filter(p => p !== port));
  };

  const handleApplyPresetBundle = (bundle: PresetBundle) => {
    setSelectedPorts(bundle.ports);
  };

  const handleSelectAllFiltered = () => {
    const filteredPortNumbers = filteredPorts.map(p => p.port);
    setSelectedPorts(prev => Array.from(new Set([...prev, ...filteredPortNumbers])));
  };

  const handleClearAll = () => {
    setSelectedPorts([]);
  };

  const handleResetDefault = () => {
    setSelectedPorts([22, 80, 443, 445, 3389]);
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-extrabold rounded-md bg-rose-950/80 border border-rose-500/50 text-rose-400 shadow-sm">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-extrabold rounded-md bg-orange-950/80 border border-orange-500/50 text-orange-400">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-extrabold rounded-md bg-amber-950/80 border border-amber-500/50 text-amber-400">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-extrabold rounded-md bg-emerald-950/80 border border-emerald-500/50 text-emerald-400">
            LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-semibold rounded-md bg-slate-800 text-slate-400 border border-slate-700">
            INFO
          </span>
        );
    }
  };

  const CATEGORIES = ['ALL', 'Active Directory', 'Remote Access', 'Database', 'Web', 'Email', 'Core Network', 'Other'];
  const RISKS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  const criticalTotal = COMMON_PORTS.filter(p => p.risk === 'CRITICAL').length;
  const highTotal = COMMON_PORTS.filter(p => p.risk === 'HIGH').length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* 1. Header & SecOps Telemetry Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-slate-900/60 border border-slate-800 p-5 sm:p-6 shadow-2xl">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-4">
            <div className="p-3.5 rounded-2xl bg-blue-500/20 border border-blue-500/40 text-blue-400 shadow-inner">
              <Radio className="w-7 h-7" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-black text-slate-100 tracking-tight">
                  Port & Service Intelligence Reference
                </h1>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
                Enterprise service encyclopedia, CVE/exploit vectors, default credential auditing, and interactive IDS/IPS-evasive Nmap command synthesis.
              </p>
            </div>
          </div>

          {/* Telemetry Stats Badges */}
          <div className="flex flex-wrap items-center gap-2 sm:gap-3 bg-black/40 border border-slate-800 p-2.5 rounded-xl text-xs">
            <div className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-center">
              <div className="text-[10px] text-slate-500 font-bold uppercase">Catalog</div>
              <div className="text-sm font-black text-slate-200">{COMMON_PORTS.length}</div>
            </div>
            <div className="px-2.5 py-1 rounded-lg bg-rose-950/30 border border-rose-900/40 text-center">
              <div className="text-[10px] text-rose-400/80 font-bold uppercase">Critical</div>
              <div className="text-sm font-black text-rose-400">{criticalTotal}</div>
            </div>
            <div className="px-2.5 py-1 rounded-lg bg-orange-950/30 border border-orange-900/40 text-center">
              <div className="text-[10px] text-orange-400/80 font-bold uppercase">High</div>
              <div className="text-sm font-black text-orange-400">{highTotal}</div>
            </div>
            <div className="px-2.5 py-1 rounded-lg bg-blue-950/40 border border-blue-500/40 text-center">
              <div className="text-[10px] text-blue-400 font-bold uppercase">Selected</div>
              <div className="text-sm font-black text-blue-300">{selectedPorts.length}</div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Tactical Preset Bundles Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/70 border border-slate-800/90 space-y-2.5 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-bold text-slate-300">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            <span>Tactical Port Presets (1-Click Selection)</span>
          </div>
          <span className="text-[11px] text-slate-500 hidden sm:inline">Select a predefined attack-surface bundle to load directly into the scanner</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {PRESET_BUNDLES.map(bundle => {
            const isMatch = bundle.ports.length === selectedPorts.length && bundle.ports.every(p => selectedPorts.includes(p));
            return (
              <button
                key={bundle.id}
                type="button"
                onClick={() => handleApplyPresetBundle(bundle)}
                className={`p-2.5 rounded-xl border text-left transition-all duration-200 group ${
                  isMatch
                    ? 'bg-blue-950/50 border-blue-500/60 ring-1 ring-blue-500/40 text-blue-200'
                    : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700 hover:bg-slate-800/40 text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm">{bundle.icon}</span>
                  <span className="text-[9px] font-mono text-slate-500 group-hover:text-slate-400">{bundle.ports.length} ports</span>
                </div>
                <div className="text-xs font-bold truncate text-slate-200">{bundle.name}</div>
                <div className="text-[10px] text-slate-400 truncate mt-0.5">{bundle.description}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 3. Dual-Pane Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Port Catalog Explorer & Filtering (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Filter Toolbar */}
          <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3 shadow-md">
            {/* Search + View Toggle */}
            <div className="flex flex-col sm:flex-row gap-2.5">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  placeholder="Search by port (e.g. 445), service (SMB), exploit (EternalBlue, Kerberoasting)..."
                  className="w-full pl-9 pr-3 py-2 bg-black/50 border border-slate-700/80 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
                />
                {searchTerm && (
                  <button
                    onClick={() => setSearchTerm('')}
                    className="absolute right-2.5 top-2.5 text-xs text-slate-500 hover:text-slate-300"
                  >
                    ×
                  </button>
                )}
              </div>

              {/* View mode toggle */}
              <div className="flex items-center space-x-1 p-1 bg-black/40 border border-slate-800 rounded-xl">
                <button
                  type="button"
                  onClick={() => setViewMode('grid')}
                  className={`p-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1 transition-colors ${
                    viewMode === 'grid' ? 'bg-violet-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title="Grid Cards View"
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                  <span className="text-[11px] hidden sm:inline">Cards</span>
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('table')}
                  className={`p-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1 transition-colors ${
                    viewMode === 'table' ? 'bg-violet-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title="Compact Table View"
                >
                  <List className="w-3.5 h-3.5" />
                  <span className="text-[11px] hidden sm:inline">Table</span>
                </button>
              </div>
            </div>

            {/* Category Pills & Risk Dropdown */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pt-2 border-t border-slate-800/80 text-xs">
              {/* Category Pills */}
              <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 sm:pb-0 scrollbar-none">
                {CATEGORIES.map(c => {
                  const isActive = selectedCategory === c;
                  return (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setSelectedCategory(c)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-medium whitespace-nowrap transition-colors ${
                        isActive
                          ? 'bg-violet-600 text-white shadow-sm'
                          : 'bg-black/40 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                      }`}
                    >
                      {c}
                    </button>
                  );
                })}
              </div>

              {/* Risk Filter & Action buttons */}
              <div className="flex items-center space-x-2 shrink-0">
                <span className="text-[11px] text-slate-500">Risk:</span>
                <select
                  value={selectedRisk}
                  onChange={e => setSelectedRisk(e.target.value)}
                  className="px-2 py-1 bg-black/50 border border-slate-700/80 rounded-lg text-[11px] text-slate-200 focus:outline-none"
                >
                  {RISKS.map(r => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Batch Action Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-[11px] text-slate-400">
              <div className="flex items-center space-x-1.5">
                <span>Showing <strong className="text-slate-200">{filteredPorts.length}</strong> services</span>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={handleSelectAllFiltered}
                  className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md transition-colors flex items-center space-x-1"
                >
                  <CheckSquare className="w-3 h-3 text-blue-400" />
                  <span>Select Visible ({filteredPorts.length})</span>
                </button>
                <button
                  type="button"
                  onClick={handleClearAll}
                  className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md transition-colors flex items-center space-x-1"
                >
                  <Square className="w-3 h-3 text-rose-400" />
                  <span>Clear All</span>
                </button>
                <button
                  type="button"
                  onClick={handleResetDefault}
                  className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md transition-colors flex items-center space-x-1"
                >
                  <RotateCcw className="w-3 h-3 text-amber-400" />
                  <span>Reset</span>
                </button>
              </div>
            </div>
          </div>

          {/* Port List: Cards View */}
          {viewMode === 'grid' && (
            <div className="space-y-3">
              {filteredPorts.map(item => {
                const isSelected = selectedPorts.includes(item.port);

                // Border accent based on risk
                let riskBorder = 'border-slate-800';
                if (isSelected) riskBorder = 'border-blue-500/60 ring-1 ring-blue-500/30';
                else if (item.risk === 'CRITICAL') riskBorder = 'border-rose-900/30 hover:border-rose-700/50';
                else if (item.risk === 'HIGH') riskBorder = 'border-orange-900/30 hover:border-orange-700/50';

                return (
                  <div
                    key={item.port}
                    className={`p-4 rounded-2xl border transition-all duration-200 space-y-3 ${
                      isSelected
                        ? ' bg-slate-900/60 shadow-md'
                        : 'bg-slate-900/70 hover:bg-slate-900/90'
                    } ${riskBorder}`}
                  >
                    {/* Top Row: Port # + Protocol + Service + Checkbox + Case Button */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center space-x-3">
                        <label className="relative flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => togglePortSelect(item.port)}
                            className="w-4 h-4 rounded bg-black/60 border-slate-700 text-blue-600 focus:ring-0 cursor-pointer"
                          />
                        </label>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-mono text-base font-black text-blue-400">
                              Port {item.port}
                            </span>
                            <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-400 border border-slate-700">
                              {item.protocol}
                            </span>
                            {getRiskBadge(item.risk)}
                            <span className="text-[10px] text-slate-500 font-medium hidden sm:inline">• {item.category}</span>
                          </div>
                          <div className="text-xs font-bold text-slate-200 mt-0.5">{item.service}</div>
                        </div>
                      </div>

                      <button
                        onClick={() => handleAddToCase(item)}
                        className={`p-1.5 rounded-lg transition-colors ${
                          recentlyAddedPort === item.port
                            ? 'text-emerald-400 bg-emerald-950/40 border border-emerald-500/40'
                            : 'text-slate-400 hover:text-indigo-300 hover:bg-slate-800'
                        }`}
                        title={recentlyAddedPort === item.port ? 'Added to Investigation Case!' : 'Add to Investigation Case'}
                      >
                        {recentlyAddedPort === item.port ? <Check className="w-4 h-4" /> : <FolderPlus className="w-4 h-4" />}
                      </button>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>

                    {/* Default Credentials Chip */}
                    {item.defaultCreds && (
                      <div className="text-[11px] bg-black/50 border border-slate-800/90 rounded-xl p-2.5 text-slate-300 font-mono">
                        <span className="text-amber-400 font-bold">Default / Common Creds: </span>
                        {item.defaultCreds}
                      </div>
                    )}

                    {/* Exploit Vectors */}
                    <div className="text-[11px] bg-rose-950/20 border border-rose-900/30 rounded-xl p-2.5 text-rose-300">
                      <div className="flex items-center space-x-1.5 font-bold text-rose-400 mb-0.5">
                        <AlertTriangle className="w-3 h-3" />
                        <span>Exploit & Abuse Vectors:</span>
                      </div>
                      <p className="text-rose-300/90">{item.exploitVectors}</p>
                    </div>

                    {/* Hardening & Defense */}
                    <div className="text-[11px] bg-emerald-950/20 border border-emerald-900/30 rounded-xl p-2.5 text-emerald-300">
                      <div className="flex items-center space-x-1.5 font-bold text-emerald-400 mb-0.5">
                        <ShieldCheck className="w-3 h-3" />
                        <span>Hardening & Mitigations:</span>
                      </div>
                      <p className="text-emerald-300/90">{item.hardening}</p>
                    </div>
                  </div>
                );
              })}

              {filteredPorts.length === 0 && (
                <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800 space-y-2">
                  <p className="text-sm font-semibold text-slate-400">No ports match your current filter</p>
                  <p className="text-xs text-slate-500">Try clearing your search term or category filters</p>
                </div>
              )}
            </div>
          )}

          {/* Port List: Compact Table View */}
          {viewMode === 'table' && (
            <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/80 shadow-md">
              <table className="w-full text-left text-xs">
                <thead className="bg-black/60 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  <tr>
                    <th className="p-3 w-10 text-center">Scan</th>
                    <th className="p-3">Port / Proto</th>
                    <th className="p-3">Service</th>
                    <th className="p-3">Category</th>
                    <th className="p-3">Risk</th>
                    <th className="p-3 text-right">Case</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {filteredPorts.map(item => {
                    const isSelected = selectedPorts.includes(item.port);
                    return (
                      <tr
                        key={item.port}
                        onClick={() => togglePortSelect(item.port)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-blue-950/30 text-blue-200' : 'hover:bg-slate-800/40 text-slate-300'
                        }`}
                      >
                        <td className="p-3 text-center" onClick={e => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => togglePortSelect(item.port)}
                            className="rounded bg-black border-slate-700 text-blue-600 focus:ring-0 cursor-pointer"
                          />
                        </td>
                        <td className="p-3 font-mono font-bold text-blue-400">
                          {item.port} <span className="text-[10px] text-slate-500 font-normal">/{item.protocol}</span>
                        </td>
                        <td className="p-3 font-medium text-slate-200 max-w-xs truncate">{item.service}</td>
                        <td className="p-3 text-[11px] text-slate-400">{item.category}</td>
                        <td className="p-3">{getRiskBadge(item.risk)}</td>
                        <td className="p-3 text-right" onClick={e => e.stopPropagation()}>
                          <button
                            onClick={() => handleAddToCase(item)}
                            className={`p-1 rounded transition-colors ${
                              recentlyAddedPort === item.port
                                ? 'text-emerald-400 bg-emerald-950/40 border border-emerald-500/40'
                                : 'text-slate-400 hover:text-indigo-300 hover:bg-slate-800'
                            }`}
                            title={recentlyAddedPort === item.port ? 'Added!' : 'Add to Case'}
                          >
                            {recentlyAddedPort === item.port ? <Check className="w-3.5 h-3.5" /> : <FolderPlus className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: Sticky Nmap Evasion & Terminal Suite (5 cols) */}
        <div className="lg:col-span-5 lg:sticky lg:top-4 space-y-4">
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-2xl backdrop-blur-sm">
            {/* Terminal Window Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <div className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                </div>
                <span className="text-xs font-mono font-bold text-slate-300 ml-2">bash - nmap v7.95</span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleAddScanPlanToCase}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-colors border border-slate-700"
                  title="Add Nmap Recon Plan to Case Dossier"
                >
                  {addedScanToCase ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <FolderPlus className="w-3.5 h-3.5 text-blue-400" />}
                  <span>{addedScanToCase ? 'Added!' : 'Add to Dossier'}</span>
                </button>
                <button
                  type="button"
                  onClick={handleCopyNmap}
                  className="px-3 py-1 bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-colors shadow-sm"
                >
                  {copiedNmap ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedNmap ? 'Copied!' : 'Copy Command'}</span>
                </button>
              </div>
            </div>

            {/* Generated Command Output Box */}
            <div className="space-y-1">
              <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase tracking-wider">
                <span>Live Synthesized Command:</span>
                <span>Click to Select All</span>
              </div>
              <div className="p-3.5 rounded-xl bg-black/90 border border-slate-800 font-mono text-xs text-blue-300 select-all overflow-x-auto shadow-inner leading-relaxed break-all">
                {nmapCommand}
              </div>
            </div>

            {/* Target Host Configurator */}
            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300">Target Host / Subnet:</span>
                <div className="flex items-center gap-2">
                  <ToolHistoryDropdown
                    history={targetHistory}
                    onSelect={(val) => setNmapTarget(val)}
                    onRemove={removeTargetEntry}
                    onClear={clearTargetHistory}
                  />
                  <span className="text-[10px] text-slate-500 font-mono">IPv4 / FQDN</span>
                </div>
              </div>
              <input
                type="text"
                value={nmapTarget}
                onChange={e => setNmapTarget(e.target.value)}
                onBlur={() => {
                  if (nmapTarget.trim()) addTargetEntry(nmapTarget.trim());
                }}
                onKeyDown={e => {
                  if (e.key === 'Enter' && nmapTarget.trim()) {
                    addTargetEntry(nmapTarget.trim());
                  }
                }}
                placeholder="e.g. 192.168.1.1/24 or 10.0.0.1"
                className="w-full px-3 py-2 text-xs bg-black/60 border border-slate-700 rounded-xl text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              />
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                {['192.168.1.1/24', '10.0.0.15', 'target.corp.local', '172.16.0.0/16'].map(t => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setNmapTarget(t)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono transition-colors ${
                      nmapTarget === t ? 'bg-violet-600/30 text-blue-300 border border-blue-500/40' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Dynamic Detection Risk Analysis Box */}
            <div className={`p-3.5 rounded-xl border ${detectionRisk.color} space-y-2 text-xs transition-colors duration-300`}>
              <div className="flex items-center justify-between">
                <span className={`px-2 py-0.5 text-[10px] font-extrabold rounded-full border ${detectionRisk.badgeColor}`}>
                  {detectionRisk.level} RISK
                </span>
                <span className="text-[10px] opacity-75 font-semibold">Firewall / EDR Assessment</span>
              </div>

              <div className="font-bold text-slate-200 text-xs">{detectionRisk.title}</div>
              <p className="text-[11px] text-slate-300 leading-relaxed">{detectionRisk.explanation}</p>

              <div className="space-y-1 pt-1">
                {detectionRisk.alerts.map((alert, idx) => (
                  <div key={idx} className="flex items-start space-x-1.5 text-[10px] text-slate-300">
                    <span className="text-blue-400 font-bold">•</span>
                    <span>{alert}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Tactical Scan Profiles Tabs */}
            <div className="space-y-2 pt-1">
              <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Tactical Profile:</span>
              <div className="grid grid-cols-2 gap-1.5">
                {[
                  { id: 'evasion', label: '🛡️ IDS/IPS Evasion', desc: 'Decoys, DNS spoof, -f' },
                  { id: 'stealth', label: '🥷 Stealth SYN', desc: 'Half-open, -T2 timing' },
                  { id: 'low_slow', label: '🐢 Low & Slow', desc: 'EDR rate-limit bypass' },
                  { id: 'discovery', label: '📡 Host Discovery', desc: 'Ping sweep, 0 port probes' },
                  { id: 'aggressive', label: '🚨 Aggressive Audit', desc: 'Full -sC scripts (Noisy)' },
                ].map(p => {
                  const isActive = scanProfile === p.id;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => applyScanProfile(p.id as any)}
                      className={`p-2 rounded-xl border text-left transition-all ${
                        isActive
                          ? 'bg-blue-950/60 border-blue-500/60 ring-1 ring-blue-500/30 text-blue-200'
                          : 'bg-black/40 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-300'
                      }`}
                    >
                      <div className="text-[11px] font-bold text-slate-200">{p.label}</div>
                      <div className="text-[9px] text-slate-400 mt-0.5 leading-tight">{p.desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Selected Ports Drawer & Custom Port Adder */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300">Active Ports ({selectedPorts.length}):</span>
                {selectedPorts.length > 0 && (
                  <button
                    type="button"
                    onClick={handleClearAll}
                    className="text-[10px] text-rose-400 hover:text-rose-300 flex items-center space-x-0.5"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>Remove All</span>
                  </button>
                )}
              </div>

              {/* Tags Cloud */}
              <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto p-2 bg-black/40 border border-slate-800/80 rounded-xl">
                {selectedPorts.map(p => (
                  <span
                    key={p}
                    className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-lg bg-blue-950/60 border border-blue-500/30 text-blue-300 font-mono text-[11px]"
                  >
                    <span>{p}</span>
                    <button
                      type="button"
                      onClick={() => handleRemovePort(p)}
                      className="text-slate-400 hover:text-rose-400 ml-1"
                      title={`Remove port ${p}`}
                    >
                      ×
                    </button>
                  </span>
                ))}
                {selectedPorts.length === 0 && (
                  <span className="text-[11px] text-slate-500 italic">No ports selected (scan will use defaults)</span>
                )}
              </div>

              {/* Add Custom Port Input */}
              <form onSubmit={handleAddCustomPort} className="flex items-center space-x-2 pt-1">
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={customPortInput}
                  onChange={e => setCustomPortInput(e.target.value)}
                  placeholder="Add custom port (e.g. 8000)..."
                  className="flex-1 px-2.5 py-1.5 text-xs bg-black/50 border border-slate-700 rounded-lg text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-1 transition-colors border border-slate-700"
                >
                  <Plus className="w-3.5 h-3.5 text-blue-400" />
                  <span>Add</span>
                </button>
              </form>
            </div>

            {/* Modular Evasion Flags Collapsible Accordion */}
            <div className="pt-2 border-t border-slate-800 space-y-2">
              <button
                type="button"
                onClick={() => setShowAdvancedEvasion(prev => !prev)}
                className="w-full flex items-center justify-between text-xs text-blue-400 hover:text-blue-300 font-semibold p-1.5 rounded-lg hover:bg-slate-800/40 transition-colors"
              >
                <div className="flex items-center space-x-1.5">
                  <Sliders className="w-3.5 h-3.5" />
                  <span>Fine-Tune Evasion Flags</span>
                </div>
                {showAdvancedEvasion ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              {showAdvancedEvasion && (
                <div className="p-3.5 rounded-xl bg-black/50 border border-slate-800 space-y-3 text-xs">
                  {/* Timing & Technique */}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] text-slate-400 font-semibold uppercase">Timing:</label>
                      <select
                        value={timing}
                        onChange={e => {
                          setTiming(e.target.value as any);
                          setScanProfile('custom');
                        }}
                        className="w-full mt-1 px-2 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
                      >
                        <option value="-T1">-T1 (Sneaky)</option>
                        <option value="-T2">-T2 (Polite)</option>
                        <option value="-T3">-T3 (Normal)</option>
                        <option value="-T4">-T4 (Aggressive)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-[10px] text-slate-400 font-semibold uppercase">Scan Type:</label>
                      <select
                        value={scanType}
                        onChange={e => {
                          setScanType(e.target.value as any);
                          setScanProfile('custom');
                        }}
                        className="w-full mt-1 px-2 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
                      >
                        <option value="-sS">-sS (SYN Stealth)</option>
                        <option value="-sT">-sT (TCP Connect)</option>
                        <option value="-sU">-sU (UDP Scan)</option>
                        <option value="-sn">-sn (Host Discovery)</option>
                      </select>
                    </div>
                  </div>

                  {/* Service & Scripts */}
                  <div>
                    <label className="text-[10px] text-slate-400 font-semibold uppercase">Service Probing:</label>
                    <select
                      value={serviceDetection}
                      onChange={e => {
                        setServiceDetection(e.target.value as any);
                        setScanProfile('custom');
                      }}
                      className="w-full mt-1 px-2 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
                    >
                      <option value="none">None (Maximum Stealth)</option>
                      <option value="version">-sV (Version Probe)</option>
                      <option value="version_light">-sV --version-light</option>
                      <option value="safe_scripts">--script "safe and not intrusive"</option>
                      <option value="scripts">-sV -sC (Default Scripts - HIGH ALERT!)</option>
                    </select>
                  </div>

                  {/* Flags Checkboxes */}
                  <div className="space-y-1.5 pt-2 border-t border-slate-800 text-[11px]">
                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enableDecoys}
                        onChange={e => {
                          setEnableDecoys(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>Decoys <code className="text-blue-400 font-mono">-D RND:5,ME</code></span>
                    </label>

                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enableSourcePort}
                        onChange={e => {
                          setEnableSourcePort(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>DNS Source Port <code className="text-blue-400 font-mono">-g 53</code></span>
                    </label>

                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enableFragment}
                        onChange={e => {
                          setEnableFragment(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>Fragmentation <code className="text-blue-400 font-mono">-f</code></span>
                    </label>

                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enableRandomizeHosts}
                        onChange={e => {
                          setEnableRandomizeHosts(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>Randomize Hosts <code className="text-blue-400 font-mono">--randomize-hosts</code></span>
                    </label>

                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enableDataPadding}
                        onChange={e => {
                          setEnableDataPadding(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>Data Padding <code className="text-blue-400 font-mono">--data-length 16</code></span>
                    </label>

                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enablePn}
                        onChange={e => {
                          setEnablePn(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>Skip Ping <code className="text-blue-400 font-mono">-Pn</code></span>
                    </label>

                    <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-50">
                      <input
                        type="checkbox"
                        checked={enableCustomUa}
                        onChange={e => {
                          setEnableCustomUa(e.target.checked);
                          setScanProfile('custom');
                        }}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>Spoof Browser User-Agent</span>
                    </label>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
