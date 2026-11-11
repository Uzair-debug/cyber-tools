# Cyber Tools Portal

A browser-based workbench for SOC triage, threat hunting and recon. It puts the tools I reach for during an investigation in one place, with `Ctrl+K` to jump to any of them.

Built with Next.js and TypeScript, deployed on Cloudflare Workers.

## Tools

**Recon and network**
- Domain & DNS Recon: records, WHOIS, mail security (SPF, DMARC, MTA-STS)
- IP & Threat Reputation, and Port & Service Intelligence
- SSL/TLS Certificate Inspector
- CIDR Subnet Calculator

**Web**
- Security Headers Evaluator
- Link & Redirection Checker, which follows redirect chains hop by hop

**Threat analysis**
- Email & Threat Analyzer: header parsing and SPF/DKIM/DMARC alignment
- Bulk IOC Extractor & Parser, with defanging and refanging
- Threat Intel Pivot Hub
- Windows Event & Sysmon Triage
- MITRE ATT&CK Navigator
- CVSS v3.1 Calculator
- SIEM Query Builder: KQL (Sentinel), SPL (Splunk), Elastic, QRadar AQL and Sigma

**Microsoft 365**
- Defender & Purview Audit log analyzer
- Tenant PowerShell & IR Hub

**Crypto and utilities**
- JWT Auditor & Exploit Checker: flags `alg: none`, weak secrets and expired tokens
- Hash & Crypto Hub
- Password & Entropy, using zxcvbn plus leet and breached-word checks
- Data Conversion Hub
- Command Cheat-Sheet Hub

## Security

The server-side tools fetch URLs and connect to hosts that you supply, so the API routes are hardened against being used as a proxy:

- **SSRF protection:** every hop is checked to be a public host, including decimal and other encoded IP forms. Redirects are followed manually, up to 5 hops.
- **Rate limiting** per IP, with a stricter limit for the routes that probe hosts.
- **Strict security headers** on every response: CSP, HSTS, `X-Frame-Options: DENY` and others.
- **Sensitive input stays in memory.** JWTs and hash input are never written to `localStorage`.
- **CSV exports** are escaped against formula injection.
- **Error messages** are generic, so they don't leak internal hosts.

## Run it locally

```bash
npm ci
npm run dev        # http://localhost:3000
npm test           # 335 unit tests (Vitest)
```

Deploy to Cloudflare Workers:

```bash
npm run cf:deploy  # runs the tests, builds with OpenNext, then deploys with wrangler
```

## Stack

Next.js · React · TypeScript · Tailwind CSS · Radix UI · Vitest · OpenNext for Cloudflare · Cloudflare Workers
