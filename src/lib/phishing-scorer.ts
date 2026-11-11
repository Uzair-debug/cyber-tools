import { AuthVerdict, ExtractedAttachment, ExtractedUrl, PhishingIndicator } from './types';

export function calculatePhishingRisk(data: {
  fromAddress: string;
  fromName: string;
  replyToAddress?: string;
  returnPath?: string;
  subject: string;
  bodyText: string;
  spf: AuthVerdict;
  dkim: AuthVerdict;
  dmarc: AuthVerdict;
  urls: ExtractedUrl[];
  attachments: ExtractedAttachment[];
}): {
  score: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: PhishingIndicator[];
} {
  const indicators: PhishingIndicator[] = [];
  let score = 0;

  // 1. DMARC / SPF / DKIM results as recorded by the receiving server
  if (data.spf.status === 'missing' && data.dkim.status === 'missing' && data.dmarc.status === 'missing') {
    indicators.push({
      id: 'auth-missing',
      title: 'No Authentication Results in Headers',
      description: 'The headers hold no SPF, DKIM or DMARC results, so authentication could not be assessed. Paste the full headers as received by your mail server.',
      severity: 'info',
      points: 0,
    });
  } else if (data.dmarc.status === 'fail') {
    indicators.push({
      id: 'dmarc-fail',
      title: 'DMARC Failed',
      description: 'Neither SPF nor DKIM passed for a domain aligned with the From address. Spoofed mail fails this way, though misconfigured or forwarded legitimate mail can too.',
      severity: 'critical',
      points: 35,
    });
    score += 35;
  } else if (data.dmarc.status === 'none') {
    indicators.push({
      id: 'dmarc-none',
      title: 'No DMARC Record for the From Domain',
      description: 'The From domain publishes no DMARC record, so receivers have no policy for mail that spoofs it.',
      severity: 'medium',
      points: 10,
    });
    score += 10;
  } else if (data.dmarc.status === 'missing') {
    indicators.push({
      id: 'dmarc-missing',
      title: 'No DMARC Result in Headers',
      description: 'The headers do not record a DMARC result, so it is unknown whether the From domain was checked.',
      severity: 'info',
      points: 0,
    });
  }

  if (data.spf.status === 'fail' || data.spf.status === 'softfail') {
    indicators.push({
      id: 'spf-fail',
      title: `SPF ${data.spf.status.toUpperCase()}`,
      description:
        data.spf.status === 'fail'
          ? 'The receiving server reports the sending IP is not authorised by the SPF record of the envelope sender domain.'
          : 'The receiving server reports the SPF record of the envelope sender domain marks the sending IP as probably not authorised.',
      severity: 'high',
      points: 25,
    });
    score += 25;
  }

  if (data.dkim.status === 'fail') {
    indicators.push({
      id: 'dkim-fail',
      title: 'DKIM Signature Did Not Verify',
      description: 'The message may have been changed after signing, or the signature is not valid.',
      severity: 'high',
      points: 25,
    });
    score += 25;
  }

  // 2. From vs Reply-To mismatch
  if (data.replyToAddress && data.fromAddress) {
    const fromClean = data.fromAddress.replace(/[<>]/g, '').trim().toLowerCase();
    const replyClean = data.replyToAddress.replace(/[<>]/g, '').trim().toLowerCase();

    if (fromClean && replyClean && fromClean !== replyClean) {
      const fromDomain = fromClean.split('@')[1] || '';
      const replyDomain = replyClean.split('@')[1] || '';
      // A subdomain of the sender's domain (or the reverse) counts as the same organisation
      const sameOrg =
        fromDomain === replyDomain || fromDomain.endsWith(`.${replyDomain}`) || replyDomain.endsWith(`.${fromDomain}`);

      if (fromDomain && replyDomain && !sameOrg) {
        indicators.push({
          id: 'replyto-mismatch-domain',
          title: 'Reply-To Uses a Different Domain',
          description: `Sender domain is '@${fromDomain}', but replies go to '@${replyDomain}'. Common in BEC and phishing, though some mailing services do this legitimately.`,
          severity: 'critical',
          points: 30,
        });
        score += 30;
      } else {
        indicators.push({
          id: 'replyto-mismatch-mailbox',
          title: 'Reply-To Uses a Different Mailbox',
          description: `Sender is '${fromClean}', but replies go to '${replyClean}' in the same organisation. Often legitimate (for example a no-reply sender), but can be used to divert replies.`,
          severity: 'medium',
          points: 10,
        });
        score += 10;
      }
    }
  }

  // 3. Urgency / pressure phrases in subject or body
  const urgentRegex =
    /\b(urgently|immediate action required|account suspended|verify your identity|unauthorized login|wire transfer|payment overdue|reset your password|gift card|invoice attached|payroll update|security alert|action needed|24 hours)\b/gi;
  const urgentHits = Array.from(
    new Set([...`${data.subject}\n${data.bodyText}`.matchAll(urgentRegex)].map(m => m[0].toLowerCase()))
  );
  if (urgentHits.length > 0) {
    indicators.push({
      id: 'urgency-detected',
      title: 'Urgency or Pressure Phrases',
      description: `Contains phrases common in social engineering: ${urgentHits.slice(0, 6).map(h => `"${h}"`).join(', ')}.`,
      severity: 'medium',
      points: 15,
    });
    score += 15;
  }

  // 4. Authority-sounding display name that the address itself doesn't back up
  const execNames = ['ceo', 'cfo', 'executive', 'director', 'it support', 'helpdesk', 'security team', 'administrator', 'microsoft support', 'google security', 'paypal support'];
  const matchesName = (text: string) => execNames.find(n => new RegExp(`\\b${n}\\b`, 'i').test(text));
  const nameHit = matchesName(data.fromName || '');
  const addressLower = (data.fromAddress || '').toLowerCase();
  if (nameHit && !execNames.some(n => addressLower.includes(n.replace(/\s+/g, '')))) {
    indicators.push({
      id: 'executive-spoof',
      title: 'Authority-Style Display Name',
      description: `Display name '${data.fromName}' suggests authority or IT support ("${nameHit}"), but the address is '${data.fromAddress}'. Check the sender is who the name claims.`,
      severity: 'high',
      points: 20,
    });
    score += 20;
  }

  // 5. High-risk attachment types
  const suspiciousAttachments = data.attachments.filter(att => att.isDangerousExt);

  if (suspiciousAttachments.length > 0) {
    indicators.push({
      id: 'dangerous-attachments',
      title: 'High-Risk Attachment Type',
      description: `File type often used to deliver malware or phishing pages: ${suspiciousAttachments.map(a => a.filename).join(', ')}`,
      severity: 'critical',
      points: 40,
    });
    score += 40;
  }

  // 6. Links flagged by the URL checks in email-parser
  const suspiciousUrls = data.urls.filter(u => u.isSuspicious);
  if (suspiciousUrls.length > 0) {
    const reasons = Array.from(new Set(suspiciousUrls.flatMap(u => u.reasons)));
    indicators.push({
      id: 'suspicious-links',
      title: 'Suspicious Links',
      description: `${suspiciousUrls.length} link${suspiciousUrls.length === 1 ? '' : 's'} flagged: ${reasons.join('; ')}.`,
      severity: 'high',
      points: 20,
    });
    score += 20;
  }

  // Cap score at 100
  const normalizedScore = Math.min(100, Math.max(0, score));

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (normalizedScore >= 70) riskLevel = 'CRITICAL';
  else if (normalizedScore >= 45) riskLevel = 'HIGH';
  else if (normalizedScore >= 20) riskLevel = 'MEDIUM';

  return {
    score: normalizedScore,
    riskLevel,
    indicators,
  };
}
