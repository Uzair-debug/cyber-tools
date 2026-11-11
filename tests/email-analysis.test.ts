import { describe, expect, it } from 'vitest';
import { parseEmailContent } from '@/lib/email-parser';
import { calculatePhishingRisk } from '@/lib/phishing-scorer';
import type { AuthVerdict } from '@/lib/types';

const v = (status: AuthVerdict['status']): AuthVerdict => ({ status, details: '' });

const base = {
  fromAddress: 'alice@contoso.com',
  fromName: 'Alice',
  subject: 'Lunch',
  bodyText: 'See you at noon.',
  spf: v('pass'),
  dkim: v('pass'),
  dmarc: v('pass'),
  urls: [],
  attachments: [],
};

const ids = (r: ReturnType<typeof calculatePhishingRisk>) => r.indicators.map(i => i.id);

describe('calculatePhishingRisk', () => {
  it('scores a clean, authenticated message as LOW with no indicators', () => {
    const r = calculatePhishingRisk(base);
    expect(r).toEqual({ score: 0, riskLevel: 'LOW', indicators: [] });
  });

  it('reports missing authentication as info only, without points', () => {
    const r = calculatePhishingRisk({ ...base, spf: v('missing'), dkim: v('missing'), dmarc: v('missing') });
    expect(ids(r)).toEqual(['auth-missing']);
    expect(r.score).toBe(0);
  });

  it('stacks DMARC, SPF and DKIM failures into CRITICAL', () => {
    const r = calculatePhishingRisk({ ...base, spf: v('fail'), dkim: v('fail'), dmarc: v('fail') });
    expect(ids(r)).toEqual(['dmarc-fail', 'spf-fail', 'dkim-fail']);
    expect(r.score).toBe(85);
    expect(r.riskLevel).toBe('CRITICAL');
  });

  it('treats SPF softfail like fail', () => {
    expect(ids(calculatePhishingRisk({ ...base, spf: v('softfail') }))).toContain('spf-fail');
  });

  it('flags a Reply-To on a different domain as critical (BEC pattern)', () => {
    const r = calculatePhishingRisk({ ...base, replyToAddress: '<payments@contoso-billing.net>' });
    expect(ids(r)).toEqual(['replyto-mismatch-domain']);
    expect(r.score).toBe(30);
    expect(r.riskLevel).toBe('MEDIUM');
  });

  it('treats a Reply-To on a subdomain of the sender as the same organisation', () => {
    const r = calculatePhishingRisk({ ...base, replyToAddress: 'support@mail.contoso.com' });
    expect(ids(r)).toEqual(['replyto-mismatch-mailbox']);
    expect(r.score).toBe(10);
  });

  it('does not flag a Reply-To that only differs in case or brackets', () => {
    expect(calculatePhishingRisk({ ...base, replyToAddress: '<ALICE@Contoso.com>' }).indicators).toEqual([]);
  });

  it('detects urgency phrases in subject and body, counting the indicator once', () => {
    const r = calculatePhishingRisk({
      ...base,
      subject: 'URGENT: Account Suspended',
      bodyText: 'Verify your identity within 24 hours or your account suspended status stays.',
    });
    expect(ids(r)).toEqual(['urgency-detected']);
    expect(r.score).toBe(15);
    expect(r.indicators[0].description).toMatch(/"account suspended"/);
  });

  it('does not match urgency words inside other words', () => {
    expect(calculatePhishingRisk({ ...base, bodyText: 'The giftcardholder said hello' }).indicators).toEqual([]);
  });

  it('flags an authority display name the address does not back up', () => {
    const r = calculatePhishingRisk({ ...base, fromName: 'Microsoft Support', fromAddress: 'ms.help.desk99@gmail.com' });
    expect(ids(r)).toContain('executive-spoof');
  });

  it('does not flag an authority name when the address matches it', () => {
    const r = calculatePhishingRisk({ ...base, fromName: 'IT Support', fromAddress: 'itsupport@contoso.com' });
    expect(ids(r)).not.toContain('executive-spoof');
  });

  it('flags dangerous attachments and suspicious links', () => {
    const r = calculatePhishingRisk({
      ...base,
      attachments: [{ filename: 'invoice.html', mimeType: 'text/html', size: 1, md5: '', sha256: '', isDangerousExt: true }],
      urls: [{ original: 'http://1.2.3.4/x', defanged: '', domain: '1.2.3.4', isSuspicious: true, reasons: ['IP address'] }],
    });
    expect(ids(r)).toEqual(['dangerous-attachments', 'suspicious-links']);
    expect(r.score).toBe(60);
    expect(r.riskLevel).toBe('HIGH');
  });

  it('caps the score at 100', () => {
    const r = calculatePhishingRisk({
      ...base,
      spf: v('fail'),
      dkim: v('fail'),
      dmarc: v('fail'),
      replyToAddress: 'x@evil.net',
      subject: 'wire transfer',
      fromName: 'CEO',
      attachments: [{ filename: 'a.exe', mimeType: '', size: 1, md5: '', sha256: '', isDangerousExt: true }],
    });
    expect(r.score).toBe(100);
    expect(r.riskLevel).toBe('CRITICAL');
  });

  // Indicator weights: DMARC none 10, Reply-To mailbox 10, urgency 15, DKIM fail 25, Reply-To domain 30, attachment 40
  const exe = [{ filename: 'a.exe', mimeType: '', size: 1, md5: '', sha256: '', isDangerousExt: true }];
  it.each([
    ['DMARC none', { dmarc: v('none') }, 10, 'LOW'],
    ['DMARC none + Reply-To mailbox', { dmarc: v('none'), replyToAddress: 'b@contoso.com' }, 20, 'MEDIUM'],
    ['DKIM fail + DMARC none', { dkim: v('fail'), dmarc: v('none') }, 35, 'MEDIUM'],
    ['DKIM fail + DMARC none + Reply-To mailbox', { dkim: v('fail'), dmarc: v('none'), replyToAddress: 'b@contoso.com' }, 45, 'HIGH'],
    ['DKIM fail + Reply-To domain', { dkim: v('fail'), replyToAddress: 'x@evil.net' }, 55, 'HIGH'],
    ['Reply-To domain + attachment', { replyToAddress: 'x@evil.net', attachments: exe }, 70, 'CRITICAL'],
  ])('%s scores %s and is %s (thresholds 20 / 45 / 70)', (_label, extra, score, level) => {
    const r = calculatePhishingRisk({ ...base, ...extra });
    expect(r.score).toBe(score);
    expect(r.riskLevel).toBe(level);
  });
});

const PHISH = `Received: from mx.contoso.com (mx.contoso.com [10.0.0.5])
 by inbox.contoso.com with ESMTPS id abc; Fri, 30 Oct 2026 10:00:05 +0000
Received: from mail.evil-sender.xyz (mail.evil-sender.xyz [203.0.113.9])
 by mx.contoso.com with ESMTP id def; Fri, 30 Oct 2026 10:00:01 +0000
Authentication-Results: mx.contoso.com;
 spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil-sender.xyz;
 dkim=none;
 dmarc=fail action=quarantine header.from=contoso.com
Return-Path: <bounce@evil-sender.xyz>
From: "IT Support" <it-support@contoso.com>
Reply-To: helpdesk@evil-sender.xyz
To: bob@contoso.com
Subject: Security alert: reset your password
Date: Fri, 30 Oct 2026 09:59:58 +0000
Message-ID: <123@evil-sender.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8

Your mailbox will be locked. Reset your password at https://login.microsoftonline.com@evil-sender.xyz/reset
or https://bit.ly/3abcde and https://203.0.113.9/portal. Legit link: https://www.contoso.com/help.

--b1
Content-Type: text/html; name="invoice.html"
Content-Disposition: attachment; filename="invoice.html"

<html><body>hi</body></html>
--b1--
`;

const CLEAN = `Received: from mail-a.contoso.com (mail-a.contoso.com [198.51.100.20])
 by mx.fabrikam.com with ESMTPS id 1; Fri, 30 Oct 2026 08:00:02 +0000
Authentication-Results: mx.fabrikam.com;
 spf=pass smtp.mailfrom=contoso.com;
 dkim=pass header.d=contoso.com header.s=selector1;
 dmarc=pass action=none header.from=contoso.com
From: Alice <alice@contoso.com>
To: carol@fabrikam.com
Subject: Meeting notes
Date: Fri, 30 Oct 2026 08:00:00 +0000
Message-ID: <abc@contoso.com>
Content-Type: text/plain

Notes are on https://www.contoso.com/notes.
`;

describe('parseEmailContent', () => {
  it('reads authentication results recorded by the receiving server', async () => {
    const r = await parseEmailContent(PHISH);
    expect(r.spf.status).toBe('fail');
    expect(r.dkim.status).toBe('none');
    expect(r.dmarc.status).toBe('fail');
  });

  it('extracts sender, reply-to and subject', async () => {
    const r = await parseEmailContent(PHISH);
    expect(r.from).toEqual({ name: 'IT Support', address: 'it-support@contoso.com' });
    expect(r.replyTo?.address).toBe('helpdesk@evil-sender.xyz');
    expect(r.returnPath).toContain('bounce@evil-sender.xyz');
    expect(r.subject).toBe('Security alert: reset your password');
  });

  it('orders Received hops oldest first and takes the sender IP from the "from" clause', async () => {
    const r = await parseEmailContent(PHISH);
    expect(r.hops).toHaveLength(2);
    expect(r.hops[0].ip).toBe('203.0.113.9');
    expect(r.hops[1].ip).toBe('10.0.0.5');
  });

  it('flags each suspicious link with the right reason', async () => {
    const r = await parseEmailContent(PHISH);
    const byDomain = Object.fromEntries(r.urls.map(u => [u.domain, u]));
    expect(byDomain['evil-sender.xyz'].reasons.join()).toMatch(/disguises the real host/);
    expect(byDomain['evil-sender.xyz'].reasons.join()).toMatch(/\.xyz/);
    expect(byDomain['bit.ly'].reasons.join()).toMatch(/shortener/);
    expect(byDomain['203.0.113.9'].reasons.join()).toMatch(/IP address/);
    expect(byDomain['www.contoso.com'].isSuspicious).toBe(false);
  });

  it('does not include trailing punctuation in extracted links', async () => {
    const r = await parseEmailContent(PHISH);
    expect(r.urls.map(u => u.original)).toContain('https://www.contoso.com/help');
  });

  it('hashes attachments and flags HTML smuggling files', async () => {
    const r = await parseEmailContent(PHISH);
    expect(r.attachments).toHaveLength(1);
    expect(r.attachments[0]).toMatchObject({ filename: 'invoice.html', isDangerousExt: true });
    expect(r.attachments[0].sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(r.attachments[0].md5).toMatch(/^[a-f0-9]{32}$/);
  });

  it('scores the phishing sample CRITICAL with the expected indicators', async () => {
    const r = await parseEmailContent(PHISH);
    expect(r.phishingRiskLevel).toBe('CRITICAL');
    const found = r.phishingIndicators.map(i => i.id);
    for (const id of ['dmarc-fail', 'spf-fail', 'replyto-mismatch-domain', 'urgency-detected', 'dangerous-attachments', 'suspicious-links']) {
      expect(found).toContain(id);
    }
  });

  it('scores a clean, authenticated message LOW', async () => {
    const r = await parseEmailContent(CLEAN);
    expect(r.spf.status).toBe('pass');
    expect(r.dkim.status).toBe('pass');
    expect(r.dmarc.status).toBe('pass');
    expect(r.phishingScore).toBe(0);
    expect(r.phishingRiskLevel).toBe('LOW');
  });

  it('accepts headers only, without a body', async () => {
    const headersOnly = CLEAN.split('\n\n')[0] + '\n';
    const r = await parseEmailContent(headersOnly);
    expect(r.from.address).toBe('alice@contoso.com');
    expect(r.urls).toEqual([]);
  });

  it('leaves the date empty when the message has no Date header', async () => {
    const r = await parseEmailContent(CLEAN.replace(/^Date:.*\n/m, ''));
    expect(r.date).toBe('');
  });

  it('rejects input with no headers', async () => {
    await expect(parseEmailContent('just some pasted text with no headers at all')).rejects.toThrow(/No email headers/);
  });

  it('rejects Outlook .msg files with a helpful message', async () => {
    const ole = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0, 0, 0]).buffer;
    await expect(parseEmailContent(ole)).rejects.toThrow(/Outlook \.msg/);
  });
});
