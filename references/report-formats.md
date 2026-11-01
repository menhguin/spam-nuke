# Abuse Report Formats

Standard formats for each reporting channel. All are official, designated abuse-handling channels.

## Transparency Disclosure

Every report includes this disclosure, placed just before the signature:

> DISCLOSURE: This report was prepared by an AI agent acting on behalf of
> [YOUR_NAME], who authorized it. The evidence is genuine and unaltered, and
> the reporter can be contacted at [YOUR_EMAIL] for follow-up.

It tells the recipient the report was agent-prepared but authorized by a real, reachable person. That keeps it credible and separates it from automated report spam. Fill every `[PLACEHOLDER]` from the actual evidence, and delete any violation line you can't support.

## 1. ESP Abuse Report (ARF-Inspired — RFC 5965)

Send to ESP's `abuse@` address. Include full original headers as evidence.

```
Subject: Abuse Report — Unsolicited Commercial Email from [SENDER_DOMAIN]

To the abuse team,

I am reporting unsolicited commercial email received from a customer using
your platform. I have had no prior business relationship with this sender
and did not opt in to receive communications from them.

SENDER INFORMATION:
- From address: [FROM_ADDRESS]
- Sending domain: [SENDER_DOMAIN]
- Company name: [COMPANY_NAME] (if identified)
- Date received: [DATE_RECEIVED]

VIOLATION DETAILS:
- Unsolicited commercial email (no prior relationship, no consent)
- [No opt-out mechanism / Opt-out not honored / Misleading subject]
- [No physical address included — CAN-SPAM violation]

EVIDENCE:
The complete original email with full headers is attached/included below.

[FULL ORIGINAL HEADERS]

I request that you investigate this sender and take appropriate action
per your acceptable use policy.

Regards,
[YOUR_NAME]
```

**Why this works:** ESPs are legally and contractually obligated to investigate abuse reports. Multiple reports trigger automated review. Account suspension is common.

## 2. Domain Registrar Abuse Report

Send to registrar's abuse contact (from WHOIS). ICANN requires registrars to maintain abuse contacts.

```
Subject: Abuse Report — Domain [DOMAIN] Used for Unsolicited Email

To the registrar abuse team,

I am reporting that the domain [DOMAIN], registered through your service,
is being used to send unsolicited commercial email in violation of your
acceptable use policy and potentially in violation of CAN-SPAM Act /
GDPR / [applicable law].

DOMAIN: [DOMAIN]
REGISTRANT: [FROM WHOIS IF AVAILABLE]
EVIDENCE: Unsolicited commercial email received [DATE] — full headers below.

[ABBREVIATED HEADERS — From, Return-Path, Received, DKIM, Message-ID]

I request investigation under your abuse handling procedures.

Regards,
[YOUR_NAME]
```

**Why this works:** ICANN-accredited registrars must investigate abuse. Repeated complaints can lead to domain suspension — costly to recover.

## 3. Hosting Provider Abuse Report

Send to hosting provider's abuse contact (from IP WHOIS).

```
Subject: Abuse Report — IP [IP_ADDRESS] Sending Unsolicited Email

To the abuse team,

A server at IP address [IP_ADDRESS], hosted on your infrastructure, is being
used to send or facilitate unsolicited commercial email.

IP ADDRESS: [IP_ADDRESS]
DOMAIN: [DOMAIN]
EVIDENCE TYPE: Unsolicited commercial email
DATE: [DATE_RECEIVED]

Relevant headers showing this IP in the sending chain:
[RECEIVED HEADERS SHOWING THIS IP]

I request investigation per your acceptable use policy.

Regards,
[YOUR_NAME]
```

## 4. SpamCop Submission

SpamCop is the gold standard for automated spam reporting. Requires free account.

**Setup (one-time):**
1. Register at https://www.spamcop.net/anonsignup.shtml
2. You receive a personal submission address: `submit.XXXXXXXXXXXXXXXX@spam.spamcop.net`

**Submission:**
- Forward the spam email **as an attachment** (not inline) to your SpamCop submission address
- SpamCop parses headers, identifies responsible networks, and sends reports automatically
- You can also paste headers into the web form at https://www.spamcop.net/sc?action=loginform

**Why this works:** SpamCop reports feed into the SpamCop DNSBL (bl.spamcop.net), used by thousands of mail servers. It also auto-reports to the source network's abuse contact.

## 5. FTC CAN-SPAM Complaint

File at https://reportfraud.ftc.gov — web form only, no API.

**Information needed for the form:**
- What happened: "Received unsolicited commercial email"
- Company name: [COMPANY_NAME]
- Company website: [DOMAIN]
- How contacted: Email
- Date: [DATE]
- Details to include:
  - No prior business relationship
  - No opt-in consent given
  - [List specific CAN-SPAM violations]

**CAN-SPAM violations to cite (each up to $51,744/email):**
- § 7704(a)(1): No opt-out mechanism provided
- § 7704(a)(2): Misleading header information (From address doesn't identify sender)
- § 7704(a)(5): No valid physical postal address
- § 7704(a)(3): Deceptive subject line
- § 7704(a)(4): Failed to identify as advertisement

Also forward the spam to: **spam@uce.gov** (FTC's spam collection inbox)

## 6. GDPR DPA Complaint (EU/EEA)

File with the Data Protection Authority of the sender's country. Template per noyb.eu guidance:

```
Subject: GDPR Complaint — Unsolicited Direct Marketing Email (Article 77 GDPR)

To the Data Protection Authority,

I wish to file a complaint under Article 77 GDPR regarding the unlawful
processing of my personal data for direct marketing purposes.

COMPLAINANT:
- Name: [YOUR_NAME]
- Email: [YOUR_EMAIL] (the personal data processed without consent)

RESPONDENT:
- Company: [COMPANY_NAME]
- Domain: [DOMAIN]
- Country: [COMPANY_COUNTRY]
- DPO contact: [IF KNOWN — check their privacy policy]

FACTS:
On [DATE], I received an unsolicited commercial email from the respondent
at my personal email address. I have no prior business relationship with
this company and have never provided consent for them to process my personal
data for direct marketing purposes.

LEGAL BASIS:
- The respondent processed my personal data (email address) without a valid
  legal basis under Article 6 GDPR.
- The respondent failed to obtain consent required under Article 13 of the
  ePrivacy Directive (2002/58/EC) for unsolicited electronic marketing.
- Legitimate interest (Art. 6(1)(f)) cannot apply as there is no prior
  relationship and no reasonable expectation of marketing contact.

EVIDENCE:
[ATTACH THE SPAM EMAIL WITH FULL HEADERS]

REQUEST:
I request that the authority investigate this matter and take appropriate
enforcement action.

Regards,
[YOUR_NAME]
```

**DPA directory:** https://edpb.europa.eu/about-edpb/about-edpb/members_en

## 6b. Phone / Text Complaint (FTC DoNotCall.gov, FCC, national regulators)

These are web forms, so map the fields rather than sending an email. Use one entry per call event. For a repeat caller, put every date/time in the description if the form has room; never file the same call twice.

```
Number that received the call/text:  [YOUR_NUMBER]
Caller ID shown:                      [CALLER_ID] (report even if it may be spoofed)
Callback number given (if any):       [CALLBACK_NUMBER]
Company/person named (if any):        [COMPANY_NAME]
Date and time:                        [DATE TIME TZ]  (list all, for repeat callers)
Type:                                 [Recorded message (robocall) / live caller / text]
Subject:                              [e.g. car warranty, debt relief, crypto, fake bank]
Prior relationship / consent:         None. Never gave [COMPANY] permission to call or text.
On Do Not Call Registry:              [Yes, since DATE / No]
Lost money or information:            [No / details]

Description:
Received [N] unsolicited [robocalls/texts] from [CALLER_ID] between [FIRST]
and [LAST]. [One-line summary of the voicemail/text content, quoted where
possible.] I have no relationship with this caller and never consented to
contact.
```

FCC path: Phone → "Unwanted calls/texts" → "All other unwanted calls/messages"; international numbers go in "Additional Information". If money was lost, use ReportFraud.ftc.gov instead of DoNotCall.gov.

## 7. Enrichment Provider Data Deletion (GDPR/CCPA)

If you can identify how they got your email (Apollo, ZoomInfo, etc.), send a data deletion request:

```
Subject: Data Deletion Request — [CCPA/GDPR] — [YOUR_EMAIL]

To whom it may concern,

Under [CCPA Cal. Civ. Code § 1798.105 / GDPR Article 17], I request the
immediate deletion of all personal data you hold associated with:

Email: [YOUR_EMAIL]
Name: [YOUR_NAME]

I also request confirmation that:
1. My data has been deleted from all systems including backups
2. My data will not be re-collected or re-sold
3. Any third parties who received my data are notified of deletion

Please confirm completion within 30 days as required by law.

Regards,
[YOUR_NAME]
```

**Send to:** The enrichment provider's privacy@ or DPO email (found in their privacy policy).
