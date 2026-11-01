---
name: spam-nuke
description: "Use when the user wants to report spam email, cold outreach, robocalls, spam texts or phishing through every legitimate channel. Traces the sender's supply chain (email platform, registrar, host, carrier, blocklists, regulators) and files reports with whatever tools you have: email, browser, shell, phone. Triggers: 'nuke this spammer', 'report spam', 'do something about these spam calls', 'file FCC complaints', 'report this phishing'."
---

# Spam Nuke

Make spam expensive for the sender. Fresh domains and rotated inboxes cost spammers almost nothing; these cost them a lot:

- **Their email platform account.** Cold emailers depend on SendGrid, Instantly, Apollo, Mailgun and similar services. Abuse reports to those platforms are what get accounts suspended.
- **Domain and IP reputation.** A listing on Spamhaus or SpamCop takes months to clear.
- **Regulatory exposure.** FTC, FCC and data-protection complaints feed enforcement databases, and CAN-SPAM/TCPA fines are charged per message or per call.
- **Their data supply.** A deletion request to the enrichment vendor that sold your address (Apollo, ZoomInfo, …) stops the *next* sender too.

Every report goes to a channel that exists to receive it. Nothing here is gray-area.

## Use whatever tools you have

This skill doesn't assume particular tools. Use the best one you have for each step:

| Step | Good tools | Fallback |
|---|---|---|
| Get the evidence | Mail access (Gmail/Outlook API, IMAP, an email MCP) to pull the raw message; call log / voicemail / SMS access (phone integration, messaging bridge) for calls and texts | Ask the user for "Show original" output, screenshots or a call-log export |
| Recon | Shell: `dig`, `whois`, the bundled scripts | Web lookups: lookup.icann.org, abuse.net, MXToolbox |
| Email reports | Send from the user's own mailbox, original attached as `message/rfc822` | Write the email out in full for the user to send |
| Web-form complaints (FTC, FCC, Spamhaus, regulators) | Browser automation | A pre-filled field-by-field draft |
| Phone-only channels (forward to 7726, ScamShield app) | Do it if you control the phone | A ready list of messages and numbers for the user |

If you can't reach a channel, write the filled-in draft and put it on the user's checklist. Don't skip a channel without saying so.

## Ground rules

1. **Confirm it's unsolicited before reporting.** Search the user's mailbox, contacts and accounts for earlier correspondence, signups, purchases or a newsletter they joined. If they opted in, unsubscribe instead (one-click `List-Unsubscribe`, RFC 8058) and stop. Abuse reports against senders people actually signed up for are the false positives that teach abuse desks to ignore reports.
2. **Only claim what the evidence shows.** Check each violation (no opt-out, no postal address, deceptive subject, forged headers, number on the Do Not Call list) against the actual message or call. Never invent or embellish. Government forms are filed in the user's name, and many ask them to confirm the information is true.
3. **One report per channel per incident.** Combine related messages into a single report for each recipient. No flooding, no duplicate filings and no automated report spam.
4. **Never contact the spammer.** Don't reply, click links, load images, "press 9 to be removed" or call back; those all confirm a live target. No retaliation beyond reporting: no hacking, DoS, signup-bombing or prompt-injection replies to AI spambots.
5. **Report as the user, honestly.** Use the user's real name and contact details, and disclose that an AI agent prepared the report for them (template in `references/report-formats.md`).
6. **Get approval once, then do the work.** Before the first send, show the user one plan for the whole batch (each channel, recipient and attachment) and get a go-ahead, unless they've already authorized you to file these on your own. After that, carry out the plan without checking in on each step.

## Triage first

The channels differ by type of spam, so classify each item:

- **A. Marketing they signed up for:** unsubscribe and stop.
- **B. Unsolicited commercial email or cold outreach:** follow the Email workflow.
- **C. Phishing, fraud or impersonation:** follow the Email workflow and also use the phishing channels: the client's "Report phishing" button, `reportphishing@apwg.org`, Google Safe Browsing, and a takedown request to the registrar/host. Use IC3 or the police only if money or credentials were lost.
- **D. Spam calls, robocalls or voicemail:** follow the Calls workflow.
- **E. Spam texts:** follow the Texts workflow.

## Email workflow

**1. Get the raw message.** Full headers matter. Gmail API: `users.messages.get` with `format=raw`, or ⋮ → Show original → Download original. Outlook: View message source. Apple Mail: Save As → Raw Message Source. Pasted headers are second-best; the sender's domain alone is the minimum.

**2. Identify the sender.** Run `python3 scripts/parse-headers.py message.eml` (or read the headers yourself). It extracts From, Return-Path, DKIM `d=`, sending IPs, the email platform's fingerprint, the SPF/DKIM/DMARC results and a company confidence score. If confidence is LOW/UNKNOWN or the domains disagree, investigate before filing anything with a regulator. Never report a domain that was merely spoofed.

**3. Map the supply chain.** Run `bash scripts/recon.sh <domain>` to get the registrar and its abuse contact, the hosting provider (A record → IP owner), the DNS provider, other sending platforms in the SPF includes, DKIM selectors and CNAMEs. Abuse addresses change, so check them on abuse.net or the provider's abuse page; `references/report-targets.md` is a starting point, not the final word.

**4. File the reports**, highest leverage first:
- **Tier 1:** the email platform's abuse desk (the account cold emailers can't cheaply replace); SpamCop if the user has an account (forward as an attachment); mark as spam in the client (e.g. add the `SPAM` label via the Gmail API, which trains the filter); Spamhaus.
- **Tier 2, regulators chosen by where the user and the sender are:** US: forward to `spam@uce.gov`, plus ReportFraud.ftc.gov for deceptive or fraudulent mail. EU: the data protection authority (GDPR Art. 77). UK: ICO. Canada: Spam Reporting Centre. Australia: forward to `report@submit.spam.acma.gov.au`. Singapore: PDPC.
- **Tier 3:** the registrar; the host; the CRM or sales-engagement tool (from tracking links or pixels); a data-deletion request to the likely enrichment vendor (GDPR Art. 17 / CCPA).
- **Tier 4:** AbuseIPDB (sending IPs), SURBL/URIBL (domains linked in the body), Google Safe Browsing (deceptive landing pages).

Templates are in `references/report-formats.md` and endpoints in `references/report-targets.md`.

## Calls workflow (robocalls and voicemail)

**1. Gather, per call:** the caller-ID number (report it even if it may be spoofed), the user's number, the date and time, any callback number or company named, and the voicemail transcript or recording if there is one.

**2. Clean the list.** Remove duplicates and group by caller number. Leave out the user's contacts, businesses they actually deal with, calls they returned and anything that looks wanted (appointment reminders, deliveries, 2FA). List anything ambiguous for the user rather than reporting it.

**3. File the reports (US):**
- **FTC:** DoNotCall.gov → Report Unwanted Calls (https://www.donotcall.gov/report.html), the streamlined form for when no money was lost. Include the number that received the call, the caller ID, any callback number, the date/time and whether it was a recording. If money was lost, use ReportFraud.ftc.gov instead. The FTC publishes reported numbers every business day for carriers' call-blocking.
- **FCC:** https://consumercomplaints.fcc.gov → Phone → "Unwanted calls/texts" → "All other unwanted calls/messages". International numbers go in Additional Information. The FCC doesn't resolve individual complaints, but it uses them for enforcement. Never file twice for the same call. For a repeat caller, one complaint listing every date and time is stronger than many copies; where the form allows only one call per complaint, file one per distinct call event.
- **Do Not Call Registry:** check whether the number is registered, and register it if not (DoNotCall.gov sends a confirmation email that must be clicked within 72h). Sales robocalls without written consent are illegal whether or not the number is registered.
- **Carrier:** block and report in the phone's or carrier's spam-call tool.
- **State attorney general:** for repeat offenders in states with strong telemarketing laws.

**Elsewhere:** Canada: CRTC National Do Not Call List complaint (lnnte-dncl.gc.ca). UK: register with TPS, then the ICO nuisance-calls form. Australia: ACMA / Do Not Call Register complaint. Singapore: the ScamShield app (answered calls only) and, for telemarketing to a Singapore number, the PDPC DNC complaint form. Other countries: the national telecom regulator.

## Texts workflow

- **Forward to 7726 ("SPAM")** from the receiving phone (most US, UK and Canadian carriers), and use "Report junk" / "Report spam" in Messages or Google Messages.
- **US:** the FCC form above (texts use the same sub-issue); ReportFraud.ftc.gov for scams.
- **Canada:** Spam Reporting Centre (https://www.fightspam.gc.ca/src); CASL covers SMS.
- **Australia:** forward to 0429 999 888.
- **Singapore:** the ScamShield app; the PDPC DNC complaint form for telemarketing.
- If you can't send from the user's phone, give them the exact messages and numbers to forward.

## Finish with a record

Write a checklist (e.g. `spam-nuke-<sender>-<date>.md`) with each channel, the date filed, the confirmation or ticket number, what's still waiting on the user, and anything you deliberately skipped and why. Keep confirmation emails and screenshots alongside it. Re-check in about two weeks: if the spam continues, escalate (state AG, a second-tier provider, a follow-up on the open ticket) rather than refiling the same reports.

## Files

| File | Purpose |
|---|---|
| `scripts/parse-headers.py` | Header analysis: email platform fingerprint (30+ platforms), sending IPs, authentication results, company confidence score. Python 3, standard library only. |
| `scripts/recon.sh` | DNS/WHOIS supply-chain map for a domain. Needs `dig` and `whois`; runs on macOS bash 3.2 and Linux. |
| `references/report-targets.md` | Directory of abuse contacts, blocklists and regulators (email, calls, texts). |
| `references/report-formats.md` | Report templates: email platform (ARF-style), registrar, host, FTC, GDPR, data deletion, phone complaints. |
