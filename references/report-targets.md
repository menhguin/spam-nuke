# Spam Report Targets — Full Reference

Abuse endpoints, filing URLs and instructions for each target in the spam-nuke checklist: email, phishing, calls and texts.

> Abuse addresses and form URLs change. Treat this as a starting point: confirm the current contact on the provider's own abuse/trust page or via https://www.abuse.net before sending, and update this file when one has moved.

## ESP Abuse Teams

Report with full email headers attached. Most ESPs will investigate within 24-48h and may suspend the sender's account.

| ESP | Abuse Contact | Notes |
|-----|--------------|-------|
| **SendGrid (Twilio)** | abuse@sendgrid.com | Header fingerprint: `X-SG-EID`, `@sendgrid.net` in Received |
| **Mailgun** | abuse@mailgun.com | Header: `X-Mailgun-Sid`, `@mailgun.org` in Message-ID |
| **AWS SES** | email-abuse@amazon.com | Header: `@amazonses.com` in Message-ID, `X-SES-Outgoing` |
| **Postmark** | support@postmarkapp.com | Header: `X-PM-Message-Id`, strict anti-spam policy |
| **Mailchimp (Intuit)** | abuse@mailchimp.com | Header: `@mail*.mcdlv.net`, `X-MC-User` |
| **HubSpot** | abuse@hubspot.com | Header: `@hubspotemail.net`, tracking links in body |
| **Constant Contact** | abuse@constantcontact.com | Header: `@ccsend.com` |
| **ActiveCampaign** | abuse@activecampaign.com | Header: `@acsend.com` |
| **Brevo (ex-Sendinblue)** | abuse@brevo.com | Header: `@sendinblue.com` |
| **ConvertKit** | support@convertkit.com | Report via their abuse form |
| **Klaviyo** | compliance@klaviyo.com | Header: tracking links with `trk.klaviyomail.com` |
| **Customer.io** | support@customer.io | Header: `@cio.email` |
| **Resend** | support@resend.com | Header: `@resend.dev` |
| **Sparkpost (MessageBird)** | abuse@sparkpost.com | Header: `@sparkpostmail.com` |
| **Mailtrap** | support@mailtrap.io | Header: `@mailtrap.io` |
| **Instantly** | support@instantly.ai | Common cold email tool |
| **Lemlist** | support@lemlist.com | Common cold email tool |
| **Apollo.io** | support@apollo.io | Both enrichment and sending |
| **Outreach.io** | abuse@outreach.io | Sales engagement platform |
| **Salesloft** | abuse@salesloft.com | Sales engagement platform |
| **Smartlead** | support@smartlead.ai | Cold email infrastructure |
| **Woodpecker** | support@woodpecker.co | Cold email tool |
| **Reply.io** | support@reply.io | Sales engagement |
| **Mixmax** | support@mixmax.com | Header: tracking pixels/links from mixmax |
| **Mailshake** | support@mailshake.com | Cold outreach tool |

## Blocklists & Spam Databases

| Service | Submission URL/Method | Impact Level |
|---------|----------------------|-------------|
| **SpamCop** | https://www.spamcop.net — create account, submit via email parsing | High — feeds into many blocklists |
| **Spamhaus SBL** | https://submit.spamhaus.org — submit evidence | Critical — SBL listing blocks mail at most major providers |
| **Spamhaus DBL** | Domain blocklist — submitted alongside SBL | Critical — domain-level block |
| **SURBL** | http://www.surbl.org — domain URI blocklist | High — blocks links in email bodies |
| **URIBL** | https://uribl.com — URI blocklist | High |
| **Barracuda BRBL** | https://www.barracudacentral.org/lookups — report via lookup tool | Medium |
| **Abusix** | https://www.abusix.com — report via their platform | Medium |
| **abuse.net** | https://www.abuse.net — find abuse contacts for any domain | Utility — aggregates contacts |
| **AbuseIPDB** | https://www.abuseipdb.com/report — report sending IP | Medium |
| **DNSBL.info** | https://www.dnsbl.info — check current listings | Utility — diagnostic |

## Regulatory Bodies

### United States

| Agency | Filing URL | Applicable Law | When to Use |
|--------|-----------|---------------|------------|
| **FTC** | https://reportfraud.ftc.gov (+ forward to spam@uce.gov) | CAN-SPAM Act | Any commercial email to US recipient without opt-out, with misleading headers, or without physical address |
| **FTC (calls)** | https://www.donotcall.gov/report.html | Telemarketing Sales Rule | Unwanted sales calls / robocalls where no money was lost |
| **FCC** | https://consumercomplaints.fcc.gov | TCPA | Unsolicited calls and texts (Phone → "Unwanted calls/texts") |
| **State AG** | Varies by state | State anti-spam laws | CA, WA, VA have strong laws. Search "[state] attorney general consumer complaint" |
| **IC3** | https://www.ic3.gov | If phishing/fraud involved | Only for fraudulent emails, not just spam |

**CAN-SPAM violation checklist** (each is a separate violation, up to $51,744 per email):
- No opt-out mechanism
- Misleading "From" or "Subject" line
- No valid physical postal address
- Doesn't identify message as an ad (if applicable)
- Opt-out not honored within 10 business days

### European Union / EEA

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **Local DPA** | https://edpb.europa.eu/about-edpb/about-edpb/members_en (directory) | Sender or recipient in EU. File with sender's country DPA. |
| **noyb.eu** | https://noyb.eu/en/exercise-your-rights-article-77-complain-your-dpa | Templates and guidance for GDPR complaints |
| **ICO (UK)** | https://ico.org.uk/make-a-complaint | UK-nexus senders/recipients |

**GDPR complaint elements:**
- Cite Article 77 GDPR + Article 13 ePrivacy Directive
- No consent obtained for direct marketing (Article 6 — no legal basis)
- No prior business relationship (legitimate interest defense fails)
- Include: sender identity, your data processed, evidence (the email), dates

### Canada

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **CRTC (CASL)** | https://fightspam.gc.ca | Sender or recipient in Canada |

### Australia

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **ACMA** | https://www.acma.gov.au/report-spam | Australian Spam Act 2003 |

### Singapore

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **PDPC** | https://www.pdpc.gov.sg/complaints | Personal Data Protection Act |

## Infrastructure Providers — Abuse Contacts

### Domain Registrars

Look up via WHOIS (`whois <domain>` or https://lookup.icann.org). The abuse contact is in the WHOIS record.

| Registrar | Abuse Contact |
|-----------|--------------|
| **GoDaddy** | abuse@godaddy.com |
| **Namecheap** | abuse@namecheap.com |
| **Cloudflare Registrar** | abuse@cloudflare.com |
| **Google Domains** | registrar-abuse@google.com |
| **Porkbun** | abuse@porkbun.com |
| **Name.com** | abuse@name.com |
| **Hover** | abuse@hover.com |
| **Dynadot** | abuse@dynadot.com |
| **Gandi** | abuse@gandi.net |

### Hosting Providers

Identify via IP WHOIS of A record or sending IP.

| Provider | Abuse Contact |
|----------|--------------|
| **AWS** | abuse@amazonaws.com |
| **Google Cloud** | https://support.google.com/code/contact/cloud_platform_report |
| **Azure/Microsoft** | abuse@microsoft.com |
| **DigitalOcean** | abuse@digitalocean.com |
| **Hetzner** | abuse@hetzner.com |
| **OVH** | abuse@ovh.net |
| **Vultr** | abuse@vultr.com |
| **Linode (Akamai)** | abuse@linode.com |
| **Vercel** | https://vercel.com/abuse |
| **Netlify** | abuse@netlify.com |
| **Render** | abuse@render.com |
| **Railway** | abuse@railway.app |

### CDN Providers

| Provider | Abuse Contact |
|----------|--------------|
| **Cloudflare** | https://www.cloudflare.com/abuse/form |
| **Fastly** | abuse@fastly.com |
| **Akamai** | abuse@akamai.com |

### CRM / Sales Tools

If identifiable (from tracking pixels, link domains, or enrichment data):

| Provider | Abuse Contact | How to Identify |
|----------|--------------|----------------|
| **HubSpot** | abuse@hubspot.com | Tracking links, forms, chat widget |
| **Salesforce** | abuse@salesforce.com | Pardot links, SF tracking |
| **Pipedrive** | support@pipedrive.com | Tracking links |
| **Close.com** | support@close.com | Sales engagement |

### Data Enrichment Providers

If you can identify how they got your email:

| Provider | Abuse/Compliance Contact |
|----------|-------------------------|
| **Apollo.io** | privacy@apollo.io — request data deletion + report |
| **ZoomInfo** | privacy@zoominfo.com |
| **Clearbit (HubSpot)** | privacy@clearbit.com |
| **Lusha** | privacy@lusha.com |
| **RocketReach** | support@rocketreach.co |
| **Hunter.io** | support@hunter.io |
| **Snov.io** | support@snov.io |
| **LeadIQ** | privacy@leadiq.com |
| **Cognism** | privacy@cognism.com |
| **Kaspr** | dpo@kaspr.io |
| **Seamless.ai** | support@seamless.ai |

For all enrichment providers: file a **data deletion request** under GDPR/CCPA in addition to the abuse report. This removes the user's email from their database, preventing future scraping.

### Payment Processors

Nuclear option — only if the spammer is a commercial product you can identify the payment flow for:

| Provider | How to Report |
|----------|--------------|
| **Stripe** | https://stripe.com/legal/report-fraud — report for facilitating unsolicited commercial communication |
| **PayPal** | https://www.paypal.com/disputes — report if payment/invoice involved |

## Phishing / Fraud (in addition to the above)

| Channel | How | Notes |
|---------|-----|-------|
| Mail client | "Report phishing" (Gmail ⋮ menu, Outlook Report button) | Distinct from "Report spam"; feeds anti-phishing models |
| **APWG** | Forward to reportphishing@apwg.org | Shared with security vendors and takedown services |
| **Google Safe Browsing** | https://safebrowsing.google.com/safebrowsing/report_phish/ | Gets the landing page flagged in Chrome/Firefox/Safari |
| **Microsoft** | https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site | Flags in Edge / SmartScreen |
| Registrar + host | Abuse contacts above, ask for takedown | Phishing gets far faster action than plain spam |
| **IC3 (US)** | https://www.ic3.gov | Only if money or credentials were actually lost |

## Calls & Texts

Gather per call/message: caller-ID number (even if spoofed), the number that received it, date/time, any callback number or company named, transcript/recording/screenshot.

### United States

| Channel | How | Notes |
|---------|-----|-------|
| **FTC DoNotCall.gov** | https://www.donotcall.gov/report.html | Streamlined call report. Reported numbers are published each business day to carriers for call-blocking. Lost money → ReportFraud.ftc.gov instead |
| **FCC** | https://consumercomplaints.fcc.gov → Phone → "Unwanted calls/texts" → "All other unwanted calls/messages" | International numbers go in "Additional Information". Used for enforcement, not individual resolution |
| **Do Not Call Registry** | https://www.donotcall.gov (register/verify) | Confirm the emailed link within 72h. Sales robocalls without written consent are illegal regardless |
| **Carrier** | Forward spam texts to **7726** ("SPAM"); block + report in the phone/carrier spam tool | 7726 works on all major US carriers |
| **State AG** | Varies by state | Repeat offenders; strong telemarketing laws in e.g. FL, OK, WA |

### Canada

| Channel | How | Notes |
|---------|-----|-------|
| **CRTC National DNCL** | https://lnnte-dncl.gc.ca (file a complaint) | Telemarketing calls — the Spam Reporting Centre does NOT take call complaints |
| **Spam Reporting Centre** | https://www.fightspam.gc.ca/src | Spam texts (CASL covers SMS) and email |
| Carrier | Forward texts to 7726 | Supported by Canadian carriers |

### United Kingdom

| Channel | How | Notes |
|---------|-----|-------|
| **Carrier** | Forward spam texts to 7726 | All UK networks |
| **TPS** | https://www.tpsonline.org.uk (register) | Telephone Preference Service — UK do-not-call list |
| **ICO** | https://ico.org.uk/make-a-complaint/nuisance-calls-and-messages/ | Nuisance calls/texts complaints (PECR) |

### Australia

| Channel | How | Notes |
|---------|-----|-------|
| **ACMA (texts)** | Forward SMS to **0429 999 888** | Standard SMS charges apply |
| **ACMA (email)** | Forward to report@submit.spam.acma.gov.au | Don't edit the message or subject |
| **ACMA (calls)** | https://www.acma.gov.au (Do Not Call Register / telemarketing complaint) | Telemarketing to registered numbers |

### Singapore

| Channel | How | Notes |
|---------|-----|-------|
| **ScamShield app** | Report message / call / website in the app | Calls must have been answered to be reportable. Reviewed by police; confirmed numbers get blocked for all users |
| **PDPC DNC complaint** | https://www.pdpc.gov.sg/complaints-and-reviews/dnc-complaint-form | Telemarketing calls/SMS to a Singapore number |
| **ScamShield Helpline** | 1799 | Advice / bank routing if money was lost; not a police report |

## LinkedIn

If the spammer also reached out on LinkedIn or is identifiable there:
- Report their profile for spam
- Report their company page
- Report individual messages as spam

## Google-Specific

- **Gmail "Report spam" button** — trains Google's filters
- **Google Safe Browsing** — https://safebrowsing.google.com/safebrowsing/report_badware/ — if their landing page is deceptive
- **Google Ads** — If they run ads, report via https://support.google.com/ads/troubleshooter/4578507
