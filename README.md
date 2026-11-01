# spam-nuke

An agent skill that turns "do something about this spam" into reports filed through every legitimate channel in the sender's supply chain.

- **Email and cold outreach:** the sending platform's abuse desk (SendGrid, Instantly, Apollo, Mailgun, …), registrar, host, Spamhaus/SpamCop, regulators (FTC, EU DPAs, ICO, CASL, ACMA, PDPC), and a data-deletion request to the enrichment vendor that sold your address.
- **Spam calls and texts:** FTC DoNotCall.gov reports, FCC complaints, 7726 forwarding, Do Not Call registration, and national regulators (CRTC, ICO/TPS, ACMA, ScamShield/PDPC).
- **Phishing:** APWG, Safe Browsing and registrar/host takedown requests.

It works with any agent that can read a `SKILL.md` and doesn't assume particular tools. The agent uses whatever it has: mail access to pull raw messages and send abuse reports, a browser for government web forms, a shell for DNS/WHOIS, and phone or messaging access for call logs and forwarding texts. When it can't reach a channel, it writes the filled-in draft and adds it to your checklist.

## Install

Clone it into your agent's skills directory:

```bash
# Claude Code
git clone https://github.com/menhguin/spam-nuke ~/.claude/skills/spam-nuke

# Hermes
git clone https://github.com/menhguin/spam-nuke ~/.hermes/skills/spam-nuke
```

For any other agent, put the folder wherever it loads skills from, or give it the link and say "read SKILL.md and follow it".

Then: *"nuke this spammer"* (with an email), *"do something about the spam calls in my voicemail"*, or *"report this phishing text"*.

## What it won't do

- **Report mail you signed up for.** The agent checks your inbox for prior contact first and unsubscribes instead. False positives are what teach abuse desks to ignore reports.
- **Claim violations the evidence doesn't show,** or file the same incident twice.
- **Contact or retaliate against the sender:** no replies, link clicks or callbacks, and nothing beyond official reports.
- **Hide that an agent wrote it.** Every report says it was prepared by an AI agent on your behalf, with your real contact details.
- **Send before you approve the plan,** unless you've told your agent it can file these on its own.

## Contents

| Path | What |
|---|---|
| `SKILL.md` | The workflow the agent follows: triage, then the email, calls and texts workflows |
| `scripts/parse-headers.py` | Email header analysis: sending-platform fingerprint (30+), sending IPs, SPF/DKIM/DMARC, company confidence score. Python 3 standard library only |
| `scripts/recon.sh` | DNS/WHOIS supply-chain map: registrar, host, DNS, SPF includes, DKIM. Needs `dig` and `whois` |
| `references/report-targets.md` | Abuse contacts, blocklists and regulators by country (email, phishing, calls, texts) |
| `references/report-formats.md` | Report templates: email platform (ARF-style), registrar, host, FTC, GDPR, phone complaint, data deletion |

Abuse addresses and form URLs move, so the agent is told to confirm each one before sending. PRs with updated contacts are welcome.

MIT licensed.
