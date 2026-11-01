#!/usr/bin/env python3
"""
parse-headers.py — Extract sending infrastructure from raw email headers.
Usage: parse-headers.py <headers-file>
       echo "<headers>" | parse-headers.py -

Identifies: ESP, sending IPs, domains, authentication results, and abuse contacts.
"""

import sys
import re
import email
import ipaddress
from email.policy import default as default_policy

ESP_SIGNATURES = {
    # Header patterns → ESP name + abuse contact
    "sendgrid.net": ("SendGrid", "abuse@sendgrid.com"),
    "X-SG-EID": ("SendGrid", "abuse@sendgrid.com"),
    "X-SG-ID": ("SendGrid", "abuse@sendgrid.com"),
    "mailgun.org": ("Mailgun", "abuse@mailgun.com"),
    "X-Mailgun": ("Mailgun", "abuse@mailgun.com"),
    "amazonses.com": ("AWS SES", "email-abuse@amazon.com"),
    "X-SES-Outgoing": ("AWS SES", "email-abuse@amazon.com"),
    "postmarkapp.com": ("Postmark", "support@postmarkapp.com"),
    "X-PM-Message-Id": ("Postmark", "support@postmarkapp.com"),
    "mcsv.net": ("Mailchimp", "abuse@mailchimp.com"),
    "mcdlv.net": ("Mailchimp", "abuse@mailchimp.com"),
    "X-MC-User": ("Mailchimp", "abuse@mailchimp.com"),
    "hubspotemail.net": ("HubSpot", "abuse@hubspot.com"),
    "ccsend.com": ("Constant Contact", "abuse@constantcontact.com"),
    "sendinblue.com": ("Brevo", "abuse@brevo.com"),
    "brevo.com": ("Brevo", "abuse@brevo.com"),
    "sparkpostmail.com": ("SparkPost", "abuse@sparkpost.com"),
    "klaviyomail.com": ("Klaviyo", "compliance@klaviyo.com"),
    "activecampaign.com": ("ActiveCampaign", "abuse@activecampaign.com"),
    "cio.email": ("Customer.io", "support@customer.io"),
    "resend.dev": ("Resend", "support@resend.com"),
    "instantly.ai": ("Instantly", "support@instantly.ai"),
    "mixmax.com": ("Mixmax", "support@mixmax.com"),
    "outreach.io": ("Outreach", "abuse@outreach.io"),
    "salesloft.com": ("Salesloft", "abuse@salesloft.com"),
    "reply.io": ("Reply.io", "support@reply.io"),
    "lemlist.com": ("Lemlist", "support@lemlist.com"),
    "woodpecker.co": ("Woodpecker", "support@woodpecker.co"),
    "smartlead.ai": ("Smartlead", "support@smartlead.ai"),
    "mailshake.com": ("Mailshake", "support@mailshake.com"),
    "apollo.io": ("Apollo", "support@apollo.io"),
    "freshworks.com": ("Freshworks", "support@freshworks.com"),
}


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_unspecified)


def parse_headers(raw: str) -> dict:
    """Parse raw email headers and extract infrastructure info."""
    # Try parsing as full email first, fall back to headers-only
    msg = email.message_from_string(raw, policy=default_policy)

    result = {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "subject": msg.get("Subject", ""),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "sending_ips": [],
        "received_chain": [],
        "dkim_domains": [],
        "esps_detected": [],
        "auth_results": msg.get("Authentication-Results", ""),
        "spf_result": "",
        "dkim_result": "",
        "dmarc_result": "",
        "x_headers": {},
        "body_snippet": "",
        "company_id": {},  # Company identification + confidence
    }

    # Extract Received headers (reverse order = sending path)
    received_headers = msg.get_all("Received", [])
    for r in received_headers:
        result["received_chain"].append(r.strip())
        # Extract IPs
        ips = re.findall(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", r)
        result["sending_ips"].extend(ips)

    # Deduplicate IPs, remove private/loopback/link-local ranges
    # (only 172.16.0.0/12 is private — 172.0–15 and 172.32+ are public)
    result["sending_ips"] = list(dict.fromkeys(
        ip for ip in result["sending_ips"]
        if _is_public_ip(ip)
    ))

    # Extract DKIM signing domains
    dkim_headers = msg.get_all("DKIM-Signature", [])
    for dkim in dkim_headers:
        d_match = re.search(r"d=([^\s;]+)", dkim)
        if d_match:
            result["dkim_domains"].append(d_match.group(1))

    # Parse Authentication-Results
    auth = result["auth_results"]
    if auth:
        spf_match = re.search(r"spf=(\w+)", auth)
        dkim_match = re.search(r"dkim=(\w+)", auth)
        dmarc_match = re.search(r"dmarc=(\w+)", auth)
        if spf_match:
            result["spf_result"] = spf_match.group(1)
        if dkim_match:
            result["dkim_result"] = dkim_match.group(1)
        if dmarc_match:
            result["dmarc_result"] = dmarc_match.group(1)

    # Collect X- headers
    for key in msg.keys():
        if key.startswith("X-"):
            result["x_headers"][key] = msg.get(key, "")

    # Detect ESPs from all header content
    all_headers_str = raw
    seen_esps = set()
    for pattern, (esp_name, abuse_contact) in ESP_SIGNATURES.items():
        if pattern in all_headers_str and esp_name not in seen_esps:
            result["esps_detected"].append({
                "name": esp_name,
                "abuse_contact": abuse_contact,
                "matched_on": pattern,
            })
            seen_esps.add(esp_name)

    # Extract body snippet for company identification
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    result["body_snippet"] = part.get_content()[:1000]
                except Exception:
                    pass
                break
    else:
        try:
            result["body_snippet"] = msg.get_content()[:1000] if hasattr(msg, 'get_content') else ""
        except Exception:
            result["body_snippet"] = msg.get_payload(decode=True, errors="replace")[:1000] if msg.get_payload() else ""

    # Company identification with confidence scoring
    result["company_id"] = identify_company(result)

    return result


def identify_company(info: dict) -> dict:
    """
    Attempt to identify the company behind the spam. Returns:
    - company_domain: the likely company domain
    - signals: list of evidence supporting the identification
    - confidence: HIGH / MEDIUM / LOW / UNKNOWN
    - notes: explanation for human review
    """
    signals = []
    domains_seen = {}  # domain → list of signal descriptions

    # Signal 1: From domain (strongest if it's a company domain, not a freemail)
    from_domain = ""
    from_match = re.search(r'@([\w.-]+)', info.get("from", ""))
    if from_match:
        from_domain = from_match.group(1).lower()
        freemail = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                    "aol.com", "protonmail.com", "icloud.com", "mail.com"}
        if from_domain not in freemail:
            signals.append(f"From address uses company domain: {from_domain}")
            domains_seen.setdefault(from_domain, []).append("From header")

    # Signal 2: Return-Path domain (often reveals the real sender)
    rp_match = re.search(r'@([\w.-]+)', info.get("return_path", ""))
    if rp_match:
        rp_domain = rp_match.group(1).lower()
        # Strip ESP subdomains (em1234.company.com → company.com)
        rp_base = re.sub(r'^em\d+\.', '', rp_domain)
        rp_base = re.sub(r'^bounces?\+?\w*\.', '', rp_base)
        if rp_base and rp_base != from_domain:
            signals.append(f"Return-Path domain: {rp_domain} (base: {rp_base})")
            domains_seen.setdefault(rp_base, []).append("Return-Path")
        elif rp_base:
            signals.append(f"Return-Path confirms From domain: {rp_base}")
            domains_seen.setdefault(rp_base, []).append("Return-Path (confirms)")

    # Signal 3: DKIM signing domain
    for d in info.get("dkim_domains", []):
        d = d.lower()
        # Skip ESP signing domains
        esp_domains = {"sendgrid.net", "mailgun.org", "amazonses.com",
                       "postmarkapp.com", "mandrillapp.com"}
        if d not in esp_domains:
            signals.append(f"DKIM signed by company domain: {d}")
            domains_seen.setdefault(d, []).append("DKIM signature")

    # Signal 4: List-Unsubscribe domain
    unsub = info.get("list_unsubscribe", "")
    unsub_match = re.search(r'https?://([\w.-]+)', unsub)
    if unsub_match:
        unsub_domain = unsub_match.group(1).lower()
        # Strip common prefixes
        unsub_base = re.sub(r'^(email|mail|unsubscribe|links?|click|track)\.',
                            '', unsub_domain)
        signals.append(f"Unsubscribe link domain: {unsub_domain}")
        domains_seen.setdefault(unsub_base, []).append("List-Unsubscribe")

    # Signal 5: Body mentions (company name, product, website)
    body = info.get("body_snippet", "")
    body_urls = re.findall(r'https?://([\w.-]+)', body)
    for url_domain in body_urls:
        url_base = re.sub(r'^(www|app|links?|click|track|email)\.', '',
                          url_domain.lower())
        # Skip known ESP/tracking domains
        skip = {"sendgrid.net", "mailgun.org", "google.com", "bit.ly",
                "mailchi.mp", "hubspot.com", "salesforce.com"}
        if url_base not in skip and not url_base.startswith("127."):
            signals.append(f"Body contains URL: {url_domain}")
            domains_seen.setdefault(url_base, []).append("Body URL")

    # Score confidence
    if not domains_seen:
        return {
            "company_domain": None,
            "signals": signals,
            "confidence": "UNKNOWN",
            "notes": "Could not identify the sender company. The spam may use "
                     "anonymized infrastructure. Manual investigation required."
        }

    # Find the most corroborated domain
    best_domain = max(domains_seen.keys(),
                      key=lambda d: len(domains_seen[d]))
    signal_count = len(domains_seen[best_domain])
    sources = domains_seen[best_domain]

    if signal_count >= 3:
        confidence = "HIGH"
        notes = (f"Domain '{best_domain}' confirmed by {signal_count} independent "
                 f"signals ({', '.join(sources)}). Very likely the correct company.")
    elif signal_count == 2:
        confidence = "MEDIUM"
        notes = (f"Domain '{best_domain}' supported by {signal_count} signals "
                 f"({', '.join(sources)}). Likely correct but verify before filing "
                 f"regulatory complaints.")
    else:
        # Check if From domain is a real company domain (not freemail)
        if "From header" in sources:
            confidence = "MEDIUM"
            notes = (f"Domain '{best_domain}' appears in From header only. "
                     f"Could be the company or a proxy domain. Check the website "
                     f"at https://{best_domain} to confirm.")
        else:
            confidence = "LOW"
            notes = (f"Domain '{best_domain}' found in {sources[0]} only. "
                     f"The actual company may be different — spammers sometimes "
                     f"use proxy domains or third-party senders. Manual investigation "
                     f"strongly recommended before filing reports.")

    # Check for domain mismatch (potential obfuscation)
    unique_bases = set(domains_seen.keys())
    if len(unique_bases) > 2:
        notes += (f"\n⚠️  Multiple distinct domains detected ({', '.join(unique_bases)}). "
                  f"This may indicate the sender is obscuring their identity or using "
                  f"third-party infrastructure. Investigate each domain.")

    return {
        "company_domain": best_domain,
        "all_domains": dict(domains_seen),
        "signals": signals,
        "confidence": confidence,
        "notes": notes,
    }


def format_report(info: dict) -> str:
    """Format parsed header info as a readable report."""
    lines = []
    lines.append("=" * 50)
    lines.append("  EMAIL HEADER ANALYSIS")
    lines.append("=" * 50)
    lines.append("")

    lines.append(f"From: {info['from']}")
    lines.append(f"Subject: {info.get('subject', '[none]')}")
    lines.append(f"Reply-To: {info['reply_to'] or '[not set]'}")
    lines.append(f"Return-Path: {info['return_path'] or '[not set]'}")
    lines.append(f"Message-ID: {info['message_id']}")
    lines.append(f"List-Unsubscribe: {info['list_unsubscribe'] or '[not set]'}")
    lines.append("")

    # Company Identification section
    cid = info.get("company_id", {})
    if cid:
        lines.append("## COMPANY IDENTIFICATION")
        if cid.get("company_domain"):
            lines.append(f"  Domain: {cid['company_domain']}")
        lines.append(f"  Confidence: {cid.get('confidence', 'UNKNOWN')}")
        lines.append(f"  Notes: {cid.get('notes', '')}")
        if cid.get("signals"):
            lines.append("  Signals:")
            for s in cid["signals"]:
                lines.append(f"    • {s}")
        if cid.get("all_domains") and len(cid["all_domains"]) > 1:
            lines.append("  All domains found:")
            for d, sources in cid["all_domains"].items():
                lines.append(f"    {d} ← {', '.join(sources)}")
        lines.append("")

    lines.append("## Authentication")
    lines.append(f"  SPF: {info['spf_result'] or '[not checked]'}")
    lines.append(f"  DKIM: {info['dkim_result'] or '[not checked]'}")
    lines.append(f"  DMARC: {info['dmarc_result'] or '[not checked]'}")
    lines.append("")

    if info["dkim_domains"]:
        lines.append("## DKIM Signing Domains")
        for d in info["dkim_domains"]:
            lines.append(f"  - {d}")
        lines.append("")

    if info["sending_ips"]:
        lines.append("## Sending IPs (public)")
        for ip in info["sending_ips"]:
            lines.append(f"  - {ip}")
        lines.append("")

    if info["esps_detected"]:
        lines.append("## DETECTED ESPs")
        for esp in info["esps_detected"]:
            lines.append(f"  ✓ {esp['name']}")
            lines.append(f"    Abuse: {esp['abuse_contact']}")
            lines.append(f"    Matched: {esp['matched_on']}")
        lines.append("")

    if info["x_headers"]:
        lines.append("## X-Headers (notable)")
        for k, v in info["x_headers"].items():
            # Only show interesting ones
            if any(kw in k.lower() for kw in ["mailer", "campaign", "sg", "pm", "mc", "ses", "mailgun", "provider"]):
                lines.append(f"  {k}: {v}")
        lines.append("")

    if info["received_chain"]:
        lines.append(f"## Received Chain ({len(info['received_chain'])} hops)")
        for i, r in enumerate(info["received_chain"]):
            lines.append(f"  [{i}] {r[:200]}{'...' if len(r) > 200 else ''}")
        lines.append("")

    lines.append("=" * 50)
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse-headers.py <headers-file>")
        print("       echo '<headers>' | parse-headers.py -")
        sys.exit(1)

    source = sys.argv[1]
    if source == "-":
        raw = sys.stdin.read()
    else:
        with open(source, "r") as f:
            raw = f.read()

    info = parse_headers(raw)
    print(format_report(info))
