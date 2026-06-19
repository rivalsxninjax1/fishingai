import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import dns.resolver
import re

# Cache DNS results for 1 hour to avoid repeated lookups
_dns_cache = {}

async def check_spf(domain: str) -> dict:
    """Check if domain has valid SPF record"""
    if domain in _dns_cache.get("spf", {}):
        return _dns_cache["spf"][domain]

    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: dns.resolver.resolve(domain, "TXT")
        )

        spf_record = None
        for record in answers:
            text = record.to_text()
            if "v=spf1" in text:
                spf_record = text
                break

        result = {
            "has_spf": spf_record is not None,
            "spf_record": spf_record,
            "spf_strict": "-all" in (spf_record or ""),  # Strict = blocks all unauthorized
        }

    except Exception:
        result = {"has_spf": False, "spf_record": None, "spf_strict": False}

    _dns_cache.setdefault("spf", {})[domain] = result
    return result


async def check_dmarc(domain: str) -> dict:
    """Check if domain has DMARC policy"""
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        )

        dmarc_record = None
        for record in answers:
            text = record.to_text()
            if "v=DMARC1" in text:
                dmarc_record = text
                break

        # Extract policy strength
        policy = "none"
        if dmarc_record:
            match = re.search(r'p=(\w+)', dmarc_record)
            if match:
                policy = match.group(1)

        return {
            "has_dmarc": dmarc_record is not None,
            "dmarc_record": dmarc_record,
            "policy": policy,           # none / quarantine / reject
            "policy_strict": policy == "reject"
        }

    except Exception:
        return {"has_dmarc": False, "dmarc_record": None, "policy": "none", "policy_strict": False}


async def check_display_name_spoofing(sender: str) -> dict:
    """
    Detect display name spoofing
    Example: "Nepal Rastra Bank <scammer@gmail.com>"
    Shows trusted name but uses untrusted email
    """
    # Extract display name and email
    display_name = ""
    email_address = sender

    if "<" in sender:
        parts = sender.split("<")
        display_name = parts[0].strip().strip('"').lower()
        email_address = parts[1].replace(">", "").strip()

    email_domain = email_address.split("@")[-1].lower() if "@" in email_address else ""

    # Known trusted organizations whose names should match their domains
    trusted_name_domain_pairs = {
        "nepal rastra bank": ["nrb.org.np"],
        "ministry of finance": ["mof.gov.np"],
        "inland revenue department": ["ird.gov.np"],
        "public service commission": ["psc.gov.np"],
        "nepal police": ["nepalpolice.gov.np"],
        "google": ["google.com", "gmail.com"],
        "paypal": ["paypal.com"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "outlook.com"],
        "esewa": ["esewa.com.np"],
        "khalti": ["khalti.com"],
        "nepal bank": ["nepalbank.com.np"],
        "nabil bank": ["nabil.com.np"],
        "ciaa": ["ciaa.gov.np"],
        "office of prime minister": ["opmcm.gov.np"],
    }

    spoofing_detected = False
    spoofing_detail = ""

    for org_name, legitimate_domains in trusted_name_domain_pairs.items():
        if org_name in display_name:
            if not any(d in email_domain for d in legitimate_domains):
                spoofing_detected = True
                spoofing_detail = (
                    f"Display name claims to be '{org_name}' "
                    f"but email domain is '{email_domain}' "
                    f"not {legitimate_domains}"
                )
                break

    return {
        "display_name": display_name,
        "email_address": email_address,
        "email_domain": email_domain,
        "spoofing_detected": spoofing_detected,
        "spoofing_detail": spoofing_detail,
    }


async def run(email_data: dict) -> dict:
    """
    LAYER 1 — Main entry point
    Runs all auth checks concurrently
    Returns score contribution + findings
    """
    sender = email_data.get("sender", "")

    # Extract domain
    email_address = sender
    if "<" in sender:
        email_address = sender.split("<")[1].replace(">", "").strip()
    domain = email_address.split("@")[-1] if "@" in email_address else ""

    # Run all checks concurrently
    spf, dmarc, spoofing = await asyncio.gather(
        check_spf(domain),
        check_dmarc(domain),
        check_display_name_spoofing(sender)
    )

    # Calculate risk score for this layer (max 25 points)
    risk_points = 0
    findings = []

    # SPF checks
    if not spf["has_spf"]:
        risk_points += 8
        findings.append("⚠️ No SPF record — domain cannot verify its senders")
    elif not spf["spf_strict"]:
        risk_points += 3
        findings.append("⚠️ SPF record exists but not strict")

    # DMARC checks
    if not dmarc["has_dmarc"]:
        risk_points += 8
        findings.append("⚠️ No DMARC policy — emails from this domain unverifiable")
    elif dmarc["policy"] == "none":
        risk_points += 4
        findings.append("⚠️ DMARC policy is 'none' — monitoring only, not enforcing")

    # Display name spoofing — most dangerous
    if spoofing["spoofing_detected"]:
        risk_points += 25  # Instant maximum — this is almost always a scam
        findings.append(f"🚨 DISPLAY NAME SPOOFING: {spoofing['spoofing_detail']}")

    return {
        "layer": "Authentication",
        "risk_points": min(risk_points, 25),  # Cap at 25
        "max_points": 25,
        "findings": findings,
        "details": {
            "spf": spf,
            "dmarc": dmarc,
            "spoofing": spoofing,
            "domain": domain
        },
        "early_exit": spoofing["spoofing_detected"]  # Skip Llama if spoofing confirmed
    }