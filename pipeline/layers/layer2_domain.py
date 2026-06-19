import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import tldextract
import re
from datetime import datetime

# Homograph characters — Unicode lookalikes for Latin letters
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
    'с': 'c', 'х': 'x', 'ν': 'v', 'и': 'u',
    'ԁ': 'd', 'ɡ': 'g', 'ι': 'i', 'ո': 'n',
}

# Suspicious TLDs commonly used in scams
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs
    "xyz", "top", "club", "online",
    "site", "website", "space",
    "click", "link", "download"
}

# Known legitimate Nepal government domains
NEPAL_GOV_DOMAINS = {
    "nrb.org.np", "mof.gov.np", "ird.gov.np",
    "psc.gov.np", "nepalpolice.gov.np", "opmcm.gov.np",
    "ciaa.gov.np", "moha.gov.np", "army.mil.np",
    "passport.gov.np", "election.gov.np",
}

# Known legitimate domains to protect against lookalikes
PROTECTED_DOMAINS = {
    "nrb.org.np", "esewa.com.np", "khalti.com",
    "google.com", "paypal.com", "apple.com",
    "microsoft.com", "amazon.com",
    *NEPAL_GOV_DOMAINS
}


def detect_homograph(domain: str) -> dict:
    """Detect Unicode homograph attacks"""
    normalized = domain
    found = []

    for char, replacement in HOMOGRAPH_MAP.items():
        if char in domain:
            normalized = normalized.replace(char, replacement)
            found.append(f"'{char}' looks like '{replacement}'")

    return {
        "has_homograph": len(found) > 0,
        "normalized": normalized,
        "suspicious_chars": found
    }


def detect_lookalike(domain: str) -> dict:
    """
    Detect lookalike domains trying to impersonate trusted domains
    Examples:
    nrb-org.np trying to look like nrb.org.np
    paypa1.com trying to look like paypal.com
    gov-nepal-finance.com trying to look like mof.gov.np
    """
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain.lower()

    lookalike_of = None
    technique = None

    for protected in PROTECTED_DOMAINS:
        p_extracted = tldextract.extract(protected)
        p_name = p_extracted.domain.lower()

        # Check: contains protected domain name with additions
        if p_name in domain_name and domain_name != p_name:
            lookalike_of = protected
            technique = "subdomain_abuse"
            break

        # Check: protected name with numbers replacing letters
        # paypal → paypa1, google → g00gle
        normalized_domain = domain_name
        normalized_domain = normalized_domain.replace("0", "o")
        normalized_domain = normalized_domain.replace("1", "l")
        normalized_domain = normalized_domain.replace("3", "e")

        if normalized_domain == p_name and domain_name != p_name:
            lookalike_of = protected
            technique = "number_substitution"
            break

        # Check: extra hyphens or words added
        # nrb-secure.com, nepal-paypal.com
        parts = re.split(r'[-_]', domain_name)
        if p_name in parts and len(parts) > 1:
            lookalike_of = protected
            technique = "hyphen_addition"
            break

    return {
        "is_lookalike": lookalike_of is not None,
        "lookalike_of": lookalike_of,
        "technique": technique
    }


async def check_domain_age(domain: str) -> dict:
    """
    Check domain registration age
    New domains (< 30 days) are extremely suspicious
    """
    try:
        import whois
        loop = asyncio.get_event_loop()

        w = await loop.run_in_executor(
            None,
            lambda: whois.whois(domain)
        )

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return {
                "age_days": age_days,
                "is_new_domain": age_days < 30,
                "is_young_domain": age_days < 180,
                "creation_date": str(creation_date)
            }

    except Exception:
        pass

    return {
        "age_days": None,
        "is_new_domain": False,
        "is_young_domain": False,
        "creation_date": None
    }


def check_suspicious_tld(domain: str) -> dict:
    """Check if domain uses a suspicious TLD"""
    extracted = tldextract.extract(domain)
    tld = extracted.suffix.lower()

    # Check if ends with .np (Nepal) but not official gov
    is_fake_nepal_gov = (
        ".gov.np" in domain and
        domain not in NEPAL_GOV_DOMAINS
    )

    return {
        "tld": tld,
        "is_suspicious_tld": tld in SUSPICIOUS_TLDS,
        "is_fake_nepal_gov": is_fake_nepal_gov
    }


async def run(email_data: dict) -> dict:
    """
    LAYER 2 — Domain Intelligence
    Runs all domain checks concurrently
    """
    sender = email_data.get("sender", "")

    # Extract clean email and domain
    if "<" in sender:
        sender = sender.split("<")[1].replace(">", "").strip()
    domain = sender.split("@")[-1].lower() if "@" in sender else ""

    # Run concurrent checks
    domain_age = await check_domain_age(domain)

    # These are sync but fast
    homograph = detect_homograph(domain)
    lookalike = detect_lookalike(domain)
    tld_check = check_suspicious_tld(domain)

    # Calculate risk (max 20 points)
    risk_points = 0
    findings = []
    early_exit = False

    if homograph["has_homograph"]:
        risk_points += 20
        early_exit = True
        findings.append(
            f"🚨 HOMOGRAPH ATTACK: Domain uses fake Unicode characters: "
            f"{', '.join(homograph['suspicious_chars'])}"
        )

    if lookalike["is_lookalike"]:
        risk_points += 18
        early_exit = True
        findings.append(
            f"🚨 LOOKALIKE DOMAIN: '{domain}' is impersonating "
            f"'{lookalike['lookalike_of']}' using {lookalike['technique']}"
        )

    if tld_check["is_fake_nepal_gov"]:
        risk_points += 20
        early_exit = True
        findings.append(
            f"🚨 FAKE NEPAL GOVERNMENT DOMAIN: '{domain}' "
            f"claims to be .gov.np but is not an official domain"
        )

    if domain_age["is_new_domain"]:
        risk_points += 15
        findings.append(
            f"⚠️ VERY NEW DOMAIN: Only {domain_age['age_days']} days old — "
            f"created {domain_age['creation_date']}"
        )
    elif domain_age["is_young_domain"]:
        risk_points += 8
        findings.append(
            f"⚠️ Young domain: {domain_age['age_days']} days old"
        )

    if tld_check["is_suspicious_tld"]:
        risk_points += 10
        findings.append(
            f"⚠️ Suspicious TLD: .{tld_check['tld']} commonly used in scams"
        )

    return {
        "layer": "Domain Intelligence",
        "risk_points": min(risk_points, 20),
        "max_points": 20,
        "findings": findings,
        "details": {
            "domain": domain,
            "homograph": homograph,
            "lookalike": lookalike,
            "domain_age": domain_age,
            "tld_check": tld_check
        },
        "early_exit": early_exit
    }