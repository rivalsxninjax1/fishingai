import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import re
import asyncio

# ─────────────────────────────────────────────────────
# PSYCHOLOGICAL TRIGGERS
# Based on Cialdini's influence principles +
# research on phishing psychology 2024
# ─────────────────────────────────────────────────────

TRIGGERS = {

    # BEC — BUSINESS EMAIL COMPROMISE
    "bec_signals": {
        "weight": 15,
        "patterns": [
            r'\b(changed?|updated?|new)\b.{0,30}\b(bank|account|banking)\b',
            r'\bnew (bank(ing)? )?(account|details|information)\b',
            r'\bupdate your (records|banking|account)\b',
            r'\bdisregard.{0,20}(previous|old|former)\b',
            r'\b(process|make|send|transfer).{0,20}(payment|transfer|wire)\b',
            r'\bwire (transfer|the funds|money)\b',
            r'\baccount (number|details):.{0,50}\d{6,}\b',
            r'\brouting.{0,20}\d{6,}\b',
            r'\b(further to|following up on|as (per|discussed|agreed))\b.{0,30}\b(meeting|conversation|call|discussion)\b',
            r'\bas (we |previously )?discussed\b',
            r'\bper our (conversation|agreement|discussion)\b',
            r'\bprocess (this |the payment )?(today|immediately|urgently|asap)\b',
            r'\bdue (today|tonight|this evening|by end of day)\b',
            r'\bvendor payment\b',
            r'\bpayment due\b',
        ]
    },

    # URGENCY
    "urgency": {
        "weight": 8,
        "patterns": [
            r'\burgent\b', r'\bimmediately\b', r'\bright now\b',
            r'\bwithin 24 hours\b', r'\bwithin \d+ hours\b',
            r'\bexpires (today|soon|shortly)\b',
            r'\blast chance\b', r'\bact now\b',
            r'\bdo not delay\b', r'\btime (is running out|sensitive)\b',
            r'\bdeadline\b', r'\btoday only\b',
            r'\bतुरुन्त\b', r'\bअत्यावश्यक\b',
        ]
    },

    # FEAR
    "fear": {
        "weight": 9,
        "patterns": [
            r'\baccount (will be |has been )?(suspended|closed|terminated|blocked)\b',
            r'\blegal action\b', r'\bcriminal (proceedings|charges)\b',
            r'\barrest\b', r'\bpenalty\b', r'\bfine\b',
            r'\bsuspended\b', r'\bblocked\b', r'\bterminated\b',
            r'\bunusual (activity|transaction)\b',
            r'\bsuspicious (activity|login|access)\b',
            r'\bcompromised\b', r'\bhacked\b', r'\bbreached\b',
            r'\bwarning\b', r'\balert\b',
        ]
    },

    # AUTHORITY
    "authority": {
        "weight": 10,
        "patterns": [
            r'\bministry\b', r'\bgovernment of nepal\b',
            r'\bnepal rastra bank\b', r'\bnrb\b',
            r'\binland revenue\b', r'\bird nepal\b',
            r'\bpublic service commission\b', r'\blok sewa\b',
            r'\bciaa\b', r'\bprime minister\b',
            r'\bnepal police\b', r'\barmy\b',
            r'\bjoint secretary\b', r'\bsecretary\b',
            r'\bdirector general\b',
            r'\bceo\b', r'\bchief executive\b',
            r'\bmanaging director\b', r'\bpresident\b',
            r'\bfbi\b', r'\binterpol\b', r'\bpolice\b',
        ]
    },

    # SECRECY
    "secrecy": {
        "weight": 10,
        "patterns": [
            r'\bkeep this (confidential|between us|private|secret)\b',
            r'\bdo not (discuss|tell|share|mention)\b',
            r'\bconfidential\b', r'\bprivate matter\b',
            r'\bdo not reply to this email\b',
            r'\bbetween you and (me|us)\b',
        ]
    },

    # FINANCIAL BAIT
    "financial_bait": {
        "weight": 7,
        "patterns": [
            r'\bnpr\s[\d,]+\b', r'\busd\s[\d,]+\b',
            r'\b\$[\d,]+\b',
            r'\bmillion\b', r'\blottery\b', r'\bprize\b',
            r'\bwon\b', r'\bwinnings\b', r'\binheritance\b',
            r'\bfund(s)?\b.*\btransfer\b',
            r'\bcommission\b', r'\breward\b',
            r'\bbonus\b', r'\ballocation\b',
            r'\bprovident fund\b', r'\bnppf\b',
        ]
    },

    # CREDENTIAL HARVESTING
    "credential_request": {
        "weight": 10,
        "patterns": [
            r'\b(enter|provide|send|confirm|verify|update)\b.{0,30}\b(password|pin|otp|mpin)\b',
            r'\bbank (account|details|number)\b',
            r'\bcitizenship (number|certificate)\b',
            r'\bpan number\b', r'\bnational id\b',
            r'\bkyc\b', r'\bverif(y|ication)\b.{0,20}\b(account|identity|details)\b',
            r'\bsocial security\b',
            r'\bcard (number|details|cvv)\b',
            r'\bexpirat(ion|y) date\b',
            r'\besewa (pin|password|otp)\b',
            r'\bkhalti (mpin|password|otp)\b',
            r'\bconnectips (password|credentials)\b',
        ]
    },

    # IMPERSONATION SIGNALS
    "impersonation": {
        "weight": 8,
        "patterns": [
            r'\bthis is (your )?(ceo|director|secretary|minister|officer)\b',
            r'\bi am (writing|contacting) (on behalf|from)\b',
            r'\bofficial notice\b', r'\bofficial communication\b',
            r'\bgovernment notice\b', r'\bformal notice\b',
            r'\byour account (has been|will be)\b',
            r'\bdear (valued |esteemed )?(customer|user|officer|employee|sir|madam)\b',
        ]
    },

    # PAYMENT PRESSURE
    "payment_pressure": {
        "weight": 9,
        "patterns": [
            r'\bwire transfer\b', r'\bbank transfer\b',
            r'\bgift card(s)?\b',
            r'\bpay (immediately|now|urgently|today)\b',
            r'\bpayment (overdue|required|pending|due)\b',
            r'\bplacement fee\b', r'\bvisa (fee|processing)\b',
            r'\bmedical (fee|clearance fee)\b',
            r'\bregistration fee\b.*\bjob\b',
            r'\bconfirm your (placement|position|seat)\b',
            r'\btransfer (funds|money|amount)\b',
            r'\besewa number\b', r'\bkhalti number\b',
            r'\bfonepay\b',
            r'\bprocessing fee\b', r'\bregistration fee\b',
            r'\badvance (payment|fee)\b',
        ]
    },
}

# ─────────────────────────────────────────────────────
# KNOWN LEGITIMATE DOMAINS
# Defined at module level — used inside run()
# ─────────────────────────────────────────────────────
LEGITIMATE_DOMAINS = {
    "tiktok.com", "google.com", "apple.com",
    "microsoft.com", "linkedin.com", "github.com",
    "amazon.com", "paypal.com", "netflix.com",
    "spotify.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "adobe.com",
    "dropbox.com", "slack.com", "zoom.us",
    "flexjobs.com", "email.flexjobs.com",
    "manutd.com", "emails.manutd.com",
    "airdroid.com", "creatorworld.io",
    "tryhackme.com", "freecodecamp.org",
    "esewa.com.np", "khalti.com", "fonepay.com",
    "nabil.com.np", "everestbank.com.np",
}


def analyze_triggers(text: str) -> dict:
    """Analyze text for psychological manipulation triggers"""
    text_lower = text.lower()
    found_triggers = {}
    total_weight = 0

    for trigger_name, trigger_data in TRIGGERS.items():
        matches = []
        for pattern in trigger_data["patterns"]:
            found = re.findall(pattern, text_lower)
            if found:
                matches.extend(found)

        if matches:
            found_triggers[trigger_name] = {
                "matches": list(set(matches))[:3],
                "weight": trigger_data["weight"],
                "count": len(matches)
            }
            total_weight += trigger_data["weight"]

    return {
        "triggers_found": found_triggers,
        "trigger_count": len(found_triggers),
        "total_weight": total_weight
    }


def check_structural_anomalies(email_data: dict) -> dict:
    """Check email structure for manipulation signs"""
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")

    anomalies = []

    if subject.isupper() and len(subject) > 5:
        anomalies.append("Subject in ALL CAPS — designed to create panic")

    if subject.count("!") > 1:
        anomalies.append("Multiple exclamation marks in subject")

    generic_greetings = [
        "dear user", "dear customer", "dear valued",
        "dear account holder", "dear sir/madam",
        "dear officer", "dear employee"
    ]
    body_lower = body.lower()
    for greeting in generic_greetings:
        if greeting in body_lower:
            anomalies.append(f"Generic non-personalized greeting: '{greeting}'")
            break

    word_count = len(body.split())
    url_count = len(re.findall(r'http[s]?://', body))
    if word_count < 50 and url_count > 0:
        anomalies.append("Very short email body with links — classic phishing pattern")

    if url_count > 3:
        anomalies.append(f"Unusual number of links: {url_count}")

    return {
        "anomalies": anomalies,
        "anomaly_count": len(anomalies)
    }


async def run(email_data: dict) -> dict:
    """LAYER 3 — Psychological Trigger Analysis"""

    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    sender = email_data.get("sender", "")
    full_text = f"{subject} {body}"

    # ─────────────────────────────────────────
    # Determine sender legitimacy
    # Reduces sensitivity for known real companies
    # ─────────────────────────────────────────
    sender_email = sender
    if "<" in sender:
        sender_email = sender.split("<")[1].replace(">", "").strip()
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

    is_known_legitimate = any(
        sender_domain == d or sender_domain.endswith("." + d)
        for d in LEGITIMATE_DOMAINS
    )

    # Legitimate senders get halved trigger weights
    sensitivity_multiplier = 0.5 if is_known_legitimate else 1.0

    # ─────────────────────────────────────────
    # Run analysis
    # ─────────────────────────────────────────
    trigger_analysis = analyze_triggers(full_text)
    structural = check_structural_anomalies(email_data)

    # Calculate risk (max 20 points)
    risk_points = 0
    findings = []

    trigger_count = trigger_analysis["trigger_count"]

    if trigger_count >= 4:
        risk_points += int(20 * sensitivity_multiplier)
        findings.append(
            f"🚨 HIGHLY MANIPULATIVE: {trigger_count} psychological "
            f"manipulation tactics detected simultaneously"
        )
    elif trigger_count == 3:
        risk_points += int(14 * sensitivity_multiplier)
        findings.append(f"⚠️ Multiple manipulation tactics: {trigger_count} triggers found")
    elif trigger_count == 2:
        risk_points += int(9 * sensitivity_multiplier)
        findings.append(f"⚠️ Manipulation tactics detected: {trigger_count} triggers")
    elif trigger_count == 1:
        risk_points += int(4 * sensitivity_multiplier)

    for trigger_name, data in trigger_analysis["triggers_found"].items():
            # Use friendly names instead of internal key names
            friendly_names = {
                "bec_signals": "Business Email Compromise signals",
                "urgency": "Urgency tactics",
                "fear": "Fear tactics",
                "authority": "Authority impersonation",
                "secrecy": "Secrecy request",
                "financial_bait": "Financial bait",
                "credential_request": "Credential harvesting",
                "impersonation": "Impersonation signals",
                "payment_pressure": "Payment pressure",
            }
            friendly = friendly_names.get(trigger_name, trigger_name.upper())
            findings.append(
                f"   • {friendly}: detected '{data['matches'][0]}'"
            )

    risk_points += min(structural["anomaly_count"] * 2, 5)
    for anomaly in structural["anomalies"]:
        findings.append(f"⚠️ {anomaly}")

    # Special overrides — always high risk regardless of sender
    if "credential_request" in trigger_analysis["triggers_found"]:
        risk_points = max(risk_points, 18)
        findings.insert(0, "🚨 EMAIL IS REQUESTING SENSITIVE CREDENTIALS")

    if "secrecy" in trigger_analysis["triggers_found"]:
        risk_points = max(risk_points, 16)
        findings.insert(0, "🚨 EMAIL REQUESTS SECRECY — Classic BEC attack pattern")

    return {
        "layer": "Psychological Analysis",
        "risk_points": min(risk_points, 20),
        "max_points": 20,
        "findings": findings,
        "details": {
            "triggers": trigger_analysis,
            "structural": structural
        },
        "early_exit": (
            "credential_request" in trigger_analysis["triggers_found"] and
            "authority" in trigger_analysis["triggers_found"]
        )
    }