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
# Most financially damaging attack type
# FBI: $2.8 billion lost in 2024
    "bec_signals": {
        "weight": 15,  # Highest weight of any trigger
        "patterns": [
            # Bank account change — #1 BEC signal
            r'\b(changed?|updated?|new)\b.{0,30}\b(bank|account|banking)\b',
            r'\bnew (bank(ing)? )?(account|details|information)\b',
            r'\bupdate your (records|banking|account)\b',
            r'\bdisregard.{0,20}(previous|old|former)\b',

            # Wire transfer requests
            r'\b(process|make|send|transfer).{0,20}(payment|transfer|wire)\b',
            r'\bwire (transfer|the funds|money)\b',
            r'\baccount (number|details):.{0,50}\d{6,}\b',
            r'\brouting.{0,20}\d{6,}\b',

            # False meeting reference
            r'\b(further to|following up on|as (per|discussed|agreed))\b.{0,30}\b(meeting|conversation|call|discussion)\b',
            r'\bas (we |previously )?discussed\b',
            r'\bper our (conversation|agreement|discussion)\b',

            # Urgency + payment combo
            r'\bprocess (this |the payment )?(today|immediately|urgently|asap)\b',
            r'\bdue (today|tonight|this evening|by end of day)\b',
            r'\bvendor payment\b',
            r'\bpayment due\b',
        ]
    },

    # URGENCY — most common phishing trigger
    # "urgency short-circuits rational evaluation" — research 2024
    "urgency": {
        "weight": 8,
        "patterns": [
            r'\burgent\b', r'\bimmediately\b', r'\bright now\b',
            r'\bwithin 24 hours\b', r'\bwithin \d+ hours\b',
            r'\bexpires (today|soon|shortly)\b',
            r'\blast chance\b', r'\bact now\b',
            r'\bdo not delay\b', r'\btime (is running out|sensitive)\b',
            r'\bdeadline\b', r'\btoday only\b',
            # Nepali context urgency
            r'\bतुरुन्त\b', r'\bअत्यावश्यक\b',
        ]
    },

    # FEAR — threats of negative consequences
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

    # AUTHORITY — impersonating figures of power
    "authority": {
        "weight": 10,
        "patterns": [
            # Nepal government authority
            r'\bministry\b', r'\bgovernment of nepal\b',
            r'\bnepal rastra bank\b', r'\bnrb\b',
            r'\binland revenue\b', r'\bird nepal\b',
            r'\bpublic service commission\b', r'\blok sewa\b',
            r'\bciaa\b', r'\bprime minister\b',
            r'\bnepal police\b', r'\barmy\b',
            r'\bjoint secretary\b', r'\bsecretary\b',
            r'\bdirector general\b',
            # Global authority
            r'\bceo\b', r'\bchief executive\b',
            r'\bmanaging director\b', r'\bpresident\b',
            r'\bfbi\b', r'\binterpol\b', r'\bpolice\b',
        ]
    },

    # SECRECY — asking to keep things private
    # Classic BEC attack pattern
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

    # FINANCIAL BAIT — promising money
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
            # Nepal specific
            r'\bprovident fund\b', r'\bnppf\b',
        ]
    },

    # CREDENTIAL HARVESTING — asking for sensitive info
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
            # Nepal digital wallets
            r'\besewa (pin|password|otp)\b',
            r'\bkhalti (mpin|password|otp)\b',
            r'\bconnectips (password|credentials)\b',
        ]
    },

    # IMPERSONATION SIGNALS — fake identity markers
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

    # PAYMENT PRESSURE — forcing payment
    "payment_pressure": {
        "weight": 9,
        "patterns": [
            r'\bwire transfer\b', r'\bbank transfer\b',
            r'\bgift card(s)?\b',
            r'\bpay (immediately|now|urgently|today)\b',
            r'\bpayment (overdue|required|pending|due)\b',
            r'\btransfer (funds|money|amount)\b',
            r'\besewa number\b', r'\bkhalti number\b',
            r'\bfonepay\b',
            r'\bprocessing fee\b', r'\bregistration fee\b',
            r'\badvance (payment|fee)\b',
        ]
    },
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
                "matches": list(set(matches))[:3],  # Max 3 examples
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
    """
    Check email structure for manipulation signs
    """
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    sender = email_data.get("sender", "")

    anomalies = []

    # ALL CAPS subject — panic inducing
    if subject.isupper() and len(subject) > 5:
        anomalies.append("Subject in ALL CAPS — designed to create panic")

    # Excessive punctuation
    if subject.count("!") > 1:
        anomalies.append("Multiple exclamation marks in subject")

    # Generic greeting — not personalized
    generic_greetings = ["dear user", "dear customer", "dear valued",
                          "dear account holder", "dear sir/madam",
                          "dear officer", "dear employee"]
    body_lower = body.lower()
    for greeting in generic_greetings:
        if greeting in body_lower:
            anomalies.append(f"Generic non-personalized greeting: '{greeting}'")
            break

    # Reply-to different from sender
    # (checked in email headers in production)

    # Very short body with link — classic phishing
    word_count = len(body.split())
    url_count = len(re.findall(r'http[s]?://', body))
    if word_count < 50 and url_count > 0:
        anomalies.append("Very short email body with links — classic phishing pattern")

    # Excessive links
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
    full_text = f"{subject} {body}"

    # Run analysis
    trigger_analysis = analyze_triggers(full_text)
    structural = check_structural_anomalies(email_data)

    # Calculate risk (max 20 points)
    risk_points = 0
    findings = []

    # Score based on triggers found
    trigger_count = trigger_analysis["trigger_count"]

    if trigger_count >= 4:
        risk_points += 20
        findings.append(
            f"🚨 HIGHLY MANIPULATIVE: {trigger_count} psychological "
            f"manipulation tactics detected simultaneously"
        )
    elif trigger_count == 3:
        risk_points += 14
        findings.append(f"⚠️ Multiple manipulation tactics: {trigger_count} triggers found")
    elif trigger_count == 2:
        risk_points += 9
        findings.append(f"⚠️ Manipulation tactics detected: {trigger_count} triggers")
    elif trigger_count == 1:
        risk_points += 4

    # Add findings for each trigger
    for trigger_name, data in trigger_analysis["triggers_found"].items():
        findings.append(
            f"   • {trigger_name.upper()}: detected '{data['matches'][0]}'"
        )

    # Structural anomalies
    risk_points += min(structural["anomaly_count"] * 2, 5)
    for anomaly in structural["anomalies"]:
        findings.append(f"⚠️ {anomaly}")

    # Special case: credential request is always high risk
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