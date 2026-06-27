import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
from models.database import SessionLocal, EmailThreat


async def check_sender_history(sender_email: str) -> dict:
    """
    Check if we have seen this sender before
    and what their history looks like
    """
    db = SessionLocal()
    try:
        # Clean sender email
        if "<" in sender_email:
            sender_email = sender_email.split("<")[1].replace(">", "").strip()

        # Get sender history
        history = db.query(EmailThreat)\
            .filter(EmailThreat.sender.contains(sender_email))\
            .order_by(EmailThreat.analyzed_at.desc())\
            .limit(10)\
            .all()

        if not history:
            return {
                "is_first_contact": True,
                "total_emails": 0,
                "previous_verdicts": [],
                "avg_risk_score": 0,
                "was_flagged_before": False
            }

        verdicts = [h.verdict for h in history]
        scores = [h.risk_score for h in history if h.risk_score]
        avg_score = sum(scores) / len(scores) if scores else 0
        was_flagged = any(v in ["SCAM", "SUSPICIOUS"] for v in verdicts)

        return {
            "is_first_contact": False,
            "total_emails": len(history),
            "previous_verdicts": verdicts,
            "avg_risk_score": round(avg_score, 1),
            "was_flagged_before": was_flagged
        }

    finally:
        db.close()


def check_reply_to_mismatch(email_data: dict) -> dict:
    """
    Check if Reply-To header is different from sender
    Classic phishing technique — you reply to attacker
    while email appears from legitimate source
    """
    sender = email_data.get("sender", "")
    reply_to = email_data.get("reply_to", "")

    if not reply_to:
        return {"mismatch": False, "detail": "No Reply-To header"}

    # Extract domains
    def get_domain(email):
        if "<" in email:
            email = email.split("<")[1].replace(">", "").strip()
        return email.split("@")[-1].lower() if "@" in email else ""

    sender_domain = get_domain(sender)
    reply_domain = get_domain(reply_to)

    mismatch = sender_domain != reply_domain and bool(reply_domain)

    return {
        "mismatch": mismatch,
        "sender_domain": sender_domain,
        "reply_domain": reply_domain,
        "detail": (
            f"Reply-To domain '{reply_domain}' differs from "
            f"sender domain '{sender_domain}'"
            if mismatch else "Reply-To matches sender"
        )
    }


async def run(email_data: dict) -> dict:
    """LAYER 5 — Sender Behaviour Analysis"""

    sender = email_data.get("sender", "")

        # Known legitimate domains — never flag as known threat
    # even if they appear in history with wrong scores
    LEGITIMATE_DOMAINS = {
        "tiktok.com", "google.com", "apple.com",
        "microsoft.com", "linkedin.com", "github.com",
        "amazon.com", "paypal.com", "netflix.com",
        "facebook.com", "instagram.com", "twitter.com",
        "flexjobs.com", "email.flexjobs.com",
        "manutd.com", "emails.manutd.com",
        "airdroid.com", "creatorworld.io",
        "tryhackme.com", "freecodecamp.org",
        "esewa.com.np", "khalti.com",
        "nabil.com.np", "everestbank.com.np",
    }

    # Extract clean domain
    sender_email = sender
    if "<" in sender:
        sender_email = sender.split("<")[1].replace(">", "").strip()
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

    is_known_legitimate = any(
        sender_domain == d or sender_domain.endswith("." + d)
        for d in LEGITIMATE_DOMAINS
    )

    # Skip history check entirely for known legitimate domains
    if is_known_legitimate:
        return {
            "layer": "Sender Behaviour",
            "risk_points": 0,
            "max_points": 10,
            "findings": [f"✅ Verified legitimate domain: {sender_domain}"],
            "details": {"legitimate": True, "history": {}},
            "early_exit": False
        }


    # Run checks
    history = await check_sender_history(sender)
    reply_check = check_reply_to_mismatch(email_data)

    risk_points = 0
    findings = []

    # First contact — slightly suspicious
    if history["is_first_contact"]:
        risk_points += 3
        findings.append("ℹ️ First time receiving email from this sender")
    elif history["was_flagged_before"]:
        risk_points += 10
        findings.append(
            f"🚨 KNOWN THREAT: This sender was previously flagged "
            f"({history['total_emails']} emails, avg risk: {history['avg_risk_score']}/100)"
        )
    else:
        findings.append(
            f"✅ Known sender: {history['total_emails']} previous emails, "
            f"avg risk score: {history['avg_risk_score']}/100"
        )

    # Reply-to mismatch
    if reply_check["mismatch"]:
        risk_points += 10
        findings.append(f"🚨 REPLY-TO MISMATCH: {reply_check['detail']}")

    return {
        "layer": "Sender Behaviour",
        "risk_points": min(risk_points, 10),
        "max_points": 10,
        "findings": findings,
        "details": {
            "history": history,
            "reply_check": reply_check
        },
        "early_exit": history["was_flagged_before"]
    }