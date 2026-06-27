import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import ollama


def get_client():
    return ollama.Client(host="http://127.0.0.1:11434")


def build_evidence_brief(previous_results: list) -> str:
    """Build a structured evidence summary for Llama"""
    brief_parts = []

    for result in previous_results:
        layer = result.get("layer", "")
        score = result.get("risk_points", 0)
        max_score = result.get("max_points", 0)
        findings = result.get("findings", [])

        if score == 0:
            continue

        relevant_findings = [
            f for f in findings
            if not f.startswith("✅") and not f.startswith("ℹ️")
        ]

        if relevant_findings:
            brief_parts.append(f"{layer} ({score}/{max_score}):")
            for f in relevant_findings[:3]:
                brief_parts.append(f"  - {f[:100]}")

    return "\n".join(brief_parts) if brief_parts else "No significant signals detected by security layers."


async def run(email_data: dict, previous_results: list = None) -> dict:

    subject = email_data.get("subject", "")
    sender = email_data.get("sender", "")
    body = email_data.get("body", "")[:600]

    # Pre-extract facts to prevent Llama hallucination
    import re
    urls_found = re.findall(r'http[s]?://\S+', body)
    has_urls = len(urls_found) > 0
    url_count = len(urls_found)
    has_action_request = any(kw in body.lower() for kw in [
        "click here", "verify now", "enter your", "provide your",
        "send us", "confirm your password", "enter pin",
        "pay now", "wire transfer", "gift card"
    ])

    evidence = build_evidence_brief(previous_results or [])

    # Add objective facts to prevent hallucination
    facts = f"""
OBJECTIVE EMAIL FACTS (verified by scanner):
- URLs in email: {url_count} {'— ' + str(urls_found[:2]) if has_urls else '— none'}
- Contains explicit action request: {'YES — ' + str([kw for kw in ['click here','verify now','enter your','provide your','pay now','wire transfer','gift card'] if kw in body.lower()]) if has_action_request else 'NO'}
- Email length: {len(body.split())} words
"""

    prompt = f"""You are PhishGuard, an expert email security analyst for Nepal government offices.

SECURITY EVIDENCE FROM TECHNICAL LAYERS:
{evidence}
{facts}
EMAIL TO ANALYZE:
From: {sender}
Subject: {subject}
Body: {body}

ANALYSIS FRAMEWORK:

1. WHAT IS THIS EMAIL ASKING THE RECIPIENT TO DO?
   Read the body carefully. Does it ask for:
   - Credentials (password, PIN, OTP, citizenship number)? → High risk
   - Money transfer or gift cards? → High risk  
   - To click a specific link to login or verify? → High risk
   - Nothing — just informing of an action already taken? → Low risk

2. IS THERE ACTUALLY A SUSPICIOUS LINK?
   Check OBJECTIVE EMAIL FACTS above.
   If URLs in email = none, do NOT mention links as a risk factor.
   Do not invent links that are not there.

3. DOES THE REQUEST MAKE SENSE?
   Security notifications saying "if you didn't do this, visit our security center"
   are NORMAL and LEGITIMATE from any real company.
   This is NOT phishing — it is standard security practice.

4. WHAT IS THE SECURITY LAYER EVIDENCE SAYING?
   Score 0-10 with no strong signals = almost certainly safe.
   Only override low scores if there is a CLEAR harmful request in the email body.

VERDICT RULES:
- SAFE: Email notifies of something. No harmful action requested. OR score under 10 with no clear threat.
- SUSPICIOUS: Unusual sender + vague request OR moderate signals with unclear intent.
- SCAM: Clear request for credentials, money, or personal documents. OR confirmed spoofing/impersonation.

Respond in EXACTLY this format:
VERDICT: [SAFE or SUSPICIOUS or SCAM]
CATEGORY: [Phishing / BEC / Advance Fee / Job Scam / Nepal Gov Impersonation / Legitimate Notification / LEGITIMATE]
CONFIDENCE: [LOW or MEDIUM or HIGH]
SUMMARY: [One sentence — what this email is doing and why verdict]
KEY_REASON: [Single most decisive factor]"""

    loop = asyncio.get_event_loop()

    try:
        response = await loop.run_in_executor(
            None,
            lambda: get_client().chat(
                model="phishguard-fast",
                messages=[{"role": "user", "content": prompt}],
                options={
                    "num_predict": 150,
                    "temperature": 0.05,
                    "top_p": 0.9,
                }
            )
        )

        text = response["message"]["content"].strip()

        verdict = "UNKNOWN"
        category = "Unknown"
        confidence = "LOW"
        summary = ""
        key_reason = ""

        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("VERDICT:"):
                verdict = line.replace("VERDICT:", "").strip()
            elif line.startswith("CATEGORY:"):
                category = line.replace("CATEGORY:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                confidence = line.replace("CONFIDENCE:", "").strip()
            elif line.startswith("SUMMARY:"):
                summary = line.replace("SUMMARY:", "").strip()
            elif line.startswith("KEY_REASON:"):
                key_reason = line.replace("KEY_REASON:", "").strip()

        # Llama's verdict directly sets risk points
        if verdict == "SCAM":
            risk_points = 5
        elif verdict == "SUSPICIOUS":
            risk_points = 3
        else:
            risk_points = 0

        return {
            "layer": "AI Analysis",
            "risk_points": risk_points,
            "max_points": 5,
            "findings": [
                f"🤖 AI ({confidence} confidence): {summary}",
                f"   Key reason: {key_reason}"
            ],
            "verdict": verdict,
            "category": category,
            "confidence": confidence,
            "summary": summary,
            "early_exit": False,
            "details": {
                "verdict": verdict,
                "confidence": confidence,
            }
        }

    except Exception as e:
        return {
            "layer": "AI Analysis",
            "risk_points": 0,
            "max_points": 5,
            "findings": [f"⚠️ AI analysis failed: {str(e)[:50]}"],
            "verdict": "UNKNOWN",
            "category": "Unknown",
            "summary": "",
            "early_exit": False,
            "details": {}
        }