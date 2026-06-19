import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import ollama


def get_client():
    return ollama.Client(host="http://127.0.0.1:11434")


async def run(email_data: dict, previous_results: list = None) -> dict:
    """
    LAYER 7 — Llama Deep Analysis
    Only runs when other layers are uncertain
    Gets full context from all previous layers
    """

    subject = email_data.get("subject", "")
    sender = email_data.get("sender", "")
    body = email_data.get("body", "")[:400]

    # Build context from previous layers
    layer_context = ""
    if previous_results:
        for result in previous_results:
            if result.get("findings"):
                layer_context += f"\n{result['layer']}:\n"
                for finding in result["findings"][:3]:
                    layer_context += f"  {finding}\n"

    prompt = f"""You are PhishGuard AI, an expert email security system 
specialized in Nepal government and enterprise email threat detection.

FINDINGS FROM SECURITY LAYERS:
{layer_context}

EMAIL TO ANALYZE:
From: {sender}
Subject: {subject}
Body: {body[:800]}

Based on the security layer findings above, provide your final analysis.
Respond in EXACTLY this format:

VERDICT: [SAFE / SUSPICIOUS / SCAM]
CATEGORY: [Phishing / BEC / Advance Fee / Impersonation / Malware / LEGITIMATE]
SUMMARY: [One sentence — why this is or isn't a threat]
KEY_REASON: [The single most important reason for your verdict]"""

    loop = asyncio.get_event_loop()

    response = await loop.run_in_executor(
        None,
        lambda: get_client().chat(
            model="phishguard-fast",
            messages=[{"role": "user", "content": prompt}],
            options={
                "num_predict": 200,
                "temperature": 0.1,
                "top_p": 0.9,
            }
        )
    )

    text = response["message"]["content"]

    # Parse response
    verdict = "UNKNOWN"
    category = "Unknown"
    summary = ""
    key_reason = ""

    for line in text.split("\n"):
        if line.startswith("VERDICT:"):
            verdict = line.replace("VERDICT:", "").strip()
        elif line.startswith("CATEGORY:"):
            category = line.replace("CATEGORY:", "").strip()
        elif line.startswith("SUMMARY:"):
            summary = line.replace("SUMMARY:", "").strip()
        elif line.startswith("KEY_REASON:"):
            key_reason = line.replace("KEY_REASON:", "").strip()

    return {
        "layer": "AI Analysis",
        "risk_points": 5 if verdict in ["SCAM", "SUSPICIOUS"] else 0,
        "max_points": 5,
        "findings": [f"🤖 AI: {summary}", f"   Key reason: {key_reason}"],
        "verdict": verdict,
        "category": category,
        "summary": summary,
        "early_exit": False
    }