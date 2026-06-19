import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
from data.scam_patterns import search_patterns, build_database

build_database()

async def run(email_data: dict) -> dict:
    """LAYER 6 — RAG Pattern Matching"""

    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    query = f"{subject} {body[:500]}"

    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(
        None,
        lambda: search_patterns(query, n_results=3)
    )

    risk_points = 0
    findings = []
    matched_patterns = []

    for i, meta in enumerate(results["metadatas"][0]):
        matched_patterns.append({
            "category": meta["category"],
            "risk": meta["risk"]
        })

        if meta["risk"] == "CRITICAL":
            risk_points += 5
            findings.append(
                f"🚨 PATTERN MATCH: {meta['category']} — {meta['explanation']}"
            )
        elif meta["risk"] == "HIGH":
            risk_points += 3
            findings.append(
                f"⚠️ Pattern match: {meta['category']} — {meta['explanation']}"
            )

    if not findings:
        findings.append("✅ No known scam patterns matched")

    return {
        "layer": "RAG Patterns",
        "risk_points": min(risk_points, 5),
        "max_points": 5,
        "findings": findings,
        "details": {"matched_patterns": matched_patterns},
        "early_exit": False
    }