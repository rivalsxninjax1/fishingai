import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
from data.scam_patterns import search_patterns, build_database

# Build database on import
build_database()


def search_patterns_with_distance(query_text, n_results=3):
    """Search database and return distances for confidence scoring"""
    from data.scam_patterns import collection
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        include=["documents", "metadatas", "distances"]
    )
    return results


async def run(email_data: dict) -> dict:
    """LAYER 6 — RAG Pattern Matching with confidence threshold"""

    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    sender = email_data.get("sender", "")
    query = f"{subject} {body[:500]}"

    loop = asyncio.get_event_loop()

    # Get matches WITH distances — lower distance = better match
    results = await loop.run_in_executor(
        None,
        lambda: search_patterns_with_distance(query, n_results=3)
    )

    risk_points = 0
    findings = []
    matched_patterns = []

    documents = results["documents"][0]
    metadatas = results["metadatas"][0]
    distances = results.get("distances", [[1.0, 1.0, 1.0]])[0]

    for i, (doc, meta, distance) in enumerate(zip(documents, metadatas, distances)):

        # Distance threshold — only trust close matches
        # ChromaDB distance: 0.0 = identical, 2.0 = completely different
        # Only count matches with distance < 0.8 (strong semantic similarity)
        if distance > 0.8:
            continue

        matched_patterns.append({
            "category": meta["category"],
            "risk": meta["risk"],
            "distance": round(distance, 3)
        })

        # Weight by both risk level AND match quality
        if meta["risk"] == "CRITICAL" and distance < 0.4:
            risk_points += 5
            findings.append(
                f"🚨 STRONG PATTERN MATCH: {meta['category']} — {meta['explanation']}"
            )
        elif meta["risk"] == "CRITICAL" and distance < 0.8:
            risk_points += 2
            findings.append(
                f"⚠️ Weak pattern match: {meta['category']}"
            )
        elif meta["risk"] == "HIGH" and distance < 0.5:
            risk_points += 3
            findings.append(
                f"⚠️ Pattern match: {meta['category']} — {meta['explanation']}"
            )
        elif meta["risk"] == "HIGH" and distance < 0.8:
            risk_points += 1
            findings.append(
                f"ℹ️ Loose pattern similarity: {meta['category']}"
            )

    if not findings:
        findings.append("✅ No strong scam patterns matched")

    return {
        "layer": "RAG Patterns",
        "risk_points": min(risk_points, 5),
        "max_points": 5,
        "findings": findings,
        "details": {"matched_patterns": matched_patterns},
        "early_exit": False
    }