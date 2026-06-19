import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import time

from pipeline.layers import (
    layer1_auth,
    layer2_domain,
    layer3_psychology,
    layer4_links,
    layer5_behavior,
    layer6_rag,
)
from pipeline.risk_engine import calculate_verdict, get_recommended_action

# Fast check threshold
# Above this → confirmed result without Llama
FAST_CONFIRM_THRESHOLD = 60
FAST_SAFE_THRESHOLD = 20


async def fast_check(email_data: dict) -> dict:
    """
    Stage 1 — Fast check using only layers 1-6
    Returns result in ~2 seconds
    If uncertain → triggers background Llama analysis
    """
    start = time.time()

    # All 6 fast layers concurrent
    results_raw = await asyncio.gather(
        layer1_auth.run(email_data),
        layer2_domain.run(email_data),
        layer3_psychology.run(email_data),
        layer4_links.run(email_data),
        layer5_behavior.run(email_data),
        layer6_rag.run(email_data),
        return_exceptions=True
    )

    results = []
    for r in results_raw:
        if isinstance(r, Exception):
            results.append({
                "layer": "Error",
                "risk_points": 0,
                "max_points": 0,
                "findings": [],
                "early_exit": False
            })
        else:
            results.append(r)

    score = min(sum(r.get("risk_points", 0) for r in results), 95)
    any_early_exit = any(r.get("early_exit", False) for r in results)
    elapsed = round(time.time() - start, 2)

    # Determine if we need Llama
    needs_llama = (
        FAST_SAFE_THRESHOLD <= score < FAST_CONFIRM_THRESHOLD and
        not any_early_exit
    )

    if any_early_exit or score >= FAST_CONFIRM_THRESHOLD:
        verdict, confidence = calculate_verdict(score, results)
        status = "CONFIRMED"
    elif score < FAST_SAFE_THRESHOLD:
        verdict = "SAFE"
        confidence = "HIGH"
        status = "CONFIRMED"
    else:
        verdict = "SUSPICIOUS"
        confidence = "LOW"
        status = "PENDING_LLAMA"

    all_findings = []
    for r in results:
        all_findings.extend(r.get("findings", []))

    return {
        "subject": email_data.get("subject", ""),
        "sender": email_data.get("sender", ""),
        "verdict": verdict,
        "risk_score": score,
        "confidence": confidence,
        "status": status,
        "needs_llama": needs_llama,
        "findings": all_findings,
        "recommended_action": get_recommended_action(verdict, score),
        "fast_check_time": elapsed,
        "layer_results": results,
    }