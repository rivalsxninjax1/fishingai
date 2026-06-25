import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import asyncio
import time

from pipeline.layers import (
    layer1_auth,
    layer2_domain,
    layer3_psychology,
    layer4_links,
    layer5_behavior,
    layer6_rag,
    layer7_llama,
)

# If preliminary score exceeds this — skip Llama
EARLY_EXIT_THRESHOLD = 75


# ─────────────────────────────────────────────────────
# SMART VERDICT CALCULATION
# Not just total score — considers critical signals
# ─────────────────────────────────────────────────────

def calculate_verdict(total_score: int, layer_results: list) -> tuple:
    """
    Smart verdict that considers:
    1. Total score
    2. Critical signal combinations
    3. RAG + AI agreement
    4. BEC specific signals
    """
    all_findings = []
    for r in layer_results:
        all_findings.extend(r.get("findings", []))
    findings_text = " ".join(all_findings).lower()

    # ── CRITICAL OVERRIDES ──
    # These combinations always = SCAM regardless of score

    # Spoofing confirmed — always scam
    spoofing_detected = (
        "spoofing" in findings_text or
        "homograph" in findings_text or
        "lookalike" in findings_text
    )

    # Known threat actor seen before
    known_threat = "known threat" in findings_text

    # BEC signals — bank account change + payment
    bec_detected = (
        "bec" in findings_text or
        (
            any(kw in findings_text for kw in [
                "changed", "new bank", "new account",
                "disregard", "update your records"
            ]) and
            any(kw in findings_text for kw in [
                "transfer", "payment", "wire", "process"
            ])
        ) or
        (
            "account number" in findings_text and
            "routing" in findings_text
        )
    )

    # RAG matched BEC/CEO/Invoice + AI also flagged
    rag_flagged = any(
        "pattern match" in f.lower() and
        any(threat in f.lower() for threat in [
            "bec", "ceo", "invoice", "impersonation",
            "advance fee", "nepal government"
        ])
        for f in all_findings
    )

    ai_flagged = any(
        r.get("layer") == "AI Analysis" and
        r.get("risk_points", 0) >= 5
        for r in layer_results
    )

    # Credential harvesting detected
    credential_theft = "requesting sensitive credentials" in findings_text

    # Fake Nepal government domain
    fake_gov = "fake nepal government" in findings_text

    # ── APPLY OVERRIDES ──
    if spoofing_detected or known_threat or fake_gov:
        return "SCAM", "HIGH"

    if bec_detected:
        return "SCAM", "HIGH"

    if credential_theft:
        return "SCAM", "HIGH"

    if rag_flagged and ai_flagged and total_score >= 20:
        return "SCAM", "HIGH"

    # ── STANDARD THRESHOLDS ──
    if total_score >= 65:
        return "SCAM", "HIGH"
    elif total_score >= 45:
        return "SUSPICIOUS", "MEDIUM"
    elif total_score < 15:
        return "SAFE", "HIGH"
    else:
        return "SAFE", "MEDIUM"


def get_recommended_action(verdict: str, score: int) -> str:
    if verdict == "SCAM":
        return (
            "🚨 DO NOT click any links, provide any information, "
            "or reply to this email. Mark as spam and report to IT security immediately."
        )
    elif verdict == "SUSPICIOUS":
        return (
            "⚠️ Treat with caution. Verify sender through official channels "
            "before responding. Do not click links or provide any information."
        )
    else:
        return "✅ Email appears safe. Normal caution still advised."


# ─────────────────────────────────────────────────────
# MAIN ENGINE — Runs all 7 layers
# ─────────────────────────────────────────────────────

async def analyze_all_layers(email_data: dict) -> dict:
    """
    Production grade 7-layer email analysis engine.

    Architecture:
    - Phase 1: Layers 1-5 run CONCURRENTLY (fast I/O bound)
    - Phase 2: Layer 6 RAG pattern matching
    - Phase 3: Layer 7 Llama — only if needed (smart skip)

    Result: Most scams caught in 2s, uncertain ones in ~20s
    """
    start_time = time.time()

    print(f"\n{'─'*60}")
    print(f"🔍 PhishGuard Analysis Starting")
    print(f"   Subject : {email_data.get('subject', '')[:60]}")
    print(f"   From    : {email_data.get('sender', '')[:60]}")
    print(f"{'─'*60}")

    # ─────────────────────────────────────────
    # PHASE 1 — Layers 1-5 ALL CONCURRENT
    # All fire at exactly the same time
    # Total wait = slowest single layer
    # ─────────────────────────────────────────
    phase1_start = time.time()
    print(f"⚡ Phase 1: Running layers 1-5 concurrently...")

    layer_results_raw = await asyncio.gather(
        layer1_auth.run(email_data),
        layer2_domain.run(email_data),
        layer3_psychology.run(email_data),
        layer4_links.run(email_data),
        layer5_behavior.run(email_data),
        return_exceptions=True
    )

    phase1_time = round(time.time() - phase1_start, 2)
    print(f"   ✅ Layers 1-5 done in {phase1_time}s")

    # Handle any layer that crashed gracefully
    processed_results = []
    for i, result in enumerate(layer_results_raw):
        if isinstance(result, Exception):
            print(f"   ⚠️  Layer {i+1} error: {result}")
            processed_results.append({
                "layer": f"Layer {i+1}",
                "risk_points": 0,
                "max_points": 0,
                "findings": [f"⚠️ Layer error — skipped"],
                "early_exit": False
            })
        else:
            processed_results.append(result)
            score = result.get("risk_points", 0)
            maximum = result.get("max_points", 0)
            print(f"   Layer {i+1} ({result.get('layer', ''):<25}): {score}/{maximum}")

    # ─────────────────────────────────────────
    # PHASE 2 — RAG Pattern Matching
    # Fast vector similarity search
    # ─────────────────────────────────────────
    print(f"\n📚 Phase 2: RAG pattern matching...")
    rag_result = await layer6_rag.run(email_data)
    processed_results.append(rag_result)
    print(f"   ✅ RAG done: {rag_result.get('risk_points', 0)}/{rag_result.get('max_points', 0)}")

    # ─────────────────────────────────────────
    # Calculate preliminary score
    # Decide if Llama is needed
    # ─────────────────────────────────────────
    preliminary_score = sum(
        r.get("risk_points", 0) for r in processed_results
    )
    any_early_exit = any(
        r.get("early_exit", False) for r in processed_results
    )

    print(f"\n📊 Preliminary score: {preliminary_score}/95")

    # ─────────────────────────────────────────
    # PHASE 3 — Llama AI
    # Smart skip: if already obviously scam
    # saves ~15 seconds on obvious cases
    # ─────────────────────────────────────────
    llama_skipped = False

    if any_early_exit or preliminary_score >= EARLY_EXIT_THRESHOLD:
        print(f"⚡ Phase 3: Llama SKIPPED — threat confirmed by earlier layers")
        llama_result = {
            "layer": "AI Analysis",
            "risk_points": 5,
            "max_points": 5,
            "findings": [
                "🚨 AI analysis skipped — "
                "threat confirmed by layers 1-6"
            ],
            "early_exit": True,
            "verdict": "SCAM",
            "category": "Confirmed Threat",
            "summary": "Threat confirmed by security layers — Llama not needed"
        }
        llama_skipped = True
    else:
        print(f"🤖 Phase 3: Running Llama analysis...")
        llama_result = await layer7_llama.run(
            email_data, processed_results
        )
        print(f"   ✅ Llama done: {llama_result.get('risk_points', 0)}/{llama_result.get('max_points', 0)}")

    processed_results.append(llama_result)

    # ─────────────────────────────────────────
    # FINAL SCORE + VERDICT
    # ─────────────────────────────────────────
    total_score = min(
        sum(r.get("risk_points", 0) for r in processed_results),
        100
    )

    verdict, confidence = calculate_verdict(total_score, processed_results)

    # Collect all meaningful findings
    all_findings = []
    for result in processed_results:
        for finding in result.get("findings", []):
            if finding and not finding.startswith("✅ No"):
                all_findings.append(finding)

    total_time = round(time.time() - start_time, 2)

    print(f"\n{'─'*60}")
    print(f"🏁 FINAL VERDICT: {verdict} ({total_score}/100)")
    print(f"   Confidence : {confidence}")
    print(f"   Total time : {total_time}s")
    print(f"   Llama used : {not llama_skipped}")
    print(f"{'─'*60}\n")

    return {
        # Email info
        "subject":      email_data.get("subject", ""),
        "sender":       email_data.get("sender", ""),
        "body":         email_data.get("body", "")[:500],

        # Verdict
        "verdict":      verdict,
        "risk_score":   total_score,
        "confidence":   confidence,
        "category":     llama_result.get("category", "Unknown"),
        "summary":      llama_result.get("summary", f"Risk score: {total_score}/100"),

        # Details
        "reasons":              all_findings,
        "recommended_action":   get_recommended_action(verdict, total_score),
        "matched_patterns":     rag_result.get("details", {}).get("matched_patterns", []),

        # Layer breakdown
        "layer_scores": {
            r["layer"]: {
                "score": r.get("risk_points", 0),
                "max":   r.get("max_points", 0)
            }
            for r in processed_results
        },

        # Meta
        "analysis_time":    total_time,
        "llama_used":       not llama_skipped,
        "phase1_time":      phase1_time,
    }