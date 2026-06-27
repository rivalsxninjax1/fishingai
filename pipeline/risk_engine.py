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

    layer_map = {r.get("layer", ""): r for r in layer_results}
    auth = layer_map.get("Authentication", {})
    domain = layer_map.get("Domain Intelligence", {})
    behavior = layer_map.get("Sender Behaviour", {})

    auth_details = auth.get("details", {})
    domain_details = domain.get("details", {})
    behavior_details = behavior.get("details", {})

    is_legitimate = behavior_details.get("legitimate", False)

    # Hard structural signals
    spoofing = auth_details.get("spoofing", {}).get("spoofing_detected", False)
    homograph = domain_details.get("homograph", {}).get("has_homograph", False)
    lookalike = domain_details.get("lookalike", {}).get("is_lookalike", False)
    fake_nepal_gov = domain_details.get("tld_check", {}).get("is_fake_nepal_gov", False)

    # ── ABSOLUTE SAFETY NET ──
    # If score is very low AND no hard structural threats
    # Nothing can make this SCAM — not even Llama
    no_structural_threat = not (spoofing or homograph or lookalike or fake_nepal_gov)
    if total_score <= 10 and no_structural_threat:
        return "SAFE", "HIGH"

    # ── REST OF LOGIC CONTINUES ──

    # ── LLAMA IS PRIMARY JUDGE ──
    llama_verdict = ai_details.get("verdict", "UNKNOWN")
    llama_confidence = ai_details.get("confidence", "LOW")
    llama_ran = not ai.get("early_exit", False) and llama_verdict != "UNKNOWN"

    # If Llama ran and gave a confident verdict — trust it
    if llama_ran:
        if llama_verdict == "SCAM":
            return "SCAM", "HIGH"
        elif llama_verdict == "SUSPICIOUS":
            if total_score >= 30:
                return "SUSPICIOUS", "MEDIUM"
            else:
                return "SAFE", "MEDIUM"
        elif llama_verdict == "SAFE":
            # Even if Llama says safe, check for critical combinations
            has_credential = "credential_request" in triggers
            has_authority = "authority" in triggers
            has_secrecy = "secrecy" in triggers
            has_payment = "payment_pressure" in triggers

            # These combinations override even Llama's SAFE verdict
            if has_credential and has_authority and not is_legitimate:
                return "SCAM", "HIGH"
            if has_secrecy and has_payment and not is_legitimate:
                return "SCAM", "HIGH"

            return "SAFE", "HIGH" if total_score < 15 else "MEDIUM"

  
    # ── FALLBACK — Llama skipped (early exit) or failed ──
    # Check if early exit was triggered — means layers already confirmed threat
    early_exit_triggered = any(
        r.get("early_exit", False) and r.get("layer") == "AI Analysis"
        for r in layer_results
    )

    if early_exit_triggered:
        return "SCAM", "HIGH"

    # Normal score based fallback
    if total_score >= 55:
        return "SCAM", "HIGH"
    elif total_score >= 35:
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