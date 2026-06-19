import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ollama
from data.scam_patterns import search_patterns, build_database

# Make sure database is ready
build_database()

def analyze_email(email_data):
    """
    Full analysis pipeline:
    1. Search RAG database for similar scam patterns
    2. Send email + patterns to Llama for analysis
    3. Return structured risk report
    """

    subject = email_data.get("subject", "")
    sender = email_data.get("sender", "")
    body = email_data.get("body", "")

    # ─────────────────────────────────────
    # STEP 1 — RAG: Find similar patterns
    # ─────────────────────────────────────
    search_query = f"{subject} {body[:500]}"
    rag_results = search_patterns(search_query, n_results=3)

    # Format RAG results for the AI
    pattern_context = ""
    for i, doc in enumerate(rag_results["documents"][0]):
        meta = rag_results["metadatas"][0][i]
        pattern_context += f"""
Pattern {i+1}:
- Category: {meta['category']}
- Risk Level: {meta['risk']}
- Why it's dangerous: {meta['explanation']}
- Similar scam text: {doc[:200]}
"""

    # ─────────────────────────────────────
    # STEP 2 — AI Analysis with RAG context
    # ─────────────────────────────────────
    prompt = f"""You are PhishGuard, an expert email security AI trained specifically for Nepal government and enterprise email threat detection.

KNOWN SCAM PATTERNS FROM DATABASE:
{pattern_context}

EMAIL TO ANALYZE:
From: {sender}
Subject: {subject}
Body: {body[:1000]}

Analyze this email and respond in this EXACT format:

VERDICT: [SAFE / SUSPICIOUS / SCAM]
RISK_SCORE: [0-100]
CATEGORY: [type of threat or LEGITIMATE]
CONFIDENCE: [LOW / MEDIUM / HIGH]
SUMMARY: [One sentence summary]
REASONS:
- [Reason 1]
- [Reason 2]
- [Reason 3]
RECOMMENDED_ACTION: [What the recipient should do]
"""

    # Send to local Llama
    print(f"\n🔍 Analyzing: {subject[:50]}...")

    response = ollama.chat(
    model="llama3.1:8b",
    messages=[{"role": "user", "content": prompt}],
    options={
        "num_predict": 500,    # Max 500 tokens in response
        "temperature": 0.1,    # Low temp = faster, more consistent
        "top_p": 0.9,
    }
    )

    ai_response = response["message"]["content"]

    # ─────────────────────────────────────
    # STEP 3 — Parse AI response
    # ─────────────────────────────────────
    report = parse_response(ai_response, email_data, rag_results)
    return report

def parse_response(ai_text, email_data, rag_results):
    """Extract structured data from AI response"""

    lines = ai_text.strip().split("\n")
    report = {
        "subject": email_data.get("subject", ""),
        "sender": email_data.get("sender", ""),
        "verdict": "UNKNOWN",
        "risk_score": 0,
        "category": "UNKNOWN",
        "confidence": "LOW",
        "summary": "",
        "reasons": [],
        "recommended_action": "",
        "raw_analysis": ai_text,
        "matched_patterns": []
    }

    # Parse each line
    for line in lines:
        if line.startswith("VERDICT:"):
            report["verdict"] = line.replace("VERDICT:", "").strip()
        elif line.startswith("RISK_SCORE:"):
            try:
                score = line.replace("RISK_SCORE:", "").strip()
                report["risk_score"] = int(score)
            except:
                report["risk_score"] = 0
        elif line.startswith("CATEGORY:"):
            report["category"] = line.replace("CATEGORY:", "").strip()
        elif line.startswith("CONFIDENCE:"):
            report["confidence"] = line.replace("CONFIDENCE:", "").strip()
        elif line.startswith("SUMMARY:"):
            report["summary"] = line.replace("SUMMARY:", "").strip()
        elif line.startswith("RECOMMENDED_ACTION:"):
            report["recommended_action"] = line.replace("RECOMMENDED_ACTION:", "").strip()
        elif line.startswith("- "):
            report["reasons"].append(line.replace("- ", "").strip())

    # Add matched patterns from RAG
    for i, meta in enumerate(rag_results["metadatas"][0]):
        report["matched_patterns"].append({
            "category": meta["category"],
            "risk": meta["risk"]
        })

    return report

def print_report(report):
    """Print a beautiful report in terminal"""

    # Risk color indicator
    score = report["risk_score"]
    if score >= 75:
        indicator = "🔴 HIGH RISK"
    elif score >= 40:
        indicator = "🟡 SUSPICIOUS"
    else:
        indicator = "🟢 SAFE"

    print("\n" + "="*60)
    print(f"  PHISHGUARD THREAT REPORT  {indicator}")
    print("="*60)
    print(f"📨 From    : {report['sender']}")
    print(f"📌 Subject : {report['subject']}")
    print(f"⚠️  Verdict : {report['verdict']}")
    print(f"📊 Risk    : {report['risk_score']}/100")
    print(f"🏷️  Category: {report['category']}")
    print(f"🎯 Summary : {report['summary']}")
    print(f"\n🔍 Reasons:")
    for reason in report["reasons"]:
        print(f"   • {reason}")
    print(f"\n✅ Action  : {report['recommended_action']}")
    print(f"\n🗄️  Matched Patterns:")
    for pattern in report["matched_patterns"]:
        print(f"   • {pattern['category']} [{pattern['risk']}]")
    print("="*60)

if __name__ == "__main__":
    # Test with a fake Nepal scam email
    test_email = {
        "subject": "Urgent: Ministry of Finance Nepal - Budget Allocation",
        "sender": "finance.nepal.gov@gmail.com",
        "body": """Dear Government Officer,

This is an urgent notice from the Ministry of Finance Nepal.
Your department has been selected for a special budget allocation
of NPR 50,00,000. To process this transfer we require your
personal bank account details and citizenship number immediately.

Please respond within 24 hours or the allocation will be cancelled.

regards,
Joint Secretary
Ministry of Finance, Nepal"""
    }

    report = analyze_email(test_email)
    print_report(report)