import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from pipeline.risk_engine import analyze_all_layers

# ─────────────────────────────────────────────────────
# TEST CASES — All 12 scam types + safe emails
# ─────────────────────────────────────────────────────

TEST_CASES = [

    # ── TEST 1 — Nigerian Prince ──
    {
        "id": "T01",
        "name": "Nigerian Prince / Advance Fee",
        "expected": "SCAM",
        "email": {
            "subject": "Confidential Business Proposal — $10 Million USD",
            "sender": "prince.ahmed@yahoo.com",
            "body": """Dear Friend,
I am Prince Ahmed Al-Rashid, son of late King of Nigeria.
I have $10,000,000 USD that I need to transfer to a safe account abroad.
I will give you 30% commission for your assistance.
Please send me your full name, bank account number and phone number urgently.
This is 100% safe and legal. God bless you.
Prince Ahmed"""
        }
    },

    # ── TEST 2 — BEC Bank Account Change ──
    {
        "id": "T02",
        "name": "BEC — Bank Account Change",
        "expected": "SCAM",
        "email": {
            "subject": "Follow up on our meeting yesterday",
            "sender": "john.miller@consulting-group.com",
            "body": """Hi,
Further to our conversation yesterday regarding the procurement contract,
please process the transfer of USD 15,000 to our new banking details.
We recently changed banks so please disregard previous account information.
Account Number: 4521896370
Routing: 021000089
Please process today as vendor payment is due tonight.
John Miller, Senior Consultant"""
        }
    },

    # ── TEST 3 — Nepal Government Impersonation ──
    {
        "id": "T03",
        "name": "Nepal Government Impersonation",
        "expected": "SCAM",
        "email": {
            "subject": "URGENT: Ministry of Finance Nepal — Budget Allocation",
            "sender": "ministry.finance.nepal@gmail.com",
            "body": """Dear Government Officer,
This is an urgent notice from the Ministry of Finance Nepal.
Your department has been selected for special budget allocation of NPR 50,00,000.
To process this transfer we require your personal bank account details
and citizenship number immediately.
Please respond within 24 hours or the allocation will be cancelled.
Joint Secretary, Ministry of Finance Nepal"""
        }
    },

    # ── TEST 4 — Fake Nepal Rastra Bank ──
    {
        "id": "T04",
        "name": "Fake Nepal Rastra Bank",
        "expected": "SCAM",
        "email": {
            "subject": "Nepal Rastra Bank — Account Verification Required",
            "sender": "Nepal Rastra Bank <nrb-verify@gmail.com>",
            "body": """Dear Account Holder,
Nepal Rastra Bank has detected suspicious transactions on your account.
You must immediately verify your identity by providing:
- Citizenship number
- Bank account number
- eSewa PIN
Click here to verify: http://nrb-nepal-verify.tk/secure
Failure to verify within 24 hours will result in account suspension.
Nepal Rastra Bank Security Team"""
        }
    },

    # ── TEST 5 — IRD Tax Threat ──
    {
        "id": "T05",
        "name": "IRD Nepal Tax Scam",
        "expected": "SCAM",
        "email": {
            "subject": "URGENT NOTICE: Unpaid Tax — Legal Action Pending",
            "sender": "ird.nepal.notice@gmail.com",
            "body": """OFFICIAL NOTICE — Inland Revenue Department Nepal
You have unpaid taxes of NPR 2,50,000 for fiscal year 2080/81.
Failure to pay immediately will result in:
- Criminal proceedings
- Asset seizure
- Arrest warrant
Pay now via eSewa: 9800000000
Case Number: IRD-2081-NPR-44521
This is your final notice before legal action.
IRD Nepal Enforcement Division"""
        }
    },

    # ── TEST 6 — eSewa Credential Theft ──
    {
        "id": "T06",
        "name": "eSewa Credential Theft",
        "expected": "SCAM",
        "email": {
            "subject": "Congratulations! Your eSewa Account Won NPR 50,000",
            "sender": "esewa.rewards@gmail.com",
            "body": """Dear eSewa Customer,
Congratulations! Your eSewa account has been selected as our lucky winner.
You have won NPR 50,000 in our anniversary celebration lucky draw.
To claim your prize please verify your eSewa account:
- Enter your eSewa ID
- Enter your eSewa PIN
- Enter OTP sent to your number
Click here to claim: http://esewa-prize-nepal.xyz/claim
Offer expires in 24 hours. Claim now!
eSewa Rewards Team"""
        }
    },

    # ── TEST 7 — CEO Gift Card Fraud ──
    {
        "id": "T07",
        "name": "CEO Gift Card Fraud",
        "expected": "SCAM",
        "email": {
            "subject": "Urgent request",
            "sender": "ceo.office.nepal@gmail.com",
            "body": """Hi,
I am currently in a board meeting and cannot talk.
I need you to urgently purchase 5 Google Play gift cards
worth NPR 10,000 each. This is for a confidential company matter.
Please buy them immediately and send me the card codes by email.
Do not discuss this with anyone in the office.
I will explain everything later.
Regards
CEO"""
        }
    },

    # ── TEST 8 — Fake Job Offer ──
    {
        "id": "T08",
        "name": "Fake Foreign Job Offer",
        "expected": "SCAM",
        "email": {
            "subject": "Job Opportunity in Qatar — NPR 80,000/month",
            "sender": "qatar.jobs.nepal@gmail.com",
            "body": """Dear Applicant,
You have been selected for a high paying job opportunity in Qatar.
Position: Construction Manager
Salary: NPR 80,000 per month + accommodation + food
To confirm your placement you must pay:
- Visa processing fee: NPR 45,000
- Medical clearance: NPR 15,000
- Insurance: NPR 20,000
Total: NPR 80,000
Pay via eSewa: 9801234567
Seats are limited. Pay within 48 hours to confirm.
Nepal Qatar Employment Agency"""
        }
    },

    # ── TEST 9 — Display Name Spoofing ──
    {
        "id": "T09",
        "name": "Display Name Spoofing — NRB",
        "expected": "SCAM",
        "email": {
            "subject": "Important security update from Nepal Rastra Bank",
            "sender": "Nepal Rastra Bank <scammer123@hotmail.com>",
            "body": """Dear Customer,
Nepal Rastra Bank requires all account holders to update their KYC.
Please login to update your details immediately to avoid account suspension.
www.nrb-kyc-update.com/login
Nepal Rastra Bank Customer Service"""
        }
    },

    # ── TEST 10 — Homograph Domain Attack ──
    {
        "id": "T10",
        "name": "Homograph Domain Attack",
        "expected": "SCAM",
        "email": {
            "subject": "Your eSewa account needs verification",
            "sender": "support@esewа.com.np",
            "body": """Dear Customer,
Your eSewa account has been temporarily suspended due to unusual activity.
Please verify your account immediately to restore access.
Enter your PIN and OTP to verify your identity.
eSewa Support Team"""
        }
    },

    # ── TEST 11 — Safe Email (Must NOT flag) ──
    {
        "id": "T11",
        "name": "SAFE — Normal Business Email",
        "expected": "SAFE",
        "email": {
            "subject": "Meeting agenda for tomorrow",
            "sender": "colleague@company.com",
            "body": """Hi,
Just sending over the agenda for tomorrow's 10am meeting.
We will be covering Q3 budget review, project updates,
and planning for the next quarter.
Please come prepared with your department updates.
See you tomorrow.
Best regards,
Ramesh"""
        }
    },

    # ── TEST 12 — Safe Newsletter (Must NOT flag) ──
    {
        "id": "T12",
        "name": "SAFE — Newsletter",
        "expected": "SAFE",
        "email": {
            "subject": "Learn JavaScript Algorithms this week",
            "sender": "Quincy Larson <quincy@freecodecamp.org>",
            "body": """Hey,
This week on freeCodeCamp we published new JavaScript algorithm
challenges to help you prepare for technical interviews.
We also published a Python tutorial for beginners.
Check out this week's articles on our website.
Happy coding!
Quincy Larson
freeCodeCamp"""
        }
    },
]


async def run_single_test(test: dict, index: int, total: int) -> dict:
    """Run one test and return result"""
    email = test["email"]
    expected = test["expected"]

    result = await analyze_all_layers(email)

    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("risk_score", 0)
    time_taken = result.get("analysis_time", 0)
    passed = verdict == expected

    return {
        "id": test["id"],
        "name": test["name"],
        "expected": expected,
        "got": verdict,
        "score": score,
        "time": time_taken,
        "passed": passed,
        "llama_used": result.get("llama_used", False),
        "key_findings": result.get("reasons", [])[:3]
    }


async def run_all_tests():
    """Run all 12 tests and show results"""

    print(f"""
{'='*65}
  PHISHGUARD — FULL SYSTEM TEST
  Testing all 12 scam types
{'='*65}
""")

    results = []
    passed = 0
    failed = 0
    total_time = 0

    for i, test in enumerate(TEST_CASES):
        print(f"[{test['id']}] Testing: {test['name']}")
        print(f"     Expected: {test['expected']}")

        result = await run_single_test(test, i, len(TEST_CASES))
        results.append(result)

        status = "✅ PASS" if result["passed"] else "❌ FAIL"
        print(f"     Got     : {result['got']} ({result['score']}/100)")
        print(f"     Result  : {status} | Time: {result['time']}s | Llama: {result['llama_used']}")

        if not result["passed"]:
            print(f"     ⚠️  Top findings:")
            for f in result["key_findings"][:2]:
                print(f"        {f[:80]}")

        print()

        if result["passed"]:
            passed += 1
        else:
            failed += 1

        total_time += result["time"]

    # ── SUMMARY ──
    accuracy = round((passed / len(TEST_CASES)) * 100, 1)
    avg_time = round(total_time / len(TEST_CASES), 1)

    print(f"""
{'='*65}
  TEST SUMMARY
{'='*65}
  Total Tests : {len(TEST_CASES)}
  Passed      : {passed} ✅
  Failed      : {failed} ❌
  Accuracy    : {accuracy}%
  Avg Time    : {avg_time}s per email
{'='*65}

  BREAKDOWN:
""")

    for r in results:
        icon = "✅" if r["passed"] else "❌"
        print(f"  {icon} [{r['id']}] {r['name']:<40} {r['got']:<12} {r['score']}/100")

    print(f"\n{'='*65}")

    if accuracy == 100:
        print("  🎉 PERFECT SCORE — PhishGuard is production ready!")
    elif accuracy >= 90:
        print(f"  🔥 EXCELLENT — {failed} test(s) need fixing")
    elif accuracy >= 75:
        print(f"  ⚠️  GOOD — {failed} test(s) need attention")
    else:
        print(f"  🔴 NEEDS WORK — {failed} failures to fix")

    print(f"{'='*65}\n")

    return results


if __name__ == "__main__":
    asyncio.run(run_all_tests())