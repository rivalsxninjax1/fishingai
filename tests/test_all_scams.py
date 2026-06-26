import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from pipeline.risk_engine import analyze_all_layers

TEST_CASES = [

    {
        "id": "T01",
        "name": "Nigerian Prince / Advance Fee",
        "expected": "SCAM",
        "email": {
            "subject": "Confidential Business Proposal — $10 Million USD",
            "sender": "prince.ahmed@yahoo.com",
            "body": """Dear Friend, I am Prince Ahmed Al-Rashid of Nigeria.
I have $10,000,000 USD to transfer to a safe account abroad.
I will give you 30% commission. Please send your bank account number urgently.
God bless you. Prince Ahmed"""
        }
    },

    {
        "id": "T02",
        "name": "BEC — Bank Account Change",
        "expected": "SCAM",
        "email": {
            "subject": "Follow up on our meeting yesterday",
            "sender": "john.miller@consulting-group.com",
            "body": """Hi, further to our conversation yesterday regarding the
procurement contract, please process the transfer of USD 15,000 to our new
banking details. We recently changed banks so please disregard previous account.
Account Number: 4521896370 Routing: 021000089
Please process today as vendor payment is due tonight. John Miller"""
        }
    },

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
and citizenship number immediately. Please respond within 24 hours.
Joint Secretary, Ministry of Finance Nepal"""
        }
    },

    {
        "id": "T04",
        "name": "Fake Nepal Rastra Bank",
        "expected": "SCAM",
        "email": {
            "subject": "Nepal Rastra Bank — Account Verification Required",
            "sender": "Nepal Rastra Bank <nrb-verify@gmail.com>",
            "body": """Dear Account Holder,
Nepal Rastra Bank has detected suspicious transactions on your account.
Verify your identity immediately by providing citizenship number and bank details.
Click here: http://nrb-nepal-verify.tk/secure
Failure to verify within 24 hours will result in account suspension.
Nepal Rastra Bank Security Team"""
        }
    },

    {
        "id": "T05",
        "name": "IRD Nepal Tax Scam",
        "expected": "SCAM",
        "email": {
            "subject": "URGENT NOTICE: Unpaid Tax — Legal Action Pending",
            "sender": "ird.nepal.notice@gmail.com",
            "body": """OFFICIAL NOTICE — Inland Revenue Department Nepal
You have unpaid taxes of NPR 2,50,000 for fiscal year 2080/81.
Failure to pay immediately will result in criminal proceedings and arrest.
Pay now via eSewa: 9800000000
Case Number: IRD-2081-NPR-44521
This is your final notice before legal action.
IRD Nepal Enforcement Division"""
        }
    },

    {
        "id": "T06",
        "name": "eSewa Credential Theft",
        "expected": "SCAM",
        "email": {
            "subject": "Congratulations! Your eSewa Account Won NPR 50,000",
            "sender": "esewa.rewards@gmail.com",
            "body": """Dear eSewa Customer,
Your eSewa account has won NPR 50,000 in our anniversary lucky draw.
To claim your prize verify your account:
Enter your eSewa PIN and OTP to verify.
Click here: http://esewa-prize-nepal.xyz/claim
Offer expires in 24 hours. Claim now!
eSewa Rewards Team"""
        }
    },

    {
        "id": "T07",
        "name": "CEO Gift Card Fraud",
        "expected": "SCAM",
        "email": {
            "subject": "Urgent request",
            "sender": "ceo.office.nepal@gmail.com",
            "body": """Hi, I am currently in a board meeting and cannot talk.
I need you to urgently purchase 5 Google Play gift cards worth NPR 10,000 each.
This is confidential. Please buy them immediately and send me the codes by email.
Do not discuss this with anyone in the office. I will explain everything later.
CEO"""
        }
    },

    {
        "id": "T08",
        "name": "Fake Foreign Job Offer",
        "expected": "SCAM",
        "email": {
            "subject": "Job Opportunity in Qatar — NPR 80,000/month",
            "sender": "qatar.jobs.nepal@gmail.com",
            "body": """Dear Applicant, you have been selected for a job in Qatar.
Position: Construction Manager. Salary: NPR 80,000 per month.
To confirm your placement you must pay:
Visa processing fee: NPR 45,000
Medical clearance: NPR 15,000
Total: NPR 60,000. Pay via eSewa: 9801234567
Seats are limited. Pay within 48 hours to confirm.
Nepal Qatar Employment Agency"""
        }
    },

    {
        "id": "T09",
        "name": "Display Name Spoofing",
        "expected": "SCAM",
        "email": {
            "subject": "Important security update from Nepal Rastra Bank",
            "sender": "Nepal Rastra Bank <scammer123@hotmail.com>",
            "body": """Dear Customer, Nepal Rastra Bank requires all account holders
to update their KYC immediately to avoid account suspension.
Please login to update your details: www.nrb-kyc-update.com/login
Nepal Rastra Bank Customer Service"""
        }
    },

    {
        "id": "T10",
        "name": "CEO Impersonation BEC",
        "expected": "SCAM",
        "email": {
            "subject": "Confidential — Wire Transfer Needed",
            "sender": "ceo.urgent@gmail.com",
            "body": """This is the CEO. I need you to process a confidential
wire transfer of $50,000 immediately to this account.
Keep this between us and do not discuss with anyone else in the office.
This is urgent. I am in a meeting and cannot call.
Process today without fail."""
        }
    },

    {
        "id": "T11",
        "name": "SAFE — Normal Business Email",
        "expected": "SAFE",
        "email": {
            "subject": "Meeting agenda for tomorrow",
            "sender": "colleague@company.com",
            "body": """Hi, just sending over the agenda for tomorrow's 10am meeting.
We will be covering Q3 budget review and project updates.
Please come prepared with your department updates.
See you tomorrow. Best regards, Ramesh"""
        }
    },

    {
        "id": "T12",
        "name": "SAFE — TikTok Notification",
        "expected": "SAFE",
        "email": {
            "subject": "Phone number removed from your account",
            "sender": "TikTok <noreply@account.tiktok.com>",
            "body": """Your phone number has been removed from your TikTok account.
If you did not make this change, please secure your account immediately
by visiting our security center. TikTok Support Team"""
        }
    },
]


async def run_single_test(test: dict) -> dict:
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
    }


async def run_all_tests():
    print(f"\n{'='*65}")
    print(f"  PHISHGUARD — FULL SYSTEM TEST SUITE")
    print(f"{'='*65}\n")

    results = []
    passed = 0
    failed = 0
    total_time = 0

    for test in TEST_CASES:
        print(f"[{test['id']}] {test['name']}")
        result = await run_single_test(test)
        results.append(result)

        status = "✅ PASS" if result["passed"] else "❌ FAIL"
        print(f"     Expected: {result['expected']:<12} Got: {result['got']:<12} Score: {result['score']}/100")
        print(f"     {status} | Time: {result['time']}s | Llama: {result['llama_used']}\n")

        if result["passed"]:
            passed += 1
        else:
            failed += 1
        total_time += result["time"]

    accuracy = round((passed / len(TEST_CASES)) * 100, 1)
    avg_time = round(total_time / len(TEST_CASES), 1)

    print(f"{'='*65}")
    print(f"  RESULTS")
    print(f"{'='*65}")
    print(f"  Passed   : {passed}/{len(TEST_CASES)}")
    print(f"  Failed   : {failed}")
    print(f"  Accuracy : {accuracy}%")
    print(f"  Avg Time : {avg_time}s per email")
    print(f"{'='*65}\n")

    for r in results:
        icon = "✅" if r["passed"] else "❌"
        print(f"  {icon} [{r['id']}] {r['name']:<40} {r['got']:<12} {r['score']}/100")

    print(f"\n{'='*65}")
    if accuracy == 100:
        print("  🎉 PERFECT — PhishGuard is ready for Phase B")
    elif accuracy >= 80:
        print(f"  ⚠️  {failed} failure(s) to fix before Phase B")
    else:
        print(f"  🔴 {failed} failures — needs work")
    print(f"{'='*65}\n")

    return results


if __name__ == "__main__":
    asyncio.run(run_all_tests())