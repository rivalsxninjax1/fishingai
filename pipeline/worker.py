import sys
import os
import time
import asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celery import Celery
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'
))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ─────────────────────────────────────
# CELERY APP CONFIGURATION
# ─────────────────────────────────────
app = Celery(
    "phishguard",
    broker=REDIS_URL,
    backend=REDIS_URL
)

app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Kathmandu",
    enable_utc=True,

    # Performance settings
    worker_concurrency=2,          # 2 parallel workers on M1 8GB
    task_acks_late=True,           # Only mark done after completion
    task_reject_on_worker_lost=True, # Requeue if worker crashes

    # Queue priority settings
    task_queues={
        "critical": {"exchange": "critical", "routing_key": "critical"},
        "high":     {"exchange": "high",     "routing_key": "high"},
        "normal":   {"exchange": "normal",   "routing_key": "normal"},
    },
    task_default_queue="normal",

    # Retry settings
    task_max_retries=3,
    task_soft_time_limit=120,      # 2 min soft limit
    task_time_limit=180,           # 3 min hard limit
)

# ─────────────────────────────────────
# CORE TASK — ANALYZE ONE EMAIL
# Uses the FULL 7-LAYER ENGINE
# ─────────────────────────────────────
@app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    name="phishguard.analyze_email"
)
def analyze_email_task(self, email_data: dict):
    """
    Celery task that:
    1. Takes one email from Redis queue
    2. Runs full 7-layer AI analysis
    3. Saves result to PostgreSQL (including layer_scores + message_id)
    4. Creates alert if high risk
    """
    from models.database import save_threat, SessionLocal, Alert, is_trusted_sender

    subject = email_data.get("subject", "Unknown")
    sender = email_data.get("sender", "Unknown")
    message_id = email_data.get("message_id", "")

    print(f"\n⚙️  Worker processing: {subject[:50]}")
    print(f"   From: {sender}")

    # Check whitelist before analyzing
    if is_trusted_sender(sender):
        print(f"✅ Trusted sender — skipping analysis: {sender}")
        return {"status": "skipped", "reason": "trusted_sender"}

    try:
        from pipeline.risk_engine import analyze_all_layers

        # Track analysis time
        start_time = time.time()

        # Run full 7-LAYER analysis
        report = asyncio.run(analyze_all_layers(email_data))

        # Make sure message_id and full body flow through to the saved report
        report["message_id"] = message_id
        report["gmail_category"] = email_data.get("gmail_category", "primary")
        # Calculate time taken
        analysis_time = round(time.time() - start_time, 2)
        print(f"⏱️  Analysis completed in {analysis_time}s")

        # Save to PostgreSQL
        threat_id = save_threat(report, analysis_time)

        # Create alert if high risk
        if report.get("risk_score", 0) >= 75:
            db = SessionLocal()
            try:
                alert = Alert(
                    email_threat_id=threat_id,
                    alert_type="CRITICAL" if report["risk_score"] >= 90 else "HIGH",
                    message=f"High risk email detected from {sender}. Score: {report['risk_score']}/100. Category: {report['category']}",
                    organization="default"
                )
                db.add(alert)
                db.commit()
                print(f"🚨 Alert created: {alert.alert_type} risk from {sender}")
            finally:
                db.close()

        print(f"✅ Done: {subject[:50]} → {report.get('verdict')} ({report.get('risk_score')}/100)")
        return {
            "status": "success",
            "threat_id": threat_id,
            "verdict": report.get("verdict"),
            "risk_score": report.get("risk_score")
        }
    

    except Exception as e:
        print(f"❌ Task failed: {e}")
        raise self.retry(exc=e, countdown=10)


# ─────────────────────────────────────
# SCHEDULED TASK — FETCH NEW EMAILS
# Runs every 15 seconds automatically
# ─────────────────────────────────────
@app.task(name="phishguard.fetch_and_queue_emails")
def fetch_and_queue_emails():
    """
    Scheduled task with CHECKPOINT system:
    1. First run ever → analyze last 20 emails, save checkpoint
    2. Every run after → only analyze emails newer than checkpoint
    """
    from pipeline.email_reader import connect_to_gmail, fetch_emails_since_checkpoint
    from models.database import get_system_state, set_system_state

    print("\n📬 Checking for new emails...")

    try:
        mail = connect_to_gmail()
        if not mail:
            print("❌ Could not connect to Gmail")
            return

        last_uid = get_system_state("last_checked_uid", default=None)

        emails, new_highest_uid = fetch_emails_since_checkpoint(
            mail, last_uid=last_uid, first_run_limit=20
        )
        mail.logout()

        if not emails:
            print("📭 No new emails")
            return {"queued": 0}

        queued = 0
        for email_data in emails:
            subject = email_data.get("subject", "").lower()
            body = email_data.get("body", "").lower()

            urgent_keywords = ["urgent", "immediately", "suspended", "verify", "password"]
            is_urgent = any(kw in subject or kw in body for kw in urgent_keywords)

            if is_urgent:
                analyze_email_task.apply_async(
                    args=[email_data], queue="high", priority=9
                )
            else:
                analyze_email_task.apply_async(
                    args=[email_data], queue="normal", priority=5
                )
            queued += 1

        # Save checkpoint — next run resumes from here
        if new_highest_uid:
            set_system_state("last_checked_uid", new_highest_uid)
            print(f"📍 Checkpoint updated: UID {new_highest_uid}")

        print(f"✅ Queued {queued} emails for analysis")
        return {"queued": queued}

    except Exception as e:
        print(f"❌ Fetch failed: {e}")


# ─────────────────────────────────────
# CELERY BEAT SCHEDULE
# Runs fetch every 15s
# ─────────────────────────────────────
app.conf.beat_schedule = {
    "fetch-emails-every-15-seconds": {
        "task": "phishguard.fetch_and_queue_emails",
        "schedule": 15.0,
    },
}

if __name__ == "__main__":
    print("🚀 PhishGuard Worker Starting...")
    print(f"📡 Redis: {REDIS_URL}")
    print(f"⚙️  Workers: 2 concurrent")
    print(f"🕐 Fetch interval: 15 seconds")