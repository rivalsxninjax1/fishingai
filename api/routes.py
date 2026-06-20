import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, HTTPException, BackgroundTasks
from datetime import datetime, timedelta
from typing import List, Optional
import asyncio
import redis
import ollama

from api.schemas import (
    EmailAnalysisRequest,
    AnalysisResponse,
    ThreatListItem,
    DashboardStats,
    AlertItem,
    SystemStatus,
)
from models.database import (
    SessionLocal,
    EmailThreat,
    Alert,
    save_threat,
    add_trusted_sender,
)
from pipeline.risk_engine import analyze_all_layers
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

# Redis connection
redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379/0")
)

# ─────────────────────────────────────────
# HEALTH + STATUS
# ─────────────────────────────────────────

@router.get("/status", response_model=SystemStatus)
async def get_system_status():
    """Check health of all system components"""

        # Check Ollama
    # Check Ollama
    try:
        import httpx
        response = httpx.get("http://127.0.0.1:11434/api/tags", timeout=3)
        ollama_ok = response.status_code == 200
    except Exception:
        ollama_ok = False

    # Check Redis
    try:
        redis_client.ping()
        redis_ok = True
        queue_size = redis_client.llen("celery")
    except Exception:
        redis_ok = False
        queue_size = 0

  
    # Check Database
    try:
        from sqlalchemy import text
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_ok = True
    except Exception:
        db_ok = False

    return SystemStatus(
        ollama=ollama_ok,
        redis=redis_ok,
        database=db_ok,
        celery_workers=2,
        emails_in_queue=queue_size,
        uptime="Running"
    )


# ─────────────────────────────────────────
# ANALYZE EMAIL — Core endpoint
# ─────────────────────────────────────────

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze a single email through all 7 layers
    Returns full threat report
    """
    email_data = {
        "subject": request.subject,
        "sender": request.sender,
        "body": request.body,
        "reply_to": request.reply_to,
    }

    try:
        result = await analyze_all_layers(email_data)
        save_threat(result)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


# ─────────────────────────────────────────
# DASHBOARD STATS
# ─────────────────────────────────────────

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(organization: str = "default"):
    """Get summary statistics for dashboard"""
    db = SessionLocal()
    try:
        from sqlalchemy import func

        # All time stats
        total = db.query(EmailThreat).filter(
            EmailThreat.organization == organization
        ).count()

        scams = db.query(EmailThreat).filter(
            EmailThreat.organization == organization,
            EmailThreat.verdict == "SCAM"
        ).count()

        suspicious = db.query(EmailThreat).filter(
            EmailThreat.organization == organization,
            EmailThreat.verdict == "SUSPICIOUS"
        ).count()

        safe = db.query(EmailThreat).filter(
            EmailThreat.organization == organization,
            EmailThreat.verdict == "SAFE"
        ).count()

        # Average risk score
        avg = db.query(
            func.avg(EmailThreat.risk_score)
        ).filter(
            EmailThreat.organization == organization
        ).scalar() or 0

        # Top threat category
        top_cat = db.query(
            EmailThreat.category,
            func.count(EmailThreat.category).label("count")
        ).filter(
            EmailThreat.organization == organization,
            EmailThreat.verdict == "SCAM"
        ).group_by(
            EmailThreat.category
        ).order_by(
            func.count(EmailThreat.category).desc()
        ).first()

        return DashboardStats(
            total_emails=total,
            total_scams=scams,
            total_suspicious=suspicious,
            total_safe=safe,
            avg_risk_score=round(float(avg), 1),
            top_category=top_cat[0] if top_cat else "None",
            system_status="Active",
            last_updated=datetime.utcnow()
        )
    finally:
        db.close()


# ─────────────────────────────────────────
# THREAT LIST
# ─────────────────────────────────────────

@router.get("/threats", response_model=List[ThreatListItem])
async def get_threats(
    limit: int = 50,
    verdict: Optional[str] = None,
    organization: str = "default"
):
    """Get list of analyzed emails"""
    db = SessionLocal()
    try:
        query = db.query(EmailThreat).filter(
            EmailThreat.organization == organization
        )

        if verdict:
            query = query.filter(EmailThreat.verdict == verdict)

        threats = query.order_by(
            EmailThreat.analyzed_at.desc()
        ).limit(limit).all()

        return [
             ThreatListItem(
                id=t.id,
                sender=t.sender,
                subject=t.subject,
                verdict=t.verdict,
                risk_score=t.risk_score,
                category=t.category or "Unknown",
                summary=t.summary or "",
                analyzed_at=t.analyzed_at,
                analysis_time=t.analysis_time or 0,
                gmail_category=t.gmail_category or "primary"
            )
            for t in threats
        ]
    finally:
        db.close()


# ─────────────────────────────────────────
# SINGLE THREAT DETAIL
# ─────────────────────────────────────────

@router.get("/threats/{threat_id}")
async def get_threat_detail(threat_id: int):
    """Get full details of one analyzed email"""
    db = SessionLocal()
    try:
        threat = db.query(EmailThreat).filter(
            EmailThreat.id == threat_id
        ).first()

        if not threat:
            raise HTTPException(
                status_code=404,
                detail="Threat not found"
            )

        return {
            "id": threat.id,
            "sender": threat.sender,
            "sender_domain": threat.sender_domain,
            "subject": threat.subject,
            "body_preview": threat.body_preview,
            "verdict": threat.verdict,
            "risk_score": threat.risk_score,
            "category": threat.category,
            "confidence": threat.confidence,
            "summary": threat.summary,
            "reasons": threat.reasons,
            "recommended_action": threat.recommended_action,
            "matched_patterns": threat.matched_patterns,
            "layer_scores": threat.layer_scores,
            "analysis_time": threat.analysis_time,
            "analyzed_at": threat.analyzed_at,
            "is_false_positive": threat.is_false_positive,
        }
    finally:
        db.close()


# ─────────────────────────────────────────
# MARK FALSE POSITIVE
# ─────────────────────────────────────────

@router.post("/threats/{threat_id}/false-positive")
async def mark_false_positive(threat_id: int):
    """Mark an email as false positive — safe email wrongly flagged"""
    db = SessionLocal()
    try:
        threat = db.query(EmailThreat).filter(
            EmailThreat.id == threat_id
        ).first()

        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")

        threat.is_false_positive = True
        threat.verdict = "SAFE"

        # Add sender to whitelist
        add_trusted_sender(
            threat.sender,
            "Marked as false positive by user"
        )

        db.commit()
        return {"message": "Marked as false positive", "id": threat_id}
    finally:
        db.close()


# ─────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────

@router.get("/alerts", response_model=List[AlertItem])
async def get_alerts(
    resolved: bool = False,
    organization: str = "default"
):
    """Get active alerts"""
    db = SessionLocal()
    try:
        alerts = db.query(Alert).filter(
            Alert.organization == organization,
            Alert.is_resolved == resolved
        ).order_by(
            Alert.created_at.desc()
        ).limit(20).all()

        return [
            AlertItem(
                id=a.id,
                email_threat_id=a.email_threat_id,
                alert_type=a.alert_type,
                message=a.message,
                is_resolved=a.is_resolved,
                created_at=a.created_at
            )
            for a in alerts
        ]
    finally:
        db.close()


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int):
    """Mark alert as resolved"""
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert.is_resolved = True
        alert.resolved_at = datetime.utcnow()
        db.commit()
        return {"message": "Alert resolved", "id": alert_id}
    finally:
        db.close()


# ─────────────────────────────────────────
# WHITELIST MANAGEMENT
# ─────────────────────────────────────────

@router.post("/whitelist")
async def add_to_whitelist(email: str, reason: str = "Manual whitelist"):
    """Add sender to trusted whitelist"""
    add_trusted_sender(email, reason)
    return {"message": f"Added {email} to whitelist"}


# ─────────────────────────────────────────
# RECENT THREATS FOR LIVE FEED
# ─────────────────────────────────────────

@router.get("/threats/live/feed")
async def get_live_feed(organization: str = "default"):
    """
    Get last 10 threats for live dashboard feed
    Designed to be polled every 5 seconds by frontend
    """
    db = SessionLocal()
    try:
        threats = db.query(EmailThreat).filter(
            EmailThreat.organization == organization
        ).order_by(
            EmailThreat.analyzed_at.desc()
        ).limit(10).all()

        return [
            {
                "id": t.id,
                "sender": t.sender,
                "subject": t.subject,
                "verdict": t.verdict,
                "risk_score": t.risk_score,
                "category": t.category,
                "analyzed_at": t.analyzed_at,
            }
            for t in threats
        ]
    finally:
        db.close()