from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict

class EmailAnalysisRequest(BaseModel):
    subject: str
    sender: str
    body: str
    reply_to: Optional[str] = ""
    organization: Optional[str] = "default"

class LayerScore(BaseModel):
    score: int
    max: int

class AnalysisResponse(BaseModel):
    subject: str
    sender: str
    verdict: str
    risk_score: int
    confidence: str
    category: str
    summary: str
    reasons: List[str]
    recommended_action: str
    matched_patterns: List[dict]
    layer_scores: Dict[str, LayerScore]
    analysis_time: float
    llama_used: bool

class ThreatListItem(BaseModel):
    id: int
    sender: str
    subject: str
    verdict: str
    risk_score: int
    category: str
    summary: str
    analyzed_at: datetime
    analysis_time: float
    gmail_category: Optional[str] = "primary"

class DashboardStats(BaseModel):
    total_emails: int
    total_scams: int
    total_suspicious: int
    total_safe: int
    avg_risk_score: float
    top_category: str
    system_status: str
    last_updated: datetime

class AlertItem(BaseModel):
    id: int
    email_threat_id: int
    alert_type: str
    message: str
    is_resolved: bool
    created_at: datetime

class SystemStatus(BaseModel):
    ollama: bool
    redis: bool
    database: bool
    celery_workers: int
    emails_in_queue: int
    uptime: str