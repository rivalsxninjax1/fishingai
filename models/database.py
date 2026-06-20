from sqlalchemy import (
    create_engine, Column, Integer, String,
    Text, DateTime, Float, Boolean, JSON
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables FIRST before anything else
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

# Verify it loaded
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("❌ DATABASE_URL not found in .env file. Check your .env file exists in project root.")

print(f"✅ Database URL loaded successfully")

# ─────────────────────────────────────
# DATABASE CONNECTION
# ─────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(
    DATABASE_URL,
    pool_size=10,          # Max 10 connections
    max_overflow=20,       # Allow 20 overflow connections
    pool_pre_ping=True,    # Check connection before using
    echo=False             # Set True to see SQL queries
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# ─────────────────────────────────────
# EMAIL THREAT TABLE
# Every analyzed email stored here
# ─────────────────────────────────────
class EmailThreat(Base):
    __tablename__ = "email_threats"

    id              = Column(Integer, primary_key=True, index=True)
    message_id      = Column(String(500), index=True)  # No longer unique - handled in app logic 
    # Email details
    sender          = Column(String(500), nullable=False)
    sender_domain   = Column(String(200))
    subject         = Column(String(1000))
    body_preview    = Column(Text)
    received_at     = Column(DateTime, default=datetime.utcnow)
    gmail_category   = Column(String(50), default="primary")
    # Analysis results
    verdict         = Column(String(50))   # SAFE / SUSPICIOUS / SCAM
    risk_score      = Column(Integer)      # 0-100
    category        = Column(String(200))  # Type of threat
    confidence      = Column(String(50))   # LOW / MEDIUM / HIGH
    summary         = Column(Text)         # One line summary
    reasons         = Column(JSON)         # List of reasons
    recommended_action = Column(Text)
    
    # RAG matching
    matched_patterns = Column(JSON)        # Patterns that matched
    layer_scores     = Column(JSON) 
    
    # System fields
    analyzed_at     = Column(DateTime, default=datetime.utcnow)
    analysis_time   = Column(Float)        # How long analysis took
    model_used      = Column(String(100), default="llama3.1:8b")
    is_false_positive = Column(Boolean, default=False)
    
    # Organization (for multi-org support)
    organization    = Column(String(200), default="default")

# ─────────────────────────────────────
# THREAT STATISTICS TABLE
# Daily aggregated stats per org
# ─────────────────────────────────────
class ThreatStatistic(Base):
    __tablename__ = "threat_statistics"

    id              = Column(Integer, primary_key=True, index=True)
    date            = Column(DateTime, default=datetime.utcnow)
    organization    = Column(String(200), default="default")
    
    total_emails    = Column(Integer, default=0)
    total_scams     = Column(Integer, default=0)
    total_suspicious = Column(Integer, default=0)
    total_safe      = Column(Integer, default=0)
    avg_risk_score  = Column(Float, default=0.0)
    top_category    = Column(String(200))


#fucntion check if we have already passed the email 

def is_already_analyzed(message_id: str) -> bool:
    """Check if this exact email was already analyzed"""
    if not message_id:
        return False
    db = SessionLocal()
    try:
        existing = db.query(EmailThreat).filter(
            EmailThreat.message_id == message_id
        ).first()
        return existing is not None
    finally:
        db.close()
# ─────────────────────────────────────
# KNOWN SENDERS TABLE
# Whitelist and blacklist
# ─────────────────────────────────────
class KnownSender(Base):
    __tablename__ = "known_senders"

    id              = Column(Integer, primary_key=True, index=True)
    email           = Column(String(500), unique=True)
    domain          = Column(String(200))
    status          = Column(String(50))   # TRUSTED / BLOCKED / SUSPICIOUS
    reason          = Column(Text)
    added_at        = Column(DateTime, default=datetime.utcnow)
    organization    = Column(String(200), default="default")

# ─────────────────────────────────────
# ALERT TABLE
# High risk emails that need attention
# ─────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, index=True)
    email_threat_id = Column(Integer)
    alert_type      = Column(String(100))  # CRITICAL / HIGH / MEDIUM
    message         = Column(Text)
    is_resolved     = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    resolved_at     = Column(DateTime, nullable=True)
    organization    = Column(String(200), default="default")




    # ─────────────────────────────────────
# SYSTEM STATE TABLE
# Tracks checkpoint for email scanning
# ─────────────────────────────────────
class SystemState(Base):
    __tablename__ = "system_state"

    id               = Column(Integer, primary_key=True, index=True)
    key              = Column(String(100), unique=True, index=True)
    value            = Column(String(500))
    updated_at       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ─────────────────────────────────────
# DATABASE UTILITIES
# ─────────────────────────────────────
def init_database():
    """Create all tables if they don't exist"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def save_threat(report: dict, analysis_time: float = 0.0):
    """Save analyzed email threat to database"""
    db = SessionLocal()
    try:
        threat = EmailThreat(
            message_id=report.get("message_id", ""),
            sender=report.get("sender", ""),
            sender_domain=report.get("sender", "").split("@")[-1].rstrip(">").strip() if "@" in report.get("sender", "") else "",
            subject=report.get("subject", ""),
            body_preview=report.get("body", "")[:500],
            verdict=report.get("verdict", "UNKNOWN"),
            risk_score=report.get("risk_score", 0),
            category=report.get("category", "UNKNOWN"),
            confidence=report.get("confidence", "LOW"),
            summary=report.get("summary", ""),
            reasons=report.get("reasons", []),
            recommended_action=report.get("recommended_action", ""),
            matched_patterns=report.get("matched_patterns", []),
            layer_scores=report.get("layer_scores", {}), 
            analysis_time=analysis_time,
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)
        print(f"💾 Saved threat to database: ID {threat.id}")
        return threat.id
    except Exception as e:
        print(f"❌ Database save failed: {e}")
        db.rollback()
        return None
    finally:
        db.close()

def get_recent_threats(limit=50, organization="default"):
    """Get most recent threats from database"""
    db = SessionLocal()
    try:
        threats = db.query(EmailThreat)\
            .filter(EmailThreat.organization == organization)\
            .order_by(EmailThreat.analyzed_at.desc())\
            .limit(limit)\
            .all()
        return threats
    finally:
        db.close()

def get_statistics(organization="default"):
    """Get threat statistics"""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        stats = db.query(
            func.count(EmailThreat.id).label("total"),
            func.sum(
                (EmailThreat.verdict == "SCAM").cast(Integer)
            ).label("scams"),
            func.avg(EmailThreat.risk_score).label("avg_risk")
        ).filter(
            EmailThreat.organization == organization
        ).first()
        return stats
    finally:
        db.close()

if __name__ == "__main__":
    init_database()

def add_trusted_sender(email_address: str, reason: str = "Manual whitelist"):
    """Add a sender to trusted whitelist"""
    db = SessionLocal()
    try:
        sender = KnownSender(
            email=email_address,
            domain=email_address.split("@")[-1] if "@" in email_address else "",
            status="TRUSTED",
            reason=reason
        )
        db.add(sender)
        db.commit()
        print(f"✅ Added {email_address} to whitelist")
    except Exception as e:
        print(f"❌ Could not add sender: {e}")
        db.rollback()
    finally:
        db.close()

def is_trusted_sender(email_address: str) -> bool:
    """Check if sender is whitelisted"""
    db = SessionLocal()
    try:
        sender = db.query(KnownSender)\
            .filter(KnownSender.email == email_address)\
            .filter(KnownSender.status == "TRUSTED")\
            .first()
        return sender is not None
    finally:
        db.close()

        
def get_system_state(key: str, default: str = None):
    """Get a system state value by key"""
    db = SessionLocal()
    try:
        state = db.query(SystemState).filter(SystemState.key == key).first()
        return state.value if state else default
    finally:
        db.close()

def set_system_state(key: str, value: str):
    """Set or update a system state value"""
    db = SessionLocal()
    try:
        state = db.query(SystemState).filter(SystemState.key == key).first()
        if state:
            state.value = value
            state.updated_at = datetime.utcnow()
        else:
            state = SystemState(key=key, value=value)
            db.add(state)
        db.commit()
    finally:
        db.close()