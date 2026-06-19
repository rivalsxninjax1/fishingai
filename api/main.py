import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router

# ─────────────────────────────────────────
# PHISHGUARD API
# ─────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="AI-Powered Email Threat Detection System for Nepal Government and Enterprise",
    version="1.0.0",
    docs_url="/docs",       # Auto-generated API docs
    redoc_url="/redoc"
)

# CORS — allows React dashboard to talk to API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routes
app.include_router(router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "system": "PhishGuard",
        "version": "1.0.0",
        "status": "Active",
        "description": "AI Email Threat Detection — Nepal Government Grade"
    }