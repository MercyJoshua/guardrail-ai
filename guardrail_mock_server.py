from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Guardrail AI Mock API")

# ---------------------------
# Models
# ---------------------------
class LogEvent(BaseModel):
    timestamp: str
    event: str
    username: str = None
    ip: str
    location: str = None
    endpoint: str = None
    risk_score: float

class ThreatAnalysisRequest(BaseModel):
    event_id: str
    event_type: str
    risk_score: float

class ThreatAnalysisResponse(BaseModel):
    threat_level: str
    context: str
    recommendation_priority: str
    notes: str

class ResponseRequest(BaseModel):
    threat_level: str
    context: str
    recommendation_priority: str

class ResponseActions(BaseModel):
    actions: List[str]

class AdminSummaryRequest(BaseModel):
    threat_summary: str
    actions: List[str]

class AdminSummaryResponse(BaseModel):
    message: str

# ---------------------------
# Endpoints
# ---------------------------

# Recent logs → Threat Monitor
@app.get("/logs/recent", response_model=List[LogEvent])
def get_recent_logs():
    return [
        {
            "timestamp": "2026-01-30T10:15:00Z",
            "event": "Failed admin login",
            "username": "admin",
            "ip": "185.22.44.10",
            "location": "Germany",
            "risk_score": 0.8
        },
        {
            "timestamp": "2026-01-30T10:20:00Z",
            "event": "Unusual API access",
            "endpoint": "/api/v1/data",
            "ip": "45.66.77.88",
            "risk_score": 0.6
        }
    ]

# Threat Analysis → Threat Analysis Agent
@app.post("/threats/analyze", response_model=ThreatAnalysisResponse)
def analyze_threat(request: ThreatAnalysisRequest):
    return {
        "threat_level": "Medium",
        "context": f"{request.event_type} detected with risk score {request.risk_score}",
        "recommendation_priority": "Immediate review",
        "notes": "Could indicate credential stuffing attempt"
    }

# Response & Recommendation → Response Agent
@app.post("/response/recommend", response_model=ResponseActions)
def recommend_response(request: ResponseRequest):
    return {
        "actions": [
            "Lock user account temporarily",
            "Notify security admin via dashboard",
            "Monitor IP for further attempts",
            "Reset password for affected account"
        ]
    }

# Admin Communication → Admin Communication Agent
@app.post("/admin/summary", response_model=AdminSummaryResponse)
def admin_summary(request: AdminSummaryRequest):
    actions_str = ", ".join(request.actions)
    return {
        "message": f"⚠️ Medium-risk activity detected: {request.threat_summary}. Recommended actions: {actions_str}."
    }
