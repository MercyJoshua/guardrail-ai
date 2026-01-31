from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from typing import Literal

app = FastAPI(title="Guardrail AI Mock API")

# ---------------------------
# Models
# ---------------------------
class LogEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    description: str
    username: str | None = None
    ip: str
    location: str | None = None
    endpoint: str | None = None
    risk_score: float
    
class ThreatAnalysisRequest(BaseModel):
    event_id: str
    event_type: str
    risk_score: float

class ThreatAnalysisResponse(BaseModel):
    event_id: str
    threat_level: Literal["LOW", "MEDIUM", "HIGH"]
    context: str
    recommendation_priority: Literal["LOW", "MEDIUM", "HIGH"]
    notes: str

class ResponseRequest(BaseModel):
    threat_level: Literal["LOW", "MEDIUM", "HIGH"]
    context: str
    recommendation_priority: Literal["LOW", "MEDIUM", "HIGH"]

class ResponseActions(BaseModel):
    actions: List[str]

class AdminSummaryRequest(BaseModel):
    event_id: str
    threat_level: Literal["LOW", "MEDIUM", "HIGH"]
    threat_summary: str
    actions: List[str]

class AdminSummaryResponse(BaseModel):
    message: str
    severity: Literal["LOW", "MEDIUM", "HIGH"]


# ---------------------------
# Endpoints
# ---------------------------



## Scenarios: normal,bruteforce,api_abuse
# Recent logs → Threat Monitor
@app.get("/logs/recent", response_model=List[LogEvent])
def get_recent_logs(scenario: str = "normal"):
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
    # Simple deterministic logic for demo purposes
    if request.risk_score >= 0.8:
        threat_level = "HIGH"
        priority = "HIGH"
        notes = "Pattern strongly suggests credential abuse behavior."
    elif request.risk_score >= 0.6:
        threat_level = "MEDIUM"
        priority = "MEDIUM"
        notes = "Activity may indicate early-stage credential stuffing."
    else:
        threat_level = "LOW"
        priority = "LOW"
        notes = "No strong indicators of malicious intent at this time."

    return {
        "event_id": request.event_id,
        "threat_level": threat_level,
        "context": f"{request.event_type} observed with risk score {request.risk_score}",
        "recommendation_priority": priority,
        "notes": notes
    }

# Response & Recommendation → Response Agent
@app.post("/response/recommend", response_model=ResponseActions)
def recommend_response(request: ResponseRequest):
    if request.threat_level == "HIGH":
        actions = [
            "Lock affected account immediately",
            "Force password reset",
            "Block source IP temporarily",
            "Notify security administrator"
        ]
    elif request.threat_level == "MEDIUM":
        actions = [
            "Lock affected account temporarily",
            "Notify security administrator via dashboard",
            "Monitor source IP for further attempts",
            "Recommend password reset"
        ]
    else:
        actions = [
            "Continue monitoring activity",
            "Log event for audit review"
        ]

    return {
        "actions": actions
    }

# Admin Communication → Admin Communication Agent
@app.post("/admin/summary", response_model=AdminSummaryResponse)
def admin_summary(request: AdminSummaryRequest):
    actions_str = ", ".join(request.actions)

    return {
        "message": (
            f"{request.threat_level} risk security activity detected. "
            f"{request.threat_summary}. "
            f"Recommended actions: {actions_str}."
        )
    }

# ---------------------------
# Run the server
# ---------------------------
# Run with: uvicorn guardrail_mock_server:app --reload --port 8000
