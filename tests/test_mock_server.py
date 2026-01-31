import pytest
from fastapi.testclient import TestClient
from src.guardrail_mock_server import app

client = TestClient(app)

# --------------------------
# Test Threat Monitor (/logs/recent)
# --------------------------
@pytest.mark.parametrize("scenario, expected_count", [
    ("normal", 2),
    ("bruteforce", 2),
    ("api_abuse", 2),
    ("invalid", 2)  # defaults to normal
])
def test_logs_recent(scenario, expected_count):
    response = client.get(f"/logs/recent?scenario={scenario}")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == expected_count
    for event in data:
        assert "event_id" in event
        assert "risk_score" in event

# --------------------------
# Test Threat Analysis (/threats/analyze)
# --------------------------
@pytest.mark.parametrize("risk_score, expected_level", [
    (0.85, "HIGH"),
    (0.7, "MEDIUM"),
    (0.3, "LOW")
])
def test_threat_analysis(risk_score, expected_level):
    request_data = {
        "event_id": "evt-test",
        "event_type": "TEST_EVENT",
        "risk_score": risk_score
    }
    response = client.post("/threats/analyze", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["threat_level"] == expected_level
    assert "context" in data
    assert "recommendation_priority" in data
    assert "notes" in data

# --------------------------
# Test Response Agent (/response/recommend)
# --------------------------
@pytest.mark.parametrize("threat_level, expected_actions", [
    ("HIGH", 4),
    ("MEDIUM", 4),
    ("LOW", 2)
])
def test_response_agent(threat_level, expected_actions):
    request_data = {
        "threat_level": threat_level,
        "context": "dummy context",
        "recommendation_priority": threat_level
    }
    response = client.post("/response/recommend", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert "actions" in data
    assert len(data["actions"]) == expected_actions

# --------------------------
# Test Admin Communication (/admin/summary)
# --------------------------
def test_admin_summary():
    request_data = {
        "event_id": "evt-test",
        "threat_level": "MEDIUM",
        "threat_summary": "Suspicious login activity",
        "actions": ["Lock account", "Notify admin"]
    }
    response = client.post("/admin/summary", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "MEDIUM" in data["message"]
    assert "Lock account" in data["message"]
    assert "Notify admin" in data["message"]

## to test this:
## pytest tests/test_mock_server.py

