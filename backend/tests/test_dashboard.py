from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ecdat-backend"

def test_dashboard_summary():
    response = client.get("/api/dashboard/summary?mode=LIVE")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert data["kpis"]["total_scanned"] >= 5
    assert "risk_distribution" in data
    assert "key_type_breakdown" in data
    assert "top_vulnerable_assets" in data
    assert len(data["top_vulnerable_assets"]) > 0

def test_mwqrs_recalculate():
    response = client.post("/api/score/recalculate")
    assert response.status_code == 200
    assert "rescored" in response.json()["message"]
