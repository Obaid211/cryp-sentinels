from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_inventory_endpoint():
    res = client.get("/api/inventory")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 5

def test_inventory_detail():
    res = client.get("/api/inventory/auth.internal.net/8443/history")
    assert res.status_code == 200
    data = res.json()
    assert "asset" in data
    assert "flag_explanations" in data
    assert "recommended_pqc_target" in data

def test_remediation_plan():
    res = client.get("/api/remediation/plan")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "queue" in data
    assert len(data["queue"]) >= 5

def test_threat_urgency_calculation():
    payload = {
        "shelf_life_years": 10.0,
        "migration_time_years": 3.0,
        "planning_horizon_years": 10.0,
        "mwqrs": 75.0,
        "is_quantum_vulnerable": True
    }
    res = client.post("/api/threat/urgency", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "CRITICAL"
    assert data["combined_requirement_years"] == 13.0

def test_compliance_summary():
    res = client.get("/api/compliance/summary")
    assert res.status_code == 200
    data = res.json()
    assert "stats" in data
    assert "implemented_controls" in data
    assert "roadmap_controls" in data

def test_cbom_export():
    res = client.get("/api/cbom/export")
    assert res.status_code == 200
    data = res.json()
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert len(data["components"]) >= 5
