import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.services.inventory import seed_demo_data
from app.models.models import CryptoAsset

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    db = SessionLocal()
    seed_demo_data(db)
    db.close()


def test_save_and_list_snapshots():
    # Save snapshot
    res_save = client.post("/api/snapshots/save", json={"name": "Baseline Production Scan"})
    assert res_save.status_code == 200
    snap = res_save.json()
    assert "id" in snap
    assert snap["asset_count"] >= 6
    assert snap["name"] == "Baseline Production Scan"

    # List snapshots
    res_list = client.get("/api/snapshots/list")
    assert res_list.status_code == 200
    snaps = res_list.json()
    assert len(snaps) >= 1
    assert any(s["id"] == snap["id"] for s in snaps)


def test_compare_snapshots():
    # 1. Baseline snapshot
    res1 = client.post("/api/snapshots/save", json={"name": "Snapshot Cycle 1"})
    snap1_id = res1.json()["id"]

    # 2. Modify one asset in DB to simulate an upgrade
    db = SessionLocal()
    asset = db.query(CryptoAsset).first()
    assert asset is not None
    original_algo = asset.cert_key_type
    original_risk = asset.risk_score

    asset.cert_key_type = "ML-KEM-768 (PQC)"
    asset.cert_key_size_bits = 768
    asset.risk_score = 12.0
    db.commit()
    db.close()

    # 3. Save second snapshot
    res2 = client.post("/api/snapshots/save", json={"name": "Snapshot Cycle 2 - After PQC Rollout"})
    snap2_id = res2.json()["id"]

    # 4. Compare snapshots
    res_diff = client.get(f"/api/snapshots/diff?old_id={snap1_id}&new_id={snap2_id}")
    assert res_diff.status_code == 200
    diff = res_diff.json()
    assert "summary" in diff
    assert diff["summary"]["modified_count"] >= 1
    assert len(diff["alerts"]) >= 1
    assert diff["summary"]["risk_decreased_count"] >= 1


def test_assistant_chat_pqc():
    res = client.post("/api/assistant/chat", json={"prompt": "Explain NIST FIPS 203 ML-KEM-768"})
    assert res.status_code == 200
    data = res.json()
    assert "response" in data
    assert "ML-KEM" in data["response"]
    assert "Kyber" in data["response"]


def test_assistant_chat_mwqrs():
    res = client.post("/api/assistant/chat", json={"prompt": "What is the MWQRS score formula?"})
    assert res.status_code == 200
    data = res.json()
    assert "response" in data
    assert "MWQRS" in data["response"]
    assert "Criticality" in data["response"]


def test_assistant_chat_empty_prompt():
    res = client.post("/api/assistant/chat", json={"prompt": "   "})
    assert res.status_code == 400
