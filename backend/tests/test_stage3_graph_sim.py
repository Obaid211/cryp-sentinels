import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.services.inventory import seed_demo_data

client = TestClient(app)

@pytest.fixture(autouse=True)
def ensure_db_seeded():
    db = SessionLocal()
    seed_demo_data(db)
    db.close()



def test_get_dependency_graph():
    response = client.get("/api/graph/dependencies")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
    assert len(data["nodes"]) >= 6
    assert len(data["edges"]) >= 5
    assert data["is_dag"] is True
    assert "critical_path" in data


def test_blast_radius_core_database():
    # Core-Database-Proxy is id=3
    response = client.get("/api/graph/blast-radius/3")
    assert response.status_code == 200
    data = response.json()
    assert data["service_id"] == 3
    assert data["service_name"] == "Core-Database-Proxy"
    assert data["dependent_count"] >= 2
    # Dependents should include services that depend directly or transitively on DB proxy
    dep_names = [d["name"] for d in data["dependent_services"]]
    assert "Payment-Gateway" in dep_names
    assert "User-Portal" in dep_names
    assert data["blast_radius_count"] >= 3
    assert len(data["impacted_assets"]) >= 1


def test_blast_radius_invalid_id():
    response = client.get("/api/graph/blast-radius/99999")
    assert response.status_code == 404


def test_simulation_strategies():
    response = client.get("/api/simulate/strategies")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    strategy_ids = [s["id"] for s in data]
    assert "HYBRID" in strategy_ids
    assert "PURE_PQC" in strategy_ids
    assert "CLASSICAL_HARDENING" in strategy_ids


def test_run_simulation_hybrid():
    response = client.post("/api/simulate/run", json={"strategy": "HYBRID"})
    assert response.status_code == 200
    data = response.json()
    assert "aggregate_posture" in data
    agg = data["aggregate_posture"]
    assert agg["total_assets"] >= 6
    assert agg["before_average_mwqrs"] > agg["after_average_mwqrs"]
    assert agg["critical_eliminated"] >= 1
    assert "migration_waves" in data
    assert len(data["migration_waves"]) == 3


def test_run_simulation_pure_pqc():
    response = client.post("/api/simulate/run", json={"strategy": "PURE_PQC"})
    assert response.status_code == 200
    data = response.json()
    agg = data["aggregate_posture"]
    # Pure PQC should reduce after score even further than hybrid
    assert agg["after_average_mwqrs"] <= 10.0
    assert agg["critical_risk_after"] == 0


def test_simulate_single_asset():
    # Asset 1
    response = client.get("/api/simulate/asset/1?strategy=HYBRID")
    assert response.status_code == 200
    data = response.json()
    assert data["asset_id"] == 1
    assert "before_state" in data
    assert "after_state" in data
    assert "nist_pqc" in data
    assert "ML-KEM" in data["nist_pqc"]["kem"]


def test_topological_sequence():
    response = client.get("/api/simulate/sequence?strategy=HYBRID")
    assert response.status_code == 200
    data = response.json()
    assert "sequence" in data
    assert "waves" in data
    assert len(data["waves"]) == 3
    assert len(data["sequence"]) >= 6
    # Sequence should be ordered
    positions = [item["sequence_position"] for item in data["sequence"]]
    assert positions == list(range(1, len(positions) + 1))
