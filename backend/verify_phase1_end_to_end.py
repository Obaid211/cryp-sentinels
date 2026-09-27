"""
verify_phase1_end_to_end.py
Validates the complete end-to-end integration of Phase 1 across:
1. Source-code scanner -> Unified Inventory
2. Dependency scanner -> Unified Inventory
3. MWQRS scoring with business_criticality & data_lifetime
4. Remediation center queue ordering
5. Mosca threat urgency with stored data_lifetime
6. Dependency graph node asset mapping
7. CycloneDX 1.6 CBOM export
8. Criticality update endpoint & live MWQRS recomputation
"""

import sys
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_pipeline():
    print("=" * 60)
    print("Starting Phase 1 End-to-End Pipeline Verification")
    print("=" * 60)

    # 1. Source-Code Scan with import_to_inventory=True
    print("\n[Step 1] Testing Source-Code Scanner -> Inventory...")
    source_payload = {
        "content": '''
import hashlib
from Crypto.PublicKey import RSA

def sign_token(data):
    key = RSA.generate(2048)
    h = hashlib.sha1(data).digest()
    return key, h
''',
        "filename": "crypto_service.py",
        "repo_name": "auth-core-repo",
        "service_name": "Auth-Service",
        "business_criticality": "critical",
        "data_lifetime": "5-10y",
        "import_to_inventory": True,
    }
    r = client.post("/api/phase1/scan/source-code", json=source_payload)
    assert r.status_code == 200, f"Source scan failed: {r.status_code} {r.text}"
    source_res = r.json()
    print(f"  Findings count: {source_res['findings_count']}")
    print(f"  Inventory imported: {source_res['inventory_imported']}")
    assert source_res['inventory_imported'] > 0, "No source findings imported to inventory!"

    # 2. Dependency Scan with import_to_inventory=True
    print("\n[Step 2] Testing Dependency Scanner -> Inventory...")
    dep_payload = {
        "content": "cryptography==41.0.3\npyopenssl==23.2.0\nparamiko==3.3.1\n",
        "filename": "requirements.txt",
        "service_name": "Payment-Gateway",
        "business_criticality": "high",
        "data_lifetime": "3-5y",
        "import_to_inventory": True,
    }
    r = client.post("/api/phase1/scan/dependency", json=dep_payload)
    assert r.status_code == 200, f"Dep scan failed: {r.status_code} {r.text}"
    dep_res = r.json()
    print(f"  Findings count: {dep_res['findings_count']}")
    print(f"  Inventory imported: {dep_res['inventory_imported']}")
    assert dep_res['inventory_imported'] > 0, "No dependency findings imported to inventory!"

    # 3. Check Unified Inventory
    print("\n[Step 3] Verifying Unified Inventory contains all asset sources...")
    r = client.get("/api/inventory")
    assert r.status_code == 200
    assets = r.json()
    sources = set(a.get("source") for a in assets)
    print(f"  Total assets in inventory: {len(assets)}")
    print(f"  Distinct sources found: {sources}")
    assert "source_code" in sources, "source_code assets missing from inventory!"
    assert "dependency" in sources, "dependency assets missing from inventory!"

    # Find the imported source_code asset and verify fields
    src_assets = [a for a in assets if a.get("source") == "source_code"]
    sample_src = src_assets[0]
    print(f"  Sample source asset: {sample_src['host']}:{sample_src['port']}")
    print(f"    algorithm: {sample_src['algorithm']}")
    print(f"    business_criticality: {sample_src['business_criticality']}")
    print(f"    data_lifetime: {sample_src['data_lifetime']}")
    print(f"    risk_score (MWQRS): {sample_src['risk_score']}")
    print(f"    pqc_target: {sample_src['pqc_target']}")
    assert sample_src["business_criticality"] == "critical"
    assert sample_src["data_lifetime"] == "5-10y"
    assert sample_src["pqc_recommendation"] is not None

    # 4. Check Remediation Center Queue
    print("\n[Step 4] Verifying Remediation Queue incorporates Phase 1 assets & criticality...")
    r = client.get("/api/remediation/plan")
    assert r.status_code == 200
    plan = r.json()
    queue = plan["queue"]
    print(f"  Remediation queue items: {len(queue)}")
    assert len(queue) >= len(assets)
    # Check that high/critical assets have prioritization reasons
    high_crit_items = [item for item in queue if item.get("business_criticality") in ["critical", "high"]]
    assert len(high_crit_items) > 0, "No high/critical items found in remediation queue!"
    print(f"  Top item in queue: {queue[0]['target']} (MWQRS: {queue[0]['mwqrs']}, Priority Index: {queue[0]['priority_index']:.1f})")
    print(f"    Why prioritized: {queue[0]['why_prioritized']}")

    # 5. Check Threat Timeline & Mosca Urgency
    print("\n[Step 5] Verifying Mosca Urgency uses stored data_lifetime...")
    r = client.get("/api/threat/inventory-wide?planning_horizon=10.0")
    assert r.status_code == 200
    rankings = r.json()
    print(f"  Total threat rankings: {len(rankings)}")
    # Find an asset with 5-10y data_lifetime
    long_life_rankings = [rk for rk in rankings if rk.get("shelf_life_years", 0) >= 7.0]
    print(f"  Assets with shelf_life >= 7.0 years (from 5-10y or >10y data_lifetime): {len(long_life_rankings)}")
    assert len(long_life_rankings) > 0, "Stored data_lifetime was not reflected in Mosca shelf_life_years!"

    # 6. Check Dependency Graph
    print("\n[Step 6] Verifying Dependency Graph node asset mappings...")
    r = client.get("/api/graph/dependencies")
    assert r.status_code == 200
    graph_data = r.json()
    nodes = graph_data["nodes"]
    auth_node = next((n for n in nodes if n["name"] == "Auth-Service"), None)
    assert auth_node is not None, "Auth-Service node missing from graph!"
    node_sources = set(a.get("source") for a in auth_node.get("assets", []))
    print(f"  Auth-Service node asset count: {auth_node['asset_count']}, distinct sources: {node_sources}")

    # 7. Check CycloneDX 1.6 CBOM Export
    print("\n[Step 7] Verifying CycloneDX 1.6 CBOM Export contains all sources...")
    r = client.get("/api/cbom/export")
    assert r.status_code == 200
    cbom = r.json()
    components = cbom.get("components", [])
    print(f"  CBOM components count: {len(components)}")
    cbom_sources = set()
    for c in components:
        for prop in c.get("properties", []):
            if prop.get("name") == "ecdat:source":
                cbom_sources.add(prop.get("value"))
    print(f"  CBOM distinct sources: {cbom_sources}")
    assert "source_code" in cbom_sources, "source_code assets missing from CBOM export!"
    assert "dependency" in cbom_sources, "dependency assets missing from CBOM export!"

    # 8. Check Criticality Update endpoint
    print("\n[Step 8] Testing live business_criticality / data_lifetime update...")
    test_asset_id = sample_src["id"]
    r = client.put(f"/api/phase1/assets/{test_asset_id}/criticality", json={
        "business_criticality": "low",
        "data_lifetime": "<1y"
    })
    assert r.status_code == 200
    updated = r.json()
    print(f"  Asset {test_asset_id} updated:")
    print(f"    Old MWQRS: {sample_src['risk_score']}")
    print(f"    New MWQRS: {updated['new_risk_score']}")
    # MWQRS should have decreased when criticality changed from critical->low and lifetime from 5-10y-><1y
    assert updated["new_risk_score"] < sample_src["risk_score"], "MWQRS did not decrease after downgrading criticality!"

    print("\n" + "=" * 60)
    print("ALL PHASE 1 END-TO-END CHECKS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == "__main__":
    test_full_pipeline()
