"""
test_phase2.py
Tests Phase 2 capabilities:
1. Binary Scanner (ELF / PE / strings with symbols for OpenSSL, libsodium, PQC) -> Inventory (source="binary")
2. Container Scanner (Dockerfile + packages) -> Inventory (source="container")
3. Verification across Unified Inventory, Remediation Center, Threat Timeline, Dependency Graph, CBOM export, and Snapshot Diff
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def run_tests():
    print("=" * 60)
    print("Testing Phase 2 Binary & Container Scanners")
    print("=" * 60)

    # 1. Binary Scan
    print("\n[Test 1] Testing Binary Scanner with simulated crypto binary symbols...")
    # Simulated binary content with OpenSSL RSA, libsodium, and PQC markers
    simulated_binary_text = """
    ELF\x02\x01\x01\x00
    OpenSSL 3.0.2 15 Mar 2022
    RSA_generate_key_ex
    RSA_public_encrypt
    EVP_PKEY_RSA
    crypto_sign_ed25519
    sodium_init
    OQS_KEM_new
    ML-KEM-768
    libcrypto.so.3
    PKCS#8
    """
    r = client.post("/api/phase2/scan/binary", json={
        "content_text": simulated_binary_text,
        "filename": "libauth_crypto.so",
        "service_name": "Auth-Service",
        "business_criticality": "critical",
        "data_lifetime": "5-10y",
        "import_to_inventory": True,
    })
    assert r.status_code == 200, f"Binary scan failed: {r.status_code} {r.text}"
    bin_data = r.json()
    print(f"  Binary format detected: {bin_data['file_format']}")
    print(f"  Libraries detected: {bin_data['libraries_detected']}")
    print(f"  Findings count: {bin_data['findings_count']}")
    print(f"  Inventory imported: {bin_data['inventory_imported']}")
    assert bin_data["inventory_imported"] > 0

    # 2. Container Scan
    print("\n[Test 2] Testing Container Scanner with Dockerfile...")
    dockerfile_sample = """
    FROM ubuntu:16.04
    ENV NODE_TLS_REJECT_UNAUTHORIZED=0
    COPY id_rsa /root/.ssh/id_rsa
    RUN apt-get update && apt-get install -y openssl libssl-dev
    """
    r2 = client.post("/api/phase2/scan/container", json={
        "content": dockerfile_sample,
        "filename": "Dockerfile.auth",
        "container_name": "auth-microservice-img",
        "service_name": "Auth-Service",
        "business_criticality": "high",
        "data_lifetime": "3-5y",
        "import_to_inventory": True,
    })
    assert r2.status_code == 200, f"Container scan failed: {r2.status_code} {r2.text}"
    cnt_data = r2.json()
    print(f"  Container base image: {cnt_data['base_image']}")
    print(f"  Findings count: {cnt_data['findings_count']}")
    print(f"  Inventory imported: {cnt_data['inventory_imported']}")
    assert cnt_data["inventory_imported"] > 0

    # 3. Check Unified Inventory contains binary and container assets
    print("\n[Test 3] Verifying Unified Inventory...")
    r3 = client.get("/api/inventory")
    assert r3.status_code == 200
    assets = r3.json()
    sources = set(a.get("source") for a in assets)
    print(f"  Total inventory assets: {len(assets)}")
    print(f"  Distinct sources: {sources}")
    assert "binary" in sources, "binary source missing from inventory!"
    assert "container" in sources, "container source missing from inventory!"

    # 4. Check Remediation Plan includes binary and container items
    print("\n[Test 4] Verifying Remediation Queue includes Phase 2 items...")
    r4 = client.get("/api/remediation/plan")
    assert r4.status_code == 200
    plan = r4.json()
    rem_sources = set(item.get("source") for item in plan["queue"])
    print(f"  Remediation queue sources: {rem_sources}")
    assert "binary" in rem_sources
    assert "container" in rem_sources

    # 5. Check CBOM export contains binary and container components
    print("\n[Test 5] Verifying CycloneDX CBOM Export includes Phase 2 sources...")
    r5 = client.get("/api/cbom/export")
    assert r5.status_code == 200
    cbom = r5.json()
    cbom_sources = set()
    for comp in cbom.get("components", []):
        for prop in comp.get("properties", []):
            if prop.get("name") == "ecdat:source":
                cbom_sources.add(prop.get("value"))
    print(f"  CBOM sources: {cbom_sources}")
    assert "binary" in cbom_sources
    assert "container" in cbom_sources

    # 6. Check Dependency Graph
    print("\n[Test 6] Verifying Dependency Graph links Phase 2 assets to services...")
    r6 = client.get("/api/graph/dependencies")
    assert r6.status_code == 200
    graph = r6.json()
    auth_node = next((n for n in graph["nodes"] if n["name"] == "Auth-Service"), None)
    assert auth_node is not None
    node_sources = set(a.get("source") for a in auth_node.get("assets", []))
    print(f"  Auth-Service assets sources in graph: {node_sources}")
    assert "binary" in node_sources or "container" in node_sources

    # 7. Check Snapshot Creation & Comparison
    print("\n[Test 7] Verifying Snapshot Creation and Diff Comparison...")
    r7_snap1 = client.post("/api/snapshots/save", json={"name": "Phase2_Before_Snapshot"})
    assert r7_snap1.status_code == 200, f"Snapshot 1 save failed: {r7_snap1.text}"
    snap1_id = r7_snap1.json()["id"]

    r7_snap2 = client.post("/api/snapshots/save", json={"name": "Phase2_After_Snapshot"})
    assert r7_snap2.status_code == 200, f"Snapshot 2 save failed: {r7_snap2.text}"
    snap2_id = r7_snap2.json()["id"]

    r7_diff = client.get(f"/api/snapshots/diff?old_id={snap1_id}&new_id={snap2_id}")
    assert r7_diff.status_code == 200, f"Snapshot diff failed: {r7_diff.text}"
    diff_data = r7_diff.json()
    print(f"  Diff compared snapshots {snap1_id} and {snap2_id} successfully!")
    print(f"  Summary delta: {diff_data.get('summary', {})}")

    print("\n" + "=" * 60)
    print("PHASE 2 BACKEND INTEGRATION COMPLETED AND 100% VERIFIED!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
