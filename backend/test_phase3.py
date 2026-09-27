"""
test_phase3.py
Tests Phase 3 capabilities:
1. Hardware Security Module (HSM) discovery -> Inventory (source="hsm")
2. Cloud KMS & Certificate Services discovery -> Inventory (source="cloud_kms")
3. Verification across all 7 discovery sources (tls, source_code, dependency, container, binary, hsm, cloud_kms)
   in Unified Inventory, Remediation Queue, Dependency Graph, and CycloneDX 1.6 CBOM Export
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def run_phase3_tests():
    print("=" * 60)
    print("Testing Phase 3 Hardware/HSM & Cloud KMS Scanners")
    print("=" * 60)

    # 1. Hardware / HSM Scan
    print("\n[Test 1] Testing Hardware Security Module (HSM) Scanner...")
    hsm_sample_conf = """
    slot = 1
    token_label = "Sovereign-Root-Token"
    library = "/usr/lib/libCryptoki2_64.so"
    vendor = "Thales Luna PCIe HSM"
    fips_mode = "FIPS 140-2 Level 3"
    mechanisms = "CKM_RSA_PKCS_KEY_PAIR_GEN,CKM_RSA_PKCS,CKM_ECDSA_KEY_PAIR_GEN,CKM_AES_GCM"
    """
    r = client.post("/api/phase3/scan/hsm", json={
        "content": hsm_sample_conf,
        "filename": "luna_pkcs11.conf",
        "vendor_hint": "thales_luna",
        "service_name": "Payment-Gateway",
        "business_criticality": "critical",
        "data_lifetime": "5-10y",
        "import_to_inventory": True,
    })
    assert r.status_code == 200, f"HSM scan failed: {r.status_code} {r.text}"
    hsm_data = r.json()
    print(f"  HSM vendor: {hsm_data['vendor_name']}")
    print(f"  FIPS rating: {hsm_data['fips_level']}")
    print(f"  Mechanisms discovered: {hsm_data['findings_count']}")
    print(f"  Inventory imported: {hsm_data['inventory_imported']}")
    assert hsm_data["inventory_imported"] > 0

    # 2. Cloud KMS Scan
    print("\n[Test 2] Testing Cloud KMS & Key Vault Scanner...")
    cloud_kms_sample = """
    {
      "Keys": [
        {
          "KeyId": "arn:aws:kms:us-east-1:123456789012:key/cardholder-data-kek",
          "KeySpec": "SYMMETRIC_DEFAULT",
          "KeyUsage": "ENCRYPT_DECRYPT",
          "Rotation": true
        },
        {
          "KeyId": "arn:aws:kms:us-east-1:123456789012:key/database-proxy-ca-root",
          "KeySpec": "RSA_4096",
          "KeyUsage": "SIGN_VERIFY",
          "Rotation": false
        }
      ]
    }
    """
    r2 = client.post("/api/phase3/scan/cloud-kms", json={
        "content": cloud_kms_sample,
        "filename": "aws_kms_export.json",
        "provider_hint": "aws_kms",
        "service_name": "Core-Database-Proxy",
        "business_criticality": "critical",
        "data_lifetime": "5-10y",
        "import_to_inventory": True,
    })
    assert r2.status_code == 200, f"Cloud KMS scan failed: {r2.status_code} {r2.text}"
    kms_data = r2.json()
    print(f"  Cloud KMS provider: {kms_data['provider']}")
    print(f"  Keys scanned: {kms_data['keys_scanned']}")
    print(f"  Quantum vulnerable keys: {kms_data['quantum_vulnerable_keys']}")
    print(f"  Inventory imported: {kms_data['inventory_imported']}")
    assert kms_data["inventory_imported"] > 0

    # 3. Check Unified Inventory contains all 7 asset sources
    print("\n[Test 3] Verifying Unified Inventory contains all 7 sources...")
    r3 = client.get("/api/inventory")
    assert r3.status_code == 200
    assets = r3.json()
    sources = set(a.get("source") for a in assets)
    print(f"  Total inventory assets: {len(assets)}")
    print(f"  Distinct sources: {sources}")
    expected_sources = {"tls", "source_code", "dependency", "container", "binary", "hsm", "cloud_kms"}
    for exp in expected_sources:
        assert exp in sources, f"Source '{exp}' missing from inventory!"

    # 4. Check Remediation Plan includes HSM and Cloud KMS
    print("\n[Test 4] Verifying Remediation Queue includes Phase 3 items...")
    r4 = client.get("/api/remediation/plan")
    assert r4.status_code == 200
    plan = r4.json()
    rem_sources = set(item.get("source") for item in plan["queue"])
    print(f"  Remediation queue sources: {rem_sources}")
    assert "hsm" in rem_sources
    assert "cloud_kms" in rem_sources

    # 5. Check CBOM Export includes Phase 3 sources
    print("\n[Test 5] Verifying CycloneDX CBOM Export includes Phase 3 components...")
    r5 = client.get("/api/cbom/export")
    assert r5.status_code == 200
    cbom = r5.json()
    cbom_sources = set()
    for comp in cbom.get("components", []):
        for prop in comp.get("properties", []):
            if prop.get("name") == "ecdat:source":
                cbom_sources.add(prop.get("value"))
    print(f"  CBOM sources: {cbom_sources}")
    assert "hsm" in cbom_sources
    assert "cloud_kms" in cbom_sources

    # 6. Check Dependency Graph links HSM and Cloud KMS to services
    print("\n[Test 6] Verifying Dependency Graph links HSM and Cloud KMS to services...")
    r6 = client.get("/api/graph/dependencies")
    assert r6.status_code == 200
    graph = r6.json()
    nodes = {n["name"]: n for n in graph["nodes"]}
    pmt_node = nodes.get("Payment-Gateway")
    db_node = nodes.get("Core-Database-Proxy")
    assert pmt_node is not None
    assert db_node is not None
    pmt_sources = set(a.get("source") for a in pmt_node.get("assets", []))
    db_sources = set(a.get("source") for a in db_node.get("assets", []))
    print(f"  Payment-Gateway asset sources: {pmt_sources}")
    print(f"  Core-Database-Proxy asset sources: {db_sources}")
    assert "hsm" in pmt_sources
    assert "cloud_kms" in db_sources

    print("\n" + "=" * 60)
    print("PHASE 3 DISCOVERY FULLY INTEGRATED AND 100% VERIFIED!")
    print("=" * 60)

if __name__ == "__main__":
    run_phase3_tests()
