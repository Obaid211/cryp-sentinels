import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.models import CryptoAsset

client = TestClient(app)

def test_code_scanner_vulnerabilities():
    code_sample = """
import hashlib
from Crypto.Cipher import DES

def process_login(pwd):
    h = hashlib.md5(pwd.encode()).hexdigest()
    cipher = DES.new(b"12345678")
    return h
"""
    response = client.post("/api/scanners/code", json={"content": code_sample, "filename": "auth.py"})
    assert response.status_code == 200
    data = response.json()
    assert data["findings_count"] >= 2
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "WEAK_HASH_MD5" in rule_ids
    assert "WEAK_CIPHER_DES" in rule_ids


def test_container_scanner_dockerfile():
    dockerfile_sample = """
FROM ubuntu:14.04
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
COPY id_rsa.key /root/.ssh/id_rsa
RUN apt-get update && apt-get install -y openssl
"""
    response = client.post("/api/scanners/container", json={"content": dockerfile_sample, "filename": "Dockerfile"})
    assert response.status_code == 200
    data = response.json()
    assert data["findings_count"] >= 3
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "CONTAINER_DEPRECATED_BASE_IMAGE" in rule_ids
    assert "CONTAINER_TLS_VERIFY_DISABLED" in rule_ids
    assert "CONTAINER_HARDCODED_KEY" in rule_ids


def test_api_scanner_jwt_rsa():
    # RS256 sample token header: {"alg":"RS256","typ":"JWT"}
    # eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
    rs256_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
    response = client.post("/api/scanners/api", json={
        "url": "https://api.internal.net/v1/auth",
        "sample_jwt": rs256_token
    })
    assert response.status_code == 200
    data = response.json()
    assert data["is_https"] is True
    assert data["jwt_analysis"] is not None
    assert data["jwt_analysis"]["classification"]["risk_level"] == "HIGH"
    assert "Shor's Algorithm" in data["jwt_analysis"]["classification"]["quantum_status"]


def test_api_scanner_jwt_pqc():
    # ML-DSA-65 sample token header: {"alg":"ML-DSA-65","typ":"JWT"}
    # eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJKV1QifQ
    pqc_token = "eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJzb3ZlcmVpZ24ifQ.sig"
    response = client.post("/api/scanners/api", json={
        "url": "https://api.internal.net/v1/pqc-auth",
        "sample_jwt": pqc_token
    })
    assert response.status_code == 200
    data = response.json()
    assert data["jwt_analysis"]["classification"]["risk_level"] == "LOW"
    assert "Quantum-Resistant" in data["jwt_analysis"]["classification"]["quantum_status"]


def test_api_scanner_insecure_http():
    response = client.post("/api/scanners/api", json={
        "url": "http://insecure-api.internal.net/users"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["is_https"] is False
    assert any(f["rule_id"] == "API_INSECURE_HTTP" for f in data["findings"])


def test_import_finding():
    finding_payload = {
        "host": "newly-discovered.internal.net",
        "port": 8443,
        "tls_version": "TLSv1.2",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 2048,
        "risk_score": 68.5,
        "status": "success",
        "risk_flags": ["DISCOVERED_IN_SCAN", "VULNERABLE_ALGO_RSA"]
    }
    response = client.post("/api/scanners/import", json={"finding": finding_payload})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "imported"
    assert data["host"] == "newly-discovered.internal.net"

    db = SessionLocal()
    asset = db.query(CryptoAsset).filter(CryptoAsset.host == "newly-discovered.internal.net").first()
    assert asset is not None
    assert asset.cert_key_type == "RSA"
    db.close()


def test_sse_stream_endpoint():
    response = client.get("/api/scanners/stream?target=test")
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
