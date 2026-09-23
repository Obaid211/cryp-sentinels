import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service, ServiceDependency
from app.services.scoring import calculate_mwqrs, QUANTUM_VULNERABLE_ALGORITHMS

def get_recommended_pqc_target(key_type: str) -> Dict[str, Any]:
    kt = (key_type or "").upper()
    if "RSA" in kt:
        return {
            "algorithm": "ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium)",
            "standards": ["NIST FIPS 203", "NIST FIPS 204"],
            "strategy": "Hybrid Dual Certificate Transition",
            "notes": "Deploy hybrid classical RSA + ML-KEM-768 during transition window."
        }
    elif "ECC" in kt or "ECDSA" in kt:
        return {
            "algorithm": "ML-DSA-65 (Dilithium) / SLH-DSA (SPHINCS+)",
            "standards": ["NIST FIPS 204", "NIST FIPS 205"],
            "strategy": "Stateful Lattice Signature Migration",
            "notes": "Transition ECDSA keys to ML-DSA or stateless hash-based SLH-DSA."
        }
    elif "ML-" in kt:
        return {
            "algorithm": "NIST FIPS 203 / 204 Production Standard",
            "standards": ["NIST FIPS 203/204"],
            "strategy": "Already PQC-Migrated",
            "notes": "Maintain implementation and monitor algorithmic agility."
        }
    return {
        "algorithm": "ML-KEM-768",
        "standards": ["NIST FIPS 203"],
        "strategy": "Hybrid Transition",
        "notes": "Transition asymmetric key exchange to ML-KEM-768."
    }

def explain_risk_flag(flag: str) -> str:
    if flag == "CERT_EXPIRED":
        return "The TLS certificate is expired; browser trust can fail and users will receive security warnings."
    if flag.startswith("CERT_EXPIRING_SOON"):
        return "The TLS certificate expires soon and should be renewed before the deadline."
    if flag.startswith("WEAK_RSA_KEY_SIZE"):
        return "The RSA certificate key is below standard 2048-bit length, creating high classical and quantum vulnerability."
    if flag.startswith("DEPRECATED_TLS_VERSION") or flag.startswith("TLS_1_2"):
        return "The endpoint is using an older TLS version that lacks forward security enhancements."
    if "VULNERABLE_ALGO" in flag:
        return "The endpoint utilizes Shor-vulnerable classical asymmetric cryptography (RSA/ECC)."
    return f"Security notification: {flag}"

def generate_cyclonedx_cbom(db: Session) -> Dict[str, Any]:
    assets = db.query(CryptoAsset).all()
    components = []
    for a in assets:
        key_type = a.cert_key_type or "Unknown"
        is_vuln = any(v.lower() in key_type.lower() for v in QUANTUM_VULNERABLE_ALGORITHMS)
        pqc = get_recommended_pqc_target(key_type)

        props = [
            {"name": "ecdat:host", "value": a.host},
            {"name": "ecdat:port", "value": str(a.port)},
            {"name": "ecdat:tls_version", "value": a.tls_version or "N/A"},
            {"name": "ecdat:cipher_suite", "value": a.cipher_suite or "N/A"},
            {"name": "ecdat:key_type", "value": key_type},
            {"name": "ecdat:key_size_bits", "value": str(a.cert_key_size_bits or 0)},
            {"name": "ecdat:mwqrs_score", "value": str(a.risk_score)},
            {"name": "ecdat:quantum_vulnerable", "value": str(is_vuln).lower()},
            {"name": "ecdat:recommended_pqc_target", "value": pqc["algorithm"]},
        ]

        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{a.id}-{a.host}:{a.port}",
            "name": f"TLS Endpoint {a.host}:{a.port}",
            "description": f"Subject: {a.cert_subject or 'N/A'} | Issuer: {a.cert_issuer or 'N/A'}",
            "properties": props
        })

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "ECDAT",
                    "name": "Enterprise Cryptographic Discovery & Analysis Tool",
                    "version": "2.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": "ECDAT Sovereign Cryptographic Inventory Assessment",
                "version": "2.0.0"
            }
        },
        "components": components
    }
