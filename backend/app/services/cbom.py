"""
cbom.py — CycloneDX 1.6 CBOM generation
Phase 1: Updated to use PQC Recommendation Engine output.
All sources (tls, source_code, dependency) appear in the CBOM export.
"""
import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service, ServiceDependency
from app.services.scoring import calculate_mwqrs, QUANTUM_VULNERABLE_ALGORITHMS


def get_recommended_pqc_target(key_type: str) -> Dict[str, Any]:
    """
    Quick PQC target lookup for display use in inventory/detail views.
    For full recommendations use pqc_engine.recommend_pqc() directly.
    """
    from app.services.pqc_engine import recommend_pqc
    rec = recommend_pqc(key_type)
    return {
        "algorithm": rec["recommendation"],
        "standards": rec["standards"],
        "strategy": "Hybrid" if "hybrid" in rec.get("hybrid_alternative", "").lower() else "Pure PQC",
        "notes": rec.get("reason", "")
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
        return "The endpoint utilises Shor-vulnerable classical asymmetric cryptography (RSA/ECC)."
    if flag.startswith("SRC_"):
        return f"Source code scanner finding: {flag.replace('SRC_', '')} pattern detected in code."
    if "QUANTUM_VULNERABLE_DEFAULT_ALGO" in flag:
        return "This library's default algorithm is vulnerable to Shor's algorithm on a quantum computer."
    if "NO_PQC_SUPPORT" in flag:
        return "This library does not natively support NIST post-quantum algorithms. Plan migration."
    if "QUANTUM_VULNERABLE_ALGO" in flag:
        return "Algorithm is vulnerable to Shor's algorithm. PQC migration required."
    if flag.startswith("SEVERITY_"):
        return f"Finding severity: {flag.replace('SEVERITY_', '')}."
    return f"Security notification: {flag}"


def generate_cyclonedx_cbom(db: Session) -> Dict[str, Any]:
    """
    Generates a CycloneDX 1.6 CBOM export.
    Phase 1: Includes all asset sources (tls, source_code, dependency)
    and uses the PQC Recommendation Engine output stored in pqc_recommendation.
    """
    assets = db.query(CryptoAsset).all()
    components = []

    for a in assets:
        key_type = a.cert_key_type or a.algorithm or "Unknown"
        is_vuln = any(v.lower() in key_type.lower() for v in QUANTUM_VULNERABLE_ALGORITHMS)

        # Use stored PQC recommendation if available, otherwise compute
        pqc_data = None
        if a.pqc_recommendation:
            try:
                pqc_data = json.loads(a.pqc_recommendation)
            except Exception:
                pqc_data = None
        if not pqc_data:
            pqc_data = get_recommended_pqc_target(key_type)

        # Determine display name based on source
        source = a.source or "tls"
        if source == "source_code":
            display_name = f"Source Code: {a.file_path or a.cert_subject or a.host}"
            desc = f"File: {a.file_path}, Line: {a.line_number}, Rule: {a.cert_issuer}"
        elif source == "dependency":
            display_name = f"Library: {a.library or a.host}"
            desc = f"Capability: {a.cert_issuer or 'N/A'} | Version: {a.cert_subject or 'N/A'}"
        elif source == "container":
            display_name = f"Container Image: {a.cert_subject or a.host}"
            desc = f"Directive: {a.cert_issuer or 'N/A'}"
        elif source == "binary":
            display_name = f"Binary Executable: {a.file_path or a.host}"
            desc = f"Library: {a.library or 'N/A'} | Issuer: {a.cert_issuer or 'N/A'}"
        elif source == "hsm":
            display_name = f"Hardware HSM: {a.library or a.host}"
            desc = f"Subject: {a.cert_subject or 'N/A'} | Mechanism: {a.algorithm or 'N/A'}"
        elif source == "cloud_kms":
            display_name = f"Cloud KMS: {a.library or a.host}"
            desc = f"Key: {a.cert_subject or 'N/A'} | Policy: {a.cert_issuer or 'N/A'}"
        else:
            display_name = f"TLS Endpoint {a.host}:{a.port}"
            desc = f"Subject: {a.cert_subject or 'N/A'} | Issuer: {a.cert_issuer or 'N/A'}"

        props = [
            {"name": "ecdat:host", "value": a.host},
            {"name": "ecdat:port", "value": str(a.port)},
            {"name": "ecdat:source", "value": source},
            {"name": "ecdat:tls_version", "value": a.tls_version or "N/A"},
            {"name": "ecdat:cipher_suite", "value": a.cipher_suite or "N/A"},
            {"name": "ecdat:key_type", "value": key_type},
            {"name": "ecdat:key_size_bits", "value": str(a.cert_key_size_bits or 0)},
            {"name": "ecdat:algorithm", "value": a.algorithm or key_type},
            {"name": "ecdat:usage_context", "value": a.usage_context or "unknown"},
            {"name": "ecdat:library", "value": a.library or "N/A"},
            {"name": "ecdat:business_criticality", "value": a.business_criticality or "medium"},
            {"name": "ecdat:data_lifetime", "value": a.data_lifetime or "1-3y"},
            {"name": "ecdat:confidence_score", "value": str(a.confidence_score or "N/A")},
            {"name": "ecdat:mwqrs_score", "value": str(a.risk_score)},
            {"name": "ecdat:quantum_vulnerable", "value": str(is_vuln).lower()},
            {
                "name": "ecdat:recommended_pqc_target",
                "value": pqc_data.get("recommendation", pqc_data.get("algorithm", "ML-KEM-768"))
            },
            {
                "name": "ecdat:hybrid_alternative",
                "value": pqc_data.get("hybrid_alternative", "N/A")
            },
            {
                "name": "ecdat:migration_complexity",
                "value": pqc_data.get("migration_complexity", "Medium")
            },
        ]

        if source == "source_code" and a.file_path:
            props.append({"name": "ecdat:file_path", "value": a.file_path})
            props.append({"name": "ecdat:line_number", "value": str(a.line_number or "N/A")})

        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{a.id}-{source}-{a.host}:{a.port}",
            "name": display_name,
            "description": desc,
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
