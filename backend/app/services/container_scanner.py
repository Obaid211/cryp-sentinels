"""
container_scanner.py — ECDAT Phase 2 Container Cryptographic Discovery
======================================================================
Analyzes container definitions (Dockerfiles, Containerfiles, image metadata,
and installed package lists) for cryptographic libraries, base OS age,
insecure TLS flags, and embedded key material.

Output writes into the unified inventory with source="container".
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service
from app.services.scoring import calculate_mwqrs
from app.services.pqc_engine import recommend_pqc


CONTAINER_SECURITY_RULES = [
    {
        "id": "CNT_EMBEDDED_PRIVATE_KEY",
        "pattern": r"(?:COPY|ADD)\s+.*?(?:\.key|\.pem|\.pkcs8|\.pfx|\.p12|id_rsa|id_ecdsa|id_ed25519)\b",
        "severity": "CRITICAL",
        "type": "Embedded Cryptographic Private Key in Layer",
        "algorithm": "RSA / ECC",
        "usage_context": "digital_signature_or_tls",
        "is_quantum_vulnerable": True,
        "confidence": 0.95,
        "recommendation": "Remove embedded keys from container image layers. Use runtime secret injection (KMS/Vault).",
    },
    {
        "id": "CNT_TLS_VERIFY_DISABLED",
        "pattern": r"(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?|--insecure\b|curl\s+-[a-zA-Z]*k\b|PYTHONHTTPSVERIFY\s*=\s*['\"]?0['\"]?)",
        "severity": "CRITICAL",
        "type": "TLS Certificate Verification Disabled",
        "algorithm": "TLS",
        "usage_context": "network_protocol",
        "is_quantum_vulnerable": False,
        "confidence": 0.99,
        "recommendation": "Enforce strict TLS certificate verification in production container images.",
    },
    {
        "id": "CNT_SECLEVEL_ZERO",
        "pattern": r"(?:SECLEVEL\s*=\s*0|CipherString\s*=\s*DEFAULT:@SECLEVEL=0)",
        "severity": "HIGH",
        "type": "OpenSSL Security Level Downgraded (SECLEVEL=0)",
        "algorithm": "OpenSSL",
        "usage_context": "cryptographic_library",
        "is_quantum_vulnerable": True,
        "confidence": 0.95,
        "recommendation": "Maintain OpenSSL SECLEVEL=2 or higher to prevent weak 1024-bit RSA and broken ciphers.",
    },
    {
        "id": "CNT_DEPRECATED_BASE_IMAGE",
        "pattern": r"FROM\s+(?:ubuntu:(?:12\.|14\.|16\.|18\.)|debian:(?:wheezy|jessie|stretch|buster)|centos:(?:6|7)|alpine:(?:2\.|3\.[0-9]\b|3\.1[0-2]\b))",
        "severity": "HIGH",
        "type": "Deprecated Base OS with Outdated Cryptographic Toolchain",
        "algorithm": "Legacy System Crypto",
        "usage_context": "base_os",
        "is_quantum_vulnerable": True,
        "confidence": 0.90,
        "recommendation": "Upgrade base image to modern LTS (Ubuntu 24.04, Debian 12, Alpine 3.19+) for OpenSSL 3.x and TLS 1.3.",
    },
    {
        "id": "CNT_CRYPTO_PACKAGE_INSTALLED",
        "pattern": r"(?:apt-get|apk|yum|dnf|microdnf)\s+(?:install|add)\s+.*?\b(openssl|libssl-dev|ca-certificates|gnutls-bin|libgcrypt20)\b",
        "severity": "MEDIUM",
        "type": "Cryptographic Library Package Installed in Layer",
        "algorithm": "OpenSSL / GnuTLS",
        "usage_context": "cryptographic_library",
        "is_quantum_vulnerable": True,
        "confidence": 0.85,
        "recommendation": "Audit installed cryptographic libraries against corporate CBOM compliance requirements.",
    },
    {
        "id": "CNT_LEGACY_ALGO_REFERENCE",
        "pattern": r"\b(rsa[-_ ]?1024|des-ede3|md5sum|sha1sum)\b",
        "severity": "MEDIUM",
        "type": "Legacy Cryptographic Primitive in Container Script",
        "algorithm": "MD5 / SHA-1 / DES",
        "usage_context": "hash",
        "is_quantum_vulnerable": False,
        "confidence": 0.88,
        "recommendation": "Replace legacy algorithms with SHA-256 or SHA-3 and modern symmetric ciphers.",
    },
    {
        "id": "CNT_PQC_READY_TOOLCHAIN",
        "pattern": r"\b(liboqs|oqs-provider|ml-kem|ml-dsa|dilithium|kyber)\b",
        "severity": "INFORMATIONAL",
        "type": "Post-Quantum Cryptography (PQC) Package/Toolchain Detected",
        "algorithm": "ML-KEM / ML-DSA",
        "usage_context": "post_quantum",
        "is_quantum_vulnerable": False,
        "confidence": 0.92,
        "recommendation": "PQC capability detected. Verify compliance with NIST FIPS 203/204.",
    },
]


def scan_container_definition(
    dockerfile_content: str,
    filename: str = "Dockerfile",
    package_list: Optional[str] = None,
    image_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Comprehensive container scanner inspecting Dockerfile layers, package manifests, and metadata.
    """
    findings: List[Dict[str, Any]] = []
    lines = dockerfile_content.splitlines()

    base_image = "unknown"
    for line in lines:
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            base_image = stripped.split()[1]
            break

    # Scan Dockerfile content line by line
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for rule in CONTAINER_SECURITY_RULES:
            match = re.search(rule["pattern"], stripped, re.IGNORECASE)
            if match:
                findings.append({
                    "rule_id": rule["id"],
                    "finding_type": rule["type"],
                    "algorithm": rule["algorithm"],
                    "usage_context": rule["usage_context"],
                    "severity": rule["severity"],
                    "confidence_score": rule["confidence"],
                    "is_quantum_vulnerable": rule["is_quantum_vulnerable"],
                    "matched_text": match.group(0)[:60],
                    "line_number": line_no,
                    "evidence": stripped[:150],
                    "recommendation": rule["recommendation"],
                    "source_file": filename,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                })

    # Optional package list analysis (e.g. dpkg -l or apk list output)
    if package_list:
        pkg_lower = package_list.lower()
        if "openssl 1." in pkg_lower or "libssl1.0" in pkg_lower or "libssl1.1" in pkg_lower:
            findings.append({
                "rule_id": "CNT_LEGACY_OPENSSL_PACKAGE",
                "finding_type": "Outdated OpenSSL 1.x Installed in Container",
                "algorithm": "OpenSSL 1.x",
                "usage_context": "cryptographic_library",
                "severity": "HIGH",
                "confidence_score": 0.95,
                "is_quantum_vulnerable": True,
                "matched_text": "OpenSSL 1.x package",
                "line_number": None,
                "evidence": "Found legacy OpenSSL 1.x package in manifest",
                "recommendation": "Upgrade to OpenSSL 3.x+ to support modern TLS 1.3 and PQC providers.",
                "source_file": "packages.txt",
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

    # Sort findings by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    return {
        "filename": filename,
        "base_image": base_image,
        "findings_count": len(findings),
        "findings": findings,
    }


def import_container_finding_to_inventory(
    db: Session,
    finding: Dict[str, Any],
    container_name: str = "app-container",
    service_name: Optional[str] = None,
    business_criticality: str = "high",
    data_lifetime: str = "1-3y",
) -> Dict[str, Any]:
    """
    Phase 2: Writes a container scanner finding to the unified CryptoAsset inventory
    with source='container'. Uses a synthetic host+port derived from container name + rule_id.
    """
    rule_id = finding.get("rule_id", "CNT_RULE")
    algorithm = finding.get("algorithm", "OpenSSL")
    usage_ctx = finding.get("usage_context", "container_environment")
    confidence = float(finding.get("confidence_score", 0.90))

    clean_name = container_name.replace("/", "-").replace(":", "-").replace(" ", "-")[:40]
    host = f"cnt.{clean_name}.internal"
    port_hash = int(hashlib.md5(f"{container_name}:{rule_id}".encode()).hexdigest(), 16) % 10000
    port = 70000 + port_hash

    linked_service_id = None
    if service_name:
        svc = db.query(Service).filter(Service.name == service_name).first()
        if svc:
            linked_service_id = svc.id

    pqc_rec = recommend_pqc(algorithm, usage_ctx)

    severity = finding.get("severity", "MEDIUM")
    risk_flags = [f"CNT_{rule_id}", f"SEVERITY_{severity}"]
    if finding.get("is_quantum_vulnerable"):
        risk_flags.append("QUANTUM_VULNERABLE_ALGO")

    asset_record = {
        "status": "success",
        "cert_key_type": algorithm,
        "cert_key_size_bits": 2048 if "RSA" in algorithm.upper() else None,
        "tls_version": None,
        "days_to_expiry": None,
        "business_criticality": business_criticality,
        "data_lifetime": data_lifetime,
    }

    svc_obj = db.get(Service, linked_service_id) if linked_service_id else None
    svc_criticality = svc_obj.criticality if svc_obj else "P1"
    mwqrs = calculate_mwqrs(asset_record, service_criticality=svc_criticality)

    existing = db.query(CryptoAsset).filter(
        CryptoAsset.host == host, CryptoAsset.port == port
    ).first()

    if not existing:
        asset = CryptoAsset(
            host=host,
            port=port,
            status="success",
            source="container",
            business_criticality=business_criticality,
            data_lifetime=data_lifetime,
            cert_key_type=algorithm,
            cert_key_size_bits=asset_record["cert_key_size_bits"],
            cert_subject=f"Container: {container_name} ({finding.get('source_file', 'Dockerfile')})",
            cert_issuer=f"Rule: {rule_id} | {finding.get('finding_type', '')}",
            algorithm=algorithm,
            usage_context=usage_ctx,
            confidence_score=confidence,
            library="Container Environment",
            file_path=finding.get("source_file", "Dockerfile"),
            line_number=finding.get("line_number"),
            risk_flags=json.dumps(risk_flags),
            risk_score=mwqrs,
            pqc_recommendation=json.dumps(pqc_rec),
            linked_service_id=linked_service_id,
        )
        db.add(asset)
    else:
        existing.source = "container"
        existing.business_criticality = business_criticality
        existing.data_lifetime = data_lifetime
        existing.risk_score = mwqrs
        existing.pqc_recommendation = json.dumps(pqc_rec)
        existing.confidence_score = confidence

    db.commit()
    return {
        "status": "imported",
        "host": host,
        "port": port,
        "risk_score": mwqrs,
        "algorithm": algorithm,
    }
