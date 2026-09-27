"""
binary_scanner.py — ECDAT Phase 2 Binary Cryptographic Discovery
================================================================
Performs static inspection of executable binaries and shared libraries
(ELF, PE, Mach-O, or raw binary blobs) for cryptographic symbols,
library signatures, TLS/PKCS strings, and PQC markers.

Does NOT claim full semantic disassembly; reports findings with an explicit
confidence score based on symbol match specificity and density.

Output writes into the unified inventory with source="binary".
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service
from app.services.scoring import calculate_mwqrs
from app.services.pqc_engine import recommend_pqc


# -----------------------------------------------------------------
# Known Cryptographic Symbols & String Signatures
# -----------------------------------------------------------------
CRYPTO_BINARY_RULES: List[Dict[str, Any]] = [
    # --- OpenSSL / Libcrypto ---
    {
        "id": "BIN_OPENSSL_RSA",
        "library": "OpenSSL",
        "algorithm": "RSA",
        "usage_context": "asymmetric_key",
        "pattern": r"\b(?:RSA_new|RSA_generate_key_ex|RSA_public_encrypt|RSA_private_decrypt|RSA_sign|RSA_verify|EVP_PKEY_RSA)\b",
        "severity": "HIGH",
        "confidence": 0.95,
        "is_quantum_vulnerable": True,
        "description": "OpenSSL RSA asymmetric key management or operations symbol",
        "remediation": "Migrate to ML-KEM (key encapsulation) or ML-DSA (signatures) per NIST FIPS 203/204.",
    },
    {
        "id": "BIN_OPENSSL_EC",
        "library": "OpenSSL",
        "algorithm": "ECDSA / ECDH",
        "usage_context": "asymmetric_key",
        "pattern": r"\b(?:EC_KEY_new|EC_KEY_generate_key|ECDSA_do_sign|ECDSA_do_verify|ECDH_compute_key|EVP_PKEY_EC)\b",
        "severity": "HIGH",
        "confidence": 0.95,
        "is_quantum_vulnerable": True,
        "description": "OpenSSL Elliptic Curve cryptography symbol (ECDSA / ECDH)",
        "remediation": "Replace with ML-DSA-65 or ML-KEM-768.",
    },
    {
        "id": "BIN_OPENSSL_EVP_CIPHER",
        "library": "OpenSSL",
        "algorithm": "AES",
        "usage_context": "symmetric_encryption",
        "pattern": r"\b(?:EVP_aes_256_gcm|EVP_aes_128_gcm|EVP_aes_256_cbc|EVP_EncryptInit_ex|AES_set_encrypt_key)\b",
        "severity": "LOW",
        "confidence": 0.90,
        "is_quantum_vulnerable": False,
        "description": "OpenSSL AES symmetric cipher primitive",
        "remediation": "Ensure 256-bit key length is enforced for post-quantum Grover resilience.",
    },
    {
        "id": "BIN_OPENSSL_LEGACY_HASH",
        "library": "OpenSSL",
        "algorithm": "MD5 / SHA-1",
        "usage_context": "hash",
        "pattern": r"\b(?:MD5_Init|MD5_Update|SHA1_Init|SHA1_Update|EVP_md5|EVP_sha1)\b",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "is_quantum_vulnerable": False,
        "description": "OpenSSL classically deprecated hash primitive (MD5 / SHA-1)",
        "remediation": "Deprecate collision-vulnerable hashes in favor of SHA-256 or SHA-3.",
    },
    {
        "id": "BIN_OPENSSL_CORE_BRAND",
        "library": "OpenSSL",
        "algorithm": "OpenSSL Stack",
        "usage_context": "cryptographic_library",
        "pattern": r"(?:OpenSSL\s+[0-9]+\.[0-9]+|libcrypto\.so|libssl\.so|libcrypto\.dylib|ssleay32\.dll|libeay32\.dll)",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "is_quantum_vulnerable": True,
        "description": "OpenSSL shared library dependency string embedded in binary",
        "remediation": "Ensure OpenSSL >= 3.x is linked with OQS-provider support.",
    },

    # --- BoringSSL ---
    {
        "id": "BIN_BORINGSSL_STACK",
        "library": "BoringSSL",
        "algorithm": "BoringSSL Stack",
        "usage_context": "cryptographic_library",
        "pattern": r"(?:BORINGSSL_API_VERSION|bssl::|libboringssl\.so)",
        "severity": "MEDIUM",
        "confidence": 0.90,
        "is_quantum_vulnerable": True,
        "description": "Google BoringSSL cryptographic library detected",
        "remediation": "Verify X25519Kyber768 hybrid key exchange is active in BoringSSL configuration.",
    },

    # --- Libsodium ---
    {
        "id": "BIN_LIBSODIUM_CRYPTO",
        "library": "libsodium",
        "algorithm": "Ed25519 / X25519 / ChaCha20",
        "usage_context": "modern_crypto",
        "pattern": r"\b(?:sodium_init|crypto_secretbox_easy|crypto_sign_ed25519|crypto_box_curve25519xsalsa20poly1305|crypto_kx_keypair)\b",
        "severity": "MEDIUM",
        "confidence": 0.92,
        "is_quantum_vulnerable": True,
        "description": "libsodium high-level cryptographic library symbols",
        "remediation": "Curve25519/Ed25519 are quantum-vulnerable. Prepare hybrid transition paths.",
    },

    # --- TLS & PKCS Artifacts ---
    {
        "id": "BIN_PKCS_STANDARDS",
        "library": "PKCS",
        "algorithm": "PKCS Standard Formats",
        "usage_context": "key_management",
        "pattern": r"(?:PKCS#1\b|PKCS#7\b|PKCS#8\b|PKCS#12\b|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)",
        "severity": "HIGH",
        "confidence": 0.88,
        "is_quantum_vulnerable": True,
        "description": "PKCS key structures or hardcoded ASN.1 PEM key blocks found in binary strings",
        "remediation": "Avoid embedding private key material in binary segments. Use secure enclave or KMS.",
    },
    {
        "id": "BIN_TLS_PROTOCOL_REFS",
        "library": "TLS Stack",
        "algorithm": "TLS Protocols",
        "usage_context": "network_protocol",
        "pattern": r"\b(?:SSLv2_method|SSLv3_method|TLSv1_client_method|TLSv1_1_client_method|TLSv1_2_client_method|TLSv1_3_client_method)\b",
        "severity": "HIGH",
        "confidence": 0.90,
        "is_quantum_vulnerable": False,
        "description": "TLS protocol version method references",
        "remediation": "Enforce TLS 1.3 only; disable SSLv3, TLS 1.0, and TLS 1.1.",
    },

    # --- Post-Quantum Cryptography (PQC) Markers ---
    {
        "id": "BIN_PQC_LIBOQS_SIG",
        "library": "liboqs",
        "algorithm": "ML-KEM / ML-DSA",
        "usage_context": "post_quantum",
        "pattern": r"\b(?:OQS_KEM_new|OQS_SIG_new|OQS_KEM_alg_ml_kem_768|OQS_SIG_alg_ml_dsa_65|liboqs\.so)\b",
        "severity": "INFORMATIONAL",
        "confidence": 0.98,
        "is_quantum_vulnerable": False,
        "description": "Open Quantum Safe (liboqs) Post-Quantum Cryptography library symbols present",
        "remediation": "PQC implementation confirmed. Verify conformance with NIST FIPS 203/204.",
    },
    {
        "id": "BIN_PQC_ALGO_NAMES",
        "library": "NIST PQC Standards",
        "algorithm": "NIST FIPS 203/204",
        "usage_context": "post_quantum",
        "pattern": r"\b(?:ML-KEM-512|ML-KEM-768|ML-KEM-1024|ML-DSA-44|ML-DSA-65|ML-DSA-87|Kyber768|Dilithium3|Falcon-512)\b",
        "severity": "INFORMATIONAL",
        "confidence": 0.85,
        "is_quantum_vulnerable": False,
        "description": "NIST Post-Quantum Cryptography algorithm identifiers detected",
        "remediation": "Ensure hybrid operation (Classical + PQC) during ecosystem migration.",
    },
]


def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts printable ASCII strings of minimum length from binary bytes."""
    pattern = re.compile(b"[ -~]{" + str(min_len).encode() + b",}")
    matches = pattern.findall(data)
    # Decode ignoring errors, cap to 50,000 strings to maintain fast performance
    return [m.decode("ascii", errors="ignore") for m in matches[:50000]]


def detect_binary_format(header: bytes) -> str:
    """Identifies executable container format from magic bytes."""
    if header.startswith(b"\x7fELF"):
        return "ELF (Linux/Unix Executable or Shared Object)"
    if header.startswith(b"MZ"):
        return "PE (Windows Portable Executable / DLL)"
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O (macOS Executable or Dynamic Library)"
    if header.startswith(b"PK\x03\x04"):
        return "ZIP/JAR/APK Archive"
    return "Raw Binary / Memory Segment"


def scan_binary_bytes(
    data: bytes,
    filename: str = "binary_target"
) -> Dict[str, Any]:
    """
    Scans binary bytes for cryptographic symbols, library references, and algorithms.
    """
    file_format = detect_binary_format(data[:16])
    strings = extract_ascii_strings(data, min_len=4)
    joined_text = "\n".join(strings)

    findings: List[Dict[str, Any]] = []
    libraries_detected = set()
    quantum_vuln_count = 0
    pqc_marker_count = 0

    for rule in CRYPTO_BINARY_RULES:
        matches = re.findall(rule["pattern"], joined_text, re.IGNORECASE)
        if matches:
            unique_matches = list(dict.fromkeys(matches))[:10]  # deduplicate
            libraries_detected.add(rule["library"])
            if rule["is_quantum_vulnerable"]:
                quantum_vuln_count += 1
            if rule["severity"] == "INFORMATIONAL" and "PQC" in rule["id"]:
                pqc_marker_count += 1

            findings.append({
                "rule_id": rule["id"],
                "library": rule["library"],
                "algorithm": rule["algorithm"],
                "usage_context": rule["usage_context"],
                "severity": rule["severity"],
                "confidence_score": rule["confidence"],
                "description": rule["description"],
                "remediation": rule["remediation"],
                "matched_symbols": unique_matches,
                "match_count": len(matches),
                "is_quantum_vulnerable": rule["is_quantum_vulnerable"],
                "source_file": filename,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

    # Sort findings by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    # Overall confidence
    if findings:
        max_conf = max(f["confidence_score"] for f in findings)
    else:
        max_conf = 0.0

    return {
        "filename": filename,
        "file_format": file_format,
        "file_size_bytes": len(data),
        "strings_analyzed": len(strings),
        "libraries_detected": sorted(list(libraries_detected)),
        "quantum_vulnerable_findings": quantum_vuln_count,
        "pqc_markers_detected": pqc_marker_count,
        "overall_confidence": max_conf,
        "findings_count": len(findings),
        "findings": findings,
    }


def import_binary_finding_to_inventory(
    db: Session,
    finding: Dict[str, Any],
    binary_name: str = "app.bin",
    service_name: Optional[str] = None,
    business_criticality: str = "high",
    data_lifetime: str = "3-5y",
) -> Dict[str, Any]:
    """
    Phase 2: Writes a binary scan finding to the unified CryptoAsset inventory
    with source='binary'. Uses a synthetic host+port derived from binary name + rule_id.
    """
    rule_id = finding.get("rule_id", "BIN_CRYPTO")
    algorithm = finding.get("algorithm", "RSA")
    usage_ctx = finding.get("usage_context", "asymmetric_key")
    library = finding.get("library", "OpenSSL")
    confidence = float(finding.get("confidence_score", 0.85))

    # Synthetic host: bin.<clean_name>.internal
    clean_bin = binary_name.replace("/", "-").replace("\\", "-").replace(" ", "-")[:40]
    host = f"bin.{clean_bin}.internal"
    port_hash = int(hashlib.md5(f"{binary_name}:{rule_id}".encode()).hexdigest(), 16) % 10000
    port = 60000 + port_hash

    linked_service_id = None
    if service_name:
        svc = db.query(Service).filter(Service.name == service_name).first()
        if svc:
            linked_service_id = svc.id

    pqc_rec = recommend_pqc(algorithm, usage_ctx)

    severity = finding.get("severity", "MEDIUM")
    risk_flags = [f"BIN_{rule_id}", f"SEVERITY_{severity}"]
    if finding.get("is_quantum_vulnerable"):
        risk_flags.append("QUANTUM_VULNERABLE_ALGO")
    if finding.get("severity") == "INFORMATIONAL" and "PQC" in rule_id:
        risk_flags.append("PQC_READY_CAPABILITY")

    asset_record = {
        "status": "success",
        "cert_key_type": algorithm,
        "cert_key_size_bits": 2048 if "RSA" in algorithm.upper() else 256 if "EC" in algorithm.upper() else None,
        "tls_version": None,
        "days_to_expiry": None,
        "business_criticality": business_criticality,
        "data_lifetime": data_lifetime,
    }

    svc_obj = db.get(Service, linked_service_id) if linked_service_id else None
    svc_criticality = svc_obj.criticality if svc_obj else "P1"
    mwqrs = calculate_mwqrs(asset_record, service_criticality=svc_criticality)

    matched_symbols = finding.get("matched_symbols", [])
    symbols_summary = ", ".join(matched_symbols[:5]) if matched_symbols else rule_id

    existing = db.query(CryptoAsset).filter(
        CryptoAsset.host == host, CryptoAsset.port == port
    ).first()

    if not existing:
        asset = CryptoAsset(
            host=host,
            port=port,
            status="success",
            source="binary",
            business_criticality=business_criticality,
            data_lifetime=data_lifetime,
            cert_key_type=algorithm,
            cert_key_size_bits=asset_record["cert_key_size_bits"],
            cert_subject=f"Binary: {binary_name} ({finding.get('file_format', 'Executable')})",
            cert_issuer=f"Library: {library} | Symbols: {symbols_summary}",
            algorithm=algorithm,
            usage_context=usage_ctx,
            confidence_score=confidence,
            library=library,
            file_path=binary_name,
            line_number=None,
            risk_flags=json.dumps(risk_flags),
            risk_score=mwqrs,
            pqc_recommendation=json.dumps(pqc_rec),
            linked_service_id=linked_service_id,
        )
        db.add(asset)
    else:
        existing.source = "binary"
        existing.business_criticality = business_criticality
        existing.data_lifetime = data_lifetime
        existing.risk_score = mwqrs
        existing.pqc_recommendation = json.dumps(pqc_rec)
        existing.library = library
        existing.confidence_score = confidence

    db.commit()
    return {
        "status": "imported",
        "host": host,
        "port": port,
        "risk_score": mwqrs,
        "algorithm": algorithm,
        "library": library,
    }
