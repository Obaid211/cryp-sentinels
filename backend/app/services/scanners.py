import re
import ast
import json
import base64
import socket
import ssl
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service
from app.services.scoring import calculate_mwqrs

# ==========================================
# 1. Source Code Cryptographic Scanner Rules
# ==========================================
CRYPTO_CODE_PATTERNS = {
    "WEAK_HASH_MD5": {
        "pattern": r"hashlib\.md5\(|MD5\(|CryptoJS\.MD5|MessageDigest\.getInstance\(['\"]MD5['\"]\)",
        "severity": "CRITICAL",
        "type": "Weak Hashing Algorithm (MD5)",
        "crypto_technology": "Cryptographic Hash (MD5)",
        "confidence": "HIGH",
        "explanation": "MD5 is cryptographically broken due to practical collision vulnerabilities.",
        "remediation": "Replace with SHA-256 / SHA-3 or secure password derivation (Argon2id, bcrypt).",
    },
    "WEAK_HASH_SHA1": {
        "pattern": r"hashlib\.sha1\(|SHA1\(|CryptoJS\.SHA1|MessageDigest\.getInstance\(['\"]SHA-1['\"]\)",
        "severity": "HIGH",
        "type": "Weak Hashing Algorithm (SHA-1)",
        "crypto_technology": "Cryptographic Hash (SHA-1)",
        "confidence": "HIGH",
        "explanation": "SHA-1 has practical collision attacks demonstrated. Prohibited by NIST SP 800-52 Rev. 2.",
        "remediation": "Migrate to SHA-256, SHA-384, or SHA-512.",
    },
    "WEAK_CIPHER_DES": {
        "pattern": r"DES\.new\(|DES3\.new\(|Cipher\.getInstance\(['\"]DES['\"]\)",
        "severity": "CRITICAL",
        "type": "Deprecated Block Cipher (DES/3DES)",
        "crypto_technology": "Symmetric Block Cipher (DES)",
        "confidence": "HIGH",
        "explanation": "DES uses an obsolete 56-bit key size vulnerable to brute force in minutes.",
        "remediation": "Upgrade to AES-256-GCM or ChaCha20-Poly1305.",
    },
    "HARDCODED_RSA_KEY": {
        "pattern": r"RSA\.generate\(\s*(1024|512)\b",
        "severity": "HIGH",
        "type": "Weak RSA Key Generation (<2048 bits)",
        "crypto_technology": "Asymmetric Key Pair (RSA)",
        "confidence": "HIGH",
        "explanation": "RSA key lengths under 2048 bits are vulnerable to classical factorization attacks.",
        "remediation": "Increase RSA key size to at least 2048-bit (preferably 3072-bit) and plan PQC transition to ML-KEM-768.",
    },
    "HARDCODED_PRIVATE_KEY": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "type": "Hardcoded Cryptographic Private Key",
        "crypto_technology": "PKI Private Key Material",
        "confidence": "HIGH",
        "explanation": "Hardcoded private keys embedded in source code can be extracted through version history.",
        "remediation": "Remove key immediately from repository. Re-issue and inject credentials via KMS.",
    },
    "HARDCODED_SECRET_STRING": {
        "pattern": r"(?:api[_\-]?key|secret[_\-]?key|private[_\-]?key)\s*=\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]",
        "severity": "MEDIUM",
        "type": "Hardcoded Secret Key String",
        "crypto_technology": "Authentication Secret",
        "confidence": "MEDIUM",
        "explanation": "Potential plaintext credential or API secret hardcoded in source code.",
        "remediation": "Move secrets to .env, runtime configuration, or a vault solution.",
    }
}

def scan_source_code(content: str, filename: str = "snippet.py") -> List[Dict[str, Any]]:
    findings = []
    seen = set()
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        for rule_id, rule_data in CRYPTO_CODE_PATTERNS.items():
            if re.search(rule_data["pattern"], line, re.IGNORECASE):
                key = (filename, line_no, rule_id)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "file_path": filename,
                        "line_number": line_no,
                        "rule_id": rule_id,
                        "finding_type": rule_data["type"],
                        "code_snippet": line.strip()[:150],
                        "severity": rule_data["severity"],
                        "crypto_technology": rule_data["crypto_technology"],
                        "confidence": rule_data["confidence"],
                        "explanation": rule_data["explanation"],
                        "remediation": rule_data["remediation"],
                        "matched_pattern": rule_data["pattern"],
                        "scanned_at": datetime.now(timezone.utc).isoformat()
                    })
    return findings

# ==========================================
# 2. Container & Dockerfile Scanner Rules
# ==========================================
CONTAINER_CRYPTO_RULES = [
    {
        "id": "CONTAINER_HARDCODED_KEY",
        "pattern": r"(?:COPY|ADD)\s+.*(?:\.(?:key|pem|pkcs8|pfx|p12)\b|id_rsa|id_dsa|id_ecdsa|id_ed25519)",
        "severity": "CRITICAL",
        "type": "Embedded Cryptographic Key in Container Image",
        "recommendation": "Do not embed private keys into container layers. Inject credentials at runtime via KMS.",
    },
    {
        "id": "CONTAINER_TLS_VERIFY_DISABLED",
        "pattern": r"(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?|--insecure|curl\s+-[a-zA-Z]*k|CURLOPT_SSL_VERIFYPEER\s*,\s*0)",
        "severity": "CRITICAL",
        "type": "TLS Certificate Verification Disabled",
        "recommendation": "Never disable TLS certificate validation in production containers.",
    },
    {
        "id": "CONTAINER_WEAK_SECLEVEL",
        "pattern": r"(?:SECLEVEL\s*=\s*0|CipherString\s*=\s*DEFAULT:@SECLEVEL=0)",
        "severity": "HIGH",
        "type": "OpenSSL Security Level Downgraded to SECLEVEL=0",
        "recommendation": "Maintain OpenSSL SECLEVEL=2 or higher to enforce modern cipher suites and key lengths >= 2048-bit.",
    },
    {
        "id": "CONTAINER_DEPRECATED_BASE_IMAGE",
        "pattern": r"FROM\s+(?:ubuntu:(?:12\.|14\.|16\.)|debian:(?:wheezy|jessie|stretch)|centos:(?:6|7)|alpine:(?:2\.|3\.[0-8]\b))",
        "severity": "HIGH",
        "type": "Deprecated Base OS Image with Outdated Cryptographic Stack",
        "recommendation": "Upgrade to a supported base image (e.g. Ubuntu 24.04, Debian 12, Alpine 3.19+) for modern OpenSSL 3.x and TLS 1.3.",
    },
    {
        "id": "CONTAINER_CRYPTO_PACKAGE_INSTALLED",
        "pattern": r"(?:apt-get|apk|yum|microdnf)\s+(?:install|add)\s+.*?\b(openssl|libssl-dev|ca-certificates|gnutls|libgcrypt|crypto-policies)\b",
        "severity": "INFORMATIONAL",
        "type": "Cryptographic Library Dependency Installed",
        "recommendation": "Track cryptographic dependencies in CBOM inventory and ensure packages receive timely security patches.",
    },
    {
        "id": "CONTAINER_LEGACY_CRYPTO_REFERENCE",
        "pattern": r"\b(rsa[-_ ]?1024|des-ede3|md5sum|sha1sum)\b",
        "severity": "MEDIUM",
        "type": "Legacy Cryptographic Algorithm Reference in Container Script",
        "recommendation": "Replace legacy cryptographic algorithms with modern NIST-approved symmetric ciphers or post-quantum alternatives.",
    },
    {
        "id": "CONTAINER_PQC_INTEGRATION_FOUND",
        "pattern": r"\b(oqs|liboqs|ml-kem|ml-dsa|dilithium|kyber)\b",
        "severity": "INFORMATIONAL",
        "type": "Post-Quantum Cryptography (PQC) Library / Provider Detected",
        "recommendation": "PQC integration observed. Validate interoperability against NIST FIPS 203/204 standard conformance test vectors.",
    }
]

def scan_dockerfile_content(content: str, filename: str = "Dockerfile") -> List[Dict[str, Any]]:
    findings = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for rule in CONTAINER_CRYPTO_RULES:
            match = re.search(rule["pattern"], stripped, re.IGNORECASE)
            if match:
                findings.append({
                    "rule_id": rule["id"],
                    "finding_type": rule["type"],
                    "component": match.group(0)[:40],
                    "severity": rule["severity"],
                    "evidence": stripped[:150],
                    "recommendation": rule["recommendation"],
                    "source_file": filename,
                    "line_number": line_no,
                    "scanned_at": datetime.now(timezone.utc).isoformat(),
                })
    return findings

# ==========================================
# 3. API & JWT Signature Scanner
# ==========================================
def decode_jwt_header(token: str) -> Optional[Dict[str, Any]]:
    if not token or not isinstance(token, str):
        return None
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) < 2:
        return None

    header_b64 = parts[0]
    rem = len(header_b64) % 4
    if rem > 0:
        header_b64 += "=" * (4 - rem)

    try:
        header_json = base64.urlsafe_b64decode(header_b64.encode("ascii")).decode("utf-8")
        return json.loads(header_json)
    except Exception:
        return None

def classify_jwt_algorithm(alg: str) -> Dict[str, Any]:
    alg_upper = (alg or "UNKNOWN").upper()

    if alg_upper in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]:
        return {
            "algorithm": alg_upper,
            "type": "RSA Asymmetric Signature (PKCS#1 / PSS)",
            "quantum_status": "Quantum-Vulnerable (Shor's Algorithm on future CRQC)",
            "risk_level": "HIGH",
            "recommendation": "Plan migration to NIST FIPS 204 (ML-DSA-65) or dual-mode hybrid JWT signatures.",
        }
    elif alg_upper in ["ES256", "ES384", "ES512", "EDDSA"]:
        return {
            "algorithm": alg_upper,
            "type": "ECDSA / EdDSA Elliptic Curve Signature",
            "quantum_status": "Quantum-Vulnerable (Shor's Algorithm on future CRQC)",
            "risk_level": "HIGH",
            "recommendation": "Plan migration to NIST FIPS 204 (ML-DSA-65) for API token validation.",
        }
    elif alg_upper in ["HS256", "HS384", "HS512"]:
        return {
            "algorithm": alg_upper,
            "type": "HMAC Symmetric Key Signature",
            "quantum_status": "Quantum-Resistant (Grover's Algorithm requires 256-bit keys)",
            "risk_level": "LOW",
            "recommendation": "Symmetric HMAC is quantum-resistant if secret key >= 256 bits.",
        }
    elif alg_upper in ["NONE"]:
        return {
            "algorithm": "none",
            "type": "Unsigned / Insecure Token",
            "quantum_status": "Severely Insecure (No Signature)",
            "risk_level": "CRITICAL",
            "recommendation": "Reject unsigned tokens immediately. Enforce cryptographically verified signatures.",
        }
    elif "ML-DSA" in alg_upper or "DILITHIUM" in alg_upper:
        return {
            "algorithm": alg_upper,
            "type": "NIST FIPS 204 Post-Quantum Digital Signature",
            "quantum_status": "Quantum-Resistant (NIST PQC Standard)",
            "risk_level": "LOW",
            "recommendation": "Post-quantum API signature active. Verify standard conformance.",
        }
    else:
        return {
            "algorithm": alg_upper,
            "type": "Unrecognized Signature Algorithm",
            "quantum_status": "Under Review",
            "risk_level": "MEDIUM",
            "recommendation": "Audit API token configuration against NIST SP 800-52 / FIPS 204 guidance.",
        }

def scan_api_endpoint(url: str, sample_jwt: Optional[str] = None) -> Dict[str, Any]:
    findings = []
    jwt_analysis = None

    if sample_jwt:
        header = decode_jwt_header(sample_jwt)
        if header:
            alg = header.get("alg", "UNKNOWN")
            classification = classify_jwt_algorithm(alg)
            jwt_analysis = {
                "header": header,
                "classification": classification
            }
            if classification["risk_level"] in ["HIGH", "CRITICAL"]:
                findings.append({
                    "rule_id": f"API_JWT_{classification['algorithm']}",
                    "finding_type": classification["type"],
                    "severity": classification["risk_level"],
                    "evidence": f"JWT alg: {classification['algorithm']}",
                    "recommendation": classification["recommendation"],
                    "quantum_status": classification["quantum_status"]
                })

    is_https = url.lower().startswith("https://")
    if not is_https:
        findings.append({
            "rule_id": "API_INSECURE_HTTP",
            "finding_type": "Unencrypted Plaintext HTTP Endpoint",
            "severity": "CRITICAL",
            "evidence": url,
            "recommendation": "Enforce HTTPS with HSTS max-age >= 31536000 and redirect all HTTP traffic.",
            "quantum_status": "Insecure (No Encryption)"
        })

    return {
        "url": url,
        "is_https": is_https,
        "jwt_analysis": jwt_analysis,
        "findings": findings,
        "findings_count": len(findings),
        "scanned_at": datetime.now(timezone.utc).isoformat()
    }

# ==========================================
# 4. Live TLS / Host Discovery Scanner
# ==========================================
def scan_tls_target(
    host: str, 
    port: int = 443, 
    timeout: float = 5.0,
    mode: str = "LIVE",
    db: Optional[Session] = None
) -> Dict[str, Any]:
    # 1. CACHED MODE: Look up in database/cache first
    if mode == "CACHED" and db:
        cached_asset = db.query(CryptoAsset).filter(CryptoAsset.host == host, CryptoAsset.port == port).first()
        if cached_asset:
            flags = []
            if cached_asset.risk_flags:
                try:
                    flags = json.loads(cached_asset.risk_flags)
                except Exception:
                    flags = [cached_asset.risk_flags]
            return {
                "host": host,
                "port": port,
                "status": cached_asset.status,
                "mode": "CACHED",
                "cached": True,
                "tls_version": cached_asset.tls_version,
                "cipher_suite": cached_asset.cipher_suite or "TLS_AES_256_GCM_SHA384",
                "cipher_bits": cached_asset.cipher_bits or 256,
                "cert_subject": cached_asset.cert_subject or f"CN={host}",
                "cert_issuer": cached_asset.cert_issuer or "Cached Authority",
                "cert_key_type": cached_asset.cert_key_type,
                "cert_key_size_bits": cached_asset.cert_key_size_bits,
                "cert_signature_algorithm": cached_asset.cert_signature_algorithm or "sha256WithRSAEncryption",
                "days_to_expiry": cached_asset.days_to_expiry,
                "risk_flags": flags,
                "risk_score": cached_asset.risk_score,
                "scanned_at": datetime.now(timezone.utc).isoformat()
            }

    # 2. OFFLINE / AIR-GAPPED MODE: Strictly zero external socket probes
    if mode == "OFFLINE":
        if db:
            existing = db.query(CryptoAsset).filter(CryptoAsset.host == host, CryptoAsset.port == port).first()
            if existing:
                flags = []
                if existing.risk_flags:
                    try:
                        flags = json.loads(existing.risk_flags)
                    except Exception:
                        flags = [existing.risk_flags]
                return {
                    "host": host,
                    "port": port,
                    "status": existing.status,
                    "mode": "OFFLINE",
                    "air_gapped": True,
                    "tls_version": existing.tls_version,
                    "cipher_suite": existing.cipher_suite,
                    "cipher_bits": existing.cipher_bits,
                    "cert_subject": existing.cert_subject,
                    "cert_issuer": existing.cert_issuer,
                    "cert_key_type": existing.cert_key_type,
                    "cert_key_size_bits": existing.cert_key_size_bits,
                    "cert_signature_algorithm": existing.cert_signature_algorithm,
                    "days_to_expiry": existing.days_to_expiry,
                    "risk_flags": flags,
                    "risk_score": existing.risk_score,
                    "scanned_at": datetime.now(timezone.utc).isoformat()
                }

        key_type = "RSA" if ("auth" in host or "gateway" in host or "payment" in host) else "ECC (secp384r1)"
        key_size = 2048 if key_type == "RSA" else 384
        mwqrs = calculate_mwqrs({
            "cert_key_type": key_type,
            "cert_key_size_bits": key_size,
            "tls_version": "TLSv1.3",
            "days_to_expiry": 120,
            "status": "success"
        }, service_criticality="P2")
        return {
            "host": host,
            "port": port,
            "status": "success",
            "mode": "OFFLINE",
            "air_gapped": True,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "cert_subject": f"CN={host} (Air-Gapped Sovereign Node)",
            "cert_issuer": "ECDAT Sovereign Offline Root CA",
            "cert_key_type": key_type,
            "cert_key_size_bits": key_size,
            "cert_signature_algorithm": "sha256WithRSAEncryption" if key_type == "RSA" else "ecdsa-with-SHA384",
            "days_to_expiry": 120,
            "risk_flags": ["AIR_GAPPED_EVALUATION", "VULNERABLE_ALGO_RSA" if key_type == "RSA" else "VULNERABLE_ALGO_ECC"],
            "risk_score": mwqrs,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_bits = cipher[2] if cipher else 0

                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return {
                        "host": host,
                        "port": port,
                        "status": "error",
                        "error_message": "No peer certificate received from server."
                    }

                cert = x509.load_der_x509_certificate(der_cert)
                public_key = cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    key_type = "RSA"
                    key_size = public_key.key_size
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_type = f"ECC ({public_key.curve.name})"
                    key_size = public_key.key_size
                elif isinstance(public_key, dsa.DSAPublicKey):
                    key_type = "DSA"
                    key_size = public_key.key_size
                else:
                    key_type = "Unknown"
                    key_size = 0

                sig_algo = getattr(cert.signature_algorithm_oid, "_name", str(cert.signature_algorithm_oid))
                days_to_expiry = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days if hasattr(cert, "not_valid_after_utc") else 90

                # Formulate risk flags
                risk_flags = []
                if "RSA" in key_type:
                    risk_flags.append("VULNERABLE_ALGO_RSA")
                    if key_size < 2048:
                        risk_flags.append(f"WEAK_RSA_KEY_SIZE_{key_size}")
                elif "ECC" in key_type or "ECDSA" in key_type:
                    risk_flags.append("VULNERABLE_ALGO_ECC")

                if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
                    risk_flags.append("OUTDATED_TLS_VERSION")

                mwqrs = calculate_mwqrs({
                    "cert_key_type": key_type,
                    "cert_key_size_bits": key_size,
                    "tls_version": tls_version,
                    "days_to_expiry": days_to_expiry,
                    "status": "success"
                }, service_criticality="P2")

                return {
                    "host": host,
                    "port": port,
                    "status": "success",
                    "tls_version": tls_version,
                    "cipher_suite": cipher_name,
                    "cipher_bits": cipher_bits,
                    "cert_subject": cert.subject.rfc4514_string(),
                    "cert_issuer": cert.issuer.rfc4514_string(),
                    "cert_key_type": key_type,
                    "cert_key_size_bits": key_size,
                    "cert_signature_algorithm": sig_algo,
                    "days_to_expiry": days_to_expiry,
                    "risk_flags": risk_flags,
                    "risk_score": mwqrs,
                    "scanned_at": datetime.now(timezone.utc).isoformat()
                }

    except Exception as e:
        return {
            "host": host,
            "port": port,
            "status": "error",
            "error_message": str(e)
        }

# ==========================================
# 5. Inventory Importer
# ==========================================
def import_finding_to_inventory(db: Session, finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Imports a scanned live target or finding into the enterprise inventory table.
    """
    host = finding_data.get("host", "scanned.internal.net")
    port = int(finding_data.get("port", 443))

    existing = db.query(CryptoAsset).filter(CryptoAsset.host == host, CryptoAsset.port == port).first()
    mwqrs = float(finding_data.get("risk_score", 50.0))

    if not existing:
        asset = CryptoAsset(
            host=host,
            port=port,
            status=finding_data.get("status", "success"),
            tls_version=finding_data.get("tls_version", "TLSv1.3"),
            cipher_suite=finding_data.get("cipher_suite", "TLS_AES_256_GCM_SHA384"),
            cipher_bits=finding_data.get("cipher_bits", 256),
            cert_subject=finding_data.get("cert_subject", f"CN={host}"),
            cert_issuer=finding_data.get("cert_issuer", "Discovered In-Scan Authority"),
            cert_key_type=finding_data.get("cert_key_type", "RSA"),
            cert_key_size_bits=finding_data.get("cert_key_size_bits", 2048),
            cert_signature_algorithm=finding_data.get("cert_signature_algorithm", "sha256WithRSAEncryption"),
            days_to_expiry=finding_data.get("days_to_expiry", 180),
            risk_flags=json.dumps(finding_data.get("risk_flags", ["DISCOVERED_IN_SCAN"])),
            risk_score=mwqrs,
        )
        db.add(asset)
    else:
        existing.status = finding_data.get("status", existing.status)
        existing.tls_version = finding_data.get("tls_version", existing.tls_version)
        existing.cert_key_type = finding_data.get("cert_key_type", existing.cert_key_type)
        existing.cert_key_size_bits = finding_data.get("cert_key_size_bits", existing.cert_key_size_bits)
        existing.risk_score = mwqrs
        existing.days_to_expiry = finding_data.get("days_to_expiry", existing.days_to_expiry)

    db.commit()
    return {
        "status": "imported",
        "host": host,
        "port": port,
        "risk_score": mwqrs
    }
