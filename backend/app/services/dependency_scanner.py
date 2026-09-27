"""
dependency_scanner.py — ECDAT Phase 1
=====================================
Parses requirements.txt, package.json/package-lock.json, pom.xml,
build.gradle, go.mod, Cargo.toml for crypto-related dependencies.

Per dependency output:
  - name, version, known_crypto_capability, inferred_risk, upgrade_note
  - flags quantum-vulnerable defaults even without direct crypto calls

Writes into unified inventory with source="dependency".
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

# -----------------------------------------------------------------
# Known crypto library capability table
# -----------------------------------------------------------------
CRYPTO_LIBRARY_DB: Dict[str, Dict[str, Any]] = {
    # Python
    "cryptography": {
        "capability": "RSA, ECC, AES, ChaCha20, X25519, Ed25519, PKCS#1/8/12, X.509, TLS",
        "default_algorithms": ["RSA-2048", "ECC-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "Use cryptography ≥41.x for X25519 / Ed25519. Plan migration to ML-KEM/ML-DSA via liboqs-python.",
        "pqc_ready": False,
    },
    "pycryptodome": {
        "capability": "AES, RSA, ECC, SHA, MD5, DES, 3DES",
        "default_algorithms": ["RSA-2048", "AES-128-CBC"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "PyCryptodome supports legacy ciphers. Ensure AES-256-GCM usage; avoid DES/3DES. No PQC support.",
        "pqc_ready": False,
    },
    "pycryptodomex": {
        "capability": "AES, RSA, ECC, SHA, MD5, DES, 3DES",
        "default_algorithms": ["RSA-2048", "AES-128-CBC"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "Same as PyCryptodome. Audit cipher modes and key sizes.",
        "pqc_ready": False,
    },
    "pyopenssl": {
        "capability": "OpenSSL bindings — TLS, X.509, RSA, ECC",
        "default_algorithms": ["RSA-2048", "ECC-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "pyOpenSSL delegates to system OpenSSL. Upgrade OpenSSL ≥3.x; plan OQS-provider for PQC.",
        "pqc_ready": False,
    },
    "liboqs-python": {
        "capability": "ML-KEM, ML-DSA, SLH-DSA, Falcon, NTRU (NIST PQC)",
        "default_algorithms": ["ML-KEM-768", "ML-DSA-65"],
        "quantum_vulnerable_defaults": False,
        "inferred_risk": "low",
        "upgrade_note": "Already PQC. Validate against final NIST FIPS 203/204/205 test vectors.",
        "pqc_ready": True,
    },
    "paramiko": {
        "capability": "SSH — RSA, ECDSA, Ed25519, AES, ChaCha20",
        "default_algorithms": ["RSA-2048", "ECDSA-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "Paramiko SSH keys (RSA/ECDSA) are quantum-vulnerable. Prefer Ed25519 now; plan PQC SSH.",
        "pqc_ready": False,
    },
    "bcrypt": {
        "capability": "bcrypt password hashing",
        "default_algorithms": ["bcrypt"],
        "quantum_vulnerable_defaults": False,
        "inferred_risk": "low",
        "upgrade_note": "bcrypt is quantum-resistant for password hashing. Ensure work-factor ≥12.",
        "pqc_ready": True,
    },
    "argon2-cffi": {
        "capability": "Argon2 password hashing (NIST recommended)",
        "default_algorithms": ["Argon2id"],
        "quantum_vulnerable_defaults": False,
        "inferred_risk": "low",
        "upgrade_note": "Argon2id is recommended by NIST for password hashing. Already quantum-safe.",
        "pqc_ready": True,
    },
    "jwt": {
        "capability": "JWT — HS256/RS256/ES256 signing",
        "default_algorithms": ["HS256", "RS256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "medium",
        "upgrade_note": "Default RS256/ES256 JWTs are quantum-vulnerable. Plan ML-DSA-based JWT signing.",
        "pqc_ready": False,
    },
    "python-jose": {
        "capability": "JOSE / JWT — RSA, ECDSA, HMAC",
        "default_algorithms": ["RS256", "ES256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "python-jose uses quantum-vulnerable RSA/ECDSA by default. Migrate to ML-DSA-65 JWT.",
        "pqc_ready": False,
    },
    # JavaScript / Node
    "node-forge": {
        "capability": "RSA, AES, TLS, X.509, SHA",
        "default_algorithms": ["RSA-2048", "AES-128"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "node-forge is based on classical RSA. No PQC roadmap. Consider migrating to @noble/curves + liboqs.",
        "pqc_ready": False,
    },
    "jsonwebtoken": {
        "capability": "JWT — HS256/RS256/ES256",
        "default_algorithms": ["RS256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "medium",
        "upgrade_note": "jsonwebtoken RS256/ES256 are quantum-vulnerable. Plan transition to ML-DSA-based JWT.",
        "pqc_ready": False,
    },
    "crypto-js": {
        "capability": "AES, DES, 3DES, MD5, SHA-1, SHA-256, RC4",
        "default_algorithms": ["AES-256-CBC", "MD5"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "crypto-js includes legacy MD5, SHA-1, DES. Audit usage; replace weak ciphers with AES-256-GCM.",
        "pqc_ready": False,
    },
    # Java
    "bouncycastle": {
        "capability": "RSA, ECC, AES, SHA, TLS, X.509, PQC (provider ≥1.72)",
        "default_algorithms": ["RSA-2048", "ECC-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "medium",
        "upgrade_note": "Upgrade to Bouncy Castle ≥1.76 for NIST PQC (ML-KEM, ML-DSA, SLH-DSA). Enable PQC provider.",
        "pqc_ready": False,  # Upgrade required
    },
    "bouncy-castle": {
        "capability": "RSA, ECC, AES, SHA, TLS, X.509",
        "default_algorithms": ["RSA-2048", "ECC-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "medium",
        "upgrade_note": "Upgrade to Bouncy Castle ≥1.76 for NIST PQC (ML-KEM, ML-DSA, SLH-DSA). Enable PQC provider.",
        "pqc_ready": False,
    },
    # C / C++ / Go / Rust (detected via package lock or import)
    "openssl": {
        "capability": "RSA, ECC, AES, SHA, TLS — OpenSSL C library",
        "default_algorithms": ["RSA-2048", "ECDHE-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "OpenSSL ≥3.x supports OQS-provider for PQC. Upgrade and enable hybrid TLS groups.",
        "pqc_ready": False,
    },
    "libsodium": {
        "capability": "Ed25519, X25519, ChaCha20-Poly1305, Argon2, AES-256-GCM",
        "default_algorithms": ["Ed25519", "X25519", "ChaCha20-Poly1305"],
        "quantum_vulnerable_defaults": True,  # X25519/Ed25519 are ECC-based
        "inferred_risk": "medium",
        "upgrade_note": "libsodium X25519/Ed25519 keys are quantum-vulnerable (Shor). Plan migration to ML-KEM/ML-DSA hybrid.",
        "pqc_ready": False,
    },
    "ring": {
        "capability": "Rust — Ed25519, ECDSA, AES-GCM, ChaCha20-Poly1305",
        "default_algorithms": ["Ed25519", "ECDSA-P-256"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "ring crate uses classical ECC. No PQC support; plan migration to pqcrypto or oqs-rust.",
        "pqc_ready": False,
    },
    "rustls": {
        "capability": "Rust TLS — ECDHE, AES-GCM, ChaCha20",
        "default_algorithms": ["ECDHE-P-256", "AES-256-GCM"],
        "quantum_vulnerable_defaults": True,
        "inferred_risk": "high",
        "upgrade_note": "rustls supports hybrid PQC TLS via aws-lc-rs or ring-with-kyber. Enable hybrid groups.",
        "pqc_ready": False,
    },
}

# -----------------------------------------------------------------
# Parsing helpers per manifest type
# -----------------------------------------------------------------

def _parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Parse Python requirements.txt → list of {name, version}."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # e.g. cryptography==41.0.3  or cryptography>=41
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~^]{0,2}\s*[0-9.*]+)?", line)
        if m:
            deps.append({"name": m.group(1).lower().replace("_", "-"), "version": (m.group(2) or "").strip()})
    return deps


def _parse_package_json(content: str) -> List[Dict[str, str]]:
    """Parse package.json → list of {name, version}."""
    deps = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append({"name": name.lower(), "version": version})
    except json.JSONDecodeError:
        pass
    return deps


def _parse_go_mod(content: str) -> List[Dict[str, str]]:
    """Parse go.mod → list of {name, version}."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r"^([a-zA-Z0-9.\-/_]+)\s+(v[0-9.]+)", line)
        if m:
            # Use last path segment as the "short name"
            name = m.group(1).split("/")[-1].lower()
            deps.append({"name": name, "version": m.group(2)})
    return deps


def _parse_cargo_toml(content: str) -> List[Dict[str, str]]:
    """Parse Cargo.toml → list of {name, version}."""
    deps = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[dependencies") or line.startswith("[dev-dependencies"):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
        if in_deps:
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\']?([0-9.*^~><=]+)["\']?', line)
            if m:
                deps.append({"name": m.group(1).lower(), "version": m.group(2)})
    return deps


def _parse_pom_xml(content: str) -> List[Dict[str, str]]:
    """Parse pom.xml → list of {name, version} for known crypto groupIds."""
    deps = []
    # Very lightweight — look for groupId/artifactId/version triplets
    blocks = re.findall(
        r"<dependency>.*?</dependency>",
        content,
        re.DOTALL | re.IGNORECASE
    )
    for block in blocks:
        artifact_m = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        version_m = re.search(r"<version>([^<]+)</version>", block)
        if artifact_m:
            name = artifact_m.group(1).strip().lower()
            version = version_m.group(1).strip() if version_m else ""
            deps.append({"name": name, "version": version})
    return deps


def _parse_build_gradle(content: str) -> List[Dict[str, str]]:
    """Parse build.gradle → {name, version}."""
    deps = []
    # e.g. implementation 'org.bouncycastle:bcprov-jdk18on:1.76'
    for m in re.finditer(
        r"""['"]([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+):([0-9.]+)['"]""",
        content
    ):
        deps.append({"name": m.group(2).lower(), "version": m.group(3)})
    return deps


def _detect_manifest_type(filename: str, content: str) -> str:
    fname = filename.lower()
    if "requirements" in fname and fname.endswith(".txt"):
        return "requirements_txt"
    if fname == "package.json" or (fname.endswith(".json") and '"dependencies"' in content):
        return "package_json"
    if fname == "go.mod":
        return "go_mod"
    if fname == "cargo.toml":
        return "cargo_toml"
    if fname == "pom.xml" or (fname.endswith(".xml") and "<dependency>" in content.lower()):
        return "pom_xml"
    if "build.gradle" in fname:
        return "build_gradle"
    return "unknown"


# -----------------------------------------------------------------
# Main scanner function
# -----------------------------------------------------------------

def scan_dependency_manifest(content: str, filename: str = "requirements.txt") -> List[Dict[str, Any]]:
    """
    Scan a dependency manifest file for crypto-related libraries.
    Returns a list of findings with risk assessment.
    """
    manifest_type = _detect_manifest_type(filename, content)

    parsers = {
        "requirements_txt": _parse_requirements_txt,
        "package_json": _parse_package_json,
        "go_mod": _parse_go_mod,
        "cargo_toml": _parse_cargo_toml,
        "pom_xml": _parse_pom_xml,
        "build_gradle": _parse_build_gradle,
    }

    deps = parsers.get(manifest_type, lambda _: [])(content)

    findings = []
    for dep in deps:
        name = dep["name"]
        version = dep.get("version", "")

        # Normalise name for lookup
        normalized = name.lower().replace("_", "-").replace(".", "-")

        # Direct match
        lib_info = CRYPTO_LIBRARY_DB.get(normalized) or CRYPTO_LIBRARY_DB.get(name.lower())

        # Partial match fallback (e.g. "bcprov-jdk18on" → "bouncycastle")
        if not lib_info:
            for key, val in CRYPTO_LIBRARY_DB.items():
                if key in normalized or normalized in key:
                    lib_info = val
                    break

        if lib_info:
            default_algo = lib_info["default_algorithms"][0] if lib_info["default_algorithms"] else "Unknown"
            pqc_rec = recommend_pqc(default_algo)
            findings.append({
                "name": name,
                "version": version,
                "capability": lib_info["capability"],
                "default_algorithms": lib_info["default_algorithms"],
                "quantum_vulnerable_defaults": lib_info["quantum_vulnerable_defaults"],
                "inferred_risk": lib_info["inferred_risk"],
                "upgrade_note": lib_info["upgrade_note"],
                "pqc_ready": lib_info["pqc_ready"],
                "pqc_recommendation": pqc_rec["recommendation"],
                "hybrid_alternative": pqc_rec["hybrid_alternative"],
                "source": "dependency",
                "source_file": filename,
                "manifest_type": manifest_type,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "confidence": "HIGH",
                "severity": "HIGH" if lib_info["inferred_risk"] == "high" else (
                    "MEDIUM" if lib_info["inferred_risk"] == "medium" else "LOW"
                ),
            })

    return findings


# -----------------------------------------------------------------
# Inventory importer for dependency findings
# -----------------------------------------------------------------

def import_dependency_to_inventory(
    db: Session,
    finding: Dict[str, Any],
    service_name: Optional[str] = None,
    business_criticality: str = "medium",
    data_lifetime: str = "1-3y",
) -> Dict[str, Any]:
    """
    Write a dependency finding into the unified CryptoAsset inventory
    with source="dependency". Uses a synthetic host/port derived from
    the library name to satisfy the unique constraint.
    """
    from app.services.pqc_engine import recommend_pqc

    lib_name = finding.get("name", "unknown-lib")
    # Synthetic host: dep.<library-name>.internal, port based on hash
    host = f"dep.{lib_name.replace('/', '-')}.internal"
    port = 50000 + (int(hashlib.md5(lib_name.encode()).hexdigest(), 16) % 10000)

    linked_service_id = None
    if service_name:
        svc = db.query(Service).filter(Service.name == service_name).first()
        if svc:
            linked_service_id = svc.id

    algo = finding.get("default_algorithms", ["RSA-2048"])[0] if finding.get("default_algorithms") else "RSA-2048"
    pqc_rec = recommend_pqc(algo)

    risk_flags = []
    if finding.get("quantum_vulnerable_defaults"):
        risk_flags.append("QUANTUM_VULNERABLE_DEFAULT_ALGO")
    if not finding.get("pqc_ready"):
        risk_flags.append("NO_PQC_SUPPORT")

    asset_record = {
        "status": "success",
        "cert_key_type": algo,
        "cert_key_size_bits": None,
        "tls_version": None,
        "days_to_expiry": None,
        "business_criticality": business_criticality,
        "data_lifetime": data_lifetime,
    }

    from app.services.scoring import calculate_mwqrs
    svc_obj = db.get(Service, linked_service_id) if linked_service_id else None
    svc_criticality = svc_obj.criticality if svc_obj else "P2"
    mwqrs = calculate_mwqrs(asset_record, service_criticality=svc_criticality)

    import json as _json
    existing = db.query(CryptoAsset).filter(
        CryptoAsset.host == host, CryptoAsset.port == port
    ).first()

    if not existing:
        asset = CryptoAsset(
            host=host,
            port=port,
            status="success",
            source="dependency",
            business_criticality=business_criticality,
            data_lifetime=data_lifetime,
            cert_key_type=algo,
            algorithm=algo,
            library=finding.get("name"),
            usage_context="library_default",
            confidence_score=0.85 if finding.get("quantum_vulnerable_defaults") else 0.7,
            risk_flags=_json.dumps(risk_flags),
            risk_score=mwqrs,
            pqc_recommendation=_json.dumps(pqc_rec),
            cert_subject=f"Library: {lib_name} v{finding.get('version', '')}",
            cert_issuer=finding.get("capability", "")[:255],
            linked_service_id=linked_service_id,
        )
        db.add(asset)
    else:
        existing.source = "dependency"
        existing.business_criticality = business_criticality
        existing.data_lifetime = data_lifetime
        existing.risk_score = mwqrs
        existing.library = finding.get("name")
        existing.pqc_recommendation = _json.dumps(pqc_rec)
        existing.risk_flags = _json.dumps(risk_flags)

    db.commit()
    return {"status": "imported", "host": host, "port": port, "risk_score": mwqrs}
