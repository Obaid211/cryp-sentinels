"""
PQC Recommendation Engine — ECDAT Phase 1
==========================================
Produces concrete per-asset PQC migration recommendations
based on algorithm type and usage context.

Rules:
  - Key exchange (ECDH, DH, RSA-OAEP) → ML-KEM-768
  - Digital signature (RSA-PSS/PKCS1, ECDSA, EdDSA, DSA) → ML-DSA-65
  - Symmetric encryption (AES, ChaCha20) → AES-256 (already safe, key-size note only)
  - Symmetric hash (MD5, SHA-1) → SHA-256 / SHA-3
  Always offer a hybrid option alongside pure-PQC.
"""

from typing import Dict, Any, List, Optional

# -----------------------------------------------------------------
# Algorithm → usage inference table
# -----------------------------------------------------------------
ALGORITHM_USAGE_MAP = {
    # Key exchange / encapsulation
    "RSA-OAEP": "key_exchange",
    "RSA": "key_exchange_or_signature",  # ambiguous by default; usage_context wins
    "ECDH": "key_exchange",
    "DH": "key_exchange",
    "X25519": "key_exchange",
    "X448": "key_exchange",
    # Signatures
    "RSA-PSS": "digital_signature",
    "RSASSA": "digital_signature",
    "ECDSA": "digital_signature",
    "EDDSA": "digital_signature",
    "ED25519": "digital_signature",
    "ED448": "digital_signature",
    "DSA": "digital_signature",
    # Symmetric encryption
    "AES": "symmetric_encryption",
    "CHACHA20": "symmetric_encryption",
    "SALSA20": "symmetric_encryption",
    "3DES": "symmetric_encryption",
    "DES": "symmetric_encryption",
    # Hash / MAC
    "MD5": "hash",
    "SHA1": "hash",
    "SHA-1": "hash",
    "SHA256": "hash",
    "SHA-256": "hash",
    "SHA384": "hash",
    "SHA-384": "hash",
    "SHA512": "hash",
    "SHA-512": "hash",
    "HMAC": "mac",
}

# -----------------------------------------------------------------
# Quantum vulnerability by algorithm family
# -----------------------------------------------------------------
QUANTUM_VULNERABLE = {"RSA", "ECDH", "ECDSA", "DH", "DSA", "EDDSA", "ED25519", "ED448", "X25519", "X448"}
WEAK_SYMMETRIC = {"MD5", "SHA1", "SHA-1", "DES", "3DES"}

# -----------------------------------------------------------------
# Core recommendation logic
# -----------------------------------------------------------------

def _infer_usage(algorithm: str, usage_context: Optional[str]) -> str:
    """Infer usage type from explicit context, then fallback to algorithm map."""
    if usage_context:
        ctx = usage_context.lower()
        if any(k in ctx for k in ["sign", "signature"]):
            return "digital_signature"
        if any(k in ctx for k in ["key_exchange", "exchange", "encap", "kem"]):
            return "key_exchange"
        if any(k in ctx for k in ["encrypt", "encrypt"]):
            return "symmetric_encryption"
        if "hash" in ctx:
            return "hash"

    algo_upper = algorithm.upper().split("-")[0].split("_")[0].strip()
    return ALGORITHM_USAGE_MAP.get(algo_upper, "unknown")


def _extract_algo_family(algorithm: str) -> str:
    """Return the short family name from algorithm string like 'RSA-2048' → 'RSA'."""
    return algorithm.upper().split("-")[0].split("_")[0].strip()


def recommend_pqc(
    current_algorithm: str,
    usage_context: Optional[str] = None,
    key_size: Optional[int] = None,
    library: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Core recommendation function.

    Returns:
    {
        "current_algorithm": str,
        "usage": str,
        "quantum_risk": "high" | "medium" | "low",
        "recommendation": str,         # pure-PQC target
        "hybrid_alternative": str,     # classical + PQC composite
        "standards": [str, ...],
        "reason": str,
        "migration_steps": [str, ...],
        "migration_complexity": "Low" | "Medium" | "High",
        "migration_cost": "Low" | "Medium" | "High",
        "latency_impact": "Minimal" | "Moderate" | "Significant",
    }
    """
    algo_family = _extract_algo_family(current_algorithm)
    usage = _infer_usage(current_algorithm, usage_context)

    # ----- Digital Signature branch -----
    if algo_family in {"ECDSA", "DSA", "EDDSA", "ED25519", "ED448"} or usage == "digital_signature":
        if algo_family in QUANTUM_VULNERABLE or algo_family in {"ECDSA", "DSA", "EDDSA", "ED25519", "ED448"}:
            return {
                "current_algorithm": current_algorithm,
                "usage": "digital_signature",
                "quantum_risk": "high",
                "recommendation": "ML-DSA-65 (NIST FIPS 204)",
                "hybrid_alternative": f"{current_algorithm} + ML-DSA-65",
                "standards": ["NIST FIPS 204"],
                "reason": "quantum_vulnerability: Shor's algorithm breaks ECDSA/DSA. ML-DSA-65 is the NIST-standardised lattice-based replacement.",
                "migration_steps": [
                    "Deploy ML-DSA-65 signing keys in parallel (hybrid mode).",
                    "Update all verifiers to accept both classical and ML-DSA-65 signatures.",
                    "Deprecate classical key after full fleet cut-over.",
                ],
                "migration_complexity": "Medium",
                "migration_cost": "Medium",
                "latency_impact": "Moderate",
            }

    # ----- RSA — ambiguous (key exchange OR signature) -----
    if algo_family == "RSA":
        resolved_usage = _infer_usage(current_algorithm, usage_context)
        if resolved_usage == "digital_signature" or (usage_context and "sign" in (usage_context or "").lower()):
            return {
                "current_algorithm": current_algorithm,
                "usage": "digital_signature",
                "quantum_risk": "high",
                "recommendation": "ML-DSA-65 (NIST FIPS 204)",
                "hybrid_alternative": f"RSA-3072 + ML-DSA-65",
                "standards": ["NIST FIPS 204"],
                "reason": "quantum_vulnerability + migration_compatibility: RSA signatures broken by Shor's algorithm.",
                "migration_steps": [
                    "Issue ML-DSA-65 keys from the existing CA hierarchy (or new PQC CA).",
                    "Deploy hybrid certs (RSA + ML-DSA-65) for backward compatibility.",
                    "Retire RSA signing after hybrid transition completes.",
                ],
                "migration_complexity": "Medium",
                "migration_cost": "Medium",
                "latency_impact": "Moderate",
            }
        else:
            # Default RSA → key exchange / encryption
            return {
                "current_algorithm": current_algorithm,
                "usage": "key_exchange",
                "quantum_risk": "high",
                "recommendation": "ML-KEM-768 (NIST FIPS 203)",
                "hybrid_alternative": f"RSA-3072 + ML-KEM-768",
                "standards": ["NIST FIPS 203"],
                "reason": "quantum_vulnerability + migration_compatibility: RSA key exchange broken by Shor's algorithm. ML-KEM-768 is the NIST-standardised KEM replacement.",
                "migration_steps": [
                    "Deploy ML-KEM-768 in hybrid mode alongside existing RSA key exchange.",
                    "Confirm TLS 1.3 with hybrid KEM groups (RFC 9370 draft extension).",
                    "Phase out RSA key transport after hybrid is universally supported.",
                ],
                "migration_complexity": "Medium",
                "migration_cost": "Medium",
                "latency_impact": "Moderate",
            }

    # ----- Key exchange branch (ECDH, DH, X25519 …) -----
    if algo_family in {"ECDH", "DH", "X25519", "X448"} or usage == "key_exchange":
        return {
            "current_algorithm": current_algorithm,
            "usage": "key_exchange",
            "quantum_risk": "high",
            "recommendation": "ML-KEM-768 (NIST FIPS 203)",
            "hybrid_alternative": f"{current_algorithm} + ML-KEM-768",
            "standards": ["NIST FIPS 203"],
            "reason": "quantum_vulnerability: Shor's algorithm breaks Diffie-Hellman/ECDH. ML-KEM-768 provides IND-CCA2-secure encapsulation.",
            "migration_steps": [
                "Enable hybrid ECDH + ML-KEM-768 TLS named-group in server config.",
                "Update client-side TLS stacks to advertise hybrid groups.",
                "Remove classical-only ECDH after hybrid coverage is confirmed.",
            ],
            "migration_complexity": "Low",
            "migration_cost": "Low",
            "latency_impact": "Minimal",
        }

    # ----- Symmetric encryption -----
    if algo_family in {"AES", "CHACHA20", "SALSA20"}:
        if key_size and key_size < 256:
            return {
                "current_algorithm": current_algorithm,
                "usage": "symmetric_encryption",
                "quantum_risk": "medium",
                "recommendation": "AES-256-GCM or ChaCha20-Poly1305",
                "hybrid_alternative": "AES-256-GCM (no hybrid needed for symmetric)",
                "standards": ["NIST SP 800-38D", "RFC 8439"],
                "reason": "grover_vulnerability: Grover's algorithm halves effective key length; sub-256-bit symmetric keys should be upgraded.",
                "migration_steps": [
                    "Re-key all symmetric encryption to AES-256-GCM or ChaCha20-Poly1305.",
                    "Ensure authenticated encryption (AEAD) mode is used throughout.",
                ],
                "migration_complexity": "Low",
                "migration_cost": "Low",
                "latency_impact": "Minimal",
            }
        return {
            "current_algorithm": current_algorithm,
            "usage": "symmetric_encryption",
            "quantum_risk": "low",
            "recommendation": "Retain AES-256-GCM / ChaCha20-Poly1305 (already quantum-safe at ≥256 bits)",
            "hybrid_alternative": "No hybrid needed",
            "standards": ["NIST SP 800-38D"],
            "reason": "already_quantum_safe: Grover's algorithm impact at 256-bit keys is negligible (2^128 security).",
            "migration_steps": ["Verify key length ≥ 256 bits and AEAD mode in all configurations."],
            "migration_complexity": "Low",
            "migration_cost": "Low",
            "latency_impact": "Minimal",
        }

    # ----- Weak symmetric (DES, 3DES) -----
    if algo_family in {"DES", "3DES"}:
        return {
            "current_algorithm": current_algorithm,
            "usage": "symmetric_encryption",
            "quantum_risk": "high",
            "recommendation": "AES-256-GCM",
            "hybrid_alternative": "AES-256-GCM (no hybrid needed)",
            "standards": ["NIST SP 800-38D"],
            "reason": "classical_vulnerability + quantum_vulnerability: DES/3DES broken classically. Replace immediately with AES-256.",
            "migration_steps": [
                "Immediately replace DES/3DES with AES-256-GCM.",
                "Audit all cipher configs and remove any DES fallback negotiation.",
            ],
            "migration_complexity": "Low",
            "migration_cost": "Low",
            "latency_impact": "Minimal",
        }

    # ----- Weak hashes (MD5, SHA-1) -----
    if algo_family in {"MD5", "SHA1", "SHA-1"}:
        return {
            "current_algorithm": current_algorithm,
            "usage": "hash",
            "quantum_risk": "high",
            "recommendation": "SHA-256 or SHA-3-256",
            "hybrid_alternative": "SHA-256 (no hybrid needed for hashes)",
            "standards": ["NIST FIPS 180-4", "NIST FIPS 202"],
            "reason": "classical_vulnerability: MD5/SHA-1 have practical collision attacks independent of quantum computers. Replace immediately.",
            "migration_steps": [
                "Replace MD5/SHA-1 with SHA-256 or SHA-3-256 in all code paths.",
                "Re-issue any certificates using SHA-1 signatures.",
            ],
            "migration_complexity": "Low",
            "migration_cost": "Low",
            "latency_impact": "Minimal",
        }

    # ----- Already PQC -----
    if any(pqc in current_algorithm.upper() for pqc in ["ML-KEM", "ML-DSA", "SLH-DSA", "DILITHIUM", "KYBER", "FALCON"]):
        return {
            "current_algorithm": current_algorithm,
            "usage": usage_context or "unknown",
            "quantum_risk": "low",
            "recommendation": f"Retain {current_algorithm} — already NIST PQC standard",
            "hybrid_alternative": "No migration required",
            "standards": ["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"],
            "reason": "already_pqc: Algorithm is a NIST-standardised post-quantum algorithm.",
            "migration_steps": ["Monitor NIST for updates; validate against FIPS test vectors."],
            "migration_complexity": "Low",
            "migration_cost": "Low",
            "latency_impact": "Minimal",
        }

    # ----- Fallback -----
    return {
        "current_algorithm": current_algorithm,
        "usage": usage or "unknown",
        "quantum_risk": "medium",
        "recommendation": "ML-KEM-768 or ML-DSA-65 (assess usage first)",
        "hybrid_alternative": f"{current_algorithm} + ML-KEM-768",
        "standards": ["NIST FIPS 203", "NIST FIPS 204"],
        "reason": "unrecognised_algorithm: Audit and confirm usage context before migration.",
        "migration_steps": [
            "Identify exact cryptographic usage (key exchange vs signature).",
            "Apply ML-KEM-768 for key exchange or ML-DSA-65 for signatures.",
        ],
        "migration_complexity": "Medium",
        "migration_cost": "Medium",
        "latency_impact": "Moderate",
    }


def get_bulk_recommendations(assets: list) -> list:
    """
    Given a list of asset dicts (each with cert_key_type, usage_context, etc.),
    return a list of recommendation dicts.
    """
    results = []
    for asset in assets:
        algo = asset.get("cert_key_type") or asset.get("algorithm") or "Unknown"
        usage = asset.get("usage_context")
        key_size = asset.get("cert_key_size_bits")
        library = asset.get("library")
        rec = recommend_pqc(algo, usage, key_size, library)
        results.append({
            "asset_id": asset.get("id"),
            "host": asset.get("host"),
            "algorithm": algo,
            **rec,
        })
    return results
