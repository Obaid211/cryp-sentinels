import os
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.core.config import settings

# Global In-Memory Cache for CACHED mode & fast responses
_RESPONSE_CACHE: Dict[str, Dict[str, Any]] = {}

EXPERT_KNOWLEDGE_BASE = [
    {
        "keywords": ["fips 203", "ml-kem", "kyber", "kem", "key encapsulation", "key exchange"],
        "topic": "NIST FIPS 203 (ML-KEM-768 / Kyber)",
        "answer": (
            "NIST FIPS 203 defines Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM), derived from CRYSTALS-Kyber. "
            "ML-KEM-768 is the primary standard replacement for classical key exchange mechanisms such as RSA key exchange and Diffie-Hellman (ECDH/DH). "
            "In ECDAT, transition to ML-KEM-768 is recommended via a hybrid classical+PQC composite mode (RFC 9370 / NIST SP 800-227) "
            "to prevent Harvest Now, Decrypt Later (HNDL) attacks while preserving backward compatibility with legacy TLS clients."
        )
    },
    {
        "keywords": ["fips 204", "ml-dsa", "dilithium", "signature", "digital signature"],
        "topic": "NIST FIPS 204 (ML-DSA-65 / Dilithium)",
        "answer": (
            "NIST FIPS 204 standardizes Module-Lattice-Based Digital Signature Algorithm (ML-DSA), derived from CRYSTALS-Dilithium. "
            "ML-DSA-65 serves as the primary replacement for classical signature schemes including RSA-2048/3072 and ECDSA (P-256/P-384). "
            "It provides mathematical resistance against Shor's polynomial-time period-finding algorithm on quantum computers."
        )
    },
    {
        "keywords": ["fips 205", "slh-dsa", "sphincs", "stateless", "hash-based"],
        "topic": "NIST FIPS 205 (SLH-DSA / SPHINCS+)",
        "answer": (
            "NIST FIPS 205 specifies Stateless Hash-Based Digital Signature Algorithm (SLH-DSA), derived from SPHINCS+. "
            "Unlike ML-DSA which relies on structured lattice assumptions, SLH-DSA relies solely on the security of underlying cryptographic hash functions (such as SHA-256 or SHAKE256). "
            "It serves as a secondary, highly conservative hedge against potential structural cryptanalysis of lattice problems."
        )
    },
    {
        "keywords": ["mwqrs", "score", "risk score", "formula", "calculation", "how is"],
        "topic": "Mosca-Weighted Quantum Risk Score (MWQRS)",
        "answer": (
            "The MWQRS is ECDAT's core quantitative risk metric (0.0 to 100.0), calculated as:\n\n"
            "MWQRS = [Base Vulnerability (40%) + Key Length Deficit (20%) + Protocol Deprecation (20%) + Certificate Urgency (20%)] × Criticality Multiplier\n\n"
            "• Algorithm Exposure: RSA/ECC vulnerable to Shor's algorithm receive 40.0 pts; PQC/quantum-safe receive 0.0 pts.\n"
            "• Key Length Deficit: Sub-2048-bit RSA or sub-256-bit ECC receive up to 20.0 pts.\n"
            "• Protocol Deprecation: TLS 1.0/1.1 receive 20.0 pts; TLS 1.2 receives 8.0 pts; TLS 1.3 receives 0.0 pts.\n"
            "• Certificate Expiry: Expiry within 30 days adds up to 20.0 pts.\n"
            "• Service Criticality Multipliers: P0 (x1.35), P1 (x1.15), P2 (x1.0), P3 (x0.8)."
        )
    },
    {
        "keywords": ["mosca", "inequality", "timeline", "x + y > z", "x+y>z", "urgency"],
        "topic": "Mosca Quantum Urgency Inequality (X + Y > Z)",
        "answer": (
            "Dr. Michele Mosca's Theorem states that an organization must migrate immediately if:\n\n"
            "X + Y > Z\n\n"
            "Where:\n"
            "• X = Migration Effort (years required to re-engineer, audit, and deploy PQC across infrastructure)\n"
            "• Y = Shelf-life (years during which encrypted data must remain strictly confidential)\n"
            "• Z = Threat Horizon (estimated years until Cryptanalytically Relevant Quantum Computers / CRQCs arrive)\n\n"
            "If X + Y > Z, adversary Harvest Now, Decrypt Later (HNDL) attacks succeed because adversary retention outlasts quantum decryption arrival."
        )
    },
    {
        "keywords": ["hybrid", "dual", "composite", "transition", "rfc 9370", "rollover"],
        "topic": "Hybrid Classical + PQC Transition Strategy",
        "answer": (
            "Hybrid deployment (RFC 9370 / NIST SP 800-227) is the recommended path for enterprise infrastructures. "
            "It combines a classical algorithm (e.g. RSA-2048 or ECDSA P-384) with a post-quantum standard (ML-KEM-768 or ML-DSA-65) in composite or dual-certificate mode. "
            "This achieves defense-in-depth: classical cryptography satisfies legacy clients and compliance audits, while post-quantum algorithms secure traffic against future quantum decryption."
        )
    },
    {
        "keywords": ["cbom", "cyclonedx", "1.6", "bill of materials", "export"],
        "topic": "CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)",
        "answer": (
            "CycloneDX 1.6 is the open standard specification for CBOMs. In ECDAT, CBOM Studio exports complete machine-readable manifests "
            "detailing cryptoProperties (asset classification, algorithm OIDs, key sizes, NIST quantum security levels, and dependencies) in both JSON and XML formats."
        )
    },
    {
        "keywords": ["shor", "grover", "quantum algorithm", "quantum attack"],
        "topic": "Quantum Attack Vectors: Shor's vs. Grover's Algorithm",
        "answer": (
            "Quantum attacks divide into two fundamental classes:\n\n"
            "1. Shor's Algorithm (Polynomial Time): Solves integer factorization and discrete logarithms in O((log N)³). Completely breaks RSA, Diffie-Hellman, and Elliptic Curve Cryptography (ECDSA, ECDH, Ed25519) on a CRQC.\n\n"
            "2. Grover's Algorithm (Quadratic Speedup): Accelerates unstructured search in O(√N). Halves the effective security of symmetric ciphers and hashes: AES-128 drops to 64-bit security (insecure), while AES-256 retains 128-bit quantum security (safe). SHA-256 collision resistance drops to 128 bits (safe)."
        )
    },
    {
        "keywords": ["cnsa", "nsa", "cnsa 2.0", "mandate", "timeline"],
        "topic": "Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)",
        "answer": (
            "NSA's CNSA 2.0 timeline mandates transition to post-quantum standards for National Security Systems:\n"
            "• Software and firmware signing: Begins 2025, mandatory by 2030 (ML-DSA-87 / LMS / XMSS).\n"
            "• Web browsers, servers, and cloud services: Client/server support begins 2025, mandatory by 2033 (ML-KEM-1024, ML-DSA-87).\n"
            "• Network equipment & gateways: Mandatory by 2026 for new gear, complete transition by 2030."
        )
    }
]

def _get_api_keys() -> List[str]:
    """Retrieves all available Gemini API keys from settings and environment."""
    keys: List[str] = []
    
    # 1. From settings GEMINI_API_KEYS (comma-separated keypool)
    raw_keys = settings.GEMINI_API_KEYS or os.environ.get("GEMINI_API_KEYS", "")
    if raw_keys:
        for k in raw_keys.split(","):
            cleaned = k.strip()
            if cleaned and len(cleaned) > 15:
                keys.append(cleaned)

    # 2. From singular GEMINI_API_KEY
    single_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if single_key and len(single_key) > 15 and single_key not in keys:
        keys.append(single_key)

    # Filter to valid Google AI Studio keys (starts with AIza) to avoid OAuth timeouts
    valid_aiza = [k for k in keys if k.startswith("AIza")]
    if valid_aiza:
        return valid_aiza
    return keys

def _get_inventory_context(db: Optional[Session]) -> str:
    """Builds a contextual summary of the organization's current cryptographic inventory."""
    if not db:
        return ""
    try:
        from app.models.models import CryptoAsset
        assets = db.query(CryptoAsset).all()
        if not assets:
            return ""
        total = len(assets)
        critical = sum(1 for a in assets if a.risk_score >= 80.0)
        medium = sum(1 for a in assets if 50.0 <= a.risk_score < 80.0)
        avg_score = round(sum(a.risk_score for a in assets) / total, 1) if total else 0.0
        
        top_vulnerable = sorted(assets, key=lambda a: a.risk_score, reverse=True)[:3]
        top_list = ", ".join([f"{a.host}:{a.port} ({a.cert_key_type} {a.cert_key_size_bits}b, MWQRS {a.risk_score})" for a in top_vulnerable])
        
        return (
            f"\nCURRENT ORGANIZATION POSTURE:\n"
            f"- Total Assets: {total} monitored cryptographic endpoints\n"
            f"- Average MWQRS: {avg_score}/100.0\n"
            f"- Critical Assets (MWQRS >= 80): {critical}\n"
            f"- Medium Assets (50 <= MWQRS < 80): {medium}\n"
            f"- Top At-Risk Endpoints: {top_list}\n"
        )
    except Exception:
        return ""

def query_cryptographic_assistant(
    prompt: str, 
    mode: str = "LIVE",
    db: Optional[Session] = None
) -> Dict[str, Any]:
    """
    Answers cryptographic and ECDAT queries.
    Respects operational modes:
    - OFFLINE: Uses Sovereign Air-Gapped Expert Engine (zero external network I/O).
    - CACHED: Checks local cache before external API; returns instant cached responses.
    - LIVE: Uses Google Gemini AI keypool (gemini-3.6-flash) with sovereign fallback.
    """
    cleaned_prompt = prompt.strip().lower()
    cache_key = f"{mode}:{cleaned_prompt}"

    # 1. CACHED MODE: Check cache first
    if mode == "CACHED" and cache_key in _RESPONSE_CACHE:
        cached_entry = _RESPONSE_CACHE[cache_key].copy()
        cached_entry["cached"] = True
        cached_entry["mode"] = "CACHED"
        cached_entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        return cached_entry

    # 2. OFFLINE / AIR-GAPPED MODE: Strictly Sovereign Knowledge Base (No outbound network calls)
    if mode == "OFFLINE":
        inv_ctx = _get_inventory_context(db)
        
        # Check specific inventory questions
        if any(w in cleaned_prompt for w in ["vulnerable", "asset", "inventory", "posture", "risk", "highest"]):
            if inv_ctx:
                resp = {
                    "source": "sovereign-expert-engine",
                    "mode": "OFFLINE",
                    "topic": "Current Cryptographic Inventory Posture",
                    "response": f"Air-Gapped Sovereign Posture Assessment:{inv_ctx}\nImmediate Recommendation: Prioritize migration of high-exposure assets using NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                _RESPONSE_CACHE[cache_key] = resp
                return resp

        # Check knowledge base matches
        for entry in EXPERT_KNOWLEDGE_BASE:
            if any(kw in cleaned_prompt for kw in entry["keywords"]):
                resp = {
                    "source": "sovereign-expert-engine",
                    "mode": "OFFLINE",
                    "topic": entry["topic"],
                    "response": entry["answer"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                _RESPONSE_CACHE[cache_key] = resp
                return resp

        # Default Sovereign Overview
        resp = {
            "source": "sovereign-expert-engine",
            "mode": "OFFLINE",
            "topic": "Sovereign Air-Gapped Advisory Engine",
            "response": (
                "You are operating in AIR-GAPPED OFFLINE MODE (Zero external network egress).\n\n"
                "I am calibrated on NIST PQC standards (FIPS 203/204/205), Mosca Urgency Theorem, and MWQRS scoring. "
                "You can query:\n"
                "• NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), FIPS 205 (SLH-DSA)\n"
                "• Mosca's Quantum Urgency Inequality (X + Y > Z) and HNDL defenses\n"
                "• MWQRS quantitative scoring and inventory risk breakdown\n"
                "• Hybrid classical + PQC transition (RFC 9370)\n"
                "• CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)\n"
                "• Shor's and Grover's algorithm quantum impacts"
            ),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        _RESPONSE_CACHE[cache_key] = resp
        return resp

    # 3. LIVE MODE: Use Google Gemini AI Keypool with Rotation
    api_keys = _get_api_keys()
    candidate_models = ["gemini-3.6-flash", "gemini-3.5-flash"]
    inv_context = _get_inventory_context(db)

    system_instruction = (
        "You are the ECDAT Cryptographic Advisor, an elite enterprise authority on post-quantum cryptography, "
        "NIST FIPS 203 (ML-KEM-768 / Kyber), FIPS 204 (ML-DSA-65 / Dilithium), FIPS 205 (SLH-DSA / SPHINCS+) standards, "
        "Mosca's Urgency theorem (X+Y>Z), MWQRS scoring, and hybrid classical+PQC TLS deployment. "
        "Always mention standard names and their historical derivation (e.g. ML-KEM and Kyber). "
        "Provide direct, concise, mathematically rigorous, and practical enterprise guidance. "
        f"{inv_context}"
    )

    last_error = None
    try:
        from google import genai
        for api_key in api_keys:
            client = genai.Client(api_key=api_key)
            for model_name in candidate_models:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={"system_instruction": system_instruction}
                    )
                    if response and response.text:
                        result = {
                            "source": f"gemini-ai ({model_name})",
                            "model": model_name,
                            "mode": mode,
                            "response": response.text.strip(),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        _RESPONSE_CACHE[cache_key] = result
                        return result
                except Exception as e:
                    last_error = str(e)
                    continue
    except Exception as e:
        last_error = str(e)

    # 4. Fallback to Sovereign Expert Engine if Gemini fails or keys exhausted
    for entry in EXPERT_KNOWLEDGE_BASE:
        if any(kw in cleaned_prompt for kw in entry["keywords"]):
            result = {
                "source": "sovereign-expert-engine",
                "mode": mode,
                "topic": entry["topic"],
                "response": entry["answer"],
                "fallback_note": f"Live Gemini API unavailable ({last_error[:60] if last_error else 'Key quota'}), served by Sovereign Engine.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            _RESPONSE_CACHE[cache_key] = result
            return result

    # Check inventory query on fallback
    if any(w in cleaned_prompt for w in ["vulnerable", "asset", "inventory", "posture", "risk"]):
        inv_ctx = _get_inventory_context(db)
        if inv_ctx:
            result = {
                "source": "sovereign-expert-engine",
                "mode": mode,
                "topic": "Current Cryptographic Posture",
                "response": f"ECDAT Sovereign Posture Assessment:{inv_ctx}\nRecommendation: Initiate Wave 1 migration targeting critical assets using hybrid ML-KEM-768.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            _RESPONSE_CACHE[cache_key] = result
            return result

    # Comprehensive fallback
    result = {
        "source": "sovereign-expert-engine",
        "mode": mode,
        "topic": "ECDAT Post-Quantum Advisory Overview",
        "response": (
            "I am the ECDAT Cryptographic Advisory Engine. You can ask me about:\n\n"
            "• NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), or FIPS 205 (SLH-DSA)\n"
            "• Mosca's Quantum Urgency Inequality (X + Y > Z) and HNDL threat vectors\n"
            "• Mosca-Weighted Quantum Risk Score (MWQRS) mathematical breakdown\n"
            "• Phased hybrid classical + PQC transition roadmaps\n"
            "• CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) standards"
        ),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    _RESPONSE_CACHE[cache_key] = result
    return result
