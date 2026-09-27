"""
scoring.py — MWQRS Multi-Factor Quantum Risk Scoring
Phase 1 update: business_criticality and data_lifetime now feed
directly into the score (not just the tier-based multiplier).
"""

QUANTUM_VULNERABLE_ALGORITHMS = ["RSA", "ECC", "DH", "DSA"]
QUANTUM_SAFE_ALGORITHMS = ["AES-256", "SHA-3", "ML-KEM", "ML-DSA", "SLH-DSA"]

RISK_WEIGHTS = {
    "algorithm_vulnerability": 0.30,
    "key_size": 0.15,
    "protocol_version": 0.12,
    "cert_expiry": 0.08,
    "service_criticality": 0.15,
    "business_criticality": 0.12,  # Phase 1: real stored field
    "data_lifetime": 0.08,          # Phase 1: Mosca shelf-life factor
}

CRITICALITY_MULTIPLIERS = {
    "P0": 1.5,
    "P1": 1.2,
    "P2": 1.0,
    "P3": 0.8,
}

# Phase 1: business criticality weights (high criticality → higher base risk)
BUSINESS_CRITICALITY_SCORES = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 40.0,
    "low": 10.0,
}

# Phase 1: data lifetime → Mosca urgency sub-score
# Longer-lived data has higher urgency (must be protected longer against HNDL)
DATA_LIFETIME_SCORES = {
    "<1y": 5.0,
    "1-3y": 20.0,
    "3-5y": 50.0,
    "5-10y": 75.0,
    ">10y": 100.0,
}

# Data lifetime → shelf-life years for Mosca formula
DATA_LIFETIME_YEARS = {
    "<1y": 0.5,
    "1-3y": 2.0,
    "3-5y": 4.0,
    "5-10y": 7.5,
    ">10y": 15.0,
}


def calculate_mwqrs(asset_record: dict, service_criticality: str = "P2") -> float:
    """
    Takes a crypto_asset dict + linked service criticality.
    Returns MWQRS score from 0.0 (safe) to 100.0 (critical).
    Phase 1: business_criticality and data_lifetime now actively contribute.
    """
    if asset_record.get("status") not in ("success", None, ""):
        # Non-TLS assets (source_code, dependency) don't have status="success"
        # Allow them through by only gating on explicit "error" states.
        if asset_record.get("status") == "error":
            return 0.0

    key_type = asset_record.get("cert_key_type") or asset_record.get("algorithm") or ""
    key_size = asset_record.get("cert_key_size_bits")
    tls_version = asset_record.get("tls_version") or ""
    days_to_expiry = asset_record.get("days_to_expiry")
    business_criticality = (asset_record.get("business_criticality") or "medium").lower()
    data_lifetime = asset_record.get("data_lifetime") or "1-3y"

    # 1. Algorithm Vulnerability Sub-score (0 - 100)
    algo_score = 0.0
    if any(vuln.lower() in key_type.lower() for vuln in QUANTUM_VULNERABLE_ALGORITHMS):
        algo_score = 100.0
    elif any(safe.lower() in key_type.lower() for safe in QUANTUM_SAFE_ALGORITHMS):
        algo_score = 0.0
    elif key_type.upper() in {"MD5", "SHA-1", "SHA1", "DES", "3DES"}:
        algo_score = 90.0  # classically weak
    else:
        algo_score = 80.0

    # 2. Key Size Sub-score (0 - 100)
    key_size_score = 0.0
    if key_size:
        if "RSA" in key_type.upper():
            if key_size < 1024:
                key_size_score = 100.0
            elif key_size < 2048:
                key_size_score = 75.0
            elif key_size < 3072:
                key_size_score = 30.0
            else:
                key_size_score = 10.0
        elif "ECC" in key_type.upper():
            if key_size < 256:
                key_size_score = 100.0
            elif key_size < 384:
                key_size_score = 30.0
            else:
                key_size_score = 10.0
        else:
            key_size_score = 50.0
    else:
        key_size_score = 50.0

    # 3. Protocol Version Sub-score (0 - 100)
    protocol_score = 0.0
    if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
        protocol_score = 100.0
    elif tls_version == "TLSv1.2":
        protocol_score = 50.0
    elif tls_version == "TLSv1.3":
        protocol_score = 10.0
    elif not tls_version:
        # Non-TLS assets — neutral on protocol score
        protocol_score = 40.0
    else:
        protocol_score = 60.0

    # 4. Certificate Expiry Sub-score (0 - 100)
    expiry_score = 0.0
    if days_to_expiry is not None:
        if days_to_expiry < 0:
            expiry_score = 100.0
        elif days_to_expiry <= 30:
            expiry_score = 75.0
        elif days_to_expiry <= 90:
            expiry_score = 35.0
        else:
            expiry_score = 0.0
    else:
        expiry_score = 0.0  # No cert — not a TLS asset

    # 5. Service Criticality Component
    crit_mult = CRITICALITY_MULTIPLIERS.get(service_criticality, 1.0)
    crit_base = 50.0 if service_criticality in ["P0", "P1"] else 20.0

    # 6. Business Criticality Sub-score (Phase 1 — real stored field)
    biz_crit_score = BUSINESS_CRITICALITY_SCORES.get(business_criticality, 40.0)

    # 7. Data Lifetime / Mosca Shelf-Life Sub-score (Phase 1)
    lifetime_score = DATA_LIFETIME_SCORES.get(data_lifetime, 20.0)

    # Weighted Sum
    weighted_sum = (
        algo_score * RISK_WEIGHTS["algorithm_vulnerability"] +
        key_size_score * RISK_WEIGHTS["key_size"] +
        protocol_score * RISK_WEIGHTS["protocol_version"] +
        expiry_score * RISK_WEIGHTS["cert_expiry"] +
        crit_base * RISK_WEIGHTS["service_criticality"] +
        biz_crit_score * RISK_WEIGHTS["business_criticality"] +
        lifetime_score * RISK_WEIGHTS["data_lifetime"]
    )

    final_score = min(100.0, weighted_sum * crit_mult)
    return round(final_score, 1)


def get_risk_band(score: float) -> tuple:
    if score >= 80:
        return "Critical", "Immediate remediation recommended"
    if score >= 50:
        return "Medium", "Review and plan remediation"
    return "Low", "No urgent cryptographic issue detected"


def get_mosca_shelf_life_years(data_lifetime: str) -> float:
    """Return shelf-life in years from data_lifetime string, for Mosca calculation."""
    return DATA_LIFETIME_YEARS.get(data_lifetime, 2.0)
