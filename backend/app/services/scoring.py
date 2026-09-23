QUANTUM_VULNERABLE_ALGORITHMS = ["RSA", "ECC", "DH", "DSA"]
QUANTUM_SAFE_ALGORITHMS = ["AES-256", "SHA-3", "ML-KEM", "ML-DSA", "SLH-DSA"]

RISK_WEIGHTS = {
    "algorithm_vulnerability": 0.35,
    "key_size": 0.20,
    "protocol_version": 0.15,
    "cert_expiry": 0.10,
    "service_criticality": 0.20,
}

CRITICALITY_MULTIPLIERS = {
    "P0": 1.5,
    "P1": 1.2,
    "P2": 1.0,
    "P3": 0.8,
}

def calculate_mwqrs(asset_record: dict, service_criticality: str = "P2") -> float:
    """
    Takes a crypto_asset dict + linked service criticality.
    Returns MWQRS score from 0.0 (safe) to 100.0 (critical).
    100% mathematical fidelity to legacy ecdat_scoring.py.
    """
    if asset_record.get("status") != "success":
        return 0.0

    key_type = asset_record.get("cert_key_type") or ""
    key_size = asset_record.get("cert_key_size_bits")
    tls_version = asset_record.get("tls_version") or ""
    days_to_expiry = asset_record.get("days_to_expiry")

    # 1. Algorithm Vulnerability Sub-score (0 - 100)
    algo_score = 0.0
    if any(vuln.lower() in key_type.lower() for vuln in QUANTUM_VULNERABLE_ALGORITHMS):
        algo_score = 100.0
    elif any(safe.lower() in key_type.lower() for safe in QUANTUM_SAFE_ALGORITHMS):
        algo_score = 0.0
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

    # 5. Service Criticality Component
    crit_mult = CRITICALITY_MULTIPLIERS.get(service_criticality, 1.0)
    crit_base = 50.0 if service_criticality in ["P0", "P1"] else 20.0

    # Weighted Sum
    weighted_sum = (
        algo_score * RISK_WEIGHTS["algorithm_vulnerability"] +
        key_size_score * RISK_WEIGHTS["key_size"] +
        protocol_score * RISK_WEIGHTS["protocol_version"] +
        expiry_score * RISK_WEIGHTS["cert_expiry"] +
        crit_base * RISK_WEIGHTS["service_criticality"]
    )

    final_score = min(100.0, weighted_sum * crit_mult)
    return round(final_score, 1)

def get_risk_band(score: float) -> tuple[str, str]:
    if score >= 80:
        return "Critical", "Immediate remediation recommended"
    if score >= 50:
        return "Medium", "Review and plan remediation"
    return "Low", "No urgent cryptographic issue detected"
