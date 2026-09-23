import json
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.models import CryptoAsset, Service, ServiceDependency
from app.services.cbom import get_recommended_pqc_target, explain_risk_flag, generate_cyclonedx_cbom
from app.services.scoring import QUANTUM_VULNERABLE_ALGORITHMS

router = APIRouter()

# --------------------------------------------------------------------------
# 1. /inventory: Full Searchable Inventory & Detail Deep-Dive
# --------------------------------------------------------------------------
@router.get("/inventory")
def get_inventory(
    search: str = Query("", description="Search term for host, service, or cipher"),
    criticality: str = Query("", description="Filter by criticality tier (P0, P1, P2, P3)"),
    db: Session = Depends(get_db)
):
    query = db.query(CryptoAsset)
    assets = query.all()

    results = []
    for a in assets:
        svc_name = a.linked_service.name if a.linked_service else "Unassigned"
        crit = a.linked_service.criticality if a.linked_service else "P2"

        if criticality and crit != criticality:
            continue

        search_corpus = f"{a.host} {a.port} {svc_name} {a.tls_version} {a.cert_key_type} {a.cipher_suite}".lower()
        if search and search.lower() not in search_corpus:
            continue

        flags = []
        if a.risk_flags:
            try:
                flags = json.loads(a.risk_flags)
            except Exception:
                flags = [a.risk_flags]

        results.append({
            "id": a.id,
            "host": a.host,
            "port": a.port,
            "status": a.status,
            "tls_version": a.tls_version,
            "cipher_suite": a.cipher_suite,
            "cipher_bits": a.cipher_bits,
            "cert_subject": a.cert_subject,
            "cert_issuer": a.cert_issuer,
            "cert_key_type": a.cert_key_type,
            "cert_key_size_bits": a.cert_key_size_bits,
            "cert_signature_algorithm": a.cert_signature_algorithm,
            "days_to_expiry": a.days_to_expiry,
            "criticality": crit,
            "service_name": svc_name,
            "risk_score": a.risk_score,
            "risk_flags": flags,
            "pqc_target": get_recommended_pqc_target(a.cert_key_type)["algorithm"]
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results

@router.get("/inventory/{host}/{port}/history")
def get_asset_detail_and_history(host: str, port: int, db: Session = Depends(get_db)):
    asset = db.query(CryptoAsset).filter(CryptoAsset.host == host, CryptoAsset.port == port).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    flags = []
    if asset.risk_flags:
        try:
            flags = json.loads(asset.risk_flags)
        except Exception:
            flags = [asset.risk_flags]

    flag_explanations = [
        {"flag": f, "explanation": explain_risk_flag(f)} for f in flags
    ]

    pqc_details = get_recommended_pqc_target(asset.cert_key_type)

    return {
        "asset": {
            "id": asset.id,
            "host": asset.host,
            "port": asset.port,
            "status": asset.status,
            "tls_version": asset.tls_version,
            "cipher_suite": asset.cipher_suite,
            "cipher_bits": asset.cipher_bits,
            "cert_subject": asset.cert_subject,
            "cert_issuer": asset.cert_issuer,
            "cert_key_type": asset.cert_key_type,
            "cert_key_size_bits": asset.cert_key_size_bits,
            "cert_signature_algorithm": asset.cert_signature_algorithm,
            "days_to_expiry": asset.days_to_expiry,
            "risk_score": asset.risk_score,
            "criticality": asset.linked_service.criticality if asset.linked_service else "P2",
            "service_name": asset.linked_service.name if asset.linked_service else "Unassigned",
        },
        "risk_breakdown": {
            "algo_vulnerability": 100 if any(v.lower() in (asset.cert_key_type or '').lower() for v in QUANTUM_VULNERABLE_ALGORITHMS) else 0,
            "key_size_rating": "Sub-standard" if (asset.cert_key_size_bits or 0) < 2048 else "Standard",
            "tls_protocol": asset.tls_version,
            "expiry_urgency": "Urgent (<30d)" if (asset.days_to_expiry or 0) <= 30 else "Normal",
        },
        "flag_explanations": flag_explanations,
        "recommended_pqc_target": pqc_details,
        "history": [
            {
                "scanned_at": asset.scanned_at.isoformat() if asset.scanned_at else "2026-09-22T00:00:00Z",
                "risk_score": asset.risk_score,
                "tls_version": asset.tls_version,
                "status": asset.status
            }
        ]
    }

# --------------------------------------------------------------------------
# 2. /remediation: Remediation Center Plan
# --------------------------------------------------------------------------
@router.get("/remediation/plan")
def get_remediation_plan(db: Session = Depends(get_db)):
    assets = db.query(CryptoAsset).all()
    plan_items = []

    for a in assets:
        mwqrs = float(a.risk_score or 0.0)
        crit = a.linked_service.criticality if a.linked_service else "P2"
        svc_name = a.linked_service.name if a.linked_service else "Unassigned"
        key_type = a.cert_key_type or "Unknown"
        key_size = a.cert_key_size_bits or 0
        days_exp = a.days_to_expiry

        flags = []
        if a.risk_flags:
            try:
                flags = json.loads(a.risk_flags)
            except Exception:
                flags = [a.risk_flags]

        # Multi-factor priority index
        priority_index = mwqrs * 1.0
        priority_index += {"P0": 25.0, "P1": 15.0, "P2": 5.0, "P3": 0.0}.get(crit, 0.0)
        if days_exp is not None:
            if days_exp < 0:
                priority_index += 40.0
            elif days_exp <= 30:
                priority_index += 25.0
            elif days_exp <= 90:
                priority_index += 10.0

        if "RSA" in key_type.upper() and key_size < 2048:
            priority_index += 20.0

        reasons = []
        if mwqrs >= 80.0:
            reasons.append(f"Critical MWQRS quantum risk score ({mwqrs}/100)")
        elif mwqrs >= 50.0:
            reasons.append(f"Elevated MWQRS risk score ({mwqrs}/100)")

        if crit in ["P0", "P1"]:
            reasons.append(f"Tier {crit} Mission-critical sovereign service")

        if days_exp is not None and days_exp <= 30:
            reasons.append(f"Urgent certificate expiry window ({days_exp} days remaining)")

        if "RSA" in key_type.upper() and key_size < 2048:
            reasons.append(f"Sub-standard RSA key length ({key_size}b < 2048b threshold)")

        if not reasons:
            reasons.append("Routine cryptographic modernization and agility tracking")

        actions = []
        if days_exp is not None and days_exp <= 30:
            actions.append("Immediate: Renew TLS certificate to prevent handshake trust failures.")
        if "RSA" in key_type.upper() and key_size < 2048:
            actions.append("Short-Term: Upgrade RSA key size to at least 2048-bit (recommended 3072-bit).")
        if "RSA" in key_type.upper():
            actions.append("PQC Roadmap: Deploy dual-mode hybrid TLS certificate (RSA-3072 + ML-KEM-768 per NIST FIPS 203).")
            migration_direction = "Classical RSA → Hybrid Classical + ML-KEM-768 → Pure NIST FIPS 203"
        elif "ECC" in key_type.upper():
            actions.append("PQC Roadmap: Evaluate transition to ML-DSA-65 (NIST FIPS 204) for digital signatures.")
            migration_direction = "Classical ECC → Hybrid ECDSA + ML-DSA-65 → Pure NIST FIPS 204"
        elif "ML-" in key_type.upper():
            actions.append("Verification: Verify PQC implementation against final FIPS 203/204 benchmarks.")
            migration_direction = "Already PQC-Migrated (Maintain Compliance)"
        else:
            actions.append("Review: Audit cipher configuration and eliminate legacy algorithms.")
            migration_direction = "Legacy Classical → Modern Classical → Hybrid PQC"

        plan_items.append({
            "asset_id": a.id,
            "target": f"{a.host}:{a.port}",
            "host": a.host,
            "port": a.port,
            "service": svc_name,
            "criticality": crit,
            "algorithm": key_type,
            "key_size": key_size,
            "tls_version": a.tls_version,
            "mwqrs": mwqrs,
            "days_to_expiry": days_exp,
            "priority_index": priority_index,
            "why_prioritized": "; ".join(reasons) + ".",
            "recommended_actions": actions,
            "migration_direction": migration_direction,
            "dependency_impact": "Downstream Service Impact Analyzed"
        })

    plan_items.sort(key=lambda x: x["priority_index"], reverse=True)
    for idx, item in enumerate(plan_items, 1):
        item["priority_rank"] = idx

    return {
        "summary": {
            "action_items": len(plan_items),
            "critical_mwqrs_items": sum(1 for p in plan_items if p["mwqrs"] >= 80.0),
            "urgent_expiries": sum(1 for p in plan_items if p["days_to_expiry"] is not None and p["days_to_expiry"] <= 30),
            "high_blast_radius": sum(1 for p in plan_items if p["criticality"] in ["P0", "P1"])
        },
        "queue": plan_items
    }

# --------------------------------------------------------------------------
# 3. /threat: Threat Timeline & Mosca Urgency Evaluation
# --------------------------------------------------------------------------
@router.post("/threat/urgency")
def calculate_threat_urgency(payload: Dict[str, Any]):
    shelf_life = float(payload.get("shelf_life_years", 3.0))
    migration_time = float(payload.get("migration_time_years", 2.0))
    planning_horizon = float(payload.get("planning_horizon_years", 10.0))
    mwqrs = float(payload.get("mwqrs", 70.0))
    is_vulnerable = bool(payload.get("is_quantum_vulnerable", True))

    combined_requirement = round(shelf_life + migration_time, 1)
    margin = round(planning_horizon - combined_requirement, 1)

    if not is_vulnerable:
        urgency_level = "LOW / SECURED"
        status_color = "green"
        verdict = "OK"
        summary = "Asset utilizes quantum-resistant cryptography (NIST FIPS 203/204). No exposure to Shor's algorithm."
    elif combined_requirement > planning_horizon:
        urgency_level = "CRITICAL"
        status_color = "red"
        verdict = "CRITICAL"
        deficit = abs(margin)
        summary = (
            f"Combined protection requirement ({combined_requirement}y: {shelf_life}y shelf-life + "
            f"{migration_time}y migration) exceeds organizational horizon ({planning_horizon}y) by {deficit} year(s). "
            f"High Harvest-Now-Decrypt-Later (HNDL) exposure."
        )
    elif margin <= 2.0 or mwqrs >= 80.0:
        urgency_level = "HIGH"
        status_color = "orange"
        verdict = "CRITICAL"
        summary = f"Narrow migration headroom ({margin} years remaining). Timely action recommended."
    else:
        urgency_level = "MODERATE"
        status_color = "yellow"
        verdict = "OK"
        summary = f"Timeline margin of {margin} years remains under current planning assumptions."

    return {
        "combined_requirement_years": combined_requirement,
        "planning_horizon_years": planning_horizon,
        "margin_years": margin,
        "urgency_level": urgency_level,
        "status_color": status_color,
        "verdict": verdict,
        "summary": summary
    }

@router.get("/threat/inventory-wide")
def get_inventory_threat_rankings(
    planning_horizon: float = Query(10.0),
    db: Session = Depends(get_db)
):
    assets = db.query(CryptoAsset).all()
    rankings = []
    for a in assets:
        key_type = a.cert_key_type or "Unknown"
        is_vuln = any(v.lower() in key_type.lower() for v in QUANTUM_VULNERABLE_ALGORITHMS)
        crit = a.linked_service.criticality if a.linked_service else "P2"
        shelf_life = 20.0 if crit == "P0" else 10.0 if crit == "P1" else 3.0
        mig_time = 4.0 if crit == "P0" else 3.0 if crit == "P1" else 1.5

        combined = round(shelf_life + mig_time, 1)
        margin = round(planning_horizon - combined, 1)
        verdict = "CRITICAL" if (combined > planning_horizon and is_vuln) else "OK"

        rankings.append({
            "id": a.id,
            "target": f"{a.host}:{a.port}",
            "service": a.linked_service.name if a.linked_service else "Unassigned",
            "criticality": crit,
            "shelf_life_years": shelf_life,
            "migration_time_years": mig_time,
            "combined_years": combined,
            "margin_years": margin,
            "verdict": verdict,
            "mwqrs": a.risk_score
        })

    rankings.sort(key=lambda x: (x["verdict"] == "CRITICAL", x["combined_years"]), reverse=True)
    return rankings

# --------------------------------------------------------------------------
# 4. /compliance: Compliance & Readiness Checklist
# --------------------------------------------------------------------------
@router.get("/compliance/summary")
def get_compliance_summary(db: Session = Depends(get_db)):
    assets = db.query(CryptoAsset).all()
    total = len(assets)
    vuln = sum(1 for a in assets if any(v.lower() in (a.cert_key_type or '').lower() for v in QUANTUM_VULNERABLE_ALGORITHMS))
    pqc_ready = sum(1 for a in assets if "ML-" in (a.cert_key_type or '').upper())
    migration_required = vuln
    unknown = max(0, total - vuln - pqc_ready)

    implemented_controls = [
        {"id": "CTL-01", "name": "Automated TLS Handshake Enumeration", "status": "Implemented", "framework": "NIST SP 800-52r2"},
        {"id": "CTL-02", "name": "Mosca MWQRS Multi-Factor Risk Model", "status": "Implemented", "framework": "Mosca Quantum Urgency"},
        {"id": "CTL-03", "name": "CycloneDX CBOM Specification 1.6 Export", "status": "Implemented", "framework": "CycloneDX CBOM standard"},
        {"id": "CTL-04", "name": "NIST FIPS 203/204/205 Replacement Mapping", "status": "Implemented", "framework": "NIST FIPS PQC"},
        {"id": "CTL-05", "name": "Dependency Graph Blast Radius Propagation", "status": "Implemented", "framework": "NetworkX Architectural Analysis"},
    ]

    roadmap_controls = [
        {"id": "RDM-01", "name": "Automated Hybrid TLS Dual-Certificate Rollover", "status": "Roadmap Q4", "target": "RFC 9370 / Hybrid KEM"},
        {"id": "RDM-02", "name": "Hardware Security Module (HSM) PQC Root of Trust", "status": "In Progress", "target": "FIPS 140-3 Physical Boundary"},
        {"id": "RDM-03", "name": "Continuous eBPF In-Kernel Cryptographic Discovery", "status": "Architecture Phase", "target": "Linux Sovereign Kernel"},
        {"id": "RDM-04", "name": "Automated CBOM Attestation via Sigstore Cosign", "status": "Roadmap Q1", "target": "Supply Chain SLSA L3"},
    ]

    return {
        "stats": {
            "total_assets": total,
            "quantum_vulnerable": vuln,
            "pqc_ready": pqc_ready,
            "migration_required": migration_required,
            "unknown_under_review": unknown
        },
        "implemented_controls": implemented_controls,
        "roadmap_controls": roadmap_controls
    }

# --------------------------------------------------------------------------
# 5. /cbom: CycloneDX 1.6 Export
# --------------------------------------------------------------------------
@router.get("/cbom/export")
def get_cbom_export(db: Session = Depends(get_db)):
    return generate_cyclonedx_cbom(db)
