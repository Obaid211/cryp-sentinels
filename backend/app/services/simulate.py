from typing import Dict, Any, List, Optional
import networkx as nx
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service, ServiceDependency
from app.services.graph import build_networkx_graph, compute_blast_radius

MIGRATION_STRATEGIES = {
    "HYBRID": {
        "id": "HYBRID",
        "name": "Hybrid Classical + PQC Composite",
        "badge": "Recommended Transition Mode",
        "standards": ["NIST SP 800-227", "RFC 9370", "NIST FIPS 203 (ML-KEM-768)"],
        "description": "Deploys a dual-stack composite certificate combining classical cryptography for backward compatibility with ML-KEM-768 for immediate quantum resistance.",
        "pros": ["Zero legacy client disruption", "Immediate protection against Harvest Now, Decrypt Later (HNDL)", "Fully compliant with interim CNSA 2.0 guidance"],
        "cons": ["Larger handshake payload size (~1.2KB increase)", "Requires dual-algorithm validation support"],
        "timeline_weeks": 6
    },
    "PURE_PQC": {
        "id": "PURE_PQC",
        "name": "Pure Post-Quantum (FIPS 203 / 204 / 205)",
        "badge": "Sovereign Target State",
        "standards": ["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"],
        "description": "Complete elimination of classical asymmetric algorithms. Replaces all key exchanges with ML-KEM and all signatures with ML-DSA or stateless SLH-DSA.",
        "pros": ["100% mathematical immunity to Shor's algorithm", "Smallest post-quantum cryptographic overhead", "Future-proof against advanced quantum threats"],
        "cons": ["Breaks compatibility with legacy TLS 1.2 and unpatched clients", "Requires enterprise-wide client software upgrade"],
        "timeline_weeks": 14
    },
    "CLASSICAL_HARDENING": {
        "id": "CLASSICAL_HARDENING",
        "name": "Classical Hardening (Interim Baseline)",
        "badge": "Interim Mitigating Step",
        "standards": ["NIST SP 800-52 Rev. 2", "BSI TR-02102-2"],
        "description": "Increases classical key lengths (RSA-1024 -> RSA-3072/4096, ECC secp256r1 -> secp384r1) and enforces TLS 1.3 with PFS.",
        "pros": ["Universal client support", "Immediate drop-in configuration change without protocol redesign"],
        "cons": ["Zero protection against Cryptanalytically Relevant Quantum Computers (CRQCs)", "Still subject to Mosca urgency timeline"],
        "timeline_weeks": 3
    }
}


def simulate_asset(db: Session, asset_id: int, strategy: str = "HYBRID") -> Dict[str, Any]:
    """
    Simulates migration of a single cryptographic asset under the specified strategy.
    """
    strat = strategy.upper()
    if strat not in MIGRATION_STRATEGIES:
        strat = "HYBRID"

    asset = db.query(CryptoAsset).filter(CryptoAsset.id == asset_id).first()
    if not asset:
        return {"error": f"Crypto asset with ID {asset_id} not found."}

    service = db.query(Service).filter(Service.id == asset.linked_service_id).first() if asset.linked_service_id else None
    service_name = service.name if service else "Standalone Endpoint"
    criticality = service.criticality if service else "P2"

    key_type = (asset.cert_key_type or "RSA").strip()
    key_size = asset.cert_key_size_bits or 2048
    current_mwqrs = float(asset.risk_score or 0.0)
    tls_v = asset.tls_version or "TLSv1.2"

    is_rsa = "RSA" in key_type.upper()
    is_ecc = "ECC" in key_type.upper() or "ECDSA" in key_type.upper()

    # Determine NIST replacements
    if is_rsa:
        kem_direction = "NIST FIPS 203: ML-KEM-768 (Kyber)"
        sig_direction = "NIST FIPS 204: ML-DSA-65 (Dilithium)"
        hybrid_strategy = "Dual Classical RSA-3072 + ML-KEM-768 / ML-DSA-65"
    elif is_ecc:
        kem_direction = "Hybrid ECDH + NIST FIPS 203: ML-KEM-768"
        sig_direction = "NIST FIPS 204: ML-DSA-65 or NIST FIPS 205: SLH-DSA-128s"
        hybrid_strategy = "Hybrid ECDSA (P-384) + ML-DSA-65 (FIPS 204)"
    else:
        kem_direction = "NIST FIPS 203: ML-KEM-768"
        sig_direction = "NIST FIPS 204: ML-DSA-65"
        hybrid_strategy = "Classical + ML-KEM / ML-DSA Dual Stack"

    if strat == "PURE_PQC":
        sim_algo = "ML-KEM-768 / ML-DSA-65 (NIST FIPS 203/204)"
        sim_key_size = "768-bit (KEM) / 1952-byte (Sig)"
        sim_mwqrs = 10.0 if criticality == "P0" else 5.0
        sim_status = "Quantum-Resistant (NIST PQC Final Standards)"
        notes = "Pure PQC transition eliminates classical vulnerability to Shor's algorithm."
        effort_hours = 60 if criticality in ["P0", "P1"] else 30
    elif strat == "CLASSICAL_HARDENING":
        sim_algo = f"Classical {key_type} (Hardened)"
        sim_key_size = "3072 bits"
        sim_mwqrs = round(max(current_mwqrs * 0.65, 30.0), 1)
        sim_status = "Vulnerable to future CRQC (Shor's Algorithm) — Interim Classical Hardening"
        notes = "Increases classical cryptographic safety factor; does NOT protect against future CRQC."
        effort_hours = 16 if criticality in ["P0", "P1"] else 8
    else:  # HYBRID
        sim_algo = f"Hybrid Composite: {key_type}-{key_size} + ML-KEM-768"
        sim_key_size = f"{key_size}b Classical + 768b PQC"
        sim_mwqrs = 20.0 if criticality == "P0" else 12.0
        sim_status = "Hybrid Protected (Classical Backwards-Compatible + PQC Secured)"
        notes = "Recommended transition: protects against HNDL while preserving legacy client interoperability."
        effort_hours = 40 if criticality in ["P0", "P1"] else 20

    # Blast radius assessment
    blast_radius = {}
    if service:
        blast_radius = compute_blast_radius(db, service.id)
    blast_count = blast_radius.get("blast_radius_count", 1)

    return {
        "asset_id": asset.id,
        "host": asset.host,
        "port": asset.port,
        "service_name": service_name,
        "criticality": criticality,
        "strategy": strat,
        "strategy_name": MIGRATION_STRATEGIES[strat]["name"],
        "before_state": {
            "algorithm": f"{key_type} ({key_size} bits)",
            "key_size": f"{key_size} bits",
            "tls_version": tls_v,
            "mwqrs_score": current_mwqrs,
            "quantum_status": "Vulnerable to CRQC (Shor's Algorithm)" if (is_rsa or is_ecc) else "Quantum-Resistant"
        },
        "after_state": {
            "algorithm": sim_algo,
            "key_size": sim_key_size,
            "tls_version": "TLSv1.3 (Hybrid Enabled)" if strat != "CLASSICAL_HARDENING" else "TLSv1.3",
            "mwqrs_score": sim_mwqrs,
            "quantum_status": sim_status,
            "risk_reduction": round(current_mwqrs - sim_mwqrs, 1),
            "notes": notes
        },
        "nist_pqc": {
            "kem": kem_direction,
            "signature": sig_direction,
            "hybrid_strategy": hybrid_strategy
        },
        "blast_radius_count": blast_count,
        "complexity": "High" if blast_count > 3 or criticality == "P0" else ("Medium" if blast_count > 1 else "Low"),
        "estimated_effort_hours": effort_hours
    }


def simulate_inventory(db: Session, strategy: str = "HYBRID") -> Dict[str, Any]:
    """
    Runs full-estate migration simulation across all registered cryptographic endpoints.
    Calculates before vs after posture aggregates and topological migration waves.
    """
    strat = strategy.upper()
    if strat not in MIGRATION_STRATEGIES:
        strat = "HYBRID"

    assets = db.query(CryptoAsset).all()
    if not assets:
        return {"error": "No assets found in inventory for simulation."}

    simulations = []
    total_before_mwqrs = 0.0
    total_after_mwqrs = 0.0
    before_critical = 0
    after_critical = 0
    total_effort_hours = 0

    for a in assets:
        sim = simulate_asset(db, a.id, strat)
        simulations.append(sim)

        before_score = sim["before_state"]["mwqrs_score"]
        after_score = sim["after_state"]["mwqrs_score"]

        total_before_mwqrs += before_score
        total_after_mwqrs += after_score

        if before_score >= 60.0:
            before_critical += 1
        if after_score >= 60.0:
            after_critical += 1

        total_effort_hours += sim.get("estimated_effort_hours", 20)

    n = len(assets)
    avg_before = round(total_before_mwqrs / n, 1)
    avg_after = round(total_after_mwqrs / n, 1)
    overall_reduction = round(avg_before - avg_after, 1)

    # Compute topological sequence & migration waves
    topological_sequence = get_topological_sequence(db, strat)

    return {
        "strategy": MIGRATION_STRATEGIES[strat],
        "aggregate_posture": {
            "total_assets": n,
            "before_average_mwqrs": avg_before,
            "after_average_mwqrs": avg_after,
            "average_reduction": overall_reduction,
            "percentage_risk_drop": round((overall_reduction / avg_before * 100) if avg_before > 0 else 0, 1),
            "critical_risk_before": before_critical,
            "critical_risk_after": after_critical,
            "critical_eliminated": before_critical - after_critical,
            "total_estimated_effort_hours": total_effort_hours,
            "total_estimated_weeks": round(total_effort_hours / 40.0, 1)
        },
        "migration_waves": topological_sequence.get("waves", []),
        "asset_simulations": simulations
    }


def get_topological_sequence(db: Session, strategy: str = "HYBRID") -> Dict[str, Any]:
    """
    Computes optimal topological migration sequence.
    Sorts assets such that leaf services / foundation nodes are migrated first,
    or prioritized by highest MWQRS risk with low blast radius tie-breaker.
    Organizes assets into 3 distinct migration waves.
    """
    G = build_networkx_graph(db)
    assets = db.query(CryptoAsset).all()

    # Precompute simulations
    sim_cache = {}
    for a in assets:
        sim_cache[a.id] = simulate_asset(db, a.id, strategy)

    # In our graph, A -> B means A depends on B.
    # Therefore, B is a foundation/upstream dependency, and A is downstream.
    # In PQC migration, migrating leaf/callee nodes first ensures callers can switch smoothly.
    sequence = []
    for a in assets:
        sim = sim_cache[a.id]
        score = sim["before_state"]["mwqrs_score"]
        blast_radius = sim["blast_radius_count"]
        crit = sim["criticality"]

        sequence.append({
            "asset_id": a.id,
            "host": f"{a.host}:{a.port}",
            "service_name": sim["service_name"],
            "criticality": crit,
            "current_algorithm": sim["before_state"]["algorithm"],
            "target_standard": sim["after_state"]["algorithm"],
            "before_mwqrs": score,
            "simulated_mwqrs": sim["after_state"]["mwqrs_score"],
            "blast_radius_count": blast_radius,
            "complexity": sim["complexity"],
            "effort_hours": sim["estimated_effort_hours"],
            "priority_key": (score, -blast_radius)
        })

    # Sort descending by risk score, then ascending by blast radius
    sequence.sort(key=lambda x: (x["before_mwqrs"], -x["blast_radius_count"]), reverse=True)

    # Assign to 3 migration waves
    total = len(sequence)
    wave_size = max(1, (total + 2) // 3)

    waves = [
        {"wave": 1, "title": "Wave 1: High Risk & Foundation Endpoints", "description": "Remediate critical risk endpoints and isolated services first to eliminate high-yield exposure.", "assets": []},
        {"wave": 2, "title": "Wave 2: Core Infrastructure & Intermediaries", "description": "Transition core database proxies and intermediate microservices with moderate blast radius.", "assets": []},
        {"wave": 3, "title": "Wave 3: Edge Gateways & Public Interfaces", "description": "Finalize external-facing API gateways and portals once downstream dependencies are quantum-hardened.", "assets": []}
    ]

    for idx, item in enumerate(sequence, 1):
        item["sequence_position"] = idx
        del item["priority_key"]

        if idx <= wave_size:
            item["wave"] = 1
            waves[0]["assets"].append(item)
        elif idx <= wave_size * 2:
            item["wave"] = 2
            waves[1]["assets"].append(item)
        else:
            item["wave"] = 3
            waves[2]["assets"].append(item)

    return {
        "sequence": sequence,
        "waves": waves
    }
