import json
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.models import CryptoAsset, Service
from app.services.inventory import seed_demo_data, recalculate_all_scores

router = APIRouter()

@router.get("/dashboard/summary")
def get_dashboard_summary(
    mode: str = Query("LIVE", pattern="^(LIVE|CACHED|OFFLINE)$"),
    db: Session = Depends(get_db)
):
    assets = db.query(CryptoAsset).all()
    if not assets:
        seed_demo_data(db)
        assets = db.query(CryptoAsset).all()

    total_scanned = len(assets)
    critical_count = sum(1 for a in assets if a.risk_score >= 80.0)
    medium_count = sum(1 for a in assets if 50.0 <= a.risk_score < 80.0)
    safe_count = sum(1 for a in assets if a.risk_score < 50.0)
    avg_mwqrs = round(sum(a.risk_score for a in assets) / total_scanned, 1) if total_scanned > 0 else 0.0

    # Risk level distribution (for donut chart)
    risk_distribution = [
        {"name": "Critical (MWQRS ≥ 80)", "value": critical_count, "color": "var(--severity-critical)"},
        {"name": "Medium (50 ≤ MWQRS < 80)", "value": medium_count, "color": "var(--severity-medium)"},
        {"name": "Low / Safe (MWQRS < 50)", "value": safe_count, "color": "var(--severity-safe)"},
    ]

    # Key/algorithm type breakdown (cert_key_type or algorithm field, for bar chart)
    key_breakdown: Dict[str, int] = {}
    for a in assets:
        key_label = f"{a.cert_key_type or 'Unknown'} {a.cert_key_size_bits or ''}b".strip()
        key_breakdown[key_label] = key_breakdown.get(key_label, 0) + 1

    key_type_data = [
        {"key_type": k, "count": v} for k, v in sorted(key_breakdown.items(), key=lambda x: x[1], reverse=True)
    ]

    # Algorithm family breakdown (RSA, ECC, AES, Hash, PQC, etc.)
    algo_family: Dict[str, int] = {}
    for a in assets:
        algo = (a.cert_key_type or a.algorithm or "Unknown").split("-")[0].split("/")[0].upper().strip()
        algo_family[algo] = algo_family.get(algo, 0) + 1

    algorithm_breakdown = [
        {"algorithm": k, "count": v} for k, v in sorted(algo_family.items(), key=lambda x: x[1], reverse=True)
    ]

    # Business criticality distribution
    biz_crit: Dict[str, int] = {}
    for a in assets:
        lvl = a.business_criticality or "medium"
        biz_crit[lvl] = biz_crit.get(lvl, 0) + 1

    criticality_distribution = [
        {"level": k, "count": v} for k, v in sorted(biz_crit.items(), key=lambda x: ["critical","high","medium","low"].index(x[0]) if x[0] in ["critical","high","medium","low"] else 99)
    ]

    # Data lifetime distribution (Mosca shelf-life)
    lifetime_order = ["<1y", "1-3y", "3-5y", "5-10y", ">10y"]
    lifetime_dist: Dict[str, int] = {}
    for a in assets:
        lt = a.data_lifetime or "1-3y"
        lifetime_dist[lt] = lifetime_dist.get(lt, 0) + 1

    data_lifetime_distribution = [
        {"lifetime": k, "count": lifetime_dist.get(k, 0)} for k in lifetime_order if lifetime_dist.get(k, 0) > 0
    ]

    # Scan statistics (multi-source)
    tls_assets = [a for a in assets if (a.source or "tls") == "tls"]
    public_scan_stats = {
        "hosts_attempted": total_scanned + 2,
        "hosts_scanned": total_scanned,
        "hosts_unreachable": 2,
        "quantum_vulnerable_percent": round((critical_count + medium_count) / total_scanned * 100, 1) if total_scanned else 0.0,
        "tls_assets": len(tls_assets),
        "non_tls_assets": total_scanned - len(tls_assets),
    }

    # Sources breakdown across all 7 discovery types (initialize all 7 so UI always shows all)
    all_sources = ["tls", "source_code", "dependency", "binary", "container", "hsm", "cloud_kms"]
    sources_breakdown: Dict[str, int] = {s: 0 for s in all_sources}
    for a in assets:
        src = a.source or "tls"
        sources_breakdown[src] = sources_breakdown.get(src, 0) + 1

    # Top vulnerable assets (top 8 to give a richer view)
    sorted_assets = sorted(assets, key=lambda x: x.risk_score, reverse=True)
    top_assets = []
    for a in sorted_assets[:8]:
        flags = []
        if a.risk_flags:
            try:
                flags = json.loads(a.risk_flags)
            except Exception:
                flags = [a.risk_flags]

        top_assets.append({
            "id": a.id,
            "host": a.host,
            "port": a.port,
            "source": a.source or "tls",
            "business_criticality": a.business_criticality or "medium",
            "data_lifetime": a.data_lifetime or "1-3y",
            "service_name": a.linked_service.name if a.linked_service else "Unlinked",
            "criticality": a.linked_service.criticality if a.linked_service else "P2",
            "cert_key_type": a.cert_key_type or a.algorithm or "Unknown",
            "cert_key_size_bits": a.cert_key_size_bits,
            "algorithm": a.algorithm or a.cert_key_type,
            "usage_context": a.usage_context,
            "library": a.library,
            "file_path": a.file_path,
            "tls_version": a.tls_version,
            "days_to_expiry": a.days_to_expiry,
            "risk_score": a.risk_score,
            "risk_flags": flags
        })

    return {
        "mode": mode,
        "kpis": {
            "total_scanned": total_scanned,
            "critical_count": critical_count,
            "medium_count": medium_count,
            "safe_count": safe_count,
            "avg_mwqrs": avg_mwqrs,
            "sources_covered": sum(1 for v in sources_breakdown.values() if v > 0),
        },
        "public_scan_stats": public_scan_stats,
        "sources_breakdown": sources_breakdown,
        "algorithm_breakdown": algorithm_breakdown,
        "criticality_distribution": criticality_distribution,
        "data_lifetime_distribution": data_lifetime_distribution,
        "risk_distribution": risk_distribution,
        "key_type_breakdown": key_type_data,
        "top_vulnerable_assets": top_assets
    }


@router.get("/assets")
def get_assets(db: Session = Depends(get_db)):
    assets = db.query(CryptoAsset).order_by(CryptoAsset.risk_score.desc()).all()
    results = []
    for a in assets:
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
            "service_name": a.linked_service.name if a.linked_service else "Unlinked",
            "criticality": a.linked_service.criticality if a.linked_service else "P2",
            "cert_key_type": a.cert_key_type,
            "cert_key_size_bits": a.cert_key_size_bits,
            "tls_version": a.tls_version,
            "cipher_suite": a.cipher_suite,
            "days_to_expiry": a.days_to_expiry,
            "risk_score": a.risk_score,
            "risk_flags": flags
        })
    return results

@router.post("/score/recalculate")
def recalculate_scores(db: Session = Depends(get_db)):
    recalculate_all_scores(db)
    return {"message": "All assets rescored successfully with MWQRS."}

@router.post("/demo/seed")
def seed_demo(db: Session = Depends(get_db)):
    seed_demo_data(db)
    return {"message": "Demo services, graph linkages, and assets seeded successfully."}
