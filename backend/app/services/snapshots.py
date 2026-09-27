import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.models import ScanSnapshot, CryptoAsset, Service

def save_snapshot(db: Session, name: Optional[str] = None) -> Dict[str, Any]:
    """Captures the current state of all cryptographic assets and stores a JSON snapshot."""
    assets = db.query(CryptoAsset).all()
    if not assets:
        return {"error": "No assets available in inventory to snapshot."}

    snapshot_name = name or f"Snapshot {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    total = len(assets)
    total_risk = 0.0
    critical_count = 0
    medium_count = 0
    safe_count = 0
    asset_records = []

    for a in assets:
        svc_name = a.linked_service.name if a.linked_service else "Unlinked"
        crit = a.linked_service.criticality if a.linked_service else "P2"
        score = float(a.risk_score or 0.0)
        total_risk += score

        if score >= 60.0:
            critical_count += 1
        elif score >= 25.0:
            medium_count += 1
        else:
            safe_count += 1

        asset_records.append({
            "id": a.id,
            "host": a.host,
            "port": a.port,
            "source": a.source or "tls",
            "business_criticality": a.business_criticality or "medium",
            "data_lifetime": a.data_lifetime or "1-3y",
            "service": svc_name,
            "criticality": crit,
            "tls_version": a.tls_version,
            "algorithm": a.cert_key_type or a.algorithm or "Unknown",
            "key_size": a.cert_key_size_bits,
            "days_to_expiry": a.days_to_expiry,
            "mwqrs": score,
            "risk_flags": json.loads(a.risk_flags) if a.risk_flags else []
        })

    avg_risk = round(total_risk / total, 1) if total > 0 else 0.0

    snapshot = ScanSnapshot(
        name=snapshot_name,
        created_at=datetime.now(timezone.utc),
        asset_count=total,
        avg_risk=avg_risk,
        critical_count=critical_count,
        medium_count=medium_count,
        safe_count=safe_count,
        snapshot_data=json.dumps(asset_records)
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)

    return {
        "id": snapshot.id,
        "name": snapshot.name,
        "created_at": snapshot.created_at.isoformat(),
        "asset_count": snapshot.asset_count,
        "avg_risk": snapshot.avg_risk,
        "critical_count": snapshot.critical_count
    }


def list_snapshots(db: Session) -> List[Dict[str, Any]]:
    """Returns chronological list of all saved snapshots."""
    snapshots = db.query(ScanSnapshot).order_by(ScanSnapshot.created_at.desc()).all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "created_at": s.created_at.isoformat(),
            "asset_count": s.asset_count,
            "avg_risk": s.avg_risk,
            "critical_count": s.critical_count,
            "medium_count": s.medium_count,
            "safe_count": s.safe_count
        }
        for s in snapshots
    ]


def compare_snapshots(db: Session, old_id: int, new_id: int) -> Dict[str, Any]:
    """
    Compares two saved snapshots and returns an exact cryptographic delta:
    added assets, removed assets, modified attributes, and MWQRS risk shift.
    """
    old_snap = db.query(ScanSnapshot).filter(ScanSnapshot.id == old_id).first()
    new_snap = db.query(ScanSnapshot).filter(ScanSnapshot.id == new_id).first()

    if not old_snap or not new_snap:
        return {"error": f"One or both snapshots could not be found (old_id={old_id}, new_id={new_id})."}

    old_assets_list = json.loads(old_snap.snapshot_data)
    new_assets_list = json.loads(new_snap.snapshot_data)

    old_dict = {f"{a['host']}:{a['port']}": a for a in old_assets_list}
    new_dict = {f"{a['host']}:{a['port']}": a for a in new_assets_list}

    old_keys = set(old_dict.keys())
    new_keys = set(new_dict.keys())

    added_keys = new_keys - old_keys
    removed_keys = old_keys - new_keys
    shared_keys = old_keys & new_keys

    added = [new_dict[k] for k in sorted(added_keys)]
    removed = [old_dict[k] for k in sorted(removed_keys)]

    modified = []
    alerts = []
    risk_increased = 0
    risk_decreased = 0

    for key in sorted(shared_keys):
        o = old_dict[key]
        n = new_dict[key]
        changes = []

        old_mwqrs = float(o.get("mwqrs") or 0.0)
        new_mwqrs = float(n.get("mwqrs") or 0.0)
        mwqrs_delta = round(new_mwqrs - old_mwqrs, 1)

        if str(o.get("algorithm")) != str(n.get("algorithm")):
            changes.append({
                "property": "Algorithm",
                "old": o.get("algorithm"),
                "new": n.get("algorithm")
            })

        if str(o.get("key_size")) != str(n.get("key_size")):
            changes.append({
                "property": "Key Size",
                "old": f"{o.get('key_size')}b",
                "new": f"{n.get('key_size')}b"
            })

        if str(o.get("tls_version")) != str(n.get("tls_version")):
            changes.append({
                "property": "TLS Version",
                "old": o.get("tls_version"),
                "new": n.get("tls_version")
            })

        if str(o.get("business_criticality")) != str(n.get("business_criticality")):
            changes.append({
                "property": "Business Criticality",
                "old": o.get("business_criticality"),
                "new": n.get("business_criticality")
            })

        if str(o.get("data_lifetime")) != str(n.get("data_lifetime")):
            changes.append({
                "property": "Data Lifetime",
                "old": o.get("data_lifetime"),
                "new": n.get("data_lifetime")
            })

        if abs(mwqrs_delta) >= 0.1:
            if mwqrs_delta > 0:
                risk_increased += 1
            else:
                risk_decreased += 1
            changes.append({
                "property": "MWQRS Risk Score",
                "old": old_mwqrs,
                "new": new_mwqrs,
                "delta": mwqrs_delta
            })

        if changes:
            mod_item = {
                "target": key,
                "host": n.get("host"),
                "port": n.get("port"),
                "service": n.get("service"),
                "criticality": n.get("criticality"),
                "old_mwqrs": old_mwqrs,
                "new_mwqrs": new_mwqrs,
                "mwqrs_delta": mwqrs_delta,
                "changes": changes
            }
            modified.append(mod_item)

            alert_desc = f"ALERT on {key} ({n.get('service')}): " + "; ".join(
                f"{c['property']} changed from {c['old']} to {c['new']}" for c in changes
            )
            alerts.append(alert_desc)

    return {
        "old_snapshot": {
            "id": old_snap.id,
            "name": old_snap.name,
            "created_at": old_snap.created_at.isoformat(),
            "avg_risk": old_snap.avg_risk,
            "asset_count": old_snap.asset_count
        },
        "new_snapshot": {
            "id": new_snap.id,
            "name": new_snap.name,
            "created_at": new_snap.created_at.isoformat(),
            "avg_risk": new_snap.avg_risk,
            "asset_count": new_snap.asset_count
        },
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
            "risk_increased_count": risk_increased,
            "risk_decreased_count": risk_decreased,
            "overall_risk_delta": round((new_snap.avg_risk or 0.0) - (old_snap.avg_risk or 0.0), 1)
        },
        "added": added,
        "removed": removed,
        "modified": modified,
        "alerts": alerts
    }
