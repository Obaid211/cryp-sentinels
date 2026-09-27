"""
phase1_routes.py — ECDAT Phase 1 API Routes
=============================================
Exposes the new Phase 1 discovery endpoints:
  POST /api/phase1/scan/source-code       — source code scanner → inventory
  POST /api/phase1/scan/dependency        — dependency manifest scanner → inventory
  POST /api/phase1/recommend              — PQC recommendation engine (standalone)
  PUT  /api/phase1/assets/{id}/criticality — Update business_criticality + data_lifetime
  GET  /api/phase1/recommendation/{id}    — Get stored PQC recommendation for an asset

All are reachable from the existing pipeline; none create standalone tools.
"""

import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import CryptoAsset, Service
from app.services.scanners import scan_source_code, import_source_finding_to_inventory
from app.services.dependency_scanner import scan_dependency_manifest, import_dependency_to_inventory
from app.services.pqc_engine import recommend_pqc, get_bulk_recommendations
from app.services.scoring import calculate_mwqrs

router = APIRouter(prefix="/phase1", tags=["Phase 1 — Multi-Source Discovery"])

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SourceCodeScanRequest(BaseModel):
    content: str = Field(..., description="Full source code content to scan")
    filename: str = Field("main.py", description="Filename for display in findings")
    repo_name: str = Field("source_repo", description="Repository/project name for synthetic host")
    service_name: Optional[str] = Field(None, description="Service name to link assets to")
    business_criticality: str = Field("medium", description="critical|high|medium|low")
    data_lifetime: str = Field("1-3y", description="<1y|1-3y|3-5y|5-10y|>10y")
    import_to_inventory: bool = Field(True, description="Write findings to unified inventory")


class DependencyScanRequest(BaseModel):
    content: str = Field(..., description="Manifest file content")
    filename: str = Field("requirements.txt", description="Manifest filename")
    service_name: Optional[str] = Field(None, description="Service name to link assets to")
    business_criticality: str = Field("medium", description="critical|high|medium|low")
    data_lifetime: str = Field("1-3y", description="<1y|1-3y|3-5y|5-10y|>10y")
    import_to_inventory: bool = Field(True, description="Write findings to unified inventory")


class PqcRecommendRequest(BaseModel):
    algorithm: str = Field(..., description="Current algorithm e.g. RSA-2048, ECDSA-P-256")
    usage_context: Optional[str] = Field(None, description="Usage: key_exchange|digital_signature|symmetric_encryption|hash")
    key_size: Optional[int] = Field(None, description="Key size in bits")
    library: Optional[str] = Field(None, description="Library name if known")


class UpdateCriticalityRequest(BaseModel):
    business_criticality: str = Field(..., description="critical|high|medium|low")
    data_lifetime: str = Field(..., description="<1y|1-3y|3-5y|5-10y|>10y")


# ---------------------------------------------------------------------------
# 1. Source-Code Scanner → Inventory
# ---------------------------------------------------------------------------

@router.post("/scan/source-code")
def scan_source_code_endpoint(
    req: SourceCodeScanRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 1: Scan source code for cryptographic usage patterns.
    Findings include per-line: file, line, algorithm, usage, confidence, quantum_risk.
    When import_to_inventory=True, writes to unified inventory with source='source_code'.
    """
    findings = scan_source_code(req.content, req.filename)

    imported = []
    if req.import_to_inventory:
        for finding in findings:
            result = import_source_finding_to_inventory(
                db=db,
                finding=finding,
                repo_name=req.repo_name,
                service_name=req.service_name,
                business_criticality=req.business_criticality,
                data_lifetime=req.data_lifetime,
            )
            imported.append(result)

    return {
        "filename": req.filename,
        "repo_name": req.repo_name,
        "source": "source_code",
        "findings_count": len(findings),
        "findings": findings,
        "inventory_imported": len(imported),
        "import_results": imported if imported else None,
    }


# ---------------------------------------------------------------------------
# 2. Dependency / Library Scanner → Inventory
# ---------------------------------------------------------------------------

@router.post("/scan/dependency")
def scan_dependency_endpoint(
    req: DependencyScanRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 1: Scan a dependency manifest for crypto library risk.
    Writes crypto-capable libraries to unified inventory with source='dependency'.
    """
    findings = scan_dependency_manifest(req.content, req.filename)

    imported = []
    if req.import_to_inventory:
        for finding in findings:
            result = import_dependency_to_inventory(
                db=db,
                finding=finding,
                service_name=req.service_name,
                business_criticality=req.business_criticality,
                data_lifetime=req.data_lifetime,
            )
            imported.append(result)

    return {
        "filename": req.filename,
        "source": "dependency",
        "findings_count": len(findings),
        "findings": findings,
        "inventory_imported": len(imported),
        "import_results": imported if imported else None,
    }


# ---------------------------------------------------------------------------
# 3. PQC Recommendation Engine (standalone)
# ---------------------------------------------------------------------------

@router.post("/recommend")
def get_pqc_recommendation(req: PqcRecommendRequest):
    """
    Phase 1: Get a concrete PQC migration recommendation for a given algorithm.
    Returns pure-PQC target + hybrid alternative + migration steps.
    """
    rec = recommend_pqc(
        current_algorithm=req.algorithm,
        usage_context=req.usage_context,
        key_size=req.key_size,
        library=req.library,
    )
    return rec


@router.post("/recommend/bulk")
def get_bulk_pqc_recommendations(assets: List[Dict[str, Any]]):
    """
    Phase 1: Get PQC recommendations for multiple assets at once.
    Each asset dict should have cert_key_type/algorithm, usage_context, cert_key_size_bits.
    """
    return get_bulk_recommendations(assets)


# ---------------------------------------------------------------------------
# 4. Update business_criticality + data_lifetime on an existing asset
# ---------------------------------------------------------------------------

@router.put("/assets/{asset_id}/criticality")
def update_asset_criticality(
    asset_id: int,
    req: UpdateCriticalityRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 1: Update the business_criticality and data_lifetime fields on an
    existing asset. These feed directly into MWQRS scoring and Mosca urgency.
    The risk_score is recalculated immediately on save.
    """
    asset = db.query(CryptoAsset).filter(CryptoAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset ID {asset_id} not found")

    valid_criticalities = {"critical", "high", "medium", "low"}
    valid_lifetimes = {"<1y", "1-3y", "3-5y", "5-10y", ">10y"}

    if req.business_criticality not in valid_criticalities:
        raise HTTPException(status_code=400, detail=f"business_criticality must be one of: {valid_criticalities}")
    if req.data_lifetime not in valid_lifetimes:
        raise HTTPException(status_code=400, detail=f"data_lifetime must be one of: {valid_lifetimes}")

    asset.business_criticality = req.business_criticality
    asset.data_lifetime = req.data_lifetime

    # Recalculate MWQRS with new criticality/lifetime
    svc_crit = asset.linked_service.criticality if asset.linked_service else "P2"
    record = {
        "status": asset.status or "success",
        "cert_key_type": asset.cert_key_type or asset.algorithm or "RSA",
        "cert_key_size_bits": asset.cert_key_size_bits,
        "tls_version": asset.tls_version,
        "days_to_expiry": asset.days_to_expiry,
        "business_criticality": req.business_criticality,
        "data_lifetime": req.data_lifetime,
    }
    asset.risk_score = calculate_mwqrs(record, service_criticality=svc_crit)

    # Refresh PQC recommendation
    from app.services.pqc_engine import recommend_pqc
    key_type = asset.cert_key_type or asset.algorithm or "RSA"
    pqc_rec = recommend_pqc(key_type, asset.usage_context)
    asset.pqc_recommendation = json.dumps(pqc_rec)

    db.commit()
    return {
        "asset_id": asset_id,
        "host": asset.host,
        "port": asset.port,
        "business_criticality": asset.business_criticality,
        "data_lifetime": asset.data_lifetime,
        "new_risk_score": asset.risk_score,
        "pqc_recommendation": pqc_rec,
    }


# ---------------------------------------------------------------------------
# 5. Get stored PQC recommendation for an asset
# ---------------------------------------------------------------------------

@router.get("/recommendation/{asset_id}")
def get_asset_pqc_recommendation(asset_id: int, db: Session = Depends(get_db)):
    """
    Phase 1: Returns the stored PQC recommendation for a specific asset,
    recomputing live if not yet stored.
    """
    asset = db.query(CryptoAsset).filter(CryptoAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset ID {asset_id} not found")

    from app.services.pqc_engine import recommend_pqc
    pqc_data = None
    if asset.pqc_recommendation:
        try:
            pqc_data = json.loads(asset.pqc_recommendation)
        except Exception:
            pass

    if not pqc_data:
        key_type = asset.cert_key_type or asset.algorithm or "RSA"
        pqc_data = recommend_pqc(key_type, asset.usage_context, asset.cert_key_size_bits)
        asset.pqc_recommendation = json.dumps(pqc_data)
        db.commit()

    return {
        "asset_id": asset_id,
        "host": asset.host,
        "port": asset.port,
        "source": asset.source or "tls",
        "algorithm": asset.cert_key_type or asset.algorithm,
        "usage_context": asset.usage_context,
        "business_criticality": asset.business_criticality,
        "data_lifetime": asset.data_lifetime,
        "pqc_recommendation": pqc_data,
    }


# ---------------------------------------------------------------------------
# 6. Backfill PQC recommendations for all existing assets
# ---------------------------------------------------------------------------

@router.post("/backfill-recommendations")
def backfill_pqc_recommendations(db: Session = Depends(get_db)):
    """
    Phase 1: Backfill pqc_recommendation for all assets that don't have one yet.
    Also ensures source='tls' for existing TLS-discovered assets.
    """
    from app.services.pqc_engine import recommend_pqc
    assets = db.query(CryptoAsset).all()
    updated = 0
    for asset in assets:
        key_type = asset.cert_key_type or asset.algorithm or "RSA"
        if not asset.pqc_recommendation:
            pqc_rec = recommend_pqc(key_type, asset.usage_context, asset.cert_key_size_bits)
            asset.pqc_recommendation = json.dumps(pqc_rec)
            updated += 1
        if not asset.source:
            asset.source = "tls"
        if not asset.business_criticality:
            asset.business_criticality = "medium"
        if not asset.data_lifetime:
            asset.data_lifetime = "1-3y"
    db.commit()
    return {"updated_assets": updated, "total_assets": len(assets)}
