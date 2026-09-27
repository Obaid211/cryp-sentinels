"""
phase3_routes.py — ECDAT Phase 3 API Routes
============================================
Exposes Phase 3 discovery endpoints:
  POST /api/phase3/scan/hsm        — Hardware Security Module (HSM) & PKCS#11 discovery -> inventory (source="hsm")
  POST /api/phase3/scan/cloud-kms  — Cloud KMS & cert-management discovery -> inventory (source="cloud_kms")
  GET  /api/phase3/status          — Status of HSM and Cloud KMS credential/driver configurations (live vs mock)

All findings write into the unified CryptoAsset inventory.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.hsm_scanner import scan_hsm_configuration, import_hsm_finding_to_inventory, get_hsm_status
from app.services.cloud_kms_scanner import scan_cloud_kms_manifest, import_cloud_kms_findings_to_inventory, get_cloud_kms_status

router = APIRouter(prefix="/phase3", tags=["Phase 3 — Hardware & Cloud Discovery"])


class HsmScanRequest(BaseModel):
    content: Optional[str] = Field(None, description="Optional PKCS#11 configuration text; if omitted, performs live module audit if configured or mock fallback")
    filename: str = Field("pkcs11.conf", description="Configuration filename")
    vendor_hint: Optional[str] = Field(None, description="Optional vendor identifier e.g. thales_luna, utimaco_cryptoserver, yubihsm2, aws_cloudhsm")
    service_name: Optional[str] = Field("Payment-Gateway", description="Target service to link findings to")
    business_criticality: str = Field("critical", description="critical|high|medium|low")
    data_lifetime: str = Field("5-10y", description="<1y|1-3y|3-5y|5-10y|>10y")
    import_to_inventory: bool = Field(True, description="Write findings to unified inventory")


class CloudKmsScanRequest(BaseModel):
    content: Optional[str] = Field(None, description="Optional Cloud KMS JSON or YAML key listing; if omitted, queries live cloud provider API or falls back to mock")
    filename: str = Field("cloud_kms_keys.json", description="Configuration filename")
    provider_hint: Optional[str] = Field("aws_kms", description="aws_kms | azure_key_vault | gcp_kms")
    service_name: Optional[str] = Field("Core-Database-Proxy", description="Target service to link findings to")
    business_criticality: str = Field("critical", description="critical|high|medium|low")
    data_lifetime: str = Field("5-10y", description="<1y|1-3y|3-5y|5-10y|>10y")
    import_to_inventory: bool = Field(True, description="Write findings to unified inventory")


@router.get("/status")
def get_phase3_status():
    """
    Returns operational status (live vs mock) and credential readiness
    for Hardware Security Modules and Cloud KMS providers.
    """
    return {
        "hsm": get_hsm_status(),
        "cloud_kms": get_cloud_kms_status(),
    }


@router.post("/scan/hsm")
def scan_hsm_endpoint(
    req: HsmScanRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 3: Hardware Security Module (HSM) discovery.
    Identifies vendor profile, supported cryptographic mechanisms, and FIPS 140 ratings.
    """
    try:
        result = scan_hsm_configuration(
            config_text=req.content,
            filename=req.filename,
            vendor_hint=req.vendor_hint,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    imported = []
    if req.import_to_inventory:
        imported = import_hsm_finding_to_inventory(
            db=db,
            hsm_result=result,
            service_name=req.service_name,
            business_criticality=req.business_criticality,
            data_lifetime=req.data_lifetime,
        )

    result["inventory_imported"] = len(imported)
    result["import_results"] = imported if imported else None
    return result


@router.post("/scan/cloud-kms")
def scan_cloud_kms_endpoint(
    req: CloudKmsScanRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 3: Cloud KMS & Certificate Management discovery.
    Audits cloud key specifications, rotation status, and PQC readiness.
    """
    result = scan_cloud_kms_manifest(
        manifest_data=req.content,
        filename=req.filename,
        provider_hint=req.provider_hint,
    )

    imported = []
    if req.import_to_inventory:
        imported = import_cloud_kms_findings_to_inventory(
            db=db,
            kms_result=result,
            service_name=req.service_name,
            business_criticality=req.business_criticality,
            data_lifetime=req.data_lifetime,
        )

    result["inventory_imported"] = len(imported)
    result["import_results"] = imported if imported else None
    return result
