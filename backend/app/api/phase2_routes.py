"""
phase2_routes.py — ECDAT Phase 2 API Routes
============================================
Exposes Phase 2 discovery endpoints:
  POST /api/phase2/scan/binary     — Binary static symbol inspection -> inventory (source="binary")
  POST /api/phase2/scan/container  — Container definition & package inspection -> inventory (source="container")

All findings write into the same unified CryptoAsset inventory.
"""

import base64
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.binary_scanner import scan_binary_bytes, import_binary_finding_to_inventory
from app.services.container_scanner import scan_container_definition, import_container_finding_to_inventory

router = APIRouter(prefix="/phase2", tags=["Phase 2 — Binary & Container Discovery"])


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------
class BinaryScanRequest(BaseModel):
    content_base64: Optional[str] = Field(None, description="Base64 encoded binary file bytes")
    content_hex: Optional[str] = Field(None, description="Hex encoded binary file bytes")
    content_text: Optional[str] = Field(None, description="Text representation or symbol dump")
    filename: str = Field("application.bin", description="Executable or shared object filename")
    service_name: Optional[str] = Field(None, description="Target service to link findings to")
    business_criticality: str = Field("high", description="critical|high|medium|low")
    data_lifetime: str = Field("3-5y", description="<1y|1-3y|3-5y|5-10y|>10y")
    import_to_inventory: bool = Field(True, description="Write findings to unified inventory")


class ContainerScanRequest(BaseModel):
    content: str = Field(..., description="Dockerfile or Containerfile content")
    filename: str = Field("Dockerfile", description="Containerfile filename")
    package_list: Optional[str] = Field(None, description="Installed package listing (dpkg/apk/rpm)")
    container_name: str = Field("app-service-container", description="Container image or service name")
    service_name: Optional[str] = Field(None, description="Target service to link findings to")
    business_criticality: str = Field("high", description="critical|high|medium|low")
    data_lifetime: str = Field("1-3y", description="<1y|1-3y|3-5y|5-10y|>10y")
    import_to_inventory: bool = Field(True, description="Write findings to unified inventory")


# ---------------------------------------------------------------------------
# 1. Binary Scanner Endpoint
# ---------------------------------------------------------------------------
@router.post("/scan/binary")
def scan_binary_endpoint(
    req: BinaryScanRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 2: Static inspection of executable binary for cryptographic symbols,
    library brand strings, and post-quantum markers.
    """
    data = b""
    if req.content_base64:
        try:
            data = base64.b64decode(req.content_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {e}")
    elif req.content_hex:
        try:
            data = bytes.fromhex(req.content_hex)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}")
    elif req.content_text:
        data = req.content_text.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Must provide content_base64, content_hex, or content_text")

    result = scan_binary_bytes(data=data, filename=req.filename)

    imported = []
    if req.import_to_inventory:
        for finding in result.get("findings", []):
            imp = import_binary_finding_to_inventory(
                db=db,
                finding=finding,
                binary_name=req.filename,
                service_name=req.service_name,
                business_criticality=req.business_criticality,
                data_lifetime=req.data_lifetime,
            )
            imported.append(imp)

    result["inventory_imported"] = len(imported)
    result["import_results"] = imported if imported else None
    return result


@router.post("/scan/binary/upload")
async def scan_binary_upload(
    file: UploadFile = File(...),
    service_name: Optional[str] = Form(None),
    business_criticality: str = Form("high"),
    data_lifetime: str = Form("3-5y"),
    import_to_inventory: bool = Form(True),
    db: Session = Depends(get_db)
):
    """
    Phase 2: Upload a binary file (.so, .dll, .exe, ELF) directly via multipart form.
    """
    content = await file.read()
    result = scan_binary_bytes(data=content, filename=file.filename or "uploaded.bin")

    imported = []
    if import_to_inventory:
        for finding in result.get("findings", []):
            imp = import_binary_finding_to_inventory(
                db=db,
                finding=finding,
                binary_name=file.filename or "uploaded.bin",
                service_name=service_name,
                business_criticality=business_criticality,
                data_lifetime=data_lifetime,
            )
            imported.append(imp)

    result["inventory_imported"] = len(imported)
    result["import_results"] = imported if imported else None
    return result


# ---------------------------------------------------------------------------
# 2. Container Scanner Endpoint
# ---------------------------------------------------------------------------
@router.post("/scan/container")
def scan_container_endpoint(
    req: ContainerScanRequest,
    db: Session = Depends(get_db)
):
    """
    Phase 2: Scans Dockerfile and container metadata for cryptographic misconfigurations,
    outdated base images, and embedded secrets.
    """
    result = scan_container_definition(
        dockerfile_content=req.content,
        filename=req.filename,
        package_list=req.package_list,
    )

    imported = []
    if req.import_to_inventory:
        for finding in result.get("findings", []):
            imp = import_container_finding_to_inventory(
                db=db,
                finding=finding,
                container_name=req.container_name,
                service_name=req.service_name,
                business_criticality=req.business_criticality,
                data_lifetime=req.data_lifetime,
            )
            imported.append(imp)

    result["inventory_imported"] = len(imported)
    result["import_results"] = imported if imported else None
    return result
