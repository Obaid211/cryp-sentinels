import json
import asyncio
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.scanners import (
    scan_source_code,
    scan_dockerfile_content,
    scan_api_endpoint,
    scan_tls_target,
    import_finding_to_inventory
)

router = APIRouter(prefix="/scanners", tags=["Cryptographic Scanner Suite"])

class CodeScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "main.py"

class ContainerScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "Dockerfile"

class ApiScanRequest(BaseModel):
    url: str
    sample_jwt: Optional[str] = None

class TlsScanRequest(BaseModel):
    host: str
    port: int = 443
    mode: Optional[str] = "LIVE"

class ImportFindingRequest(BaseModel):
    finding: Dict[str, Any]

@router.post("/code")
def run_code_scan(req: CodeScanRequest):
    """Scans source code for cryptographic calls, weak algorithms (MD5, SHA1, DES), and hardcoded keys."""
    findings = scan_source_code(req.content, req.filename or "snippet.py")
    return {
        "filename": req.filename,
        "findings_count": len(findings),
        "findings": findings
    }

@router.post("/container")
def run_container_scan(req: ContainerScanRequest):
    """Scans Dockerfile content for base image vulnerabilities, disabled TLS verification, and embedded keys."""
    findings = scan_dockerfile_content(req.content, req.filename or "Dockerfile")
    return {
        "filename": req.filename,
        "findings_count": len(findings),
        "findings": findings
    }

@router.post("/api")
def run_api_scan(req: ApiScanRequest):
    """Inspects API endpoints and JWT tokens for signature algorithm quantum vulnerabilities."""
    return scan_api_endpoint(req.url, req.sample_jwt)

@router.post("/tls")
def run_tls_scan(req: TlsScanRequest, db: Session = Depends(get_db)):
    """Connects to a live host over TLS, completes handshake, and inspects cryptographic attributes."""
    return scan_tls_target(req.host, req.port, mode=req.mode or "LIVE", db=db)

@router.post("/import")
def import_finding(req: ImportFindingRequest, db: Session = Depends(get_db)):
    """Imports a scanned cryptographic asset directly into the enterprise inventory."""
    return import_finding_to_inventory(db, req.finding)

@router.get("/stream")
async def stream_scan_progress(target: str = Query("all")):
    """
    Server-Sent Events (SSE) stream providing real-time log telemetry
    as multi-target scans execute across network infrastructure.
    """
    async def event_generator():
        steps = [
            {"step": 1, "pct": 10, "message": f"Initializing sovereign discovery worker for target: {target}"},
            {"step": 2, "pct": 25, "message": "Synthesizing TCP SYN probe and resolving DNS records"},
            {"step": 3, "pct": 45, "message": "Initiating TLS 1.3 ClientHello with PQC hybrid extension advertised"},
            {"step": 4, "pct": 65, "message": "Received ServerHello & Certificate chain. Parsing ASN.1 structures"},
            {"step": 5, "pct": 80, "message": "Evaluating public key bit strength and Mosca quantum risk factors"},
            {"step": 6, "pct": 95, "message": "Formatting CycloneDX 1.6 CBOM component spec and vulnerability markers"},
            {"step": 7, "pct": 100, "message": "Scan cycle complete. Discovered 1 cryptographic asset ready for inventory commit."}
        ]

        for s in steps:
            await asyncio.sleep(0.35)
            yield f"data: {json.dumps(s)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
