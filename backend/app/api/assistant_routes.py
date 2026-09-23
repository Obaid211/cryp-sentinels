from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.snapshots import save_snapshot, list_snapshots, compare_snapshots
from app.services.assistant import query_cryptographic_assistant, _get_api_keys

router = APIRouter(prefix="", tags=["Assistant & Snapshots"])

class SaveSnapshotRequest(BaseModel):
    name: Optional[str] = None

class ChatRequest(BaseModel):
    prompt: str
    mode: Optional[str] = "LIVE"

@router.post("/snapshots/save")
def create_snapshot(req: SaveSnapshotRequest, db: Session = Depends(get_db)):
    """Saves the current state of cryptographic inventory as an immutable snapshot."""
    res = save_snapshot(db, req.name)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res

@router.get("/snapshots/list")
def get_snapshot_list(db: Session = Depends(get_db)):
    """Returns all saved scan snapshots in descending chronological order."""
    return list_snapshots(db)

@router.get("/snapshots/diff")
def get_diff(
    old_id: int = Query(..., description="ID of baseline snapshot"),
    new_id: int = Query(..., description="ID of comparison snapshot"),
    db: Session = Depends(get_db)
):
    """Computes exact cryptographic attribute and MWQRS delta between two snapshots."""
    res = compare_snapshots(db, old_id, new_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res

@router.get("/assistant/status")
def get_assistant_status(mode: str = Query("LIVE", pattern="^(LIVE|CACHED|OFFLINE)$")):
    """Returns live operational telemetry of the AI Advisor engine."""
    keys = _get_api_keys()
    has_keys = len(keys) > 0
    return {
        "status": "online",
        "mode": mode,
        "primary_model": "gemini-3.6-flash" if (has_keys and mode != "OFFLINE") else "sovereign-expert-engine",
        "gemini_connected": has_keys and mode != "OFFLINE",
        "keypool_size": len(keys) if mode != "OFFLINE" else 0,
        "sovereign_fallback_active": True,
        "capabilities": [
            "NIST FIPS 203/204/205 Guidance",
            "Mosca Urgency Inequality Evaluation",
            "MWQRS Quantitative Mathematical Analysis",
            "Live Inventory Posture Grounding",
            "Hybrid Classical+PQC Transition Sequences"
        ]
    }

@router.post("/assistant/chat")
def chat_with_assistant(req: ChatRequest, db: Session = Depends(get_db)):
    """Interacts with the ECDAT Cryptographic Advisor (Gemini or Sovereign Engine)."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")
    return query_cryptographic_assistant(req.prompt, mode=req.mode or "LIVE", db=db)
