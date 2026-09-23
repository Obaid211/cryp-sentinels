from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.simulate import (
    MIGRATION_STRATEGIES,
    simulate_asset,
    simulate_inventory,
    get_topological_sequence
)

router = APIRouter(prefix="/simulate", tags=["PQC Migration Simulator"])

class SimulationRequest(BaseModel):
    strategy: str = "HYBRID"
    asset_ids: Optional[List[int]] = None

@router.get("/strategies")
def get_available_strategies():
    """
    Returns available PQC migration simulation strategies (HYBRID, PURE_PQC, CLASSICAL_HARDENING).
    """
    return list(MIGRATION_STRATEGIES.values())

@router.post("/run")
def run_simulation(req: SimulationRequest, db: Session = Depends(get_db)):
    """
    Executes an estate-wide PQC migration simulation under the chosen strategy.
    Returns before vs after MWQRS scores, effort hours, critical elimination count, and migration waves.
    """
    result = simulate_inventory(db, req.strategy)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/asset/{asset_id}")
def simulate_single_asset(
    asset_id: int,
    strategy: str = Query("HYBRID", description="HYBRID, PURE_PQC, or CLASSICAL_HARDENING"),
    db: Session = Depends(get_db)
):
    """
    Simulates PQC migration for a specific crypto asset.
    """
    result = simulate_asset(db, asset_id, strategy)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/sequence")
def get_migration_sequence(
    strategy: str = Query("HYBRID", description="HYBRID, PURE_PQC, or CLASSICAL_HARDENING"),
    db: Session = Depends(get_db)
):
    """
    Returns optimal topological migration sequence and phased wave assignments.
    """
    return get_topological_sequence(db, strategy)
