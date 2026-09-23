from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.graph import get_graph_data, compute_blast_radius

router = APIRouter(prefix="/graph", tags=["Dependency Graph & Blast Radius"])

@router.get("/dependencies")
def get_dependency_graph(db: Session = Depends(get_db)):
    """
    Returns the complete NetworkX dependency graph data for all services,
    including node criticality, MWQRS risk scores, edge mappings, and critical path.
    """
    return get_graph_data(db)

@router.get("/blast-radius/{service_id}")
def get_service_blast_radius(service_id: int, db: Session = Depends(get_db)):
    """
    Computes the blast radius impact for a given service using reversed DAG reachability.
    Identifies all downstream services and cryptographic assets impacted by a compromise or rollover.
    """
    result = compute_blast_radius(db, service_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
