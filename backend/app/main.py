from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.session import init_db
from app.api.dashboard import router as dashboard_router
from app.api.stage2_routes import router as stage2_router
from app.api.graph import router as graph_router
from app.api.simulate import router as simulate_router
from app.api.scanners import router as scanners_router
from app.api.assistant_routes import router as assistant_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Backend API for ECDAT — Enterprise Cryptographic Discovery & Analysis Tool",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "ecdat-backend",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# Include API routers
app.include_router(dashboard_router, prefix="/api", tags=["Dashboard"])
app.include_router(stage2_router, prefix="/api", tags=["Data & Inventory"])
app.include_router(graph_router, prefix="/api", tags=["Dependency Graph & Blast Radius"])
app.include_router(simulate_router, prefix="/api", tags=["PQC Migration Simulator"])
app.include_router(scanners_router, prefix="/api", tags=["Scanner Suite"])
app.include_router(assistant_router, prefix="/api", tags=["Assistant & Snapshots"])



