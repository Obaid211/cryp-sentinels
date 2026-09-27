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
from app.api.phase1_routes import router as phase1_router
from app.api.phase2_routes import router as phase2_router
from app.api.phase3_routes import router as phase3_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        from app.db.session import SessionLocal
        from app.services.inventory import seed_demo_data
        from app.models.models import Service, CryptoAsset
        from app.services.pqc_engine import recommend_pqc
        import json

        db = SessionLocal()
        if db.query(Service).count() == 0 or db.query(CryptoAsset).count() == 0:
            seed_demo_data(db)

        assets = db.query(CryptoAsset).all()
        for asset in assets:
            if not asset.pqc_recommendation:
                key_type = asset.cert_key_type or asset.algorithm or "RSA"
                pqc_rec = recommend_pqc(key_type, asset.usage_context, asset.cert_key_size_bits)
                asset.pqc_recommendation = json.dumps(pqc_rec)
            if not asset.source:
                asset.source = "tls"
            if not asset.business_criticality:
                asset.business_criticality = "medium"
            if not asset.data_lifetime:
                asset.data_lifetime = "1-3y"
        db.commit()
        db.close()
    except Exception as e:
        print(f"[startup] Initialization / backfill warning: {e}")
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
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", tags=["Health"])
def health_check():
    from app.services.cloud_kms_scanner import get_cloud_kms_status
    from app.services.hsm_scanner import get_hsm_status

    kms_status = get_cloud_kms_status()
    hsm_status = get_hsm_status()

    scanner_modes = {
        "aws_kms": kms_status.get("aws_kms", {}),
        "azure_key_vault": kms_status.get("azure_key_vault", {}),
        "gcp_kms": kms_status.get("gcp_kms", {}),
        "hsm_pkcs11": hsm_status,
        "tls": {"provider": "TLS Network Prober", "mode": "live", "details": "Direct socket handshake TLS discovery active"},
        "source_code": {"provider": "Source Code Static Scanner", "mode": "live", "details": "Direct regex/AST scanning active"},
        "dependency": {"provider": "Dependency Manifest Scanner", "mode": "live", "details": "Direct package manifest parsing active"},
        "container": {"provider": "Container Image Scanner", "mode": "live", "details": "Dockerfile & container layer static analysis active"},
        "binary": {"provider": "Binary Symbol Scanner", "mode": "live", "details": "ELF/PE/Mach-O symbol and string analysis active"}
    }

    return {
        "status": "healthy",
        "service": "ecdat-backend",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_modes": scanner_modes
    }

# Include API routers
app.include_router(dashboard_router, prefix="/api", tags=["Dashboard"])
app.include_router(stage2_router, prefix="/api", tags=["Data & Inventory"])
app.include_router(graph_router, prefix="/api", tags=["Dependency Graph & Blast Radius"])
app.include_router(simulate_router, prefix="/api", tags=["PQC Migration Simulator"])
app.include_router(scanners_router, prefix="/api", tags=["Scanner Suite"])
app.include_router(assistant_router, prefix="/api", tags=["Assistant & Snapshots"])
app.include_router(phase1_router, prefix="/api", tags=["Phase 1 — Multi-Source Discovery"])
app.include_router(phase2_router, prefix="/api", tags=["Phase 2 — Binary & Container Discovery"])
app.include_router(phase3_router, prefix="/api", tags=["Phase 3 — Hardware & Cloud Discovery"])

from fastapi import Depends
from app.core.auth import get_current_user

@app.get("/api/auth/me", tags=["Authentication"])
def get_auth_status(current_user: dict = Depends(get_current_user)):
    return {
        "status": "authenticated" if not current_user.get("is_anonymous") else "anonymous",
        "user": current_user,
        "require_auth": settings.REQUIRE_AUTH
    }



