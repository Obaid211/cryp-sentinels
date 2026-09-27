from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, ForeignKey, UniqueConstraint, Boolean
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    criticality = Column(String(10), default="P2")  # P0, P1, P2, P3
    description = Column(Text, nullable=True)

    assets = relationship("CryptoAsset", back_populates="linked_service")

class ServiceDependency(Base):
    __tablename__ = "service_dependencies"

    service_id = Column(Integer, ForeignKey("services.id"), primary_key=True)
    depends_on_service_id = Column(Integer, ForeignKey("services.id"), primary_key=True)

class CryptoAsset(Base):
    __tablename__ = "crypto_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(50), default="unknown")
    tls_version = Column(String(50), nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    cipher_bits = Column(Integer, nullable=True)
    cert_subject = Column(Text, nullable=True)
    cert_issuer = Column(Text, nullable=True)
    cert_key_type = Column(String(100), nullable=True)
    cert_key_size_bits = Column(Integer, nullable=True)
    cert_signature_algorithm = Column(String(100), nullable=True)
    cert_not_after = Column(DateTime, nullable=True)
    days_to_expiry = Column(Integer, nullable=True)
    risk_flags = Column(Text, nullable=True)  # JSON encoded list of strings
    risk_score = Column(Float, default=0.0)
    linked_service_id = Column(Integer, ForeignKey("services.id"), nullable=True)

    # --- Phase 1: Multi-source discovery fields ---
    # Discovery source: "tls" | "source_code" | "dependency" | "binary" | "container"
    source = Column(String(50), default="tls", nullable=False)
    # Business criticality (stored attribute — feeds MWQRS and remediation ordering)
    business_criticality = Column(String(20), default="medium", nullable=True)  # critical|high|medium|low
    # Data lifetime / shelf-life (feeds Mosca calculator directly)
    data_lifetime = Column(String(20), default="1-3y", nullable=True)  # <1y|1-3y|3-5y|5-10y|>10y
    # PQC recommendation JSON (output of the recommendation engine)
    pqc_recommendation = Column(Text, nullable=True)  # JSON
    # Enriched algorithm fields for non-TLS assets
    algorithm = Column(String(255), nullable=True)    # e.g. "RSA-2048", "AES-128-CBC"
    usage_context = Column(String(100), nullable=True)  # e.g. "digital_signature", "key_exchange"
    confidence_score = Column(Float, nullable=True)    # 0.0 – 1.0
    library = Column(String(255), nullable=True)       # e.g. "cryptography", "openssl"
    # File-level metadata for source code findings
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)

    linked_service = relationship("Service", back_populates="assets")

    __table_args__ = (
        UniqueConstraint("host", "port", name="uq_host_port"),
    )

class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    asset_count = Column(Integer, nullable=False)
    avg_risk = Column(Float, nullable=True)
    critical_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    safe_count = Column(Integer, default=0)
    snapshot_data = Column(Text, nullable=False)  # JSON dump of assets
