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
