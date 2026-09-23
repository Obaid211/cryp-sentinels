import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import Service, ServiceDependency, CryptoAsset
from app.services.scoring import calculate_mwqrs

DEMO_SERVICES = [
    {"name": "Auth-Service", "criticality": "P0", "description": "Identity Provider, OAuth2 & PKI token issuer"},
    {"name": "Payment-Gateway", "criticality": "P0", "description": "Financial transaction processing & PCI-DSS HSM boundary"},
    {"name": "Core-Database-Proxy", "criticality": "P0", "description": "TLS termination proxy for sovereign data store"},
    {"name": "User-Portal", "criticality": "P1", "description": "Customer-facing web application frontend & session tier"},
    {"name": "Analytics-Pipeline", "criticality": "P2", "description": "Telemetry, event ingestion, and audit reporting engine"},
    {"name": "Notification-Service", "criticality": "P3", "description": "Async SMS/Email alert dispatcher with rate limiting"},
]

# Service A -> Service B (A depends on B)
DEMO_DEPENDENCIES = [
    ("User-Portal", "Auth-Service"),
    ("User-Portal", "Payment-Gateway"),
    ("Payment-Gateway", "Core-Database-Proxy"),
    ("Analytics-Pipeline", "Core-Database-Proxy"),
    ("Analytics-Pipeline", "Notification-Service"),
]

DEMO_ASSETS = [
    {
        "host": "auth.internal.net",
        "port": 8443,
        "status": "success",
        "tls_version": "TLSv1.2",
        "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "cipher_bits": 256,
        "cert_subject": "CN=auth.internal.net, O=ECDAT Enterprise",
        "cert_issuer": "CN=Internal Sovereign CA",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 2048,
        "cert_signature_algorithm": "sha256WithRSAEncryption",
        "cert_not_after": datetime(2026, 11, 15, tzinfo=timezone.utc),
        "days_to_expiry": 54,
        "risk_flags": json.dumps(["VULNERABLE_ALGO_RSA", "TLS_1_2_DEPRECATED_TARGET"]),
        "service_name": "Auth-Service"
    },
    {
        "host": "payment.gateway.internal",
        "port": 9443,
        "status": "success",
        "tls_version": "TLSv1.2",
        "cipher_suite": "DHE-RSA-AES128-SHA",
        "cipher_bits": 128,
        "cert_subject": "CN=payment.gateway.internal",
        "cert_issuer": "CN=Financial Root Authority",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 1024,
        "cert_signature_algorithm": "sha1WithRSAEncryption",
        "cert_not_after": datetime(2026, 9, 30, tzinfo=timezone.utc),
        "days_to_expiry": 8,
        "risk_flags": json.dumps(["WEAK_RSA_KEY_SIZE_1024", "CERT_EXPIRING_SOON", "SHA1_SIGNATURE"]),
        "service_name": "Payment-Gateway"
    },
    {
        "host": "db-proxy.sovereign.local",
        "port": 5432,
        "status": "success",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "cert_subject": "CN=db-proxy.sovereign.local",
        "cert_issuer": "CN=Internal Sovereign CA",
        "cert_key_type": "ECC",
        "cert_key_size_bits": 384,
        "cert_signature_algorithm": "ecdsa-with-sha384",
        "cert_not_after": datetime(2027, 8, 20, tzinfo=timezone.utc),
        "days_to_expiry": 332,
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC"]),
        "service_name": "Core-Database-Proxy"
    },
    {
        "host": "portal.company.com",
        "port": 443,
        "status": "success",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
        "cipher_bits": 256,
        "cert_subject": "CN=portal.company.com",
        "cert_issuer": "CN=Global Trust Public CA",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 4096,
        "cert_signature_algorithm": "sha256WithRSAEncryption",
        "cert_not_after": datetime(2027, 3, 10, tzinfo=timezone.utc),
        "days_to_expiry": 169,
        "risk_flags": json.dumps(["VULNERABLE_ALGO_RSA"]),
        "service_name": "User-Portal"
    },
    {
        "host": "analytics.pipeline.internal",
        "port": 8088,
        "status": "success",
        "tls_version": "TLSv1.2",
        "cipher_suite": "ECDHE-ECDSA-AES128-GCM-SHA256",
        "cipher_bits": 128,
        "cert_subject": "CN=analytics.pipeline.internal",
        "cert_issuer": "CN=Internal Sovereign CA",
        "cert_key_type": "ECC",
        "cert_key_size_bits": 256,
        "cert_signature_algorithm": "ecdsa-with-sha256",
        "cert_not_after": datetime(2026, 12, 1, tzinfo=timezone.utc),
        "days_to_expiry": 70,
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC"]),
        "service_name": "Analytics-Pipeline"
    },
    {
        "host": "pqc.experimental.node",
        "port": 8445,
        "status": "success",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "cert_subject": "CN=pqc.experimental.node",
        "cert_issuer": "CN=OQS Hybrid Prototype CA",
        "cert_key_type": "ML-KEM",
        "cert_key_size_bits": 768,
        "cert_signature_algorithm": "ml-dsa-65",
        "cert_not_after": datetime(2027, 9, 22, tzinfo=timezone.utc),
        "days_to_expiry": 365,
        "risk_flags": json.dumps([]),
        "service_name": "Notification-Service"
    },
]

def seed_demo_data(db: Session):
    # 1. Seed Services
    service_map = {}
    for svc in DEMO_SERVICES:
        existing = db.query(Service).filter(Service.name == svc["name"]).first()
        if not existing:
            new_svc = Service(name=svc["name"], criticality=svc["criticality"], description=svc["description"])
            db.add(new_svc)
            db.flush()
            service_map[svc["name"]] = new_svc.id
        else:
            existing.criticality = svc["criticality"]
            existing.description = svc["description"]
            service_map[svc["name"]] = existing.id

    # 2. Seed Dependencies
    for parent_name, dep_name in DEMO_DEPENDENCIES:
        if parent_name in service_map and dep_name in service_map:
            p_id = service_map[parent_name]
            d_id = service_map[dep_name]
            exists = db.query(ServiceDependency).filter(
                ServiceDependency.service_id == p_id,
                ServiceDependency.depends_on_service_id == d_id
            ).first()
            if not exists:
                db.add(ServiceDependency(service_id=p_id, depends_on_service_id=d_id))

    # 3. Seed Assets
    for asset_data in DEMO_ASSETS:
        svc_id = service_map.get(asset_data["service_name"])
        existing_asset = db.query(CryptoAsset).filter(
            CryptoAsset.host == asset_data["host"],
            CryptoAsset.port == asset_data["port"]
        ).first()

        crit = "P2"
        if svc_id:
            svc_obj = db.query(Service).get(svc_id)
            if svc_obj:
                crit = svc_obj.criticality

        mwqrs = calculate_mwqrs(asset_data, service_criticality=crit)

        if not existing_asset:
            asset = CryptoAsset(
                host=asset_data["host"],
                port=asset_data["port"],
                status=asset_data["status"],
                tls_version=asset_data["tls_version"],
                cipher_suite=asset_data["cipher_suite"],
                cipher_bits=asset_data["cipher_bits"],
                cert_subject=asset_data["cert_subject"],
                cert_issuer=asset_data["cert_issuer"],
                cert_key_type=asset_data["cert_key_type"],
                cert_key_size_bits=asset_data["cert_key_size_bits"],
                cert_signature_algorithm=asset_data["cert_signature_algorithm"],
                cert_not_after=asset_data["cert_not_after"],
                days_to_expiry=asset_data["days_to_expiry"],
                risk_flags=asset_data["risk_flags"],
                risk_score=mwqrs,
                linked_service_id=svc_id
            )
            db.add(asset)
        else:
            existing_asset.risk_score = mwqrs
            existing_asset.linked_service_id = svc_id
            existing_asset.risk_flags = asset_data["risk_flags"]
            existing_asset.days_to_expiry = asset_data["days_to_expiry"]

    db.commit()

def recalculate_all_scores(db: Session):
    assets = db.query(CryptoAsset).all()
    for a in assets:
        crit = "P2"
        if a.linked_service:
            crit = a.linked_service.criticality
        
        record = {
            "status": a.status,
            "cert_key_type": a.cert_key_type,
            "cert_key_size_bits": a.cert_key_size_bits,
            "tls_version": a.tls_version,
            "days_to_expiry": a.days_to_expiry,
        }
        a.risk_score = calculate_mwqrs(record, service_criticality=crit)
    db.commit()
