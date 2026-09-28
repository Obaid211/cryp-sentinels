import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import Service, ServiceDependency, CryptoAsset
from app.services.scoring import calculate_mwqrs

DEMO_SERVICES = [
    {"name": "Auth-Service", "criticality": "P0", "description": "Identity Provider, OAuth2 & PKI token issuer for all enterprise services"},
    {"name": "Payment-Gateway", "criticality": "P0", "description": "Financial transaction processing & PCI-DSS HSM boundary"},
    {"name": "Core-Database-Proxy", "criticality": "P0", "description": "TLS termination proxy for sovereign data store"},
    {"name": "User-Portal", "criticality": "P1", "description": "Customer-facing web application frontend & session tier"},
    {"name": "Analytics-Pipeline", "criticality": "P2", "description": "Telemetry, event ingestion, and audit reporting engine"},
    {"name": "Notification-Service", "criticality": "P3", "description": "Async SMS/Email alert dispatcher with rate limiting"},
    {"name": "Source-Code-Repos", "criticality": "P1", "description": "Internal GitLab repositories containing application cryptographic implementations"},
    {"name": "Container-Registry", "criticality": "P1", "description": "Docker/OCI container image registry with embedded cryptographic libraries"},
    {"name": "HSM-Cluster", "criticality": "P0", "description": "Hardware Security Module cluster for key generation, signing, and key wrapping"},
    {"name": "Cloud-KMS", "criticality": "P0", "description": "Cloud Key Management Service for envelope encryption of data-at-rest"},
    {"name": "Binary-Services", "criticality": "P2", "description": "Compiled service binaries with statically linked cryptographic symbols"},
    {"name": "Dependency-Registry", "criticality": "P2", "description": "Internal npm/PyPI/Maven artifact repository with pinned cryptographic dependencies"},
]

DEMO_DEPENDENCIES = [
    ("User-Portal", "Auth-Service"),
    ("User-Portal", "Payment-Gateway"),
    ("Payment-Gateway", "Core-Database-Proxy"),
    ("Payment-Gateway", "HSM-Cluster"),
    ("Analytics-Pipeline", "Core-Database-Proxy"),
    ("Analytics-Pipeline", "Notification-Service"),
    ("Auth-Service", "HSM-Cluster"),
    ("Auth-Service", "Cloud-KMS"),
    ("Payment-Gateway", "Cloud-KMS"),
    ("Source-Code-Repos", "Dependency-Registry"),
    ("Container-Registry", "Source-Code-Repos"),
]

# ─────────────────────────────────────────────
# UNIFIED DEMO ASSETS — all 7 discovery sources
# Each uses (host, port) as unique key.
# Non-TLS assets use port in range 10000-19999
# ─────────────────────────────────────────────
DEMO_ASSETS = [

    # ── SOURCE: TLS / Network ────────────────────────────────────────────────

    {
        "host": "auth.internal.net", "port": 8443,
        "status": "success", "source": "tls",
        "tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "cipher_bits": 256,
        "cert_subject": "CN=auth.internal.net, O=NTRO Enterprise",
        "cert_issuer": "CN=Internal Sovereign CA",
        "cert_key_type": "RSA", "cert_key_size_bits": 2048, "cert_signature_algorithm": "sha256WithRSAEncryption",
        "cert_not_after": datetime(2026, 11, 15, tzinfo=timezone.utc), "days_to_expiry": 54,
        "algorithm": "RSA", "usage_context": "key_exchange",
        "business_criticality": "critical", "data_lifetime": "3-5y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_RSA", "TLS_1_2_DEPRECATED_TARGET"]),
        "service_name": "Auth-Service", "confidence_score": 0.97,
    },
    {
        "host": "payment.gateway.internal", "port": 9443,
        "status": "success", "source": "tls",
        "tls_version": "TLSv1.2", "cipher_suite": "DHE-RSA-AES128-SHA", "cipher_bits": 128,
        "cert_subject": "CN=payment.gateway.internal",
        "cert_issuer": "CN=Financial Root Authority",
        "cert_key_type": "RSA", "cert_key_size_bits": 1024, "cert_signature_algorithm": "sha1WithRSAEncryption",
        "cert_not_after": datetime(2026, 9, 30, tzinfo=timezone.utc), "days_to_expiry": 8,
        "algorithm": "RSA", "usage_context": "key_exchange",
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["WEAK_RSA_KEY_SIZE_1024", "CERT_EXPIRING_SOON", "SHA1_SIGNATURE", "WEAK_CIPHER_SHA1"]),
        "service_name": "Payment-Gateway", "confidence_score": 0.99,
    },
    {
        "host": "db-proxy.sovereign.local", "port": 5432,
        "status": "success", "source": "tls",
        "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256,
        "cert_subject": "CN=db-proxy.sovereign.local",
        "cert_issuer": "CN=Internal Sovereign CA",
        "cert_key_type": "ECC", "cert_key_size_bits": 384, "cert_signature_algorithm": "ecdsa-with-sha384",
        "cert_not_after": datetime(2027, 8, 20, tzinfo=timezone.utc), "days_to_expiry": 332,
        "algorithm": "ECC", "usage_context": "key_exchange",
        "business_criticality": "critical", "data_lifetime": "5-10y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC"]),
        "service_name": "Core-Database-Proxy", "confidence_score": 0.95,
    },
    {
        "host": "portal.company.com", "port": 443,
        "status": "success", "source": "tls",
        "tls_version": "TLSv1.3", "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256", "cipher_bits": 256,
        "cert_subject": "CN=portal.company.com",
        "cert_issuer": "CN=Global Trust Public CA",
        "cert_key_type": "RSA", "cert_key_size_bits": 4096, "cert_signature_algorithm": "sha256WithRSAEncryption",
        "cert_not_after": datetime(2027, 3, 10, tzinfo=timezone.utc), "days_to_expiry": 169,
        "algorithm": "RSA", "usage_context": "key_exchange",
        "business_criticality": "high", "data_lifetime": "1-3y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_RSA"]),
        "service_name": "User-Portal", "confidence_score": 0.98,
    },
    {
        "host": "analytics.pipeline.internal", "port": 8088,
        "status": "success", "source": "tls",
        "tls_version": "TLSv1.2", "cipher_suite": "ECDHE-ECDSA-AES128-GCM-SHA256", "cipher_bits": 128,
        "cert_subject": "CN=analytics.pipeline.internal",
        "cert_issuer": "CN=Internal Sovereign CA",
        "cert_key_type": "ECC", "cert_key_size_bits": 256, "cert_signature_algorithm": "ecdsa-with-sha256",
        "cert_not_after": datetime(2026, 12, 1, tzinfo=timezone.utc), "days_to_expiry": 70,
        "algorithm": "ECC", "usage_context": "key_exchange",
        "business_criticality": "medium", "data_lifetime": "1-3y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC", "TLS_1_2_DEPRECATED_TARGET"]),
        "service_name": "Analytics-Pipeline", "confidence_score": 0.94,
    },
    {
        "host": "pqc.experimental.node", "port": 8445,
        "status": "success", "source": "tls",
        "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256,
        "cert_subject": "CN=pqc.experimental.node",
        "cert_issuer": "CN=OQS Hybrid Prototype CA",
        "cert_key_type": "ML-KEM", "cert_key_size_bits": 768, "cert_signature_algorithm": "ml-dsa-65",
        "cert_not_after": datetime(2027, 9, 22, tzinfo=timezone.utc), "days_to_expiry": 365,
        "algorithm": "ML-KEM-768", "usage_context": "key_exchange",
        "business_criticality": "low", "data_lifetime": "<1y",
        "risk_flags": json.dumps([]),
        "service_name": "Notification-Service", "confidence_score": 0.91,
    },

    # ── SOURCE: Source Code ──────────────────────────────────────────────────

    {
        "host": "src-repo.internal", "port": 10001,
        "status": "success", "source": "source_code",
        "algorithm": "RSA-2048", "usage_context": "digital_signature",
        "library": "cryptography==38.0.4", "file_path": "auth_service/crypto/token_signer.py", "line_number": 47,
        "cert_key_type": "RSA", "cert_key_size_bits": 2048,
        "business_criticality": "critical", "data_lifetime": "3-5y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_RSA", "HARDCODED_KEY_DETECTED", "DEPRECATED_LIBRARY_VERSION"]),
        "service_name": "Source-Code-Repos", "confidence_score": 0.96,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "src-repo.internal", "port": 10002,
        "status": "success", "source": "source_code",
        "algorithm": "AES-128-CBC", "usage_context": "data_encryption",
        "library": "pycryptodome==3.15.0", "file_path": "payment_service/encryption/data_cipher.py", "line_number": 112,
        "cert_key_type": "AES", "cert_key_size_bits": 128,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["WEAK_AES_128", "DEPRECATED_CBC_MODE", "INSECURE_IV_REUSE"]),
        "service_name": "Source-Code-Repos", "confidence_score": 0.93,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "src-repo.internal", "port": 10003,
        "status": "success", "source": "source_code",
        "algorithm": "MD5", "usage_context": "hashing",
        "library": "hashlib (stdlib)", "file_path": "portal/utils/file_integrity.py", "line_number": 23,
        "cert_key_type": "Hash", "cert_key_size_bits": 128,
        "business_criticality": "high", "data_lifetime": "1-3y",
        "risk_flags": json.dumps(["BROKEN_HASH_MD5", "COLLISION_VULNERABLE"]),
        "service_name": "Source-Code-Repos", "confidence_score": 0.99,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "src-repo.internal", "port": 10004,
        "status": "success", "source": "source_code",
        "algorithm": "SHA-1", "usage_context": "hashing",
        "library": "openssl via ctypes", "file_path": "analytics_service/audit/log_hasher.go", "line_number": 78,
        "cert_key_type": "Hash", "cert_key_size_bits": 160,
        "business_criticality": "medium", "data_lifetime": "5-10y",
        "risk_flags": json.dumps(["BROKEN_HASH_SHA1", "SHATTERED_ATTACK_VULNERABLE"]),
        "service_name": "Source-Code-Repos", "confidence_score": 0.97,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "src-repo.internal", "port": 10005,
        "status": "success", "source": "source_code",
        "algorithm": "DES-3DES-EDE", "usage_context": "data_encryption",
        "library": "javax.crypto (Java stdlib)", "file_path": "notification_service/src/MessageCipher.java", "line_number": 34,
        "cert_key_type": "3DES", "cert_key_size_bits": 112,
        "business_criticality": "high", "data_lifetime": "1-3y",
        "risk_flags": json.dumps(["DEPRECATED_3DES", "WEAK_KEY_SIZE_112", "SWEET32_VULNERABLE"]),
        "service_name": "Source-Code-Repos", "confidence_score": 0.98,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },

    # ── SOURCE: Dependency / Library ─────────────────────────────────────────

    {
        "host": "dep-registry.internal", "port": 10011,
        "status": "success", "source": "dependency",
        "algorithm": "RSA", "usage_context": "key_exchange",
        "library": "pyOpenSSL==22.1.0", "file_path": "auth_service/requirements.txt", "line_number": 12,
        "cert_key_type": "RSA", "cert_key_size_bits": 2048,
        "business_criticality": "critical", "data_lifetime": "3-5y",
        "risk_flags": json.dumps(["VULNERABLE_LIBRARY_CVE_2023_0286", "QUANTUM_VULNERABLE_RSA"]),
        "service_name": "Dependency-Registry", "confidence_score": 0.95,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "dep-registry.internal", "port": 10012,
        "status": "success", "source": "dependency",
        "algorithm": "ECC-P256", "usage_context": "digital_signature",
        "library": "node-forge@1.3.1", "file_path": "portal/package.json", "line_number": 8,
        "cert_key_type": "ECC", "cert_key_size_bits": 256,
        "business_criticality": "high", "data_lifetime": "1-3y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC", "DEPRECATED_NODE_CRYPTO_LIB"]),
        "service_name": "Dependency-Registry", "confidence_score": 0.88,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "dep-registry.internal", "port": 10013,
        "status": "success", "source": "dependency",
        "algorithm": "RSA", "usage_context": "key_generation",
        "library": "bouncy-castle-1.68.jar", "file_path": "payment_service/pom.xml", "line_number": 45,
        "cert_key_type": "RSA", "cert_key_size_bits": 4096,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["QUANTUM_VULNERABLE_RSA", "UNPATCHED_LIBRARY"]),
        "service_name": "Dependency-Registry", "confidence_score": 0.92,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },

    # ── SOURCE: Binary / Compiled ────────────────────────────────────────────

    {
        "host": "binary-store.internal", "port": 10021,
        "status": "success", "source": "binary",
        "algorithm": "RSA", "usage_context": "key_exchange",
        "library": "libssl.so.1.1 (OpenSSL 1.1.1f)", "file_path": "/opt/ntro/auth-service/bin/auth-daemon",
        "cert_key_type": "RSA", "cert_key_size_bits": 2048,
        "business_criticality": "critical", "data_lifetime": "5-10y",
        "risk_flags": json.dumps(["OPENSSL_1_1_EOL", "VULNERABLE_ALGO_RSA", "STATIC_LINK_DETECTED"]),
        "service_name": "Binary-Services", "confidence_score": 0.85,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "binary-store.internal", "port": 10022,
        "status": "success", "source": "binary",
        "algorithm": "ECC-P521", "usage_context": "digital_signature",
        "library": "libcrypto.so.3 (OpenSSL 3.0.2)", "file_path": "/opt/ntro/payment-service/bin/pgsign",
        "cert_key_type": "ECC", "cert_key_size_bits": 521,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC", "SHOR_ALGORITHM_TARGET"]),
        "service_name": "Binary-Services", "confidence_score": 0.82,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "binary-store.internal", "port": 10023,
        "status": "success", "source": "binary",
        "algorithm": "DH-1024", "usage_context": "key_exchange",
        "library": "libgnutls.so.30 (GnuTLS 3.6.14)", "file_path": "/opt/ntro/analytics/bin/event-processor",
        "cert_key_type": "DH", "cert_key_size_bits": 1024,
        "business_criticality": "medium", "data_lifetime": "1-3y",
        "risk_flags": json.dumps(["WEAK_DH_1024", "LOGJAM_ATTACK_VULNERABLE", "QUANTUM_VULNERABLE_DH"]),
        "service_name": "Binary-Services", "confidence_score": 0.79,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },

    # ── SOURCE: Container ────────────────────────────────────────────────────

    {
        "host": "container-registry.internal", "port": 10031,
        "status": "success", "source": "container",
        "algorithm": "RSA", "usage_context": "key_exchange",
        "library": "openssl 1.0.2k (base: centos:7)",
        "file_path": "docker.io/ntro/auth-service:v2.4.1 → Dockerfile layer sha256:a8f3c...",
        "cert_key_type": "RSA", "cert_key_size_bits": 2048,
        "business_criticality": "critical", "data_lifetime": "3-5y",
        "risk_flags": json.dumps(["BASE_IMAGE_EOL_CENTOS7", "OPENSSL_1_0_EOL", "VULNERABLE_ALGO_RSA"]),
        "service_name": "Container-Registry", "confidence_score": 0.91,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "container-registry.internal", "port": 10032,
        "status": "success", "source": "container",
        "algorithm": "ECC", "usage_context": "digital_signature",
        "library": "libssl3 v3.0.2 (base: ubuntu:22.04)",
        "file_path": "docker.io/ntro/payment-gw:v1.9.0 → Dockerfile RUN apt-get install libssl3",
        "cert_key_type": "ECC", "cert_key_size_bits": 256,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC", "CONTAINER_TLS_VALIDATION_DISABLED"]),
        "service_name": "Container-Registry", "confidence_score": 0.88,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "container-registry.internal", "port": 10033,
        "status": "success", "source": "container",
        "algorithm": "ML-KEM-768", "usage_context": "key_exchange",
        "library": "liboqs 0.8.0 (base: ubuntu:22.04)",
        "file_path": "docker.io/ntro/pqc-proxy:v0.2.0 → Dockerfile RUN apt-get install liboqs-dev",
        "cert_key_type": "ML-KEM", "cert_key_size_bits": 768,
        "business_criticality": "low", "data_lifetime": "<1y",
        "risk_flags": json.dumps([]),
        "service_name": "Container-Registry", "confidence_score": 0.75,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },

    # ── SOURCE: HSM / Hardware ───────────────────────────────────────────────

    {
        "host": "hsm-cluster.internal", "port": 10041,
        "status": "success", "source": "hsm",
        "algorithm": "RSA-4096", "usage_context": "key_generation",
        "library": "Thales Luna Network HSM 7 (FIPS 140-2 Level 3)",
        "file_path": "PKCS#11 Slot 0 / Token: NTRO-PROD-KMS / Label: ROOT-CA-KEY",
        "cert_key_type": "RSA", "cert_key_size_bits": 4096,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["QUANTUM_VULNERABLE_RSA", "HSM_NO_PQC_FIRMWARE", "SHOR_ALGORITHM_TARGET"]),
        "service_name": "HSM-Cluster", "confidence_score": 0.99,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "hsm-cluster.internal", "port": 10042,
        "status": "success", "source": "hsm",
        "algorithm": "ECC-P384", "usage_context": "digital_signature",
        "library": "Utimaco CryptoServer Se (FIPS 140-2 Level 3)",
        "file_path": "PKCS#11 Slot 1 / Token: NTRO-PAY-HSM / Label: PAYMENT-SIGNING-KEY",
        "cert_key_type": "ECC", "cert_key_size_bits": 384,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC", "QUANTUM_VULNERABLE_ECDSA", "HARVEST_NOW_DECRYPT_LATER"]),
        "service_name": "HSM-Cluster", "confidence_score": 0.99,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "hsm-cluster.internal", "port": 10043,
        "status": "success", "source": "hsm",
        "algorithm": "AES-256-GCM", "usage_context": "data_encryption",
        "library": "YubiHSM 2 (FIPS 140-2 Level 3)",
        "file_path": "PKCS#11 Slot 2 / Token: NTRO-DATA-ENC / Label: AES-MASTER-KEY",
        "cert_key_type": "AES", "cert_key_size_bits": 256,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps([]),
        "service_name": "HSM-Cluster", "confidence_score": 0.98,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },

    # ── SOURCE: Cloud KMS ────────────────────────────────────────────────────

    {
        "host": "kms.amazonaws.com", "port": 10051,
        "status": "success", "source": "cloud_kms",
        "algorithm": "RSA-2048", "usage_context": "key_wrapping",
        "library": "AWS KMS / CMK arn:aws:kms:ap-south-1:123456789012:key/a1b2c3d4",
        "file_path": "AWS KMS Key ID: a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 (SYMMETRIC_DEFAULT)",
        "cert_key_type": "RSA", "cert_key_size_bits": 2048,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["QUANTUM_VULNERABLE_RSA", "SHOR_ALGORITHM_TARGET", "NO_KEY_ROTATION_ENABLED"]),
        "service_name": "Cloud-KMS", "confidence_score": 0.95,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "kms.azure.internal", "port": 10052,
        "status": "success", "source": "cloud_kms",
        "algorithm": "ECC-P256", "usage_context": "digital_signature",
        "library": "Azure Key Vault / Key: ntro-signing-key (EC P-256)",
        "file_path": "Azure Key Vault: https://ntro-prod.vault.azure.net/keys/app-signing-key",
        "cert_key_type": "ECC", "cert_key_size_bits": 256,
        "business_criticality": "high", "data_lifetime": "5-10y",
        "risk_flags": json.dumps(["VULNERABLE_ALGO_ECC", "QUANTUM_VULNERABLE_ECDSA"]),
        "service_name": "Cloud-KMS", "confidence_score": 0.93,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
    },
    {
        "host": "cloudkms.googleapis.com", "port": 10053,
        "status": "success", "source": "cloud_kms",
        "algorithm": "AES-256", "usage_context": "data_encryption",
        "library": "Google Cloud KMS / KeyRing: ntro-prod-kr / Key: db-encryption-key",
        "file_path": "GCP KMS: projects/ntro-prod/locations/asia-south1/keyRings/ntro-prod-kr/cryptoKeys/db-enc-key",
        "cert_key_type": "AES", "cert_key_size_bits": 256,
        "business_criticality": "critical", "data_lifetime": ">10y",
        "risk_flags": json.dumps(["KEY_ROTATION_OVERDUE_365_DAYS"]),
        "service_name": "Cloud-KMS", "confidence_score": 0.97,
        "tls_version": None, "cipher_suite": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_signature_algorithm": None, "cert_not_after": None, "days_to_expiry": None,
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

    # 3. Seed Assets — idempotent upsert
    for asset_data in DEMO_ASSETS:
        svc_id = service_map.get(asset_data["service_name"])
        existing_asset = db.query(CryptoAsset).filter(
            CryptoAsset.host == asset_data["host"],
            CryptoAsset.port == asset_data["port"]
        ).first()

        crit = "P2"
        if svc_id:
            svc_obj = db.get(Service, svc_id)
            if svc_obj:
                crit = svc_obj.criticality

        # Build scoring record — handle non-TLS assets gracefully
        score_record = {
            "status": asset_data.get("status", "success"),
            "cert_key_type": asset_data.get("cert_key_type"),
            "cert_key_size_bits": asset_data.get("cert_key_size_bits"),
            "tls_version": asset_data.get("tls_version"),
            "days_to_expiry": asset_data.get("days_to_expiry"),
        }
        mwqrs = calculate_mwqrs(score_record, service_criticality=crit)

        if not existing_asset:
            asset = CryptoAsset(
                host=asset_data["host"],
                port=asset_data["port"],
                status=asset_data.get("status", "success"),
                tls_version=asset_data.get("tls_version"),
                cipher_suite=asset_data.get("cipher_suite"),
                cipher_bits=asset_data.get("cipher_bits"),
                cert_subject=asset_data.get("cert_subject"),
                cert_issuer=asset_data.get("cert_issuer"),
                cert_key_type=asset_data.get("cert_key_type"),
                cert_key_size_bits=asset_data.get("cert_key_size_bits"),
                cert_signature_algorithm=asset_data.get("cert_signature_algorithm"),
                cert_not_after=asset_data.get("cert_not_after"),
                days_to_expiry=asset_data.get("days_to_expiry"),
                risk_flags=asset_data.get("risk_flags", "[]"),
                risk_score=mwqrs,
                linked_service_id=svc_id,
                source=asset_data.get("source", "tls"),
                business_criticality=asset_data.get("business_criticality", "medium"),
                data_lifetime=asset_data.get("data_lifetime", "1-3y"),
                algorithm=asset_data.get("algorithm"),
                usage_context=asset_data.get("usage_context"),
                confidence_score=asset_data.get("confidence_score"),
                library=asset_data.get("library"),
                file_path=asset_data.get("file_path"),
                line_number=asset_data.get("line_number"),
            )
            db.add(asset)
        else:
            # Upsert — update all fields to keep data fresh
            existing_asset.risk_score = mwqrs
            existing_asset.linked_service_id = svc_id
            existing_asset.risk_flags = asset_data.get("risk_flags", "[]")
            existing_asset.days_to_expiry = asset_data.get("days_to_expiry")
            existing_asset.source = asset_data.get("source", "tls")
            existing_asset.business_criticality = asset_data.get("business_criticality", "medium")
            existing_asset.data_lifetime = asset_data.get("data_lifetime", "1-3y")
            existing_asset.algorithm = asset_data.get("algorithm")
            existing_asset.usage_context = asset_data.get("usage_context")
            existing_asset.confidence_score = asset_data.get("confidence_score")
            existing_asset.library = asset_data.get("library")
            existing_asset.file_path = asset_data.get("file_path")
            existing_asset.line_number = asset_data.get("line_number")
            existing_asset.cert_key_type = asset_data.get("cert_key_type", existing_asset.cert_key_type)
            existing_asset.cert_key_size_bits = asset_data.get("cert_key_size_bits", existing_asset.cert_key_size_bits)

    db.commit()


def recalculate_all_scores(db: Session):
    assets = db.query(CryptoAsset).all()
    for a in assets:
        crit = "P2"
        if a.linked_service:
            crit = a.linked_service.criticality

        record = {
            "status": a.status,
            "cert_key_type": a.cert_key_type or a.algorithm,
            "cert_key_size_bits": a.cert_key_size_bits,
            "tls_version": a.tls_version,
            "days_to_expiry": a.days_to_expiry,
        }
        a.risk_score = calculate_mwqrs(record, service_criticality=crit)
    db.commit()
