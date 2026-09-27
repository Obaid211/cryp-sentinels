"""
cloud_kms_scanner.py — ECDAT Phase 3 Cloud Cryptographic Service Discovery
==========================================================================
Discovers and audits cloud KMS and certificate management configurations
across AWS KMS, Azure Key Vault, and Google Cloud KMS.

Operates in two modes:
1. Live mode: Uses active cloud credentials (boto3 default credential chain,
   DefaultAzureCredential, or GOOGLE_APPLICATION_CREDENTIALS) to query real
   cloud KMS endpoints.
2. Mock mode: If live credentials are not set, logs a clear warning and falls
   back to high-fidelity simulated keys with zero downtime.

Writes findings into the unified inventory with source="cloud_kms".
"""

import os
import re
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.models import CryptoAsset, Service
from app.services.scoring import calculate_mwqrs
from app.services.pqc_engine import recommend_pqc

logger = logging.getLogger("ecdat.scanners.cloud_kms")


CLOUD_PROVIDER_SPECS: Dict[str, Dict[str, Any]] = {
    "aws_kms": {
        "provider": "AWS Key Management Service (KMS)",
        "key_types": {
            "SYMMETRIC_DEFAULT": {"algo": "AES-256-GCM", "usage": "symmetric_encryption", "pqc_ready": True, "vuln": False},
            "RSA_2048": {"algo": "RSA-2048", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "RSA_3072": {"algo": "RSA-3072", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "RSA_4096": {"algo": "RSA-4096", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "ECC_NIST_P256": {"algo": "ECDSA-P-256", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "ECC_NIST_P384": {"algo": "ECDSA-P-384", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "ECC_SECG_P256K1": {"algo": "ECDSA-secp256k1", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
        },
        "default_fips": "FIPS 140-3 Level 3 (AWS CloudHSM backing)",
    },
    "azure_key_vault": {
        "provider": "Azure Key Vault / Managed HSM",
        "key_types": {
            "RSA-HSM-2048": {"algo": "RSA-2048", "usage": "wrap_key", "pqc_ready": False, "vuln": True},
            "RSA-HSM-3072": {"algo": "RSA-3072", "usage": "wrap_key", "pqc_ready": False, "vuln": True},
            "RSA-HSM-4096": {"algo": "RSA-4096", "usage": "wrap_key", "pqc_ready": False, "vuln": True},
            "EC-HSM-P256": {"algo": "ECDSA-P-256", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "oct-HSM-256": {"algo": "AES-256", "usage": "symmetric_encryption", "pqc_ready": True, "vuln": False},
        },
        "default_fips": "FIPS 140-2 Level 2 / Managed HSM Level 3",
    },
    "gcp_kms": {
        "provider": "Google Cloud KMS / Cloud HSM",
        "key_types": {
            "GOOGLE_SYMMETRIC_ENCRYPTION": {"algo": "AES-256-GCM", "usage": "symmetric_encryption", "pqc_ready": True, "vuln": False},
            "RSA_SIGN_PSS_2048_SHA256": {"algo": "RSA-2048", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "RSA_SIGN_PSS_3072_SHA256": {"algo": "RSA-3072", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
            "EC_SIGN_P256_SHA256": {"algo": "ECDSA-P-256", "usage": "sign_verify", "pqc_ready": False, "vuln": True},
        },
        "default_fips": "FIPS 140-2 Level 3 (Cloud HSM)",
    }
}


def get_aws_kms_status() -> Dict[str, Any]:
    """
    Evaluates whether AWS KMS has valid live credentials via standard AWS credential chain:
    AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_PROFILE,
    or ambient IAM instance roles.
    """
    has_explicit_keys = bool(os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))
    has_role = bool(os.getenv("AWS_ROLE_ARN") or os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"

    if has_explicit_keys or has_role:
        return {
            "provider": "aws_kms",
            "name": "AWS Key Management Service (KMS)",
            "mode": "live",
            "region": region,
            "details": "AWS credentials configured via environment / IAM credential chain",
        }

    try:
        import botocore.session
        session = botocore.session.get_session()
        creds = session.get_credentials()
        if creds and creds.access_key:
            return {
                "provider": "aws_kms",
                "name": "AWS Key Management Service (KMS)",
                "mode": "live",
                "region": region,
                "details": "AWS credentials resolved from ambient environment/profile",
            }
    except Exception:
        pass

    logger.warning("[AWS KMS] No AWS credentials detected (AWS_ACCESS_KEY_ID / IAM role). Operating in offline MOCK mode.")
    return {
        "provider": "aws_kms",
        "name": "AWS Key Management Service (KMS)",
        "mode": "mock",
        "region": region,
        "details": "AWS credentials absent. Falling back to offline mock mode.",
    }


def get_azure_kms_status() -> Dict[str, Any]:
    """
    Evaluates whether Azure Key Vault has live credentials configured.
    Requires AZURE_KEY_VAULT_URL. Supports AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
    or ambient DefaultAzureCredential managed identity.
    """
    vault_url = os.getenv("AZURE_KEY_VAULT_URL", "").strip()
    if not vault_url:
        logger.warning("[Azure Key Vault] AZURE_KEY_VAULT_URL is not set. Operating in offline MOCK mode.")
        return {
            "provider": "azure_key_vault",
            "name": "Azure Key Vault / Managed HSM",
            "mode": "mock",
            "vault_url": None,
            "details": "AZURE_KEY_VAULT_URL not configured. Operating in offline mock mode.",
        }

    has_sp = bool(os.getenv("AZURE_CLIENT_ID") and os.getenv("AZURE_CLIENT_SECRET") and os.getenv("AZURE_TENANT_ID"))
    return {
        "provider": "azure_key_vault",
        "name": "Azure Key Vault / Managed HSM",
        "mode": "live",
        "vault_url": vault_url,
        "details": f"Vault endpoint active ({vault_url}) using {'Service Principal' if has_sp else 'DefaultAzureCredential'}",
    }


def get_gcp_kms_status() -> Dict[str, Any]:
    """
    Evaluates whether Google Cloud KMS has live credentials configured.
    Checks GOOGLE_APPLICATION_CREDENTIALS path exists on disk.
    """
    sa_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if not sa_path:
        logger.warning("[GCP KMS] GOOGLE_APPLICATION_CREDENTIALS is not set. Operating in offline MOCK mode.")
        return {
            "provider": "gcp_kms",
            "name": "Google Cloud KMS / Cloud HSM",
            "mode": "mock",
            "credentials_file": None,
            "details": "GOOGLE_APPLICATION_CREDENTIALS not configured. Operating in offline mock mode.",
        }

    if not os.path.isfile(sa_path):
        logger.error(f"[GCP KMS] GOOGLE_APPLICATION_CREDENTIALS path '{sa_path}' does not exist on disk.")
        return {
            "provider": "gcp_kms",
            "name": "Google Cloud KMS / Cloud HSM",
            "mode": "error",
            "credentials_file": sa_path,
            "details": f"Credentials file '{sa_path}' not found on disk.",
        }

    return {
        "provider": "gcp_kms",
        "name": "Google Cloud KMS / Cloud HSM",
        "mode": "live",
        "credentials_file": sa_path,
        "details": f"Service account credential file verified at {sa_path}",
    }


def get_cloud_kms_status() -> Dict[str, Any]:
    """
    Returns consolidated operational mode status for all supported Cloud KMS providers.
    """
    return {
        "aws_kms": get_aws_kms_status(),
        "azure_key_vault": get_azure_kms_status(),
        "gcp_kms": get_gcp_kms_status(),
    }


def fetch_aws_kms_live_keys(region: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Connects to live AWS KMS via boto3 to enumerate customer keys and rotation status.
    """
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    target_region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    client = boto3.client("kms", region_name=target_region)
    keys_list: List[Dict[str, Any]] = []

    paginator = client.get_paginator("list_keys")
    for page in paginator.paginate():
        for k in page.get("Keys", []):
            kid = k.get("KeyId")
            try:
                desc = client.describe_key(KeyId=kid)
                meta = desc.get("KeyMetadata", {})
                spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec", "SYMMETRIC_DEFAULT")
                arn = meta.get("Arn", kid)
                enabled = meta.get("Enabled", True)

                # Check rotation status if symmetric
                rotation = False
                if "SYMMETRIC" in spec.upper():
                    try:
                        rot_resp = client.get_key_rotation_status(KeyId=kid)
                        rotation = rot_resp.get("KeyRotationEnabled", False)
                    except Exception:
                        rotation = False

                keys_list.append({
                    "KeyId": arn,
                    "KeySpec": spec,
                    "Rotation": rotation,
                    "Enabled": enabled,
                })
            except (BotoCoreError, ClientError) as e:
                logger.warning(f"Error describing AWS KMS key {kid}: {e}")

    return keys_list


def fetch_azure_keyvault_live_keys(vault_url: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Connects to live Azure Key Vault using azure-identity and azure-keyvault-keys if installed.
    """
    target_url = vault_url or os.getenv("AZURE_KEY_VAULT_URL", "")
    if not target_url:
        raise ValueError("AZURE_KEY_VAULT_URL is required for live Azure Key Vault discovery.")

    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
    except ImportError:
        logger.warning("azure-identity or azure-keyvault-keys not installed. Returning mock keys.")
        return []

    credential = DefaultAzureCredential()
    client = KeyClient(vault_url=target_url, credential=credential)
    keys_list: List[Dict[str, Any]] = []

    for prop in client.list_properties_of_keys():
        try:
            key = client.get_key(prop.name)
            ktype = key.key_type or "RSA"
            algo = "RSA-HSM-2048" if "RSA" in ktype else "EC-HSM-P256" if "EC" in ktype else "oct-HSM-256"
            keys_list.append({
                "KeyId": key.id,
                "KeySpec": algo,
                "Rotation": bool(key.properties.expires_on),
            })
        except Exception as e:
            logger.warning(f"Error fetching Azure key {prop.name}: {e}")

    return keys_list


def fetch_gcp_kms_live_keys(credentials_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Connects to live Google Cloud KMS using google-cloud-kms if installed.
    """
    sa_path = credentials_path or os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not sa_path or not os.path.isfile(sa_path):
        raise ValueError("Valid GOOGLE_APPLICATION_CREDENTIALS file required for live GCP KMS discovery.")

    try:
        from google.cloud import kms_v1
    except ImportError:
        logger.warning("google-cloud-kms not installed. Returning mock keys.")
        return []

    client = kms_v1.KeyManagementServiceClient()
    keys_list: List[Dict[str, Any]] = []
    # If project/keyring is specified in environment
    project_id = os.getenv("GCP_PROJECT_ID")
    location = os.getenv("GCP_LOCATION", "global")
    keyring_id = os.getenv("GCP_KEYRING_ID")

    if project_id and keyring_id:
        parent = f"projects/{project_id}/locations/{location}/keyRings/{keyring_id}"
        for crypto_key in client.list_crypto_keys(request={"parent": parent}):
            algo = "GOOGLE_SYMMETRIC_ENCRYPTION"
            if crypto_key.primary and crypto_key.primary.algorithm:
                algo = crypto_key.primary.algorithm.name
            keys_list.append({
                "KeyId": crypto_key.name,
                "KeySpec": algo,
                "Rotation": bool(crypto_key.rotation_period),
            })

    return keys_list


def scan_cloud_kms_manifest(
    manifest_data: Optional[str] = None,
    filename: str = "cloud_kms_keys.json",
    provider_hint: Optional[str] = None,
    force_live: bool = False,
) -> Dict[str, Any]:
    """
    Scans cloud KMS configurations.
    If manifest_data is provided, parses the text as JSON/YAML.
    If manifest_data is empty/None, automatically checks if live provider credentials
    are available:
      - If live mode configured: queries live provider endpoints.
      - If mock mode: logs a clear warning and falls back to simulated keys.
    """
    keys_parsed: List[Dict[str, Any]] = []
    provider = provider_hint or "aws_kms"
    execution_mode = "mock"
    mode_info = get_cloud_kms_status().get(provider, {})

    has_payload = bool(manifest_data and manifest_data.strip())
    raw_keys: List[Dict[str, Any]] = []

    if has_payload and manifest_data:
        # Try parsing payload as JSON
        try:
            parsed_json = json.loads(manifest_data)
            if isinstance(parsed_json, list):
                raw_keys = parsed_json
            elif isinstance(parsed_json, dict):
                raw_keys = parsed_json.get("Keys", parsed_json.get("keys", [parsed_json]))
            else:
                raw_keys = []
        except Exception:
            # Fallback to key-value regex parsing
            raw_keys = []
            for line in manifest_data.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.search(r"(?:KeyId|KeyArn|name)\s*[:=]\s*['\"]?([^'\",\s]+)", line, re.IGNORECASE)
                spec_m = re.search(r"(?:KeySpec|algorithm|type)\s*[:=]\s*['\"]?([^'\",\s]+)", line, re.IGNORECASE)
                if m:
                    raw_keys.append({
                        "KeyId": m.group(1),
                        "KeySpec": spec_m.group(1) if spec_m else "RSA_2048"
                    })
    else:
        # No payload passed — check if live mode is enabled for this provider
        if mode_info.get("mode") == "live" or force_live:
            logger.info(f"[Cloud KMS] Attempting live key discovery for provider: {provider}")
            try:
                if provider == "aws_kms":
                    raw_keys = fetch_aws_kms_live_keys()
                    execution_mode = "live"
                elif provider == "azure_key_vault":
                    raw_keys = fetch_azure_keyvault_live_keys()
                    execution_mode = "live"
                elif provider == "gcp_kms":
                    raw_keys = fetch_gcp_kms_live_keys()
                    execution_mode = "live"
            except Exception as e:
                logger.error(f"[Cloud KMS] Live query failed for {provider}: {e}. Falling back to mock data.")
                execution_mode = "mock"
        else:
            logger.warning(f"[Cloud KMS] No live credentials configured for {provider}. Falling back to offline MOCK mode.")
            execution_mode = "mock"

    if not raw_keys:
        # High-fidelity mock fallback
        execution_mode = "mock"
        raw_keys = [
            {"KeyId": "arn:aws:kms:us-east-1:123456789012:key/auth-token-signing-key", "KeySpec": "RSA_2048", "Rotation": True},
            {"KeyId": "arn:aws:kms:us-east-1:123456789012:key/payment-envelope-kek", "KeySpec": "SYMMETRIC_DEFAULT", "Rotation": True},
            {"KeyId": "arn:aws:kms:us-east-1:123456789012:key/inter-service-identity-key", "KeySpec": "ECC_NIST_P256", "Rotation": False},
        ]

    findings: List[Dict[str, Any]] = []
    for item in raw_keys:
        key_id = item.get("KeyId") or item.get("id") or item.get("name") or "kms-key-unknown"
        key_spec = item.get("KeySpec") or item.get("algorithm") or item.get("type") or "RSA_2048"
        rotation_enabled = bool(item.get("Rotation") or item.get("enableKeyRotation") or False)

        # Detect provider from ARN/ID if not specified
        detected_provider = provider
        if "arn:aws:" in key_id or "kms." in key_id:
            detected_provider = "aws_kms"
        elif "vault.azure.net" in key_id or "keys/" in key_id:
            detected_provider = "azure_key_vault"
        elif "cloudkms.googleapis.com" in key_id or "cryptoKeys" in key_id:
            detected_provider = "gcp_kms"

        spec_info = CLOUD_PROVIDER_SPECS.get(detected_provider, CLOUD_PROVIDER_SPECS["aws_kms"])
        type_info = spec_info["key_types"].get(key_spec, {
            "algo": key_spec,
            "usage": "sign_verify" if "RSA" in key_spec or "EC" in key_spec else "symmetric_encryption",
            "pqc_ready": False,
            "vuln": any(k in key_spec.upper() for k in ["RSA", "ECC", "ECDSA"])
        })

        algo = type_info["algo"]
        is_vuln = type_info["vuln"]

        findings.append({
            "key_id": key_id,
            "provider": spec_info["provider"],
            "key_spec": key_spec,
            "algorithm": algo,
            "usage": type_info["usage"],
            "is_quantum_vulnerable": is_vuln,
            "pqc_ready": type_info["pqc_ready"],
            "rotation_enabled": rotation_enabled,
            "severity": "HIGH" if is_vuln else "LOW",
            "recommendation": (
                "Shor's algorithm breaks this asymmetric key. Prepare hybrid ML-KEM / ML-DSA KMS key specification."
                if is_vuln else
                "Symmetric 256-bit key provides 128-bit quantum Grover security. Maintain automated annual rotation."
            )
        })

    return {
        "filename": filename,
        "provider": CLOUD_PROVIDER_SPECS.get(provider, {}).get("provider", "Cloud KMS Provider"),
        "execution_mode": execution_mode,
        "provider_status": mode_info,
        "keys_scanned": len(findings),
        "quantum_vulnerable_keys": sum(1 for f in findings if f["is_quantum_vulnerable"]),
        "findings": findings,
    }


def import_cloud_kms_findings_to_inventory(
    db: Session,
    kms_result: Dict[str, Any],
    service_name: Optional[str] = "Core-Database-Proxy",
    business_criticality: str = "critical",
    data_lifetime: str = "5-10y",
) -> List[Dict[str, Any]]:
    """
    Phase 3: Writes Cloud KMS findings to the unified CryptoAsset inventory
    with source="cloud_kms".
    """
    provider_name = kms_result.get("provider", "Cloud KMS")
    imported = []

    linked_service_id = None
    if service_name:
        svc = db.query(Service).filter(Service.name == service_name).first()
        if svc:
            linked_service_id = svc.id

    for finding in kms_result.get("findings", []):
        key_id = finding.get("key_id", "kms-key")
        clean_key = re.sub(r"[^a-zA-Z0-9_-]", "-", key_id.split("/")[-1])[:35]
        algo = finding.get("algorithm", "RSA-2048")

        host = f"kms.{clean_key.lower()}.internal"
        port_hash = int(hashlib.md5(key_id.encode()).hexdigest(), 16) % 10000
        port = 90000 + port_hash

        pqc_rec = recommend_pqc(algo, finding.get("usage", "sign_verify"))

        risk_flags = [f"KMS_{algo}", "CLOUD_KMS_MANAGED"]
        if finding.get("is_quantum_vulnerable"):
            risk_flags.append("QUANTUM_VULNERABLE_ALGO")
        if not finding.get("rotation_enabled"):
            risk_flags.append("KEY_ROTATION_DISABLED")

        key_size = 2048 if "2048" in algo else 4096 if "4096" in algo else 256 if "256" in algo else None

        asset_record = {
            "status": "success",
            "cert_key_type": algo,
            "cert_key_size_bits": key_size,
            "tls_version": None,
            "days_to_expiry": None,
            "business_criticality": business_criticality,
            "data_lifetime": data_lifetime,
        }

        svc_obj = db.get(Service, linked_service_id) if linked_service_id else None
        svc_crit = svc_obj.criticality if svc_obj else "P0"
        mwqrs = calculate_mwqrs(asset_record, service_criticality=svc_crit)

        existing = db.query(CryptoAsset).filter(
            CryptoAsset.host == host, CryptoAsset.port == port
        ).first()

        if not existing:
            asset = CryptoAsset(
                host=host,
                port=port,
                status="success",
                source="cloud_kms",
                business_criticality=business_criticality,
                data_lifetime=data_lifetime,
                cert_key_type=algo,
                cert_key_size_bits=key_size,
                cert_subject=f"Cloud KMS: {key_id[:60]}",
                cert_issuer=f"{provider_name} | Rotation: {'Enabled' if finding.get('rotation_enabled') else 'Disabled'}",
                algorithm=algo,
                usage_context=finding.get("usage", "sign_verify"),
                confidence_score=0.99,
                library=provider_name,
                file_path=key_id,
                risk_flags=json.dumps(risk_flags),
                risk_score=mwqrs,
                pqc_recommendation=json.dumps(pqc_rec),
                linked_service_id=linked_service_id,
            )
            db.add(asset)
        else:
            existing.source = "cloud_kms"
            existing.business_criticality = business_criticality
            existing.data_lifetime = data_lifetime
            existing.risk_score = mwqrs
            existing.pqc_recommendation = json.dumps(pqc_rec)

        imported.append({"host": host, "port": port, "algorithm": algo, "risk_score": mwqrs})

    db.commit()
    return imported
