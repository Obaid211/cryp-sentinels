"""
test_live_credential_modes.py
=============================
Tests live vs mock mode code-path detection and healthcheck reporting for:
1. AWS KMS (credential chain)
2. Azure Key Vault (vault URL & credentials)
3. Google Cloud KMS (service account ADC)
4. Hardware Security Module (PKCS#11 module path validation)
5. Scanner modes health check API (/health and /api/scanners/modes)
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.services.cloud_kms_scanner import (
    get_aws_kms_status,
    get_azure_kms_status,
    get_gcp_kms_status,
    get_cloud_kms_status,
    scan_cloud_kms_manifest,
)
from app.services.hsm_scanner import (
    get_hsm_status,
    scan_hsm_configuration,
)

client = TestClient(app)


def test_cloud_kms_default_mock_mode(monkeypatch):
    """When credentials are absent, cloud scanners report mock mode."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    monkeypatch.delenv("AZURE_KEY_VAULT_URL", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    aws_status = get_aws_kms_status()
    assert aws_status["mode"] == "mock"

    azure_status = get_azure_kms_status()
    assert azure_status["mode"] == "mock"

    gcp_status = get_gcp_kms_status()
    assert gcp_status["mode"] == "mock"

    # Default manifest scan runs in mock mode
    result = scan_cloud_kms_manifest(manifest_data=None, provider_hint="aws_kms")
    assert result["execution_mode"] == "mock"
    assert result["keys_scanned"] > 0


def test_aws_kms_live_mode_detection(monkeypatch):
    """Setting AWS env vars engages live mode and code path selection."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock-aws-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock-aws-secret-key")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    status = get_aws_kms_status()
    assert status["mode"] == "live"
    assert status["provider"] == "aws_kms"

    # Mock boto3 list_keys and describe_key to test code path execution
    mock_boto_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Keys": [{"KeyId": "arn:aws:kms:us-east-1:123456789012:key/test-live-key"}]}
    ]
    mock_boto_client.get_paginator.return_value = mock_paginator
    mock_boto_client.describe_key.return_value = {
        "KeyMetadata": {
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/test-live-key",
            "KeySpec": "RSA_4096",
            "Enabled": True,
        }
    }
    mock_boto_client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}

    with patch("boto3.client", return_value=mock_boto_client):
        scan_result = scan_cloud_kms_manifest(manifest_data=None, provider_hint="aws_kms")
        assert scan_result["execution_mode"] == "live"
        assert scan_result["keys_scanned"] == 1
        assert scan_result["findings"][0]["key_spec"] == "RSA_4096"
        assert scan_result["findings"][0]["is_quantum_vulnerable"] is True


def test_azure_kms_live_mode_detection(monkeypatch):
    """Setting AZURE_KEY_VAULT_URL engages live mode."""
    monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://prod-vault.vault.azure.net/")
    monkeypatch.setenv("AZURE_CLIENT_ID", "dummy-client-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "dummy-secret")
    monkeypatch.setenv("AZURE_TENANT_ID", "dummy-tenant")

    status = get_azure_kms_status()
    assert status["mode"] == "live"
    assert status["vault_url"] == "https://prod-vault.vault.azure.net/"


def test_gcp_kms_live_mode_detection(monkeypatch):
    """Setting GOOGLE_APPLICATION_CREDENTIALS to a real file path engages live mode."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b'{"type": "service_account", "project_id": "test-pqc-project"}')
        temp_creds_path = f.name

    try:
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", temp_creds_path)
        status = get_gcp_kms_status()
        assert status["mode"] == "live"
        assert status["credentials_file"] == temp_creds_path
    finally:
        if os.path.exists(temp_creds_path):
            os.remove(temp_creds_path)


def test_hsm_default_mock_mode(monkeypatch):
    """When PKCS11_MODULE_PATH is absent, HSM scanner reports mock mode."""
    monkeypatch.delenv("PKCS11_MODULE_PATH", raising=False)
    monkeypatch.delenv("PKCS11_LIB_PATH", raising=False)

    status = get_hsm_status()
    assert status["mode"] == "mock"

    result = scan_hsm_configuration(config_text=None, vendor_hint="thales_luna")
    assert result["execution_mode"] == "mock"
    assert result["vendor_key"] == "thales_luna"
    assert result["findings_count"] > 0


def test_hsm_live_mode_detection(monkeypatch):
    """Setting PKCS11_MODULE_PATH to an existing file engages live mode."""
    with tempfile.NamedTemporaryFile(suffix=".dll" if os.name == "nt" else ".so", delete=False) as f:
        f.write(b"mock driver binary content")
        driver_path = f.name

    try:
        monkeypatch.setenv("PKCS11_MODULE_PATH", driver_path)
        status = get_hsm_status()
        assert status["mode"] == "live"
        assert status["module_path"] == driver_path

        result = scan_hsm_configuration(config_text=None)
        assert result["execution_mode"] == "live"
    finally:
        if os.path.exists(driver_path):
            os.remove(driver_path)


def test_hsm_missing_module_error_mode(monkeypatch):
    """Setting PKCS11_MODULE_PATH to a nonexistent path reports error mode."""
    monkeypatch.setenv("PKCS11_MODULE_PATH", "/non/existent/path/to/driver.so")
    status = get_hsm_status()
    assert status["mode"] == "error"

    # Calling scan with no text raises descriptive error
    with pytest.raises(ValueError) as exc:
        scan_hsm_configuration(config_text=None)
    assert "not found on disk" in str(exc.value)


def test_health_and_scanner_modes_endpoints():
    """Validates /health and /api/scanners/modes return live/mock telemetry."""
    # Test /health
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    health_data = health_resp.json()
    assert "scanner_modes" in health_data
    modes = health_data["scanner_modes"]
    for scanner_name in ["aws_kms", "azure_key_vault", "gcp_kms", "hsm_pkcs11", "tls", "source_code", "dependency", "container", "binary"]:
        assert scanner_name in modes
        assert "mode" in modes[scanner_name]

    # Test /api/scanners/modes
    modes_resp = client.get("/api/scanners/modes")
    assert modes_resp.status_code == 200
    modes_data = modes_resp.json()
    assert "aws_kms" in modes_data
    assert "hsm_pkcs11" in modes_data

    # Test /api/phase3/status
    phase3_resp = client.get("/api/phase3/status")
    assert phase3_resp.status_code == 200
    phase3_data = phase3_resp.json()
    assert "hsm" in phase3_data
    assert "cloud_kms" in phase3_data
