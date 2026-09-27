import React, { useState, useEffect, useRef } from 'react';
import { API_BASE_URL } from '../config';

type ScannerTab = 'TLS' | 'CODE' | 'DEPENDENCY' | 'CONTAINER' | 'BINARY' | 'HSM' | 'CLOUD_KMS' | 'API';

interface TlsScanResult {
  host: string;
  port: number;
  status: 'success' | 'error';
  tls_version?: string;
  cipher_suite?: string;
  cipher_bits?: number;
  cert_subject?: string;
  cert_issuer?: string;
  cert_key_type?: string;
  cert_key_size_bits?: number;
  cert_signature_algorithm?: string;
  days_to_expiry?: number;
  risk_flags?: string[];
  risk_score?: number;
  error_message?: string;
  scanned_at?: string;
}

interface FindingItem {
  rule_id: string;
  finding_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  code_snippet?: string;
  evidence?: string;
  component?: string;
  explanation?: string;
  remediation?: string;
  recommendation?: string;
  quantum_status?: string;
  line_number?: number;
  source_file?: string;
}

interface ApiScanResult {
  url: string;
  is_https: boolean;
  jwt_analysis?: {
    header: Record<string, unknown>;
    classification: {
      algorithm: string;
      type: string;
      quantum_status: string;
      risk_level: string;
      recommendation: string;
    };
  };
  findings: FindingItem[];
  findings_count: number;
}

const PRESET_CODE_VULN = `import hashlib
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA

# Hardcoded legacy private key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Yh05s6J60bX...
-----END RSA PRIVATE KEY-----"""

def authenticate_user(username, password):
    # CRITICAL: Collision-vulnerable hashing
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    
    # CRITICAL: Deprecated 56-bit DES cipher
    cipher = DES.new(b"12345678", DES.MODE_ECB)
    
    # HIGH: Under-strength RSA key generation
    rsa_key = RSA.generate(1024)
    return pwd_hash
`;

const PRESET_CODE_SECURE = `import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Modern post-quantum hybrid ready configuration
def secure_encrypt_payload(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    # NIST FIPS 197 Approved AES-256-GCM AEAD
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)

def compute_hmac_sha256(secret: bytes, message: bytes) -> bytes:
    # Quantum-resistant symmetric integrity (Grover security: 128-bit)
    return hmac.new(secret, message, hashlib.sha256).digest()
`;

const PRESET_DOCKER_VULN = `FROM ubuntu:14.04
MAINTAINER security-team@legacy.internal

# Insecure certificate verification bypass
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

# Embedding root private keys into container layer
COPY id_rsa.key /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa

# Downgrading OpenSSL security level to zero
RUN sed -i 's/SECLEVEL=2/SECLEVEL=0/' /etc/ssl/openssl.cnf

CMD ["python", "app.py"]
`;

const PRESET_DOCKER_SECURE = `FROM debian:12-slim
LABEL maintainer="ecdat-security@sovereign.internal"

# Enforce strict system-wide cryptographic policies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates openssl libssl3 && \\
    rm -rf /var/lib/apt/lists/*

# Strict unprivileged execution boundary
USER 10001:10001
CMD ["./server"]
`;

const PRESET_JWT_RS256 = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.signature';
const PRESET_JWT_PQC = 'eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJzb3ZlcmVpZ24tdXNlciIsInJvbGUiOiJhdXRoIn0.pqc_sig';

const PRESET_BIN_OPENSSL = `ELF\\x02\\x01\\x01\\x00
OpenSSL 3.0.2 15 Mar 2022
RSA_generate_key_ex
RSA_public_encrypt
EVP_PKEY_RSA
EC_KEY_new
ECDSA_do_sign
libcrypto.so.3
PKCS#8
`;

const PRESET_BIN_PQC = `ELF\\x02\\x01\\x01\\x00
OQS_KEM_new
OQS_KEM_alg_ml_kem_768
ML-KEM-768
OQS_SIG_alg_ml_dsa_65
ML-DSA-65
liboqs.so.0
`;

const PRESET_BIN_LIBSODIUM = `ELF\\x02\\x01\\x01\\x00
sodium_init
crypto_secretbox_easy
crypto_sign_ed25519
crypto_box_curve25519xsalsa20poly1305
libsodium.so.23
`;

const PRESET_HSM_LUNA = `slot = 1
token_label = "Production Sovereign Root PKCS#11 Token"
library = "/usr/lib/libCryptoki2_64.so"
vendor = "Thales Luna PCIe HSM"
fips_mode = "FIPS 140-2 Level 3"
mechanisms = "CKM_RSA_PKCS_KEY_PAIR_GEN,CKM_RSA_PKCS,CKM_ECDSA_KEY_PAIR_GEN,CKM_AES_GCM"
`;

const PRESET_HSM_YUBI = `slot = 0
token_label = "YubiHSM2 Auth Token"
connector = "http://127.0.0.1:12345"
vendor = "Yubico YubiHSM 2"
mechanisms = "RSA_2048,ECDSA_P256,ED25519,AES_128_CCM"
`;

const PRESET_CLOUD_KMS = `{
  "Keys": [
    {
      "KeyId": "arn:aws:kms:us-east-1:123456789012:key/auth-token-signing-key",
      "KeySpec": "RSA_2048",
      "KeyUsage": "SIGN_VERIFY",
      "Rotation": true,
      "Description": "Production JWT Token Root Authority"
    },
    {
      "KeyId": "arn:aws:kms:us-east-1:123456789012:key/payment-envelope-kek",
      "KeySpec": "SYMMETRIC_DEFAULT",
      "KeyUsage": "ENCRYPT_DECRYPT",
      "Rotation": true,
      "Description": "Cardholder Data Envelope Key"
    },
    {
      "KeyId": "arn:aws:kms:us-east-1:123456789012:key/inter-service-identity-key",
      "KeySpec": "ECC_NIST_P256",
      "KeyUsage": "SIGN_VERIFY",
      "Rotation": false,
      "Description": "Mutual Service Authentication Signature Key"
    }
  ]
}`;

interface ScannerSuiteProps {
  mode?: 'LIVE' | 'CACHED' | 'OFFLINE';
}

export const ScannerSuite: React.FC<ScannerSuiteProps> = ({ mode = 'LIVE' }) => {
  const [activeTab, setActiveTab] = useState<ScannerTab>('TLS');

  // TLS Scan State
  const [tlsHost, setTlsHost] = useState(mode === 'OFFLINE' ? 'auth.internal.net' : 'api.github.com');
  const [tlsPort, setTlsPort] = useState('443');
  const [tlsResult, setTlsResult] = useState<TlsScanResult | null>(null);
  const [tlsLoading, setTlsLoading] = useState(false);
  const [importStatus, setImportStatus] = useState<string | null>(null);

  // Code Scan State
  const [codeContent, setCodeContent] = useState(PRESET_CODE_VULN);
  const [codeFilename, setCodeFilename] = useState('auth_service.py');
  const [codeFindings, setCodeFindings] = useState<FindingItem[]>([]);
  const [codeLoading, setCodeLoading] = useState(false);

  // Dependency Scan State (Phase 1)
  const [depContent, setDepContent] = useState(`cryptography==41.0.3
pyopenssl>=22.0.0
pycryptodome==3.19.0
jwt==1.3.1
bcrypt==4.0.1
paramiko==3.3.1
argon2-cffi==23.1.0
`);
  const [depFilename, setDepFilename] = useState('requirements.txt');
  const [depFindings, setDepFindings] = useState<Record<string, unknown>[]>([]);
  const [depLoading, setDepLoading] = useState(false);
  const [depImportStatus, setDepImportStatus] = useState<string | null>(null);

  // Container Scan State
  const [dockerContent, setDockerContent] = useState(PRESET_DOCKER_VULN);
  const [dockerFindings, setDockerFindings] = useState<FindingItem[]>([]);
  const [dockerLoading, setDockerLoading] = useState(false);
  const [containerImportStatus, setContainerImportStatus] = useState<string | null>(null);

  // Binary Scan State (Phase 2)
  const [binContent, setBinContent] = useState(PRESET_BIN_OPENSSL);
  const [binFilename, setBinFilename] = useState('libauth_crypto.so');
  const [binFindings, setBinFindings] = useState<Record<string, unknown>[]>([]);
  const [binLoading, setBinLoading] = useState(false);
  const [binImportStatus, setBinImportStatus] = useState<string | null>(null);
  const [binLibraries, setBinLibraries] = useState<string[]>([]);
  const [binFormat, setBinFormat] = useState<string | null>(null);

  // HSM Scan State (Phase 3)
  const [hsmContent, setHsmContent] = useState(PRESET_HSM_LUNA);
  const [hsmFilename, setHsmFilename] = useState('pkcs11.conf');
  const [hsmFindings, setHsmFindings] = useState<Record<string, unknown>[]>([]);
  const [hsmLoading, setHsmLoading] = useState(false);
  const [hsmImportStatus, setHsmImportStatus] = useState<string | null>(null);

  // Cloud KMS Scan State (Phase 3)
  const [kmsContent, setKmsContent] = useState(PRESET_CLOUD_KMS);
  const [kmsFilename, setKmsFilename] = useState('cloud_kms_keys.json');
  const [kmsFindings, setKmsFindings] = useState<Record<string, unknown>[]>([]);
  const [kmsLoading, setKmsLoading] = useState(false);
  const [kmsImportStatus, setKmsImportStatus] = useState<string | null>(null);

  // API Scan State
  const [apiUrl, setApiUrl] = useState('https://api.internal.net/v1/auth/token');
  const [jwtToken, setJwtToken] = useState(PRESET_JWT_RS256);
  const [apiResult, setApiResult] = useState<ApiScanResult | null>(null);
  const [apiLoading, setApiLoading] = useState(false);

  // Stream Terminal Logs
  const [streamLogs, setStreamLogs] = useState<Array<{ step: number; pct: number; message: string }>>([]);
  const [streamActive, setStreamActive] = useState(false);
  const [streamProgress, setStreamProgress] = useState(0);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [streamLogs]);

  // Trigger SSE stream
  const triggerScanStream = (targetName: string) => {
    setStreamLogs([]);
    setStreamActive(true);
    setStreamProgress(0);

    const eventSource = new EventSource(`${API_BASE_URL}/api/scanners/stream?target=${encodeURIComponent(targetName)}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setStreamLogs((prev) => [...prev, data]);
        setStreamProgress(data.pct);
        if (data.pct >= 100) {
          eventSource.close();
          setStreamActive(false);
        }
      } catch (err) {
        console.error('SSE JSON error:', err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      setStreamActive(false);
    };
  };

  // Run TLS scan
  const handleTlsScan = async () => {
    setTlsLoading(true);
    setImportStatus(null);
    triggerScanStream(`${tlsHost}:${tlsPort}`);

    try {
      const res = await fetch(`${API_BASE_URL}/api/scanners/tls`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: tlsHost, port: parseInt(tlsPort, 10) || 443, mode }),
      });
      const data: TlsScanResult = await res.json();
      setTlsResult(data);
    } catch (err) {
      console.error('TLS scan error:', err);
      setTlsResult({ host: tlsHost, port: parseInt(tlsPort, 10), status: 'error', error_message: String(err) });
    } finally {
      setTlsLoading(false);
    }
  };

  // Import finding to inventory
  const handleImportToInventory = async () => {
    if (!tlsResult || tlsResult.status !== 'success') return;
    try {
      setImportStatus('Importing...');
      const res = await fetch(`${API_BASE_URL}/api/scanners/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding: tlsResult }),
      });
      if (res.ok) {
        setImportStatus('Successfully Imported into Inventory!');
      } else {
        setImportStatus('Import failed.');
      }
    } catch (err) {
      setImportStatus('Import error: ' + String(err));
    }
  };

  // Run Code scan (Phase 1: use /api/phase1/scan/source-code → imports to inventory)
  const handleCodeScan = async () => {
    setCodeLoading(true);
    triggerScanStream(`AST Scanner: ${codeFilename}`);

    try {
      const res = await fetch(`${API_BASE_URL}/api/phase1/scan/source-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: codeContent,
          filename: codeFilename,
          repo_name: codeFilename.replace('.py', '').replace('.js', ''),
          import_to_inventory: true,
          business_criticality: 'high',
          data_lifetime: '3-5y',
        }),
      });
      const data = await res.json();
      setCodeFindings(data.findings || []);
    } catch (err) {
      console.error('Code scan error:', err);
    } finally {
      setCodeLoading(false);
    }
  };

  // Run Dependency scan (Phase 1)
  const handleDepScan = async () => {
    setDepLoading(true);
    setDepImportStatus(null);
    triggerScanStream(`Dependency Scanner: ${depFilename}`);
    try {
      const res = await fetch(`${API_BASE_URL}/api/phase1/scan/dependency`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: depContent,
          filename: depFilename,
          import_to_inventory: true,
          business_criticality: 'high',
          data_lifetime: '3-5y',
        }),
      });
      const data = await res.json();
      setDepFindings(data.findings || []);
      if (data.inventory_imported > 0) {
        setDepImportStatus(`✓ ${data.inventory_imported} library assets imported to Inventory`);
      }
    } catch (err) {
      console.error('Dependency scan error:', err);
    } finally {
      setDepLoading(false);
    }
  };


  // Run Container scan (Phase 2: imports to inventory with source="container")
  const handleContainerScan = async () => {
    setDockerLoading(true);
    setContainerImportStatus(null);
    triggerScanStream('Dockerfile Build Layers');

    try {
      const res = await fetch(`${API_BASE_URL}/api/phase2/scan/container`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: dockerContent,
          filename: 'Dockerfile',
          container_name: 'auth-microservice-img',
          service_name: 'Auth-Service',
          import_to_inventory: true,
          business_criticality: 'high',
          data_lifetime: '1-3y',
        }),
      });
      const data = await res.json();
      setDockerFindings(data.findings || []);
      if (data.inventory_imported > 0) {
        setContainerImportStatus(`✓ ${data.inventory_imported} container finding(s) imported to Inventory (source: container)`);
      }
    } catch (err) {
      console.error('Container scan error:', err);
    } finally {
      setDockerLoading(false);
    }
  };

  // Run Binary scan (Phase 2: static inspection of binary symbols -> inventory)
  const handleBinaryScan = async () => {
    setBinLoading(true);
    setBinImportStatus(null);
    triggerScanStream(`Binary Symbol Scanner: ${binFilename}`);

    try {
      const res = await fetch(`${API_BASE_URL}/api/phase2/scan/binary`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content_text: binContent,
          filename: binFilename,
          service_name: 'Auth-Service',
          import_to_inventory: true,
          business_criticality: 'critical',
          data_lifetime: '5-10y',
        }),
      });
      const data = await res.json();
      setBinFindings(data.findings || []);
      setBinLibraries(data.libraries_detected || []);
      setBinFormat(data.file_format || null);
      if (data.inventory_imported > 0) {
        setBinImportStatus(`✓ ${data.inventory_imported} binary finding(s) imported to Inventory (source: binary)`);
      }
    } catch (err) {
      console.error('Binary scan error:', err);
    } finally {
      setBinLoading(false);
    }
  };

  // Run HSM scan (Phase 3)
  const handleHsmScan = async () => {
    setHsmLoading(true);
    setHsmImportStatus(null);
    triggerScanStream(`Hardware HSM Prober: ${hsmFilename}`);

    try {
      const res = await fetch(`${API_BASE_URL}/api/phase3/scan/hsm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: hsmContent,
          filename: hsmFilename,
          service_name: 'Payment-Gateway',
          import_to_inventory: true,
          business_criticality: 'critical',
          data_lifetime: '5-10y',
        }),
      });
      const data = await res.json();
      setHsmFindings(data.findings || []);
      if (data.inventory_imported > 0) {
        setHsmImportStatus(`✓ ${data.inventory_imported} HSM cryptographic mechanism(s) imported to Inventory (source: hsm)`);
      }
    } catch (err) {
      console.error('HSM scan error:', err);
    } finally {
      setHsmLoading(false);
    }
  };

  // Run Cloud KMS scan (Phase 3)
  const handleCloudKmsScan = async () => {
    setKmsLoading(true);
    setKmsImportStatus(null);
    triggerScanStream(`Cloud KMS Auditor: ${kmsFilename}`);

    try {
      const res = await fetch(`${API_BASE_URL}/api/phase3/scan/cloud-kms`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: kmsContent,
          filename: kmsFilename,
          service_name: 'Core-Database-Proxy',
          import_to_inventory: true,
          business_criticality: 'critical',
          data_lifetime: '5-10y',
        }),
      });
      const data = await res.json();
      setKmsFindings(data.findings || []);
      if (data.inventory_imported > 0) {
        setKmsImportStatus(`✓ ${data.inventory_imported} Cloud KMS key(s) imported to Inventory (source: cloud_kms)`);
      }
    } catch (err) {
      console.error('Cloud KMS scan error:', err);
    } finally {
      setKmsLoading(false);
    }
  };

  // Run API scan
  const handleApiScan = async () => {
    setApiLoading(true);
    triggerScanStream(apiUrl);

    try {
      const res = await fetch(`${API_BASE_URL}/api/scanners/api`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: apiUrl, sample_jwt: jwtToken }),
      });
      const data: ApiScanResult = await res.json();
      setApiResult(data);
    } catch (err) {
      console.error('API scan error:', err);
    } finally {
      setApiLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="border border-[var(--border)] bg-[var(--surface)] p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-semibold">
              Capability 01 & 07 / 09
            </span>
            <span className="h-3 w-px bg-[var(--border)]" />
            <span className="font-mono text-xs text-[var(--text-muted)]">
              Multi-Vector Cryptographic Discovery & AST Analysis
            </span>
          </div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-tight text-[var(--text-primary)] mt-1">
            Cryptographic Scanner Suite
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-3xl">
            Live multi-surface discovery engines across TLS handshakes, source code AST primitives, container image build layers, and API JWT signature algorithms.
          </p>
        </div>

        {/* Scanner Tabs */}
        <div className="inline-flex border border-[var(--border)] bg-[var(--surface-raised)]">
          {(
            [
              { id: 'TLS', label: '1. Live TLS' },
              { id: 'CODE', label: '2. Source AST' },
              { id: 'DEPENDENCY', label: '3. Dependencies' },
              { id: 'CONTAINER', label: '4. Dockerfile' },
              { id: 'BINARY', label: '5. Binary' },
              { id: 'HSM', label: '6. Hardware HSM' },
              { id: 'CLOUD_KMS', label: '7. Cloud KMS' },
              { id: 'API', label: '8. API & JWT' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 font-mono text-xs font-bold uppercase transition-colors ${
                activeTab === tab.id
                  ? 'bg-[var(--text-primary)] text-[var(--surface)]'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Scanner Body */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Interactive Probe Pane */}
        <div className="lg:col-span-7 space-y-6">
          {/* TAB 1: LIVE TLS */}
          {activeTab === 'TLS' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-5">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                  Live Network TLS Prober
                </h2>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Presets:</span>
                  <button
                    onClick={() => { setTlsHost('api.github.com'); setTlsPort('443'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    GitHub
                  </button>
                  <button
                    onClick={() => { setTlsHost('google.com'); setTlsPort('443'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    Google
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className="sm:col-span-2 space-y-1">
                  <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                    Target Hostname or IP
                  </label>
                  <input
                    type="text"
                    value={tlsHost}
                    onChange={(e) => setTlsHost(e.target.value)}
                    placeholder="example.com"
                    className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2.5 text-[var(--text-primary)] font-mono outline-none focus:border-[var(--accent)]"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                    Port
                  </label>
                  <input
                    type="number"
                    value={tlsPort}
                    onChange={(e) => setTlsPort(e.target.value)}
                    className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2.5 text-[var(--text-primary)] font-mono outline-none focus:border-[var(--accent)]"
                  />
                </div>
              </div>

              <button
                onClick={handleTlsScan}
                disabled={tlsLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase tracking-wider hover:bg-[var(--accent)] transition-colors flex items-center justify-center gap-2"
              >
                {tlsLoading ? 'Initiating Handshake...' : '▶ Probe Live TLS Handshake'}
              </button>

              {/* TLS Findings Card */}
              {tlsResult && (
                <div className="border border-[var(--border)] bg-[var(--surface-raised)] overflow-hidden">
                  {/* Card Header */}
                  <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)] bg-[var(--surface)]">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-base font-bold text-[var(--text-primary)]">
                        {tlsResult.host}:{tlsResult.port}
                      </span>
                      <span className="font-mono text-xs text-[var(--text-muted)] uppercase tracking-widest">
                        Scan Result
                      </span>
                    </div>
                    <span
                      className={`px-3 py-1 font-mono text-sm font-bold uppercase tracking-wider ${
                        tlsResult.status === 'success'
                          ? 'bg-[#ecfdf5] text-[#047857] border border-[#10b981]'
                          : 'bg-[#fee2e2] text-[#b91c1c] border border-[#ef4444]'
                      }`}
                    >
                      {tlsResult.status}
                    </span>
                  </div>

                  {tlsResult.status === 'success' ? (
                    <div className="divide-y divide-[var(--border)]">

                      {/* TLS Version Row */}
                      <div className="flex items-start justify-between px-5 py-4 gap-4">
                        <div className="space-y-0.5">
                          <div className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">
                            TLS Protocol Version
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-muted)] leading-snug max-w-xs">
                            Negotiated handshake protocol. TLS 1.3 is the current NIST-recommended standard with forward secrecy.
                          </div>
                        </div>
                        <div className="font-mono text-base font-bold text-[var(--text-primary)] whitespace-nowrap shrink-0">
                          {tlsResult.tls_version}
                        </div>
                      </div>

                      {/* Cipher Suite Row */}
                      <div className="flex items-start justify-between px-5 py-4 gap-4">
                        <div className="space-y-0.5">
                          <div className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">
                            Active Cipher Suite
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-muted)] leading-snug max-w-xs">
                            Symmetric encryption algorithm used for the session. AES-256-GCM provides 256-bit AEAD protection.
                          </div>
                        </div>
                        <div className="font-mono text-sm font-bold text-[var(--text-primary)] whitespace-nowrap shrink-0 text-right">
                          {tlsResult.cipher_suite}
                        </div>
                      </div>

                      {/* Key Type Row */}
                      <div className="flex items-start justify-between px-5 py-4 gap-4">
                        <div className="space-y-0.5">
                          <div className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">
                            Certificate Key Type & Strength
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-muted)] leading-snug max-w-xs">
                            Public key algorithm and bit-length. ECC secp256r1 is quantum-vulnerable (Shor's algorithm applicable).
                          </div>
                        </div>
                        <div className="font-mono text-base font-bold text-[var(--text-primary)] whitespace-nowrap shrink-0 text-right">
                          {tlsResult.cert_key_type}
                          <span className="ml-1.5 text-sm font-normal text-[var(--text-muted)]">
                            ({tlsResult.cert_key_size_bits} bits)
                          </span>
                        </div>
                      </div>

                      {/* Expiry Row */}
                      <div className="flex items-start justify-between px-5 py-4 gap-4">
                        <div className="space-y-0.5">
                          <div className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">
                            Certificate Expiry Window
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-muted)] leading-snug max-w-xs">
                            Days until the certificate expires. Short-lived certs (&lt;90d) reduce HNDOY harvest-now-decrypt-later exposure.
                          </div>
                        </div>
                        <div className={`font-mono text-base font-bold whitespace-nowrap shrink-0 ${
                          (tlsResult.days_to_expiry ?? 999) < 30
                            ? 'text-[#b91c1c]'
                            : (tlsResult.days_to_expiry ?? 999) < 90
                            ? 'text-[#d97706]'
                            : 'text-[#047857]'
                        }`}>
                          {tlsResult.days_to_expiry} days
                        </div>
                      </div>

                      {/* MWQRS Score Row */}
                      <div className="flex items-center justify-between px-5 py-5 bg-[var(--surface)] gap-4">
                        <div className="space-y-0.5">
                          <div className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">
                            Mosca-Weighted Quantum Risk Score
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-muted)] leading-snug max-w-xs">
                            MWQRS v2.4 composite score: algorithm strength, key size, expiry window, and PQC migration readiness. Lower is safer.
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <div className="font-display text-3xl font-extrabold text-[var(--accent)]">
                            {tlsResult.risk_score?.toFixed(1)}
                          </div>
                          <div className="font-mono text-xs text-[var(--text-muted)] font-semibold">
                            / 100 MWQRS
                          </div>
                        </div>
                      </div>

                      {/* Commit Footer */}
                      <div className="flex items-center justify-between px-5 py-3">
                        <span className="text-xs font-mono text-[var(--accent)] font-bold">
                          {importStatus || ''}
                        </span>
                        <button
                          onClick={handleImportToInventory}
                          className="px-5 py-2 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)] text-xs font-mono font-bold uppercase tracking-wider transition-colors"
                        >
                          + Commit to Inventory
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="px-5 py-4 text-sm text-[#b91c1c] font-mono">
                      Error: {tlsResult.error_message}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SOURCE CODE AST */}
          {activeTab === 'CODE' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                  Source Code AST Scanner
                </h2>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Presets:</span>
                  <button
                    onClick={() => { setCodeContent(PRESET_CODE_VULN); setCodeFilename('auth_legacy.py'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    Vulnerable Code
                  </button>
                  <button
                    onClick={() => { setCodeContent(PRESET_CODE_SECURE); setCodeFilename('crypto_modern.py'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    PQC Clean
                  </button>
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  File Identifier
                </label>
                <input
                  type="text"
                  value={codeFilename}
                  onChange={(e) => setCodeFilename(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2 text-[var(--text-primary)] font-mono text-xs"
                />
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  Source Code Buffer
                </label>
                <textarea
                  rows={9}
                  value={codeContent}
                  onChange={(e) => setCodeContent(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[#1e1e1e] text-[#d4d4d4] p-3 font-mono text-xs leading-relaxed outline-none"
                />
              </div>

              <button
                onClick={handleCodeScan}
                disabled={codeLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase hover:bg-[var(--accent)] transition-colors"
              >
                {codeLoading ? 'Executing AST Parse...' : '▶ Run AST Cryptographic Inspection'}
              </button>

              {/* Code Findings */}
              {codeFindings.length > 0 && (
                <div className="space-y-2 pt-2">
                  <span className="font-mono text-xs uppercase text-[var(--accent)] font-bold">
                    Findings Detected ({codeFindings.length})
                  </span>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {codeFindings.map((f, i) => (
                      <div key={i} className="border border-[var(--border)] bg-[var(--surface-raised)] p-3 text-xs space-y-1">
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-bold text-[var(--text-primary)]">
                            Line {f.line_number}: {f.finding_type}
                          </span>
                          <span className="px-1.5 py-0.2 bg-[#fee2e2] text-[#b91c1c] border border-[#ef4444] font-bold text-[10px]">
                            {f.severity}
                          </span>
                        </div>
                        <pre className="p-2 bg-[var(--surface)] border border-[var(--border)] text-[11px] font-mono overflow-x-auto text-[var(--text-secondary)]">
                          {f.code_snippet}
                        </pre>
                        <p className="text-[11px] text-[var(--text-secondary)]">
                          <strong>Remediation:</strong> {f.remediation}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: DEPENDENCY SCANNER (Phase 1) */}
          {activeTab === 'DEPENDENCY' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <div>
                  <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                    Dependency / Library Scanner
                  </h2>
                  <p className="text-[11px] font-mono text-[var(--text-muted)] mt-0.5">
                    Phase 1 · Parses requirements.txt, package.json, go.mod, Cargo.toml, pom.xml, build.gradle
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Manifest type:</span>
                  {['requirements.txt', 'package.json', 'go.mod', 'Cargo.toml', 'pom.xml', 'build.gradle'].map(f => (
                    <button
                      key={f}
                      onClick={() => setDepFilename(f)}
                      className={`font-mono text-[10px] px-2 py-0.5 border transition-colors ${
                        depFilename === f
                          ? 'border-[var(--accent)] bg-[var(--accent)] text-white'
                          : 'border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]'
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  Manifest Content — {depFilename}
                </label>
                <textarea
                  rows={8}
                  value={depContent}
                  onChange={(e) => setDepContent(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[#1e1e1e] text-[#d4d4d4] p-3 font-mono text-xs leading-relaxed outline-none"
                />
              </div>

              <button
                onClick={handleDepScan}
                disabled={depLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase tracking-wider hover:bg-[var(--accent)] transition-colors flex items-center justify-center gap-2"
              >
                {depLoading ? 'Scanning Dependencies...' : '▶ Scan Dependency Manifest → Import to Inventory'}
              </button>

              {depImportStatus && (
                <div className="border border-green-300 bg-green-50 text-green-800 font-mono text-xs px-4 py-2 font-bold">
                  {depImportStatus}
                </div>
              )}

              {depFindings.length > 0 && (
                <div className="border border-[var(--border)] overflow-hidden">
                  <div className="bg-[var(--surface-raised)] border-b border-[var(--border)] px-4 py-2 font-mono text-xs font-bold text-[var(--text-muted)] uppercase flex justify-between">
                    <span>Crypto Library Findings — {depFindings.length} detected</span>
                    <span>source: dependency → unified inventory</span>
                  </div>
                  <div className="divide-y divide-[var(--border)]">
                    {(depFindings as Record<string, unknown>[]).map((f, i) => {
                      const risk = String(f.inferred_risk || 'medium');
                      const riskColor = risk === 'high' ? 'text-red-700 bg-red-50 border-red-300'
                        : risk === 'medium' ? 'text-amber-700 bg-amber-50 border-amber-300'
                        : 'text-green-700 bg-green-50 border-green-300';
                      return (
                        <div key={i} className="p-4 font-mono text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[var(--text-primary)] text-sm">{String(f.name)}</span>
                              {Boolean(f.version) && <span className="text-[var(--text-muted)]">v{String(f.version)}</span>}
                              <span className={`border px-2 py-0.5 font-bold uppercase text-[10px] ${riskColor}`}>
                                {risk} risk
                              </span>
                              {Boolean(f.pqc_ready) && (
                                <span className="border border-green-300 bg-green-50 text-green-700 px-2 py-0.5 font-bold uppercase text-[10px]">
                                  PQC Ready
                                </span>
                              )}
                            </div>
                            {Boolean(f.quantum_vulnerable_defaults) && (
                              <span className="text-red-600 font-bold text-[10px] uppercase">⚠ Quantum-Vulnerable Defaults</span>
                            )}
                          </div>
                          <div className="text-[var(--text-muted)]">{String(f.capability || '')}</div>
                          <div className="flex items-start gap-2">
                            <span className="text-[var(--text-muted)] uppercase text-[10px] font-bold shrink-0">PQC Target:</span>
                            <span className="text-[var(--accent)] font-semibold">{String(f.pqc_recommendation || '')}</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <span className="text-[var(--text-muted)] uppercase text-[10px] font-bold shrink-0">Upgrade Note:</span>
                            <span className="text-[var(--text-secondary)] text-[11px]">{String(f.upgrade_note || '')}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: CONTAINER SCANNER */}
          {activeTab === 'CONTAINER' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                  Dockerfile Layer Scanner
                </h2>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Presets:</span>
                  <button
                    onClick={() => setDockerContent(PRESET_DOCKER_VULN)}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    Vulnerable Image
                  </button>
                  <button
                    onClick={() => setDockerContent(PRESET_DOCKER_SECURE)}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    Hardened Base
                  </button>
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  Dockerfile Instructions
                </label>
                <textarea
                  rows={9}
                  value={dockerContent}
                  onChange={(e) => setDockerContent(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[#1e1e1e] text-[#d4d4d4] p-3 font-mono text-xs leading-relaxed outline-none"
                />
              </div>

              <button
                onClick={handleContainerScan}
                disabled={dockerLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase hover:bg-[var(--accent)] transition-colors"
              >
                {dockerLoading ? 'Parsing Container Layers...' : '▶ Analyze Container Build Directives → Import to Inventory'}
              </button>

              {containerImportStatus && (
                <div className="border border-green-300 bg-green-50 text-green-800 font-mono text-xs px-4 py-2 font-bold">
                  {containerImportStatus}
                </div>
              )}

              {/* Container Findings */}
              {dockerFindings.length > 0 && (
                <div className="space-y-2 pt-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs uppercase text-[var(--accent)] font-bold">
                      Container Findings ({dockerFindings.length})
                    </span>
                    <span className="font-mono text-[10px] text-[var(--text-muted)] uppercase">
                      source: container → unified inventory
                    </span>
                  </div>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {dockerFindings.map((f, i) => (
                      <div key={i} className="border border-[var(--border)] bg-[var(--surface-raised)] p-3 text-xs space-y-1">
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-bold text-[var(--text-primary)]">
                            Line {f.line_number}: {f.finding_type}
                          </span>
                          <span className="px-1.5 py-0.2 bg-[#fee2e2] text-[#b91c1c] border border-[#ef4444] font-bold text-[10px]">
                            {f.severity}
                          </span>
                        </div>
                        <pre className="p-1.5 bg-[var(--surface)] border border-[var(--border)] text-[11px] font-mono text-[var(--text-secondary)]">
                          {f.evidence}
                        </pre>
                        <p className="text-[11px] text-[var(--text-secondary)]">
                          <strong>Fix:</strong> {f.recommendation}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: BINARY SCANNER (Phase 2) */}
          {activeTab === 'BINARY' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <div>
                  <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                    Binary Symbol &amp; Signature Scanner
                  </h2>
                  <p className="text-[11px] font-mono text-[var(--text-muted)] mt-0.5">
                    Phase 2 · Static symbol &amp; string inspection (OpenSSL, BoringSSL, libsodium, PKCS, PQC)
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Presets:</span>
                  <button
                    onClick={() => { setBinContent(PRESET_BIN_OPENSSL); setBinFilename('libauth_crypto.so'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    OpenSSL .so
                  </button>
                  <button
                    onClick={() => { setBinContent(PRESET_BIN_PQC); setBinFilename('liboqs_provider.so'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    PQC Provider
                  </button>
                  <button
                    onClick={() => { setBinContent(PRESET_BIN_LIBSODIUM); setBinFilename('libsecure_box.so'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    libsodium
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className="sm:col-span-3 space-y-1">
                  <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                    Binary Target Name
                  </label>
                  <input
                    type="text"
                    value={binFilename}
                    onChange={(e) => setBinFilename(e.target.value)}
                    className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2 text-[var(--text-primary)] font-mono outline-none"
                  />
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  Extracted Binary Strings / Symbol Table Dump
                </label>
                <textarea
                  rows={8}
                  value={binContent}
                  onChange={(e) => setBinContent(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[#1e1e1e] text-[#d4d4d4] p-3 font-mono text-xs leading-relaxed outline-none"
                />
              </div>

              <button
                onClick={handleBinaryScan}
                disabled={binLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase tracking-wider hover:bg-[var(--accent)] transition-colors flex items-center justify-center gap-2"
              >
                {binLoading ? 'Inspecting Binary Symbols...' : '▶ Inspect Binary Symbols → Import to Inventory'}
              </button>

              {binImportStatus && (
                <div className="border border-green-300 bg-green-50 text-green-800 font-mono text-xs px-4 py-2 font-bold">
                  {binImportStatus}
                </div>
              )}

              {binFormat && (
                <div className="flex flex-wrap gap-2 items-center font-mono text-xs">
                  <span className="border border-[var(--border)] bg-[var(--surface-raised)] px-2.5 py-1 font-bold text-[var(--text-primary)]">
                    Format: {binFormat}
                  </span>
                  {binLibraries.map(lib => (
                    <span key={lib} className="border border-[var(--accent)] bg-[var(--surface-raised)] text-[var(--accent)] px-2 py-0.5 font-bold text-[11px]">
                      {lib}
                    </span>
                  ))}
                </div>
              )}

              {binFindings.length > 0 && (
                <div className="border border-[var(--border)] overflow-hidden">
                  <div className="bg-[var(--surface-raised)] border-b border-[var(--border)] px-4 py-2 font-mono text-xs font-bold text-[var(--text-muted)] uppercase flex justify-between">
                    <span>Cryptographic Symbol Findings — {binFindings.length} detected</span>
                    <span>source: binary → unified inventory</span>
                  </div>
                  <div className="divide-y divide-[var(--border)]">
                    {(binFindings as Record<string, unknown>[]).map((f, i) => {
                      const sev = String(f.severity || 'MEDIUM');
                      const sevColor = sev === 'CRITICAL' ? 'bg-[#fee2e2] text-[#b91c1c] border-[#ef4444]'
                        : sev === 'HIGH' ? 'bg-orange-50 text-orange-700 border-orange-300'
                        : sev === 'INFORMATIONAL' ? 'bg-blue-50 text-blue-700 border-blue-300'
                        : 'bg-yellow-50 text-yellow-700 border-yellow-300';
                      const conf = Number(f.confidence_score || 0.85);
                      return (
                        <div key={i} className="p-4 font-mono text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[var(--text-primary)] text-sm">{String(f.library)}</span>
                              <span className="text-[var(--text-secondary)] font-semibold">({String(f.algorithm)})</span>
                              <span className={`border px-1.5 py-0.5 text-[10px] font-bold uppercase ${sevColor}`}>
                                {sev}
                              </span>
                            </div>
                            <span className="text-[10px] text-[var(--text-muted)] font-bold">
                              Confidence: {(conf * 100).toFixed(0)}%
                            </span>
                          </div>
                          <div className="text-[var(--text-secondary)]">{String(f.description || '')}</div>
                          {Array.isArray(f.matched_symbols) && f.matched_symbols.length > 0 && (
                            <div className="flex flex-wrap gap-1 items-center">
                              <span className="text-[10px] uppercase font-bold text-[var(--text-muted)]">Symbols:</span>
                              {(f.matched_symbols as string[]).map((s, idx) => (
                                <code key={idx} className="bg-[var(--surface)] border border-[var(--border)] px-1 py-0.5 text-[11px] text-[var(--accent)]">
                                  {s}
                                </code>
                              ))}
                            </div>
                          )}
                          <div className="text-[11px] text-[var(--text-secondary)]">
                            <strong>Remediation:</strong> {String(f.remediation || '')}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 6: HARDWARE SECURITY MODULE (HSM) (Phase 3) */}
          {activeTab === 'HSM' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <div>
                  <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                    Hardware Security Module (HSM) Prober
                  </h2>
                  <p className="text-[11px] font-mono text-[var(--text-muted)] mt-0.5">
                    Phase 3 · FIPS 140 Level 3 roots of trust, PKCS#11 slots &amp; hardware mechanism discovery
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Device Presets:</span>
                  <button
                    onClick={() => { setHsmContent(PRESET_HSM_LUNA); setHsmFilename('luna_pkcs11.conf'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    Thales Luna
                  </button>
                  <button
                    onClick={() => { setHsmContent(PRESET_HSM_YUBI); setHsmFilename('yubihsm.conf'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    YubiHSM 2
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className="sm:col-span-3 space-y-1">
                  <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                    PKCS#11 Configuration / Module Path
                  </label>
                  <input
                    type="text"
                    value={hsmFilename}
                    onChange={(e) => setHsmFilename(e.target.value)}
                    className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2 text-[var(--text-primary)] font-mono outline-none"
                  />
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  PKCS#11 Cryptoki Configuration Content
                </label>
                <textarea
                  rows={8}
                  value={hsmContent}
                  onChange={(e) => setHsmContent(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[#1e1e1e] text-[#d4d4d4] p-3 font-mono text-xs leading-relaxed outline-none"
                />
              </div>

              <button
                onClick={handleHsmScan}
                disabled={hsmLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase tracking-wider hover:bg-[var(--accent)] transition-colors flex items-center justify-center gap-2"
              >
                {hsmLoading ? 'Probing PKCS#11 Slots...' : '▶ Probe Hardware HSM → Import to Inventory'}
              </button>

              {hsmImportStatus && (
                <div className="border border-green-300 bg-green-50 text-green-800 font-mono text-xs px-4 py-2 font-bold">
                  {hsmImportStatus}
                </div>
              )}

              {hsmFindings.length > 0 && (
                <div className="border border-[var(--border)] overflow-hidden">
                  <div className="bg-[var(--surface-raised)] border-b border-[var(--border)] px-4 py-2 font-mono text-xs font-bold text-[var(--text-muted)] uppercase flex justify-between">
                    <span>HSM Cryptographic Mechanisms — {hsmFindings.length} discovered</span>
                    <span>source: hsm → unified inventory</span>
                  </div>
                  <div className="divide-y divide-[var(--border)]">
                    {(hsmFindings as Record<string, unknown>[]).map((f, i) => {
                      const isVuln = Boolean(f.is_quantum_vulnerable);
                      return (
                        <div key={i} className="p-4 font-mono text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[var(--text-primary)] text-sm">{String(f.mechanism)}</span>
                              <span className="text-[var(--text-secondary)]">({String(f.vendor)})</span>
                              <span className={`border px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                                isVuln ? 'bg-[#fee2e2] text-[#b91c1c] border-[#ef4444]' : 'bg-green-50 text-green-700 border-green-300'
                              }`}>
                                {isVuln ? 'Quantum Vulnerable' : 'Safe / Symmetric'}
                              </span>
                            </div>
                            <span className="text-[10px] border border-[var(--border)] bg-[var(--surface-raised)] px-2 py-0.5 text-[var(--text-primary)] font-bold">
                              {String(f.fips_level)}
                            </span>
                          </div>
                          <div className="flex items-start gap-2">
                            <span className="text-[var(--text-muted)] uppercase text-[10px] font-bold shrink-0">PQC Agility:</span>
                            <span className="text-[var(--accent)] text-[11px]">{String(f.pqc_support || '')}</span>
                          </div>
                          <div className="text-[11px] text-[var(--text-secondary)]">
                            <strong>Upgrade Guidance:</strong> {String(f.remediation || '')}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 7: CLOUD KMS & CERTIFICATE SERVICES (Phase 3) */}
          {activeTab === 'CLOUD_KMS' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <div>
                  <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                    Cloud KMS &amp; Certificate Discovery
                  </h2>
                  <p className="text-[11px] font-mono text-[var(--text-muted)] mt-0.5">
                    Phase 3 · AWS KMS, Azure Key Vault, Google Cloud KMS cryptographic posture audit
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Presets:</span>
                  <button
                    onClick={() => { setKmsContent(PRESET_CLOUD_KMS); setKmsFilename('aws_kms_keys.json'); }}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    AWS KMS
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className="sm:col-span-3 space-y-1">
                  <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                    Cloud Provider Manifest File
                  </label>
                  <input
                    type="text"
                    value={kmsFilename}
                    onChange={(e) => setKmsFilename(e.target.value)}
                    className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2 text-[var(--text-primary)] font-mono outline-none"
                  />
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  KMS JSON Key Listing / Resource Definition
                </label>
                <textarea
                  rows={8}
                  value={kmsContent}
                  onChange={(e) => setKmsContent(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[#1e1e1e] text-[#d4d4d4] p-3 font-mono text-xs leading-relaxed outline-none"
                />
              </div>

              <button
                onClick={handleCloudKmsScan}
                disabled={kmsLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase tracking-wider hover:bg-[var(--accent)] transition-colors flex items-center justify-center gap-2"
              >
                {kmsLoading ? 'Auditing Cloud KMS Keys...' : '▶ Audit Cloud KMS Keys → Import to Inventory'}
              </button>

              {kmsImportStatus && (
                <div className="border border-green-300 bg-green-50 text-green-800 font-mono text-xs px-4 py-2 font-bold">
                  {kmsImportStatus}
                </div>
              )}

              {kmsFindings.length > 0 && (
                <div className="border border-[var(--border)] overflow-hidden">
                  <div className="bg-[var(--surface-raised)] border-b border-[var(--border)] px-4 py-2 font-mono text-xs font-bold text-[var(--text-muted)] uppercase flex justify-between">
                    <span>Cloud KMS Keys Audited — {kmsFindings.length} discovered</span>
                    <span>source: cloud_kms → unified inventory</span>
                  </div>
                  <div className="divide-y divide-[var(--border)]">
                    {(kmsFindings as Record<string, unknown>[]).map((f, i) => {
                      const isVuln = Boolean(f.is_quantum_vulnerable);
                      return (
                        <div key={i} className="p-4 font-mono text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[var(--text-primary)] text-sm">{String(f.key_spec)}</span>
                              <span className="text-[var(--text-secondary)] font-mono text-[11px]">({String(f.provider)})</span>
                              <span className={`border px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                                isVuln ? 'bg-[#fee2e2] text-[#b91c1c] border-[#ef4444]' : 'bg-green-50 text-green-700 border-green-300'
                              }`}>
                                {isVuln ? 'Shor Vulnerable' : 'Quantum Safe'}
                              </span>
                            </div>
                            <span className={`text-[10px] border px-2 py-0.5 font-bold ${
                              f.rotation_enabled
                                ? 'border-green-300 bg-green-50 text-green-700'
                                : 'border-amber-300 bg-amber-50 text-amber-700'
                            }`}>
                              Rotation: {f.rotation_enabled ? 'Enabled' : 'Disabled'}
                            </span>
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-muted)] break-all">{String(f.key_id)}</div>
                          <div className="text-[11px] text-[var(--text-secondary)]">
                            <strong>Guidance:</strong> {String(f.recommendation || '')}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 8: API & JWT SCANNER */}
          {activeTab === 'API' && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
                <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                  API & JWT Token Validator
                </h2>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">Token Presets:</span>
                  <button
                    onClick={() => setJwtToken(PRESET_JWT_RS256)}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    RS256 (RSA)
                  </button>
                  <button
                    onClick={() => setJwtToken(PRESET_JWT_PQC)}
                    className="font-mono text-[10px] px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
                  >
                    ML-DSA-65 (PQC)
                  </button>
                </div>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  API Endpoint URL
                </label>
                <input
                  type="text"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2 font-mono text-xs text-[var(--text-primary)]"
                />
              </div>

              <div className="space-y-1 font-mono text-xs">
                <label className="text-[10px] uppercase text-[var(--text-muted)] font-bold">
                  Authorization Bearer / Sample JWT
                </label>
                <textarea
                  rows={3}
                  value={jwtToken}
                  onChange={(e) => setJwtToken(e.target.value)}
                  className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2 font-mono text-xs text-[var(--text-primary)] outline-none"
                />
              </div>

              <button
                onClick={handleApiScan}
                disabled={apiLoading}
                className="w-full py-2.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase hover:bg-[var(--accent)] transition-colors"
              >
                {apiLoading ? 'Auditing API Cryptography...' : '▶ Inspect API Endpoint & Token Algorithm'}
              </button>

              {/* API Results */}
              {apiResult?.jwt_analysis && (
                <div className="border border-[var(--border)] bg-[var(--surface-raised)] p-4 space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-[var(--border)] pb-2">
                    <span className="font-bold text-[var(--text-primary)]">
                      JWT Algorithm: {apiResult.jwt_analysis.classification.algorithm}
                    </span>
                    <span
                      className={`px-2 py-0.5 font-bold uppercase ${
                        apiResult.jwt_analysis.classification.risk_level === 'LOW'
                          ? 'bg-[#ecfdf5] text-[#047857] border border-[#10b981]'
                          : 'bg-[#fee2e2] text-[#b91c1c] border border-[#ef4444]'
                      }`}
                    >
                      {apiResult.jwt_analysis.classification.risk_level} Risk
                    </span>
                  </div>

                  <div className="space-y-1 text-[11px]">
                    <div><strong>Signature Family:</strong> {apiResult.jwt_analysis.classification.type}</div>
                    <div><strong>Quantum Status:</strong> {apiResult.jwt_analysis.classification.quantum_status}</div>
                    <div className="pt-1 text-[var(--text-secondary)]">
                      <strong>Guidance:</strong> {apiResult.jwt_analysis.classification.recommendation}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Live Streamed Telemetry Terminal Console */}
        <div className="lg:col-span-5 border border-[var(--border)] bg-[var(--surface)] flex flex-col min-h-[520px]">
          {/* Terminal Title Bar */}
          <div className="border-b border-[var(--border)] px-4 py-2.5 bg-[var(--surface-raised)] flex items-center justify-between font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="inline-block w-2.5 h-2.5 bg-[var(--accent)] animate-pulse" />
              <span className="font-bold text-[var(--text-primary)] uppercase">
                Scanner Stream Telemetry
              </span>
            </div>
            <span className="text-[10px] text-[var(--text-muted)]">
              SSE Real-Time Feed
            </span>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-[var(--surface-raised)] h-1.5 border-b border-[var(--border)]">
            <div
              className="bg-[var(--accent)] h-full transition-all duration-300"
              style={{ width: `${streamProgress}%` }}
            />
          </div>

          {/* Monospace Output Window */}
          <div className="flex-1 bg-[#111111] text-[#e0e0e0] p-4 font-mono text-xs overflow-y-auto space-y-2 select-text">
            <div className="text-[#888888] pb-1 border-b border-[#333333]">
              ECDAT Sovereign Scanner Engine v2.0 • SSE Pipe Active
            </div>

            {streamLogs.length === 0 && !streamActive && (
              <div className="text-[#666666] italic py-8 text-center">
                Ready for scan trigger. Select a scanner tab and click probe to begin live discovery.
              </div>
            )}

            {streamLogs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-2 text-[11px]">
                <span className="text-[var(--accent)] font-bold">[{log.pct}%]</span>
                <span className="text-[#ffffff]">{log.message}</span>
              </div>
            ))}

            {streamActive && (
              <div className="flex items-center gap-2 text-[11px] text-[var(--accent)]">
                <span className="animate-spin">◒</span> Processing cryptographic verification...
              </div>
            )}

            <div ref={terminalEndRef} />
          </div>

          {/* Terminal Footer */}
          <div className="border-t border-[var(--border)] p-3 bg-[var(--surface-raised)] flex items-center justify-between font-mono text-[11px] text-[var(--text-muted)]">
            <span>Logged Events: {streamLogs.length}</span>
            <button
              onClick={() => { setStreamLogs([]); setStreamProgress(0); }}
              className="hover:text-[var(--text-primary)] uppercase font-bold"
            >
              Clear Buffer
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
