import React, { useState, useEffect, useRef } from 'react';
import { API_BASE_URL } from '../config';

type ScannerTab = 'TLS' | 'CODE' | 'CONTAINER' | 'API';

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

  // Container Scan State
  const [dockerContent, setDockerContent] = useState(PRESET_DOCKER_VULN);
  const [dockerFindings, setDockerFindings] = useState<FindingItem[]>([]);
  const [dockerLoading, setDockerLoading] = useState(false);

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

  // Run Code scan
  const handleCodeScan = async () => {
    setCodeLoading(true);
    triggerScanStream(`AST Scanner: ${codeFilename}`);

    try {
      const res = await fetch(`${API_BASE_URL}/api/scanners/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: codeContent, filename: codeFilename }),
      });
      const data = await res.json();
      setCodeFindings(data.findings || []);
    } catch (err) {
      console.error('Code scan error:', err);
    } finally {
      setCodeLoading(false);
    }
  };

  // Run Container scan
  const handleContainerScan = async () => {
    setDockerLoading(true);
    triggerScanStream('Dockerfile Build Layers');

    try {
      const res = await fetch(`${API_BASE_URL}/api/scanners/container`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: dockerContent, filename: 'Dockerfile' }),
      });
      const data = await res.json();
      setDockerFindings(data.findings || []);
    } catch (err) {
      console.error('Container scan error:', err);
    } finally {
      setDockerLoading(false);
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
              { id: 'CONTAINER', label: '3. Dockerfile' },
              { id: 'API', label: '4. API & JWT' },
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

          {/* TAB 3: CONTAINER SCANNER */}
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
                {dockerLoading ? 'Parsing Container Layers...' : '▶ Analyze Container Build Directives'}
              </button>

              {/* Container Findings */}
              {dockerFindings.length > 0 && (
                <div className="space-y-2 pt-2">
                  <span className="font-mono text-xs uppercase text-[var(--accent)] font-bold">
                    Container Findings ({dockerFindings.length})
                  </span>
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

          {/* TAB 4: API & JWT SCANNER */}
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
