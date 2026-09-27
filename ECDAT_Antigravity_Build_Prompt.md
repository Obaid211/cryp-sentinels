# ECDAT — Build Prompt for Antigravity

**Project:** ECDAT (Enterprise Cryptographic Discovery & Analysis Tool)
**Team:** CryptoSentinels — SIH 2026, PS ID SIH26164

---

## Context — do not rebuild this

ECDAT already has a working full-stack app (React/Vite + FastAPI + PostgreSQL) with these modules live and demo-ready:

Executive Dashboard · Cryptographic Asset Inventory · Quantum Risk Assessment (MWQRS) · Prioritized Remediation · Mosca Migration-Urgency Analysis · Dependency Graph · PQC Transition Simulator · Live TLS/Network Scanner · CBOM Studio (CycloneDX) · Compliance/Readiness view · AI Advisor · Scan History · Snapshot Diff · Interactive GUI (12 tabs).

**Do not touch the UI/UX, dashboard layout, or visual design.** The demo already proves the interface. All work below is backend/pipeline work — new discovery scanners feeding into the *existing* inventory, risk, Mosca, and CBOM systems. Not new standalone tools. Not new screens, unless a screen is required to display genuinely new data.

## Goal

Close the gap between what ECDAT demonstrates and the full SIH26164 problem statement by adding the missing discovery sources and recommendation logic — all flowing into the one existing pipeline:

```
Source Code → Libraries → Binaries → Containers → TLS/Network
                        ↓
              UNIFIED CRYPTO INVENTORY
                        ↓
                QUANTUM RISK ENGINE
                 ↓              ↓
          MOSCA ANALYSIS   BUSINESS CRITICALITY
                 ↓              ↓
              PQC / HYBRID RECOMMENDATION ENGINE
        ↓              ↓              ↓
  Remediation    Dependency Graph    CBOM
        ↓              ↓              ↓
              READINESS / REPORTS
```

Every new scanner writes into the **same unified asset schema** the existing TLS scanner already populates. No parallel data models, no separate tables per scanner.

---

## PHASE 1 — MUST DO (build in this order)

**1. Source-Code Scanner**
Input: GitHub repo URL, uploaded ZIP, or local path. Static analysis (regex + AST) for RSA, ECC, AES, SHA, DES/3DES, TLS config, hardcoded keys/certs. Capture per finding: file, line, library, algorithm, key size (if determinable), usage context, confidence score.
```json
{
  "file": "auth.py", "line": 47, "library": "cryptography",
  "algorithm": "RSA-2048", "usage": "digital_signature",
  "quantum_risk": "high", "confidence": 0.9,
  "recommendation_ref": "ML-DSA"
}
```
Write into the unified inventory with `source: "source_code"`.

**2. Library / Dependency Scanner**
Parse `requirements.txt`, `package.json`/`package-lock.json`, `pom.xml`, `build.gradle`, `go.mod`, `Cargo.toml`. Per dependency: name, version, known crypto capability (small internal lookup table — OpenSSL, pyca/cryptography, Bouncy Castle, libsodium), inferred risk, upgrade note. Flag quantum-vulnerable defaults even without direct crypto calls in app code. `source: "dependency"`.

**3. Business Criticality — real field, not a UI label**
Add `business_criticality: critical | high | medium | low` as a stored asset attribute. Must actively feed into MWQRS scoring and remediation ordering — not just display as a badge.

**4. Data Lifetime / Shelf-Life**
Add `data_lifetime` as an explicit stored field (`<1y`, `1-3y`, `3-5y`, `5-10y`, `>10y`). Wire directly into the existing Mosca calculator instead of a hardcoded/default value.

**5. Explicit PQC + Hybrid Recommendation Engine**
Distinct from the existing Simulator (which shows *what-if* impact). A rules engine producing a concrete recommendation per asset:
```json
{
  "current_algorithm": "RSA-2048", "usage": "digital_signature",
  "recommendation": "ML-DSA",
  "hybrid_alternative": "RSA + ML-DSA",
  "reason": "quantum_vulnerability + migration_compatibility"
}
```
Key exchange (ECDH etc.) → recommend ML-KEM. Always offer a hybrid option alongside pure-PQC. Branch by usage type (signature / key exchange / encryption) — never one blind PQC recommendation for every case. Remediation and CBOM should call this engine, replacing any hardcoded mapping in the Simulator.

**6. Wire it all together**
All five items above must land correctly in the existing Inventory, Risk Engine, Mosca view, Remediation queue, Dependency Graph, and CBOM export. Verify each new asset type appears in all of them before starting Phase 2.

---

## PHASE 2 — NEXT

**7. Binary Scanner** — static inspection of uploaded binaries for crypto-related symbols/strings (OpenSSL, BoringSSL, libsodium, TLS/PKCS references), reported with a confidence level, not a claim of full semantic detection.

**8. Container Scanner** — Dockerfile + image metadata + installed packages, output into the same unified inventory.

**9. Cost / Latency / Migration-Complexity factors** — add `migration_cost`, `latency_impact`, `migration_complexity` (Low/Medium/High) to the recommendation engine's output, with a one-line rationale.

**10. Integrate Phase 2 scanners with Snapshot Diff and Dependency Graph** — new asset types must appear in diffs and as graph nodes, same as existing types.

---

## PHASE 3 — ONLY IF TIME REMAINS

**11. Hardware/HSM discovery** — presence, vendor, algorithm support, key-management metadata (config/metadata level only).

**12. Cloud crypto-service discovery** — metadata-level support for cloud KMS / cert-management services (don't attempt every provider).

---

## Hard constraints for the agent

- **No new data model per scanner** — every scanner writes to the same unified asset schema, extended with source-specific metadata fields.
- **No UI redesign** — only add fields/columns to existing views (e.g. `source` and `business_criticality` columns in the existing Inventory table).
- **No isolated demo tools** — every scanner must be reachable from the existing scan pipeline entry point, not a separate script or standalone page.
- **Ship Phase 1 completely, end-to-end, before starting Phase 2.** A half-integrated Phase 2 feature is worse than a fully-integrated Phase 1.
- After each module, scan real test targets (same approach as the existing github.com / google.com / local test server demo) and confirm findings flow correctly through Inventory → Risk → Mosca → Remediation → CBOM.
