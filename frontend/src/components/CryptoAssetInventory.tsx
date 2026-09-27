import { useState, useEffect, useCallback } from 'react';
import { Search, X, ShieldAlert, Cpu, Code, Package, Globe, Box, HardDrive, Cloud } from 'lucide-react';
import { API_BASE_URL } from '../config';

// Phase 1: Extended asset record with new discovery fields
interface AssetRecord {
  id: number;
  host: string;
  port: number;
  status: string;
  source: string;               // Phase 1: "tls" | "source_code" | "dependency"
  business_criticality: string; // Phase 1: critical | high | medium | low
  data_lifetime: string;        // Phase 1: <1y | 1-3y | 3-5y | 5-10y | >10y
  tls_version: string;
  cipher_suite: string;
  cipher_bits: number;
  cert_subject: string;
  cert_issuer: string;
  cert_key_type: string;
  cert_key_size_bits: number;
  cert_signature_algorithm: string;
  algorithm: string;            // Phase 1
  usage_context: string;        // Phase 1
  library: string;              // Phase 1
  file_path: string;            // Phase 1
  line_number: number;          // Phase 1
  confidence_score: number;     // Phase 1
  days_to_expiry: number;
  criticality: string;
  service_name: string;
  risk_score: number;
  risk_flags: string[];
  pqc_target: string;
  pqc_recommendation?: {        // Phase 1: full recommendation object
    recommendation: string;
    hybrid_alternative: string;
    migration_complexity: string;
    migration_cost: string;
    latency_impact: string;
    reason: string;
    migration_steps: string[];
  };
}

interface AssetDetail {
  asset: AssetRecord;
  risk_breakdown: {
    algo_vulnerability: number;
    key_size_rating: string;
    tls_protocol: string;
    expiry_urgency: string;
  };
  flag_explanations: Array<{ flag: string; explanation: string }>;
  recommended_pqc_target: {
    algorithm: string;
    standards: string[];
    strategy: string;
    notes: string;
  };
  history: Array<{
    scanned_at: string;
    risk_score: number;
    tls_version: string;
    status: string;
  }>;
}

// Phase 1: Source type display helpers
const SOURCE_BADGE: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  tls: { label: 'TLS/Network', icon: <Globe className="h-3 w-3" />, color: 'text-blue-700 bg-blue-50 border-blue-200' },
  source_code: { label: 'Source Code', icon: <Code className="h-3 w-3" />, color: 'text-violet-700 bg-violet-50 border-violet-200' },
  dependency: { label: 'Dependency', icon: <Package className="h-3 w-3" />, color: 'text-amber-700 bg-amber-50 border-amber-200' },
  container: { label: 'Container', icon: <Box className="h-3 w-3" />, color: 'text-emerald-700 bg-emerald-50 border-emerald-200' },
  binary: { label: 'Binary', icon: <Cpu className="h-3 w-3" />, color: 'text-gray-700 bg-gray-50 border-gray-200' },
  hsm: { label: 'Hardware/HSM', icon: <HardDrive className="h-3 w-3" />, color: 'text-purple-700 bg-purple-50 border-purple-200' },
  cloud_kms: { label: 'Cloud KMS', icon: <Cloud className="h-3 w-3" />, color: 'text-sky-700 bg-sky-50 border-sky-200' },
};

const BIZ_CRIT_COLOR: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-300',
  high: 'text-orange-700 bg-orange-50 border-orange-300',
  medium: 'text-yellow-700 bg-yellow-50 border-yellow-200',
  low: 'text-green-700 bg-green-50 border-green-200',
};

export const CryptoAssetInventory = () => {
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [search, setSearch] = useState('');
  const [criticalityFilter, setCriticalityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<AssetRecord | null>(null);
  const [detailData, setDetailData] = useState<AssetDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (criticalityFilter) params.append('criticality', criticalityFilter);
      const res = await fetch(`${API_BASE_URL}/api/inventory?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setAssets(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [search, criticalityFilter]);

  useEffect(() => {
    void fetchAssets();
  }, [fetchAssets]);

  const handleSelectAsset = async (asset: AssetRecord) => {
    setSelectedAsset(asset);
    setDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/inventory/${asset.host}/${asset.port}/history`);
      if (res.ok) {
        const data = await res.json();
        setDetailData(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setDetailLoading(false);
    }
  };

  // Phase 1: filter by source
  const displayedAssets = sourceFilter
    ? assets.filter(a => (a.source || 'tls') === sourceFilter)
    : assets;

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header */}
      <div className="border-b border-[#e5e5e5] pb-6">
        <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
          <span className="inline-block h-2 w-2 bg-primary" />
          <span>CRYPTOGRAPHIC INVENTORY REPOSITORY</span>
          <span>·</span>
          <span>X.509 &amp; MULTI-SOURCE POSTURE TELEMETRY</span>
        </div>
        <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
          Crypto Asset Inventory &amp; Inspection
        </h1>
        {/* Phase 1 source stats */}
        <div className="mt-3 flex flex-wrap gap-3">
          {Object.entries(SOURCE_BADGE).map(([src, badge]) => {
            const count = assets.filter(a => (a.source || 'tls') === src).length;
            if (count === 0) return null;
            return (
              <button
                key={src}
                onClick={() => setSourceFilter(sourceFilter === src ? '' : src)}
                className={`flex items-center gap-1.5 border px-2.5 py-1 font-mono text-[11px] font-semibold transition-all ${
                  sourceFilter === src ? badge.color + ' border-2' : badge.color
                }`}
              >
                {badge.icon}
                {badge.label}
                <span className="ml-1 font-bold">{count}</span>
              </button>
            );
          })}
          {sourceFilter && (
            <button
              onClick={() => setSourceFilter('')}
              className="flex items-center gap-1 border border-[#e5e5e5] px-2 py-1 font-mono text-[11px] text-tertiary hover:border-secondary"
            >
              <X className="h-3 w-3" /> Clear filter
            </button>
          )}
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-3 h-4 w-4 text-tertiary" />
          <input
            type="text"
            placeholder="Search by hostname, port, service name, library, algorithm, or cipher..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full border border-secondary bg-white pl-9 pr-4 py-2 font-mono text-xs text-secondary outline-none focus:border-primary shadow-flat-sm"
          />
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-tertiary uppercase">Tier:</span>
          {['', 'P0', 'P1', 'P2', 'P3'].map((crit) => (
            <button
              key={crit}
              onClick={() => setCriticalityFilter(crit)}
              className={`px-3 py-2 border transition-colors ${
                criticalityFilter === crit
                  ? 'border-secondary bg-secondary text-white font-bold'
                  : 'border-[#e5e5e5] bg-white text-secondary hover:border-secondary'
              }`}
            >
              {crit || 'ALL'}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="border border-secondary bg-white shadow-flat overflow-x-auto">
        <table className="w-full text-left font-mono text-xs border-collapse">
          <thead>
            <tr className="border-b border-secondary bg-[#faf9f5] text-tertiary uppercase">
              <th className="py-3 px-3">SOURCE</th>
              <th className="py-3 px-3">ENDPOINT / ASSET</th>
              <th className="py-3 px-3">SERVICE</th>
              <th className="py-3 px-3">TIER</th>
              <th className="py-3 px-3">BIZ CRIT</th>
              <th className="py-3 px-3">KEY / ALGO</th>
              <th className="py-3 px-3">DATA LIFETIME</th>
              <th className="py-3 px-3">PQC TARGET</th>
              <th className="py-3 px-3 text-right">MWQRS</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-tertiary">
                  Loading cryptographic inventory...
                </td>
              </tr>
            ) : displayedAssets.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-tertiary">
                  No cryptographic assets matched the current search criteria.
                </td>
              </tr>
            ) : (
              displayedAssets.map((asset) => {
                const src = asset.source || 'tls';
                const badge = SOURCE_BADGE[src] || SOURCE_BADGE.tls;
                const bizCritColor = BIZ_CRIT_COLOR[asset.business_criticality || 'medium'] || BIZ_CRIT_COLOR.medium;
                return (
                  <tr
                    key={asset.id}
                    onClick={() => void handleSelectAsset(asset)}
                    className={`border-b border-[#eeeeea] hover:bg-[#faf9f5] cursor-pointer transition-colors ${
                      selectedAsset?.id === asset.id ? 'bg-[#faf9f5] font-bold' : ''
                    }`}
                  >
                    <td className="py-3 px-3">
                      <span className={`flex items-center gap-1 border px-1.5 py-0.5 text-[10px] font-semibold ${badge.color}`}>
                        {badge.icon}
                        {badge.label}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-bold text-secondary">
                      {src === 'source_code' && asset.file_path
                        ? <span title={`${asset.file_path}:${asset.line_number}`}>{asset.file_path.split('/').pop()}:{asset.line_number}</span>
                        : src === 'dependency' && asset.library
                        ? <span>{asset.library}</span>
                        : `${asset.host}:${asset.port}`
                      }
                    </td>
                    <td className="py-3 px-3 text-secondary">{asset.service_name}</td>
                    <td className="py-3 px-3">
                      <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-secondary">
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`border px-2 py-0.5 font-semibold text-[10px] uppercase ${bizCritColor}`}>
                        {asset.business_criticality || 'medium'}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-tertiary">
                      {(asset.algorithm || asset.cert_key_type || '—')}
                      {asset.cert_key_size_bits ? ` ${asset.cert_key_size_bits}b` : ''}
                    </td>
                    <td className="py-3 px-3 text-tertiary">{asset.data_lifetime || '1-3y'}</td>
                    <td className="py-3 px-3 text-primary font-semibold text-[10px]">
                      {asset.pqc_recommendation?.recommendation || asset.pqc_target}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className="border border-secondary bg-white px-2 py-0.5 font-bold text-secondary">
                        {asset.risk_score.toFixed(1)}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Deep-Dive Asset Inspection Card */}
      {selectedAsset && (
        <div className="border border-secondary bg-white p-6 shadow-flat space-y-6">
          <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-4">
            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-primary font-bold flex items-center gap-2">
                DEEP-DIVE ASSET INSPECTION CARD
                {(() => {
                  const src = selectedAsset.source || 'tls';
                  const badge = SOURCE_BADGE[src] || SOURCE_BADGE.tls;
                  return (
                    <span className={`flex items-center gap-1 border px-1.5 py-0.5 ${badge.color}`}>
                      {badge.icon} {badge.label}
                    </span>
                  );
                })()}
              </div>
              <h3 className="mt-1 font-display text-xl font-bold uppercase text-secondary">
                {selectedAsset.library || selectedAsset.file_path || `${selectedAsset.host}:${selectedAsset.port}`}
                {selectedAsset.service_name !== 'Unassigned' && ` (${selectedAsset.service_name})`}
              </h3>
            </div>
            <button
              onClick={() => {
                setSelectedAsset(null);
                setDetailData(null);
              }}
              className="border border-secondary p-1 hover:bg-secondary hover:text-white transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Phase 1: Business criticality + data lifetime panel */}
          <div className="flex flex-wrap gap-4 font-mono text-xs">
            <div className="border border-[#e5e5e5] bg-[#faf9f5] px-4 py-3 flex flex-col gap-1">
              <span className="text-tertiary uppercase text-[10px] font-bold">Business Criticality</span>
              <span className={`border px-2 py-0.5 font-bold text-sm uppercase ${BIZ_CRIT_COLOR[selectedAsset.business_criticality || 'medium']}`}>
                {selectedAsset.business_criticality || 'medium'}
              </span>
            </div>
            <div className="border border-[#e5e5e5] bg-[#faf9f5] px-4 py-3 flex flex-col gap-1">
              <span className="text-tertiary uppercase text-[10px] font-bold">Data Lifetime (Mosca Shelf-Life)</span>
              <span className="font-bold text-secondary">{selectedAsset.data_lifetime || '1-3y'}</span>
            </div>
            {selectedAsset.usage_context && (
              <div className="border border-[#e5e5e5] bg-[#faf9f5] px-4 py-3 flex flex-col gap-1">
                <span className="text-tertiary uppercase text-[10px] font-bold">Usage Context</span>
                <span className="font-bold text-secondary">{selectedAsset.usage_context}</span>
              </div>
            )}
            {selectedAsset.confidence_score != null && (
              <div className="border border-[#e5e5e5] bg-[#faf9f5] px-4 py-3 flex flex-col gap-1">
                <span className="text-tertiary uppercase text-[10px] font-bold">Confidence Score</span>
                <span className="font-bold text-secondary">{(selectedAsset.confidence_score * 100).toFixed(0)}%</span>
              </div>
            )}
          </div>

          {detailLoading || !detailData ? (
            <div className="py-8 text-center font-mono text-xs text-tertiary">
              Extracting metadata and risk explanations...
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 font-mono text-xs">
              {/* X.509 / Asset Metadata */}
              <div className="lg:col-span-6 space-y-3 border border-[#e5e5e5] p-4 bg-[#faf9f5]">
                <div className="font-bold text-secondary uppercase border-b border-[#e5e5e5] pb-2">
                  {(selectedAsset.source || 'tls') === 'tls' ? 'X.509 Certificate Metadata' :
                   (selectedAsset.source || 'tls') === 'source_code' ? 'Source Code Finding Details' :
                   'Library / Dependency Details'}
                </div>
                {(selectedAsset.source || 'tls') === 'tls' ? (
                  <>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Subject</span>
                      <span className="text-secondary text-right max-w-[280px] truncate">{detailData.asset.cert_subject || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Issuer</span>
                      <span className="text-secondary text-right max-w-[280px] truncate">{detailData.asset.cert_issuer || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Cipher Suite</span>
                      <span className="text-secondary">{detailData.asset.cipher_suite}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Signature Algorithm</span>
                      <span className="text-secondary">{detailData.asset.cert_signature_algorithm || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-tertiary">Days to Expiration</span>
                      <span className="text-secondary font-bold">{detailData.asset.days_to_expiry} days</span>
                    </div>
                  </>
                ) : (selectedAsset.source || 'tls') === 'source_code' ? (
                  <>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">File Path</span>
                      <span className="text-secondary text-right max-w-[280px] truncate">{selectedAsset.file_path || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Line Number</span>
                      <span className="text-secondary">{selectedAsset.line_number || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Algorithm Detected</span>
                      <span className="text-secondary font-bold">{selectedAsset.algorithm || selectedAsset.cert_key_type}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-tertiary">Rule</span>
                      <span className="text-secondary">{detailData.asset.cert_issuer || 'N/A'}</span>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Library</span>
                      <span className="text-secondary font-bold">{selectedAsset.library || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                      <span className="text-tertiary">Default Algorithm</span>
                      <span className="text-secondary">{selectedAsset.algorithm || selectedAsset.cert_key_type}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-tertiary">Capability</span>
                      <span className="text-secondary text-right max-w-[280px] truncate">{detailData.asset.cert_issuer || 'N/A'}</span>
                    </div>
                  </>
                )}
              </div>

              {/* PQC Recommendation (Phase 1 Engine Output) */}
              <div className="lg:col-span-6 space-y-3 border border-[#e5e5e5] p-4 bg-white">
                <div className="font-bold text-secondary uppercase border-b border-[#e5e5e5] pb-2 flex items-center justify-between">
                  <span>PQC Recommendation Engine</span>
                  <Cpu className="h-4 w-4 text-primary" />
                </div>
                {selectedAsset.pqc_recommendation ? (
                  <div className="space-y-3">
                    <div className="bg-[#faf9f5] border border-primary p-3">
                      <div className="text-primary font-bold text-sm">
                        {selectedAsset.pqc_recommendation.recommendation}
                      </div>
                      <div className="mt-1 text-tertiary text-[11px]">
                        Hybrid: {selectedAsset.pqc_recommendation.hybrid_alternative}
                      </div>
                      <p className="mt-2 text-secondary text-[11px] leading-relaxed">
                        {selectedAsset.pqc_recommendation.reason}
                      </p>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        ['Complexity', selectedAsset.pqc_recommendation.migration_complexity],
                        ['Cost', selectedAsset.pqc_recommendation.migration_cost],
                        ['Latency', selectedAsset.pqc_recommendation.latency_impact],
                      ].map(([label, val]) => (
                        <div key={label} className="border border-[#e5e5e5] p-2 text-center">
                          <div className="text-[10px] text-tertiary uppercase">{label}</div>
                          <div className="font-bold text-secondary text-xs mt-0.5">{val}</div>
                        </div>
                      ))}
                    </div>
                    {selectedAsset.pqc_recommendation.migration_steps?.length > 0 && (
                      <div>
                        <div className="text-[10px] text-tertiary uppercase font-bold mb-1">Migration Steps</div>
                        <ol className="space-y-1">
                          {selectedAsset.pqc_recommendation.migration_steps.map((step, i) => (
                            <li key={i} className="flex gap-2 text-[11px] text-secondary">
                              <span className="font-bold text-primary">{i + 1}.</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="bg-[#faf9f5] border border-primary p-3">
                    <div className="text-primary font-bold text-sm">
                      {detailData.recommended_pqc_target.algorithm}
                    </div>
                    <div className="mt-1 text-tertiary text-[11px]">
                      Standards: {detailData.recommended_pqc_target.standards.join(', ')}
                    </div>
                    <p className="mt-2 text-secondary text-[11px] leading-relaxed">
                      {detailData.recommended_pqc_target.notes}
                    </p>
                  </div>
                )}

                <div className="pt-2 font-bold text-secondary uppercase border-b border-[#e5e5e5] pb-1">
                  Detected Risk Flags ({detailData.flag_explanations.length})
                </div>
                {detailData.flag_explanations.length === 0 ? (
                  <div className="text-severity-safe py-1">No anomalous risk flags detected.</div>
                ) : (
                  <div className="space-y-2">
                    {detailData.flag_explanations.map((f, i) => (
                      <div key={i} className="border border-severity-critical/30 bg-[#faf9f5] p-2">
                        <div className="text-severity-critical font-bold flex items-center gap-1.5">
                          <ShieldAlert className="h-3.5 w-3.5" />
                          <span>{f.flag}</span>
                        </div>
                        <div className="text-tertiary text-[11px] mt-1">{f.explanation}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
