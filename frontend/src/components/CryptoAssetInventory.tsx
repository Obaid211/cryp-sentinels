import { useState, useEffect, useCallback } from 'react';
import { Search, X, ShieldAlert, Cpu } from 'lucide-react';
import { API_BASE_URL } from '../config';

interface AssetRecord {
  id: number;
  host: string;
  port: number;
  status: string;
  tls_version: string;
  cipher_suite: string;
  cipher_bits: number;
  cert_subject: string;
  cert_issuer: string;
  cert_key_type: string;
  cert_key_size_bits: number;
  cert_signature_algorithm: string;
  days_to_expiry: number;
  criticality: string;
  service_name: string;
  risk_score: number;
  risk_flags: string[];
  pqc_target: string;
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

export const CryptoAssetInventory = () => {
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [search, setSearch] = useState('');
  const [criticalityFilter, setCriticalityFilter] = useState('');
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

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header */}
      <div className="border-b border-[#e5e5e5] pb-6">
        <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
          <span className="inline-block h-2 w-2 bg-primary" />
          <span>CRYPTOGRAPHIC INVENTORY REPOSITORY</span>
          <span>·</span>
          <span>X.509 & POSTURE TELEMETRY</span>
        </div>
        <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
          Crypto Asset Inventory & Inspection
        </h1>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-3 h-4 w-4 text-tertiary" />
          <input
            type="text"
            placeholder="Search by hostname, port, service name, or cipher..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full border border-secondary bg-white pl-9 pr-4 py-2 font-mono text-xs text-secondary outline-none focus:border-primary shadow-flat-sm"
          />
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-tertiary uppercase">Criticality:</span>
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
              <th className="py-3 px-3">ENDPOINT</th>
              <th className="py-3 px-3">SERVICE</th>
              <th className="py-3 px-3">TIER</th>
              <th className="py-3 px-3">KEY SPECS</th>
              <th className="py-3 px-3">TLS VERSION</th>
              <th className="py-3 px-3">EXPIRY</th>
              <th className="py-3 px-3">RECOMMENDED PQC</th>
              <th className="py-3 px-3 text-right">MWQRS</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-tertiary">
                  Loading cryptographic inventory...
                </td>
              </tr>
            ) : assets.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-tertiary">
                  No cryptographic assets matched the current search criteria.
                </td>
              </tr>
            ) : (
              assets.map((asset) => (
                <tr
                  key={asset.id}
                  onClick={() => void handleSelectAsset(asset)}
                  className={`border-b border-[#eeeeea] hover:bg-[#faf9f5] cursor-pointer transition-colors ${
                    selectedAsset?.id === asset.id ? 'bg-[#faf9f5] font-bold' : ''
                  }`}
                >
                  <td className="py-3 px-3 font-bold text-secondary">
                    {asset.host}:{asset.port}
                  </td>
                  <td className="py-3 px-3 text-secondary">{asset.service_name}</td>
                  <td className="py-3 px-3">
                    <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-secondary">
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-tertiary">
                    {asset.cert_key_type} {asset.cert_key_size_bits}b
                  </td>
                  <td className="py-3 px-3 text-tertiary">{asset.tls_version}</td>
                  <td className="py-3 px-3 text-tertiary">{asset.days_to_expiry} days</td>
                  <td className="py-3 px-3 text-primary font-semibold">{asset.pqc_target}</td>
                  <td className="py-3 px-3 text-right">
                    <span className="border border-secondary bg-white px-2 py-0.5 font-bold text-secondary">
                      {asset.risk_score.toFixed(1)}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Deep-Dive Asset Inspection Card Drawer/Panel */}
      {selectedAsset && (
        <div className="border border-secondary bg-white p-6 shadow-flat space-y-6">
          <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-4">
            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-primary font-bold">
                DEEP-DIVE ASSET INSPECTION CARD
              </div>
              <h3 className="mt-1 font-display text-xl font-bold uppercase text-secondary">
                {selectedAsset.host}:{selectedAsset.port} ({selectedAsset.service_name})
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

          {detailLoading || !detailData ? (
            <div className="py-8 text-center font-mono text-xs text-tertiary">
              Extracting X.509 metadata and risk explanations...
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 font-mono text-xs">
              {/* X.509 Metadata */}
              <div className="lg:col-span-6 space-y-3 border border-[#e5e5e5] p-4 bg-[#faf9f5]">
                <div className="font-bold text-secondary uppercase border-b border-[#e5e5e5] pb-2">
                  X.509 Certificate Metadata
                </div>
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
              </div>

              {/* MWQRS Breakdown & PQC Target */}
              <div className="lg:col-span-6 space-y-3 border border-[#e5e5e5] p-4 bg-white">
                <div className="font-bold text-secondary uppercase border-b border-[#e5e5e5] pb-2 flex items-center justify-between">
                  <span>Recommended NIST PQC Target</span>
                  <Cpu className="h-4 w-4 text-primary" />
                </div>
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
