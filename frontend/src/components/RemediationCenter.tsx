import { useState, useEffect, useCallback } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { apiFetch } from '../lib/api';

interface RemediationItem {
  priority_rank: number;
  asset_id: number;
  target: string;
  host: string;
  port: number;
  service: string;
  source: string;                  // Phase 1
  business_criticality: string;    // Phase 1
  data_lifetime: string;           // Phase 1
  library: string;                 // Phase 1
  usage_context: string;           // Phase 1
  file_path: string;               // Phase 1
  criticality: string;
  algorithm: string;
  key_size: number;
  tls_version: string;
  mwqrs: number;
  days_to_expiry: number;
  priority_index: number;
  why_prioritized: string;
  recommended_actions: string[];
  migration_direction: string;
  hybrid_alternative: string;      // Phase 1
  migration_complexity: string;    // Phase 1
  migration_cost: string;          // Phase 1
  latency_impact: string;          // Phase 1
  dependency_impact: string;
}

interface RemediationResponse {
  summary: {
    action_items: number;
    critical_mwqrs_items: number;
    urgent_expiries: number;
    high_blast_radius: number;
  };
  queue: RemediationItem[];
}

export const RemediationCenter = () => {
  const [data, setData] = useState<RemediationResponse | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPlan = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/remediation/plan');
      if (res.ok) {
        const json = await res.json();
        setData(json);
      } else {
        setError(`Failed to fetch remediation plan (HTTP ${res.status})`);
      }
    } catch (err: unknown) {
      console.warn('[RemediationCenter] Plan fetch fallback:', err);
      setError('Unable to connect to remediation telemetry service.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect
    void fetchPlan();
  }, [fetchPlan]);

  if (loading && !data) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <div className="border border-[#e5e5e5] bg-white p-12 text-center shadow-flat-sm font-mono text-xs text-tertiary">
          Sequencing cryptographic remediation priority queue...
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <div className="border border-red-200 bg-red-50 p-8 text-center shadow-flat-sm">
          <p className="font-mono text-xs text-red-600 mb-3">{error}</p>
          <button
            onClick={() => void fetchPlan()}
            className="px-4 py-1.5 bg-secondary text-white font-mono text-xs uppercase tracking-wider hover:bg-black transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const { summary, queue } = data;

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header */}
      <div className="border-b border-[#e5e5e5] pb-6">
        <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
          <span className="inline-block h-2 w-2 bg-primary" />
          <span>REMEDIATION CENTER & SEQUENCER</span>
          <span>·</span>
          <span>EXPLAINABLE MIGRATION QUEUE</span>
        </div>
        <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
          Prioritized Cryptographic Remediation
        </h1>
      </div>

      {/* Summary Stat Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 font-mono">
        <div className="border border-[#e5e5e5] bg-white p-5 shadow-flat-sm">
          <div className="text-[11px] text-tertiary uppercase">Total Action Items</div>
          <div className="mt-2 font-display text-3xl font-extrabold text-secondary">{summary.action_items}</div>
        </div>
        <div className="border border-severity-critical bg-white p-5 shadow-flat">
          <div className="text-[11px] text-severity-critical uppercase font-bold">Critical MWQRS Items</div>
          <div className="mt-2 font-display text-3xl font-extrabold text-severity-critical">{summary.critical_mwqrs_items}</div>
        </div>
        <div className="border border-[#e5e5e5] bg-white p-5 shadow-flat-sm">
          <div className="text-[11px] text-severity-medium uppercase">Urgent Expiries (&lt;30d)</div>
          <div className="mt-2 font-display text-3xl font-extrabold text-severity-medium">{summary.urgent_expiries}</div>
        </div>
        <div className="border border-secondary bg-white p-5 shadow-flat-sm">
          <div className="text-[11px] text-secondary uppercase font-bold">High Blast Radius (P0/P1)</div>
          <div className="mt-2 font-display text-3xl font-extrabold text-secondary">{summary.high_blast_radius}</div>
        </div>
      </div>

      {/* Sequenced Remediation Queue */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-3">
          <h2 className="font-display text-xl font-bold uppercase text-secondary">
            Sequenced Remediation Queue
          </h2>
          <span className="font-mono text-xs text-tertiary uppercase">RANKED BY MULTI-FACTOR URGENCY</span>
        </div>

        {queue.map((item) => {
          const isExpanded = expandedId === item.asset_id;

          return (
            <div
              key={item.asset_id}
              className="border border-secondary bg-white shadow-flat-sm transition-all"
            >
              {/* Card Header Bar */}
              <div
                onClick={() => setExpandedId(isExpanded ? null : item.asset_id)}
                className="flex flex-col md:flex-row md:items-center justify-between p-5 cursor-pointer hover:bg-[#faf9f5] gap-4"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-8 w-8 items-center justify-center bg-secondary text-white font-mono text-xs font-bold">
                    #{item.priority_rank}
                  </div>
                  <div>
                    <div className="font-mono text-sm font-bold text-secondary">
                      {item.target} <span className="text-tertiary font-normal">({item.service})</span>
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-tertiary">
                      {item.algorithm} {item.key_size}b · {item.tls_version} · Expiry in {item.days_to_expiry}d
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <span className="font-mono text-xs border border-[#e5e5e5] bg-white px-2 py-1 font-bold text-secondary">
                    {item.criticality}
                  </span>
                  <span className={`font-mono text-xs border px-2 py-1 font-bold ${
                    item.mwqrs >= 80 ? 'border-severity-critical bg-white text-severity-critical' :
                    item.mwqrs >= 50 ? 'border-severity-medium bg-white text-severity-medium' :
                    'border-severity-safe bg-white text-severity-safe'
                  }`}>
                    MWQRS {item.mwqrs.toFixed(1)}
                  </span>
                  {isExpanded ? <ChevronUp className="h-5 w-5 text-secondary" /> : <ChevronDown className="h-5 w-5 text-secondary" />}
                </div>
              </div>

              {/* Expandable Details */}
              {isExpanded && (
                <div className="border-t border-[#e5e5e5] bg-[#faf9f5] p-6 space-y-4 font-mono text-xs">
                  {/* Phase 1: Source + Criticality meta row */}
                  <div className="flex flex-wrap gap-3">
                    {item.source && (
                      <span className={`border px-2 py-0.5 font-bold text-[10px] uppercase ${
                        item.source === 'source_code' ? 'text-violet-700 bg-violet-50 border-violet-200' :
                        item.source === 'dependency' ? 'text-amber-700 bg-amber-50 border-amber-200' :
                        item.source === 'container' ? 'text-emerald-700 bg-emerald-50 border-emerald-200' :
                        item.source === 'binary' ? 'text-gray-700 bg-gray-50 border-gray-200' :
                        item.source === 'hsm' ? 'text-purple-700 bg-purple-50 border-purple-200' :
                        item.source === 'cloud_kms' ? 'text-sky-700 bg-sky-50 border-sky-200' :
                        'text-blue-700 bg-blue-50 border-blue-200'
                      }`}>
                        {item.source === 'source_code' ? 'Source Code' :
                         item.source === 'dependency' ? 'Dependency' :
                         item.source === 'container' ? 'Container' :
                         item.source === 'binary' ? 'Binary' :
                         item.source === 'hsm' ? 'Hardware HSM' :
                         item.source === 'cloud_kms' ? 'Cloud KMS' : 'TLS/Network'}
                      </span>
                    )}
                    {item.business_criticality && (
                      <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-[10px] text-secondary">
                        Biz Crit: {item.business_criticality}
                      </span>
                    )}
                    {item.data_lifetime && (
                      <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-[10px] text-secondary">
                        Data Lifetime: {item.data_lifetime}
                      </span>
                    )}
                  </div>
                  {/* Why Prioritized Reasoning */}
                  <div className="border-l-2 border-primary bg-white p-4">
                    <div className="text-[10px] text-primary uppercase font-bold">Why It Was Prioritized:</div>
                    <div className="mt-1 text-secondary leading-relaxed">{item.why_prioritized}</div>
                  </div>

                  {/* Migration Trajectory & Impact (Phase 1 enriched) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="border border-[#e5e5e5] bg-white p-4">
                      <div className="text-tertiary uppercase text-[10px]">PQC Migration Target:</div>
                      <div className="mt-1 font-bold text-secondary">{item.migration_direction}</div>
                      {item.hybrid_alternative && (
                        <div className="mt-1 text-tertiary text-[11px]">Hybrid: {item.hybrid_alternative}</div>
                      )}
                    </div>
                    <div className="border border-[#e5e5e5] bg-white p-4">
                      <div className="text-tertiary uppercase text-[10px]">Migration Attributes:</div>
                      <div className="mt-2 flex flex-col gap-1">
                        {item.migration_complexity && (
                          <div className="flex justify-between"><span className="text-tertiary">Complexity:</span><span className="font-bold text-secondary">{item.migration_complexity}</span></div>
                        )}
                        {item.migration_cost && (
                          <div className="flex justify-between"><span className="text-tertiary">Cost:</span><span className="font-bold text-secondary">{item.migration_cost}</span></div>
                        )}
                        {item.latency_impact && (
                          <div className="flex justify-between"><span className="text-tertiary">Latency Impact:</span><span className="font-bold text-secondary">{item.latency_impact}</span></div>
                        )}
                        <div className="flex justify-between"><span className="text-tertiary">Dependency Impact:</span><span className="font-bold text-secondary">{item.dependency_impact}</span></div>
                      </div>
                    </div>
                  </div>

                  {/* Prescribed Remediation Actions */}
                  <div className="border border-[#e5e5e5] bg-white p-4">
                    <div className="text-secondary font-bold uppercase mb-2">
                      Prescribed Remediation Actions:
                    </div>
                    <ul className="space-y-1.5 list-disc pl-4 text-tertiary">
                      {item.recommended_actions.map((act, idx) => (
                        <li key={idx} className="text-secondary">{act}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
