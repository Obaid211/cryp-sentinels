import { useState, useEffect } from 'react';
import { CheckCircle2, Clock } from 'lucide-react';
import { API_BASE_URL } from '../config';

interface ComplianceData {
  stats: {
    total_assets: number;
    quantum_vulnerable: number;
    pqc_ready: number;
    migration_required: number;
    unknown_under_review: number;
  };
  implemented_controls: Array<{
    id: string;
    name: string;
    status: string;
    framework: string;
  }>;
  roadmap_controls: Array<{
    id: string;
    name: string;
    status: string;
    target: string;
  }>;
}

export const ComplianceReadiness = () => {
  const [data, setData] = useState<ComplianceData | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchCompliance = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE_URL}/api/compliance/summary`);
        if (res.ok) {
          const json = await res.json();
          setData(json);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    void fetchCompliance();
  }, []);

  if (loading || !data) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <div className="border border-[#e5e5e5] bg-white p-12 text-center shadow-flat-sm font-mono text-xs text-tertiary">
          Auditing technical controls & NIST FIPS compliance baseline...
        </div>
      </div>
    );
  }

  const { stats, implemented_controls, roadmap_controls } = data;

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header */}
      <div className="border-b border-[#e5e5e5] pb-6">
        <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
          <span className="inline-block h-2 w-2 bg-primary" />
          <span>STANDARDS & READINESS FRAMEWORK</span>
          <span>·</span>
          <span>NIST FIPS 203/204/205 POSTURE</span>
        </div>
        <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
          Compliance & Cryptographic Readiness
        </h1>
      </div>

      {/* Scope Disclaimer Banner */}
      <div className="border border-secondary bg-white p-5 shadow-flat-sm">
        <div className="font-mono text-xs text-tertiary leading-relaxed">
          <span className="font-bold text-secondary uppercase">Compliance Scope: </span>
          Technical verification against finalized NIST Post-Quantum Cryptographic Standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA,
          FIPS 205 SLH-DSA) and Keyfactor AgileSec Pipeline Architecture guidelines.
        </div>
      </div>

      {/* Stat Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 font-mono">
        <div className="border border-[#e5e5e5] bg-white p-4 shadow-flat-sm">
          <div className="text-[10px] text-tertiary uppercase">Total Assets</div>
          <div className="mt-2 font-display text-2xl font-bold text-secondary">{stats.total_assets}</div>
        </div>
        <div className="border border-severity-critical bg-white p-4 shadow-flat">
          <div className="text-[10px] text-severity-critical uppercase font-bold">Vulnerable</div>
          <div className="mt-2 font-display text-2xl font-bold text-severity-critical">{stats.quantum_vulnerable}</div>
        </div>
        <div className="border border-severity-safe bg-white p-4 shadow-flat-sm">
          <div className="text-[10px] text-severity-safe uppercase font-bold">PQC-Ready</div>
          <div className="mt-2 font-display text-2xl font-bold text-severity-safe">{stats.pqc_ready}</div>
        </div>
        <div className="border border-severity-medium bg-white p-4 shadow-flat-sm">
          <div className="text-[10px] text-severity-medium uppercase">Migrate Req.</div>
          <div className="mt-2 font-display text-2xl font-bold text-severity-medium">{stats.migration_required}</div>
        </div>
        <div className="border border-[#e5e5e5] bg-white p-4 shadow-flat-sm">
          <div className="text-[10px] text-tertiary uppercase">Under Review</div>
          <div className="mt-2 font-display text-2xl font-bold text-secondary">{stats.unknown_under_review}</div>
        </div>
      </div>

      {/* Two Column Control Checklist */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Column 1: Implemented Prototype Controls */}
        <div className="border border-secondary bg-white p-6 shadow-flat space-y-4">
          <div className="border-b border-[#e5e5e5] pb-3 flex items-center justify-between">
            <h2 className="font-display text-base font-bold uppercase text-secondary">
              Implemented Prototype Controls
            </h2>
            <span className="font-mono text-[10px] text-severity-safe font-bold uppercase">100% OPERATIONAL</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {implemented_controls.map((ctl) => (
              <div key={ctl.id} className="border border-[#e5e5e5] p-3 bg-[#faf9f5]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-secondary">
                    <CheckCircle2 className="h-4 w-4 text-severity-safe" />
                    <span>{ctl.id}: {ctl.name}</span>
                  </div>
                  <span className="border border-severity-safe bg-white px-2 py-0.5 text-[10px] font-bold text-severity-safe">
                    {ctl.status}
                  </span>
                </div>
                <div className="mt-1 text-tertiary text-[11px] pl-6">
                  Standard: {ctl.framework}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Column 2: Controls in Progress & Roadmap Items */}
        <div className="border border-[#e5e5e5] bg-white p-6 shadow-flat-sm space-y-4">
          <div className="border-b border-[#e5e5e5] pb-3 flex items-center justify-between">
            <h2 className="font-display text-base font-bold uppercase text-secondary">
              Controls in Progress & Roadmap Items
            </h2>
            <span className="font-mono text-[10px] text-tertiary uppercase">NEXT MILESTONES</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {roadmap_controls.map((ctl) => (
              <div key={ctl.id} className="border border-[#e5e5e5] p-3 bg-white">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-secondary">
                    <Clock className="h-4 w-4 text-primary" />
                    <span>{ctl.id}: {ctl.name}</span>
                  </div>
                  <span className="border border-primary bg-[#faf9f5] px-2 py-0.5 text-[10px] font-bold text-primary">
                    {ctl.status}
                  </span>
                </div>
                <div className="mt-1 text-tertiary text-[11px] pl-6">
                  Target Spec: {ctl.target}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
