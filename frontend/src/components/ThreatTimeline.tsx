import { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, CheckCircle, Info } from 'lucide-react';

interface UrgencyVerdict {
  combined_requirement_years: number;
  planning_horizon_years: number;
  margin_years: number;
  urgency_level: string;
  status_color: string;
  verdict: 'CRITICAL' | 'OK';
  summary: string;
}

interface ThreatRanking {
  id: number;
  target: string;
  service: string;
  criticality: string;
  shelf_life_years: number;
  migration_time_years: number;
  combined_years: number;
  margin_years: number;
  verdict: string;
  mwqrs: number;
}

export const ThreatTimeline = () => {
  const [shelfLife, setShelfLife] = useState<number>(10.0);
  const [migrationEffort, setMigrationEffort] = useState<number>(3.0);
  const [planningHorizon, setPlanningHorizon] = useState<number>(10.0);
  const [dataSensitivity, setDataSensitivity] = useState<string>('Confidential / PII (P1)');
  const [verdictData, setVerdictData] = useState<UrgencyVerdict | null>(null);
  const [rankings, setRankings] = useState<ThreatRanking[]>([]);
  const [loading, setLoading] = useState(false);

  const calculateUrgency = useCallback(async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/threat/urgency', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          shelf_life_years: shelfLife,
          migration_time_years: migrationEffort,
          planning_horizon_years: planningHorizon,
          mwqrs: 75.0,
          is_quantum_vulnerable: true,
          data_sensitivity: dataSensitivity
        })
      });
      if (res.ok) {
        const json = await res.json();
        setVerdictData(json);
      }
    } catch (err) {
      console.error(err);
    }
  }, [shelfLife, migrationEffort, planningHorizon, dataSensitivity]);

  const fetchRankings = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/threat/inventory-wide?planning_horizon=${planningHorizon}`);
      if (res.ok) {
        const json = await res.json();
        setRankings(json);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [planningHorizon]);

  useEffect(() => {
    void calculateUrgency();
    void fetchRankings();
  }, [calculateUrgency, fetchRankings]);

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header */}
      <div className="border-b border-[#e5e5e5] pb-6">
        <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
          <span className="inline-block h-2 w-2 bg-primary" />
          <span>THREAT TIMELINE & MOSCA ENGINE</span>
          <span>·</span>
          <span>HARVEST-NOW-DECRYPT-LATER MODEL</span>
        </div>
        <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
          Mosca Migration Urgency Evaluation
        </h1>
      </div>

      {/* Methodology Disclaimer Banner */}
      <div className="border border-secondary bg-white p-5 shadow-flat-sm flex items-start gap-4">
        <Info className="h-5 w-5 text-secondary flex-shrink-0 mt-0.5" />
        <div className="font-mono text-xs text-tertiary leading-relaxed">
          <span className="font-bold text-secondary uppercase">Methodology Disclaimer: </span>
          This tool evaluates cryptographic transition urgency using Mosca's Inequality framework (
          <code className="text-secondary font-bold">X + Y &gt; Z</code>: Migration Time + Data Shelf-Life vs Planning Horizon).
          It does not predict the exact arrival date of a Cryptographically Relevant Quantum Computer (CRQC), but calculates
          exposure to Harvest-Now-Decrypt-Later (HNDL) attacks.
        </div>
      </div>

      {/* Interactive Urgency Calculator */}
      <div className="border border-secondary bg-white p-8 shadow-flat space-y-6">
        <div className="border-b border-[#e5e5e5] pb-4 flex items-center justify-between">
          <h2 className="font-display text-lg font-bold uppercase text-secondary">
            Interactive Migration Urgency Calculator
          </h2>
          <span className="font-mono text-xs text-tertiary uppercase">MOSCA PARAMETERS</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 font-mono text-xs">
          {/* Sliders & Inputs */}
          <div className="lg:col-span-7 space-y-5">
            <div>
              <div className="flex justify-between text-secondary font-bold mb-1">
                <span>DATA SENSITIVITY PROFILE:</span>
              </div>
              <select
                value={dataSensitivity}
                onChange={(e) => {
                  setDataSensitivity(e.target.value);
                  if (e.target.value.includes('P0')) setShelfLife(20.0);
                  else if (e.target.value.includes('P1')) setShelfLife(10.0);
                  else setShelfLife(3.0);
                }}
                className="w-full border border-secondary p-2 bg-white outline-none"
              >
                <option value="Public / Non-Sensitive">Public / Non-Sensitive (1y shelf-life)</option>
                <option value="Standard Operational (P2/P3)">Standard Operational P2/P3 (3y shelf-life)</option>
                <option value="Confidential / PII (P1)">Confidential / PII P1 (10y shelf-life)</option>
                <option value="Critical / National Security (P0)">Critical / National Security P0 (20y shelf-life)</option>
              </select>
            </div>

            <div>
              <div className="flex justify-between text-secondary font-bold mb-1">
                <span>ESTIMATED DATA SHELF-LIFE (Y):</span>
                <span className="text-primary">{shelfLife} Years</span>
              </div>
              <input
                type="range"
                min="0.5"
                max="30"
                step="0.5"
                value={shelfLife}
                onChange={(e) => setShelfLife(parseFloat(e.target.value))}
                className="w-full accent-primary"
              />
            </div>

            <div>
              <div className="flex justify-between text-secondary font-bold mb-1">
                <span>ESTIMATED MIGRATION EFFORT (X):</span>
                <span className="text-primary">{migrationEffort} Years</span>
              </div>
              <input
                type="range"
                min="0.5"
                max="10"
                step="0.5"
                value={migrationEffort}
                onChange={(e) => setMigrationEffort(parseFloat(e.target.value))}
                className="w-full accent-primary"
              />
            </div>

            <div>
              <div className="flex justify-between text-secondary font-bold mb-1">
                <span>ORGANIZATIONAL PLANNING HORIZON (Z):</span>
                <span className="text-primary">{planningHorizon} Years</span>
              </div>
              <input
                type="number"
                min="1"
                max="30"
                value={planningHorizon}
                onChange={(e) => setPlanningHorizon(parseFloat(e.target.value) || 1)}
                className="w-full border border-secondary p-2 bg-white outline-none"
              />
            </div>
          </div>

          {/* Live Recalculating Verdict Banner */}
          <div className="lg:col-span-5 flex flex-col justify-between border border-secondary p-6 bg-[#faf9f5]">
            {verdictData ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-3">
                  <span className="text-tertiary uppercase font-bold">TIMELINE VERDICT:</span>
                  <span className={`inline-flex items-center gap-1.5 px-3 py-1 font-bold text-xs border ${
                    verdictData.verdict === 'CRITICAL'
                      ? 'border-severity-critical bg-white text-severity-critical'
                      : 'border-severity-safe bg-white text-severity-safe'
                  }`}>
                    {verdictData.verdict === 'CRITICAL' ? <AlertTriangle className="h-4 w-4" /> : <CheckCircle className="h-4 w-4" />}
                    {verdictData.verdict}
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-tertiary">Combined Req (X + Y):</span>
                    <span className="font-bold text-secondary">{verdictData.combined_requirement_years} Years</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-tertiary">Planning Horizon (Z):</span>
                    <span className="font-bold text-secondary">{verdictData.planning_horizon_years} Years</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-tertiary">Timeline Headroom/Deficit:</span>
                    <span className={`font-bold ${verdictData.margin_years < 0 ? 'text-severity-critical' : 'text-severity-safe'}`}>
                      {verdictData.margin_years > 0 ? `+${verdictData.margin_years}` : verdictData.margin_years} Years
                    </span>
                  </div>
                </div>

                <div className="border-t border-[#e5e5e5] pt-3 text-[11px] text-secondary leading-relaxed">
                  {verdictData.summary}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>

      {/* Inventory-Wide Threat Urgency Rankings Table */}
      <div className="border border-secondary bg-white p-6 shadow-flat space-y-4">
        <div className="border-b border-[#e5e5e5] pb-3 flex items-center justify-between">
          <h2 className="font-display text-lg font-bold uppercase text-secondary">
            Inventory-Wide Threat Urgency Rankings
          </h2>
          <span className="font-mono text-xs text-tertiary uppercase">SORTED BY MOSCA MARGIN</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-secondary bg-[#faf9f5] text-tertiary uppercase">
                <th className="py-2.5 px-3">TARGET</th>
                <th className="py-2.5 px-3">SERVICE</th>
                <th className="py-2.5 px-3">TIER</th>
                <th className="py-2.5 px-3">SHELF-LIFE (Y)</th>
                <th className="py-2.5 px-3">MIGRATION (X)</th>
                <th className="py-2.5 px-3">COMBINED</th>
                <th className="py-2.5 px-3">HEADROOM (Z - [X+Y])</th>
                <th className="py-2.5 px-3 text-right">VERDICT</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-tertiary">Loading rankings...</td>
                </tr>
              ) : (
                rankings.map((r) => (
                  <tr key={r.id} className="border-b border-[#eeeeea] hover:bg-[#faf9f5]">
                    <td className="py-3 px-3 font-bold text-secondary">{r.target}</td>
                    <td className="py-3 px-3 text-secondary">{r.service}</td>
                    <td className="py-3 px-3">
                      <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-secondary">
                        {r.criticality}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-tertiary">{r.shelf_life_years}y</td>
                    <td className="py-3 px-3 text-tertiary">{r.migration_time_years}y</td>
                    <td className="py-3 px-3 font-bold text-secondary">{r.combined_years}y</td>
                    <td className="py-3 px-3">
                      <span className={r.margin_years < 0 ? 'text-severity-critical font-bold' : 'text-severity-safe font-bold'}>
                        {r.margin_years > 0 ? `+${r.margin_years}` : r.margin_years}y
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className={`px-2 py-0.5 font-bold border ${
                        r.verdict === 'CRITICAL'
                          ? 'border-severity-critical bg-white text-severity-critical'
                          : 'border-severity-safe bg-white text-severity-safe'
                      }`}>
                        {r.verdict}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
