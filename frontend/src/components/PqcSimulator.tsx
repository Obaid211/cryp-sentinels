import React, { useState, useEffect, useCallback } from 'react';
import { API_BASE_URL } from '../config';

interface StrategyDef {
  id: string;
  name: string;
  badge: string;
  standards: string[];
  description: string;
  pros: string[];
  cons: string[];
  timeline_weeks: number;
}

interface AssetSimulation {
  asset_id: number;
  host: string;
  port: number;
  service_name: string;
  criticality: string;
  strategy: string;
  strategy_name: string;
  before_state: {
    algorithm: string;
    key_size: string;
    tls_version: string;
    mwqrs_score: number;
    quantum_status: string;
  };
  after_state: {
    algorithm: string;
    key_size: string;
    tls_version: string;
    mwqrs_score: number;
    quantum_status: string;
    risk_reduction: number;
    notes: string;
  };
  nist_pqc: {
    kem: string;
    signature: string;
    hybrid_strategy: string;
  };
  blast_radius_count: number;
  complexity: 'Low' | 'Medium' | 'High';
  estimated_effort_hours: number;
}

interface SimulationResponse {
  strategy: StrategyDef;
  aggregate_posture: {
    total_assets: number;
    before_average_mwqrs: number;
    after_average_mwqrs: number;
    average_reduction: number;
    percentage_risk_drop: number;
    critical_risk_before: number;
    critical_risk_after: number;
    critical_eliminated: number;
    total_estimated_effort_hours: number;
    total_estimated_weeks: number;
  };
  migration_waves: Array<{
    wave: number;
    title: string;
    description: string;
    assets: Array<{
      sequence_position: number;
      asset_id: number;
      host: string;
      service_name: string;
      criticality: string;
      current_algorithm: string;
      target_standard: string;
      before_mwqrs: number;
      simulated_mwqrs: number;
      blast_radius_count: number;
      complexity: string;
      effort_hours: number;
      wave: number;
    }>;
  }>;
  asset_simulations: AssetSimulation[];
}

export const PqcSimulator: React.FC = () => {
  const [strategies, setStrategies] = useState<StrategyDef[]>([]);
  const [selectedStrategy, setSelectedStrategy] = useState<string>('HYBRID');
  const [simResult, setSimResult] = useState<SimulationResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAssetModal, setSelectedAssetModal] = useState<AssetSimulation | null>(null);
  const [activeWaveTab, setActiveWaveTab] = useState<number>(0);
  const [completedSequenceIds, setCompletedSequenceIds] = useState<Set<number>>(new Set());

  // Fetch available strategies
  const fetchStrategies = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/simulate/strategies`);
      if (res.ok) {
        const data: StrategyDef[] = await res.json();
        setStrategies(data);
      }
    } catch (err) {
      console.error('Failed to load strategies:', err);
    }
  }, []);

  // Run simulation
  const runSimulation = useCallback(async (stratId: string) => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE_URL}/api/simulate/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ strategy: stratId }),
      });
      if (res.ok) {
        const data: SimulationResponse = await res.json();
        setSimResult(data);
      }
    } catch (err) {
      console.error('Simulation execution failed:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect
    void fetchStrategies();
  }, [fetchStrategies]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect
    void runSimulation(selectedStrategy);
  }, [selectedStrategy, runSimulation]);

  const toggleSequenceStatus = (assetId: number) => {
    setCompletedSequenceIds((prev) => {
      const next = new Set(prev);
      if (next.has(assetId)) {
        next.delete(assetId);
      } else {
        next.add(assetId);
      }
      return next;
    });
  };

  const handleExportJson = () => {
    if (!simResult) return;
    const blob = new Blob([JSON.stringify(simResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ecdat_pqc_simulation_${selectedStrategy.toLowerCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const currentWave = simResult?.migration_waves[activeWaveTab];

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="border border-[var(--border)] bg-[var(--surface)] p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-semibold">
              Capability 06 / 09
            </span>
            <span className="h-3 w-px bg-[var(--border)]" />
            <span className="font-mono text-xs text-[var(--text-muted)]">
              NIST FIPS 203 / 204 / 205 Migration Simulator
            </span>
          </div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-tight text-[var(--text-primary)] mt-1">
            PQC Transition & Posture Simulator
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-3xl">
            Simulate post-quantum cryptographic transitions across your enterprise inventory. Model before vs after MWQRS risk posture deltas, estimate engineering effort, and generate topologically sequenced migration waves.
          </p>
        </div>

        <button
          onClick={handleExportJson}
          disabled={!simResult}
          className="border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)] px-4 py-2 font-mono text-xs font-bold uppercase tracking-wider transition-colors inline-flex items-center gap-2"
        >
          <span>↓ Export Simulation JSON</span>
        </button>
      </div>

      {/* Strategy Selection Cards */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="font-mono text-xs uppercase tracking-widest text-[var(--text-muted)] font-bold">
            Select Cryptographic Migration Trajectory
          </span>
          <span className="font-mono text-xs text-[var(--text-muted)]">
            Active: <strong className="text-[var(--accent)]">{selectedStrategy}</strong>
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {strategies.map((strat) => {
            const isSelected = strat.id === selectedStrategy;
            return (
              <div
                key={strat.id}
                onClick={() => setSelectedStrategy(strat.id)}
                className={`cursor-pointer border p-5 transition-all relative flex flex-col justify-between ${
                  isSelected
                    ? 'border-[var(--accent)] bg-[#fffbf9] shadow-[3px_3px_0px_var(--accent)]'
                    : 'border-[var(--border)] bg-[var(--surface)] hover:border-[var(--text-primary)]'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span
                      className={`font-mono text-[10px] px-2 py-0.5 font-bold uppercase ${
                        isSelected
                          ? 'bg-[var(--accent)] text-white'
                          : 'bg-[var(--surface-raised)] text-[var(--text-secondary)] border border-[var(--border)]'
                      }`}
                    >
                      {strat.badge}
                    </span>
                    <span className="font-mono text-xs text-[var(--text-muted)] font-semibold">
                      ~{strat.timeline_weeks} wks
                    </span>
                  </div>

                  <h3 className="font-display text-base font-bold text-[var(--text-primary)]">
                    {strat.name}
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] mt-2 line-clamp-3">
                    {strat.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-[var(--border)]">
                  <div className="font-mono text-[10px] text-[var(--text-muted)] uppercase tracking-wider mb-1">
                    Standards Mapped:
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {strat.standards.map((std) => (
                      <span
                        key={std}
                        className="font-mono text-[10px] px-1.5 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)] text-[var(--text-primary)]"
                      >
                        {std}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Aggregate Posture Impact Cards */}
      {loading ? (
        <div className="border border-[var(--border)] bg-[var(--surface)] p-12 text-center font-mono text-sm text-[var(--text-muted)]">
          <div className="animate-spin w-6 h-6 border-2 border-[var(--accent)] border-t-transparent mx-auto mb-3" />
          Running estate-wide PQC migration simulation...
        </div>
      ) : simResult ? (
        <div className="space-y-6">
          <div className="border border-[var(--border)] bg-[var(--surface)] p-6">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-[var(--border)]">
              <div>
                <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-bold">
                  Posture Delta Analysis
                </span>
                <h2 className="font-display text-lg font-bold uppercase text-[var(--text-primary)]">
                  Before vs. After Simulation Forecast
                </h2>
              </div>
              <span className="font-mono text-xs px-2.5 py-1 border border-[var(--border)] bg-[var(--surface-raised)] text-[var(--text-secondary)] font-bold">
                {simResult.aggregate_posture.total_assets} Endpoints Evaluated
              </span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              {/* KPI 1: Average MWQRS Delta */}
              <div className="border-r border-[var(--border)] pr-4 last:border-none">
                <span className="font-mono text-xs uppercase text-[var(--text-muted)] block">
                  System MWQRS Score
                </span>
                <div className="flex items-baseline gap-2 mt-2">
                  <span className="font-display text-3xl font-bold text-[var(--text-muted)] line-through">
                    {simResult.aggregate_posture.before_average_mwqrs}
                  </span>
                  <span className="font-display text-3xl font-bold text-[#10b981]">
                    → {simResult.aggregate_posture.after_average_mwqrs}
                  </span>
                </div>
                <span className="font-mono text-xs text-[#10b981] font-bold block mt-1">
                  ↓ {simResult.aggregate_posture.average_reduction} pts (-{simResult.aggregate_posture.percentage_risk_drop}%)
                </span>
              </div>

              {/* KPI 2: Critical Assets */}
              <div className="border-r border-[var(--border)] pr-4 last:border-none">
                <span className="font-mono text-xs uppercase text-[var(--text-muted)] block">
                  Critical Risk Assets
                </span>
                <div className="flex items-baseline gap-2 mt-2">
                  <span className="font-display text-3xl font-bold text-[#b91c1c]">
                    {simResult.aggregate_posture.critical_risk_before}
                  </span>
                  <span className="font-display text-3xl font-bold text-[#10b981]">
                    → {simResult.aggregate_posture.critical_risk_after}
                  </span>
                </div>
                <span className="font-mono text-xs text-[#10b981] font-bold block mt-1">
                  {simResult.aggregate_posture.critical_eliminated} Critical Vulnerabilities Remediated
                </span>
              </div>

              {/* KPI 3: Estimated Effort */}
              <div className="border-r border-[var(--border)] pr-4 last:border-none">
                <span className="font-mono text-xs uppercase text-[var(--text-muted)] block">
                  Estimated Engineering
                </span>
                <div className="font-display text-3xl font-bold text-[var(--text-primary)] mt-2">
                  {simResult.aggregate_posture.total_estimated_effort_hours} hrs
                </div>
                <span className="font-mono text-xs text-[var(--text-muted)] block mt-1">
                  ~{simResult.aggregate_posture.total_estimated_weeks} person-weeks across 3 waves
                </span>
              </div>

              {/* KPI 4: Compliance Alignment */}
              <div>
                <span className="font-mono text-xs uppercase text-[var(--text-muted)] block">
                  FIPS 203/204 Compliance
                </span>
                <div className="font-display text-3xl font-bold text-[var(--text-primary)] mt-2">
                  {selectedStrategy === 'CLASSICAL_HARDENING' ? '0%' : '100%'}
                </div>
                <span className="font-mono text-xs text-[var(--accent)] font-bold block mt-1">
                  {selectedStrategy === 'PURE_PQC'
                    ? 'Full Quantum Immunity'
                    : selectedStrategy === 'HYBRID'
                    ? 'Composite Interoperable'
                    : 'Interim Mitigation Only'}
                </span>
              </div>
            </div>
          </div>

          {/* Phased Migration Waves & Topological Sequence */}
          <div className="border border-[var(--border)] bg-[var(--surface)]">
            <div className="border-b border-[var(--border)] p-4 bg-[var(--surface-raised)] flex flex-wrap items-center justify-between gap-4">
              <div>
                <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-bold">
                  Topological Roadmap
                </span>
                <h3 className="font-display text-lg font-bold uppercase text-[var(--text-primary)]">
                  Sequenced Migration Waves
                </h3>
              </div>

              {/* Wave Tabs */}
              <div className="inline-flex border border-[var(--border)] bg-[var(--surface)]">
                {simResult.migration_waves.map((wave, idx) => (
                  <button
                    key={wave.wave}
                    onClick={() => setActiveWaveTab(idx)}
                    className={`px-4 py-2 font-mono text-xs font-bold uppercase transition-colors ${
                      activeWaveTab === idx
                        ? 'bg-[var(--text-primary)] text-[var(--surface)]'
                        : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    Wave {wave.wave} ({wave.assets.length})
                  </button>
                ))}
              </div>
            </div>

            {/* Current Wave Description */}
            {currentWave && (
              <div className="p-4 border-b border-[var(--border)] bg-[#faf8f4] flex items-center justify-between">
                <div>
                  <h4 className="font-display text-sm font-bold text-[var(--text-primary)] uppercase">
                    {currentWave.title}
                  </h4>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    {currentWave.description}
                  </p>
                </div>
                <span className="font-mono text-xs px-2.5 py-1 border border-[var(--border)] bg-[var(--surface)] text-[var(--text-muted)]">
                  {currentWave.assets.reduce((sum, a) => sum + a.effort_hours, 0)} Total Hours
                </span>
              </div>
            )}

            {/* Assets Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[var(--border)] bg-[var(--surface-raised)] text-[var(--text-muted)] font-mono uppercase text-[11px]">
                    <th className="p-3 w-12 text-center">Seq</th>
                    <th className="p-3">Endpoint / Host</th>
                    <th className="p-3">Linked Service</th>
                    <th className="p-3">Current Classical</th>
                    <th className="p-3">Target PQC Standard</th>
                    <th className="p-3 text-center">MWQRS Delta</th>
                    <th className="p-3 text-center">Blast Radius</th>
                    <th className="p-3 text-center">Est. Effort</th>
                    <th className="p-3 text-right">Deep Dive</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)] font-mono">
                  {currentWave?.assets.map((item) => {
                    const isCompleted = completedSequenceIds.has(item.asset_id);
                    const matchingSim = simResult.asset_simulations.find(
                      (s) => s.asset_id === item.asset_id
                    );

                    return (
                      <tr
                        key={item.asset_id}
                        className={`hover:bg-[var(--surface-raised)] transition-colors ${
                          isCompleted ? 'opacity-60 bg-[#f9f9f9]' : ''
                        }`}
                      >
                        <td className="p-3 text-center">
                          <button
                            onClick={() => toggleSequenceStatus(item.asset_id)}
                            className={`w-6 h-6 border font-bold text-xs flex items-center justify-center ${
                              isCompleted
                                ? 'bg-[#10b981] text-white border-[#10b981]'
                                : 'border-[var(--border)] bg-[var(--surface)] text-[var(--text-secondary)]'
                            }`}
                            title="Toggle Migration Status"
                          >
                            {isCompleted ? '✓' : item.sequence_position}
                          </button>
                        </td>

                        <td className="p-3 font-bold text-[var(--text-primary)]">
                          {item.host}
                        </td>

                        <td className="p-3">
                          <div className="flex items-center gap-1.5">
                            <span className="font-semibold text-[var(--text-primary)]">
                              {item.service_name}
                            </span>
                            <span className="text-[10px] px-1.5 py-0.2 border border-[var(--border)] bg-[var(--surface-raised)]">
                              {item.criticality}
                            </span>
                          </div>
                        </td>

                        <td className="p-3 text-[var(--text-secondary)]">
                          {item.current_algorithm}
                        </td>

                        <td className="p-3 font-semibold text-[var(--accent)]">
                          {item.target_standard}
                        </td>

                        <td className="p-3 text-center">
                          <span className="text-[var(--text-muted)] line-through mr-1">
                            {item.before_mwqrs}
                          </span>
                          <span className="font-bold text-[#10b981]">
                            → {item.simulated_mwqrs}
                          </span>
                        </td>

                        <td className="p-3 text-center">
                          <span
                            className={`px-2 py-0.5 border ${
                              item.blast_radius_count > 3
                                ? 'border-[#ef4444] bg-[#fee2e2] text-[#b91c1c]'
                                : item.blast_radius_count > 1
                                ? 'border-[#f59e0b] bg-[#fef3c7] text-[#b45309]'
                                : 'border-[var(--border)] bg-[var(--surface-raised)] text-[var(--text-secondary)]'
                            }`}
                          >
                            {item.blast_radius_count} service{item.blast_radius_count !== 1 ? 's' : ''}
                          </span>
                        </td>

                        <td className="p-3 text-center text-[var(--text-primary)]">
                          {item.effort_hours} hrs
                        </td>

                        <td className="p-3 text-right">
                          <button
                            onClick={() => matchingSim && setSelectedAssetModal(matchingSim)}
                            className="px-2.5 py-1 border border-[var(--border)] bg-[var(--surface-raised)] hover:bg-[var(--text-primary)] hover:text-[var(--surface)] text-[11px] font-bold uppercase transition-colors"
                          >
                            Inspect Specs
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}

      {/* Modal: Single Asset Simulation Deep-Dive */}
      {selectedAssetModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[var(--surface)] border-2 border-[var(--text-primary)] max-w-2xl w-full p-6 space-y-6 shadow-[8px_8px_0px_#111111]">
            <div className="flex items-start justify-between border-b border-[var(--border)] pb-4">
              <div>
                <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-bold">
                  NIST PQC Specification Deep-Dive
                </span>
                <h3 className="font-display text-xl font-bold uppercase text-[var(--text-primary)] mt-1">
                  {selectedAssetModal.host}:{selectedAssetModal.port}
                </h3>
                <span className="font-mono text-xs text-[var(--text-muted)]">
                  Service: {selectedAssetModal.service_name} ({selectedAssetModal.criticality})
                </span>
              </div>
              <button
                onClick={() => setSelectedAssetModal(null)}
                className="w-8 h-8 border border-[var(--border)] bg-[var(--surface-raised)] font-mono font-bold hover:bg-[var(--text-primary)] hover:text-[var(--surface)]"
              >
                ✕
              </button>
            </div>

            {/* Before vs After Card Comparison */}
            <div className="grid grid-cols-2 gap-4">
              {/* Before */}
              <div className="border border-[var(--border)] p-4 bg-[var(--surface-raised)] space-y-2 text-xs font-mono">
                <span className="text-[10px] uppercase font-bold text-[var(--text-muted)]">
                  Current State
                </span>
                <div className="font-bold text-sm text-[var(--text-primary)]">
                  {selectedAssetModal.before_state.algorithm}
                </div>
                <div>Protocol: {selectedAssetModal.before_state.tls_version}</div>
                <div>Key Size: {selectedAssetModal.before_state.key_size}</div>
                <div className="text-[#b91c1c] font-bold">
                  Risk Score: {selectedAssetModal.before_state.mwqrs_score} MWQRS
                </div>
                <div className="text-[10px] text-[var(--text-muted)]">
                  {selectedAssetModal.before_state.quantum_status}
                </div>
              </div>

              {/* After */}
              <div className="border border-[var(--accent)] p-4 bg-[#fffaf8] space-y-2 text-xs font-mono">
                <span className="text-[10px] uppercase font-bold text-[var(--accent)]">
                  Target Simulated State
                </span>
                <div className="font-bold text-sm text-[var(--accent)]">
                  {selectedAssetModal.after_state.algorithm}
                </div>
                <div>Protocol: {selectedAssetModal.after_state.tls_version}</div>
                <div>Key Size: {selectedAssetModal.after_state.key_size}</div>
                <div className="text-[#10b981] font-bold">
                  Simulated MWQRS: {selectedAssetModal.after_state.mwqrs_score} (↓{selectedAssetModal.after_state.risk_reduction})
                </div>
                <div className="text-[10px] text-[#047857]">
                  {selectedAssetModal.after_state.quantum_status}
                </div>
              </div>
            </div>

            {/* NIST Mapping Standards */}
            <div className="border border-[var(--border)] p-4 bg-[var(--surface-raised)] space-y-2 text-xs">
              <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-bold">
                NIST Standard Replacement Architecture
              </span>
              <div className="font-mono space-y-1">
                <div><strong>Key Encapsulation (KEM):</strong> {selectedAssetModal.nist_pqc.kem}</div>
                <div><strong>Digital Signature:</strong> {selectedAssetModal.nist_pqc.signature}</div>
                <div><strong>Hybrid Deployment:</strong> {selectedAssetModal.nist_pqc.hybrid_strategy}</div>
              </div>
              <p className="text-[11px] text-[var(--text-secondary)] italic pt-1">
                {selectedAssetModal.after_state.notes}
              </p>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedAssetModal(null)}
                className="px-5 py-2 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
