import React, { useState, useEffect, useCallback } from 'react';
import { API_BASE_URL } from '../config';

interface SnapshotItem {
  id: number;
  name: string;
  created_at: string;
  asset_count: number;
  avg_risk: number;
  critical_count: number;
  medium_count?: number;
  safe_count?: number;
}

interface DiffResult {
  old_snapshot: SnapshotItem;
  new_snapshot: SnapshotItem;
  summary: {
    added_count: number;
    removed_count: number;
    modified_count: number;
    risk_increased_count: number;
    risk_decreased_count: number;
    overall_risk_delta: number;
  };
  modified: Array<{
    target: string;
    host: string;
    port: number;
    service: string;
    criticality: string;
    old_mwqrs: number;
    new_mwqrs: number;
    mwqrs_delta: number;
    changes: Array<{
      property: string;
      old: string | number;
      new: string | number;
      delta?: number;
    }>;
  }>;
  alerts: string[];
}

export const ScanHistoryDiff: React.FC = () => {
  const [snapshots, setSnapshots] = useState<SnapshotItem[]>([]);
  const [oldId, setOldId] = useState<number | null>(null);
  const [newId, setNewId] = useState<number | null>(null);
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [newSnapshotName, setNewSnapshotName] = useState('');
  const [saving, setSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Fetch snapshots list
  const fetchSnapshots = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/snapshots/list`);
      if (res.ok) {
        const data: SnapshotItem[] = await res.json();
        setSnapshots(data);
        if (data.length >= 2 && oldId === null && newId === null) {
          setOldId(data[data.length - 1].id);
          setNewId(data[0].id);
        } else if (data.length === 1 && oldId === null) {
          setOldId(data[0].id);
          setNewId(data[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to load snapshots:', err);
    }
  }, [oldId, newId]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect
    void fetchSnapshots();
  }, [fetchSnapshots]);

  // Compute diff
  const handleCompare = async () => {
    if (oldId === null || newId === null) return;
    setLoading(true);
    setStatusMessage(null);

    try {
      const res = await fetch(`${API_BASE_URL}/api/snapshots/diff?old_id=${oldId}&new_id=${newId}`);
      if (res.ok) {
        const data: DiffResult = await res.json();
        setDiff(data);
      } else {
        setStatusMessage('Failed to compute diff between selected snapshots.');
      }
    } catch (err) {
      setStatusMessage('Error comparing snapshots: ' + String(err));
    } finally {
      setLoading(false);
    }
  };

  // Save new snapshot
  const handleSaveSnapshot = async () => {
    setSaving(true);
    setStatusMessage(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/snapshots/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newSnapshotName || undefined }),
      });
      if (res.ok) {
        setNewSnapshotName('');
        setStatusMessage('Snapshot captured and committed successfully!');
        void fetchSnapshots();
      } else {
        setStatusMessage('Failed to create snapshot.');
      }
    } catch (err) {
      setStatusMessage('Error saving snapshot: ' + String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="border border-[var(--border)] bg-[var(--surface)] p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-semibold">
              Capability 08 / 09
            </span>
            <span className="h-3 w-px bg-[var(--border)]" />
            <span className="font-mono text-xs text-[var(--text-muted)]">
              24-Hour Rescan & Diff-Based Alerting Engine
            </span>
          </div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-tight text-[var(--text-primary)] mt-1">
            Scan History & Snapshot Diff
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-3xl">
            Compare historical audit snapshots across rescan cycles. Detect cryptographic drift, algorithm modifications, approaching certificate expirations, and MWQRS risk score transitions.
          </p>
        </div>

        {/* Capture Snapshot Action */}
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Snapshot label..."
            value={newSnapshotName}
            onChange={(e) => setNewSnapshotName(e.target.value)}
            className="border border-[var(--border)] bg-[var(--surface-raised)] px-3 py-2 font-mono text-xs text-[var(--text-primary)] outline-none"
          />
          <button
            onClick={handleSaveSnapshot}
            disabled={saving}
            className="bg-[var(--text-primary)] text-[var(--surface)] px-4 py-2 font-mono text-xs font-bold uppercase hover:bg-[var(--accent)] transition-colors"
          >
            {saving ? 'Capturing...' : '+ Capture Snapshot'}
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 border border-[var(--accent)] bg-[#fff7f5] text-[var(--accent)] font-mono text-xs font-bold">
          {statusMessage}
        </div>
      )}

      {/* Snapshot Comparison Selector */}
      <div className="border border-[var(--border)] bg-[var(--surface)] p-6 space-y-4">
        <h2 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
          Select Snapshots for Delta Analysis
        </h2>

        {snapshots.length === 0 ? (
          <div className="p-6 text-center font-mono text-xs text-[var(--text-muted)] border border-[var(--border)] bg-[var(--surface-raised)]">
            No snapshots captured yet. Click '+ Capture Snapshot' above to create your baseline snapshot.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
            <div className="md:col-span-5 space-y-1">
              <label className="font-mono text-[10px] uppercase text-[var(--text-muted)] font-bold">
                Baseline Snapshot (A)
              </label>
              <select
                value={oldId || ''}
                onChange={(e) => setOldId(parseInt(e.target.value, 10))}
                className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2.5 font-mono text-xs text-[var(--text-primary)] outline-none"
              >
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    #{s.id} — {s.name} ({s.asset_count} assets, {s.avg_risk} MWQRS)
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-5 space-y-1">
              <label className="font-mono text-[10px] uppercase text-[var(--text-muted)] font-bold">
                Comparison Snapshot (B)
              </label>
              <select
                value={newId || ''}
                onChange={(e) => setNewId(parseInt(e.target.value, 10))}
                className="w-full border border-[var(--border)] bg-[var(--surface-raised)] p-2.5 font-mono text-xs text-[var(--text-primary)] outline-none"
              >
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    #{s.id} — {s.name} ({s.asset_count} assets, {s.avg_risk} MWQRS)
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <button
                onClick={handleCompare}
                disabled={loading || oldId === null || newId === null}
                className="w-full py-2.5 bg-[var(--accent)] text-white font-mono text-xs font-bold uppercase hover:bg-[var(--text-primary)] transition-colors"
              >
                {loading ? 'Comparing...' : '▶ Compute Diff'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Diff Results View */}
      {diff && (
        <div className="space-y-6">
          {/* Delta KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="border border-[var(--border)] bg-[var(--surface)] p-4">
              <span className="font-mono text-[10px] uppercase text-[var(--text-muted)]">
                Modified Endpoints
              </span>
              <div className="font-display text-2xl font-bold text-[var(--text-primary)] mt-1">
                {diff.summary.modified_count}
              </div>
            </div>

            <div className="border border-[var(--border)] bg-[var(--surface)] p-4">
              <span className="font-mono text-[10px] uppercase text-[var(--text-muted)]">
                Net MWQRS Delta
              </span>
              <div
                className={`font-display text-2xl font-bold mt-1 ${
                  diff.summary.overall_risk_delta < 0
                    ? 'text-[#10b981]'
                    : diff.summary.overall_risk_delta > 0
                    ? 'text-[#b91c1c]'
                    : 'text-[var(--text-primary)]'
                }`}
              >
                {diff.summary.overall_risk_delta > 0 ? '+' : ''}
                {diff.summary.overall_risk_delta}
              </div>
            </div>

            <div className="border border-[var(--border)] bg-[var(--surface)] p-4">
              <span className="font-mono text-[10px] uppercase text-[var(--text-muted)]">
                Risk Decreased Endpoints
              </span>
              <div className="font-display text-2xl font-bold text-[#10b981] mt-1">
                {diff.summary.risk_decreased_count}
              </div>
            </div>

            <div className="border border-[var(--border)] bg-[var(--surface)] p-4">
              <span className="font-mono text-[10px] uppercase text-[var(--text-muted)]">
                Risk Increased Endpoints
              </span>
              <div className="font-display text-2xl font-bold text-[#b91c1c] mt-1">
                {diff.summary.risk_increased_count}
              </div>
            </div>
          </div>

          {/* Diff Alerts Feed */}
          {diff.alerts.length > 0 && (
            <div className="border border-[var(--border)] bg-[var(--surface)] p-5 space-y-3">
              <h3 className="font-mono text-xs uppercase tracking-wider font-bold text-[var(--text-primary)]">
                Diff Alert Log ({diff.alerts.length})
              </h3>
              <div className="space-y-2">
                {diff.alerts.map((alert, idx) => (
                  <div
                    key={idx}
                    className="p-3 border-l-4 border-[var(--accent)] bg-[var(--surface-raised)] font-mono text-xs text-[var(--text-primary)]"
                  >
                    {alert}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Modified Assets Table */}
          {diff.modified.length > 0 && (
            <div className="border border-[var(--border)] bg-[var(--surface)]">
              <div className="p-4 border-b border-[var(--border)] bg-[var(--surface-raised)]">
                <h3 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
                  Cryptographic Attribute Delta Table
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[var(--border)] bg-[var(--surface-raised)] text-[var(--text-muted)] text-[10px] uppercase">
                      <th className="p-3">Endpoint</th>
                      <th className="p-3">Service</th>
                      <th className="p-3">Changed Properties</th>
                      <th className="p-3 text-center">MWQRS Shift</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border)]">
                    {diff.modified.map((item, idx) => (
                      <tr key={idx} className="hover:bg-[var(--surface-raised)]">
                        <td className="p-3 font-bold text-[var(--text-primary)]">{item.target}</td>
                        <td className="p-3">
                          {item.service} ({item.criticality})
                        </td>
                        <td className="p-3 space-y-1">
                          {item.changes.map((c, i) => (
                            <div key={i} className="text-[11px]">
                              <span className="font-bold text-[var(--text-secondary)]">{c.property}:</span>{' '}
                              <span className="line-through text-[var(--text-muted)]">{c.old}</span>{' '}
                              <span className="text-[var(--accent)] font-bold">→ {c.new}</span>
                            </div>
                          ))}
                        </td>
                        <td className="p-3 text-center">
                          <span
                            className={`font-bold px-2 py-0.5 border ${
                              item.mwqrs_delta < 0
                                ? 'bg-[#ecfdf5] text-[#047857] border-[#10b981]'
                                : item.mwqrs_delta > 0
                                ? 'bg-[#fee2e2] text-[#b91c1c] border-[#ef4444]'
                                : 'bg-[var(--surface-raised)] text-[var(--text-muted)] border-[var(--border)]'
                            }`}
                          >
                            {item.mwqrs_delta > 0 ? '+' : ''}
                            {item.mwqrs_delta} pts
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Chronological Snapshot Library */}
      <div className="border border-[var(--border)] bg-[var(--surface)]">
        <div className="p-4 border-b border-[var(--border)] bg-[var(--surface-raised)] flex items-center justify-between">
          <h3 className="font-display text-base font-bold uppercase text-[var(--text-primary)]">
            Chronological Snapshot Library ({snapshots.length})
          </h3>
        </div>
        <div className="divide-y divide-[var(--border)]">
          {snapshots.map((s) => (
            <div
              key={s.id}
              className="p-4 flex flex-wrap items-center justify-between gap-4 font-mono text-xs hover:bg-[var(--surface-raised)]"
            >
              <div>
                <span className="font-bold text-[var(--text-primary)] text-sm">
                  #{s.id} — {s.name}
                </span>
                <div className="text-[11px] text-[var(--text-muted)] mt-0.5">
                  Captured: {new Date(s.created_at).toLocaleString()}
                </div>
              </div>

              <div className="flex items-center gap-4">
                <span className="px-2 py-1 border border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)]">
                  {s.asset_count} assets
                </span>
                <span className="px-2 py-1 border border-[var(--border)] bg-[var(--surface)] font-bold text-[var(--accent)]">
                  {s.avg_risk} MWQRS
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
