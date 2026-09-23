import React, { useState, useEffect, useMemo, useCallback } from 'react';

interface CryptoAssetSummary {
  id: number;
  host: string;
  port: number;
  cert_key_type: string;
  cert_key_size_bits: number;
  tls_version: string;
  risk_score: number;
  is_vulnerable: boolean;
}

interface GraphNode {
  id: number;
  name: string;
  criticality: 'P0' | 'P1' | 'P2' | 'P3';
  description: string;
  asset_count: number;
  max_risk_score: number;
  has_vulnerable: boolean;
  assets: CryptoAssetSummary[];
  in_degree: number;
  out_degree: number;
  centrality: number;
}

interface GraphEdge {
  source: number;
  target: number;
  source_name: string;
  target_name: string;
  relation: string;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  critical_path: string[];
  is_dag: boolean;
  stats: {
    total_nodes: number;
    total_edges: number;
    isolated_nodes: number;
    critical_path_length: number;
  };
}

interface BlastRadiusData {
  service_id: number;
  service_name: string;
  criticality: string;
  blast_radius_count: number;
  severity: 'Low' | 'Medium' | 'High';
  dependent_services: Array<{
    id: number;
    name: string;
    criticality: string;
    is_direct: boolean;
    max_risk_score: number;
    asset_count: number;
  }>;
  dependent_count: number;
  upstream_services: Array<{
    id: number;
    name: string;
    criticality: string;
    is_direct: boolean;
  }>;
  upstream_count: number;
  impacted_assets: Array<{
    id: number;
    host: string;
    port: number;
    cert_key_type: string;
    risk_score: number;
    service_name: string;
  }>;
  impacted_asset_count: number;
  cumulative_risk_score: number;
}

export const DependencyGraph: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedServiceId, setSelectedServiceId] = useState<number | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusData | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);
  const [filterMode, setFilterMode] = useState<'ALL' | 'CRITICAL_PATH' | 'VULNERABLE'>('ALL');
  const [zoomLevel, setZoomLevel] = useState(1);
  const [hoveredNode, setHoveredNode] = useState<number | null>(null);

  const fetchGraph = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch('http://127.0.0.1:8000/api/graph/dependencies');
      if (res.ok) {
        const data: GraphData = await res.json();
        setGraphData(data);
        if (data.nodes.length > 0 && selectedServiceId === null) {
          // Default select Core-Database-Proxy (id=3) or first node
          const dbProxy = data.nodes.find((n) => n.name.toLowerCase().includes('database')) || data.nodes[0];
          setSelectedServiceId(dbProxy.id);
        }
      }
    } catch (err) {
      console.error('Failed to load dependency graph:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedServiceId]);

  const fetchBlastRadius = useCallback(async (serviceId: number) => {
    try {
      setBlastLoading(true);
      const res = await fetch(`http://127.0.0.1:8000/api/graph/blast-radius/${serviceId}`);
      if (res.ok) {
        const data: BlastRadiusData = await res.json();
        setBlastRadius(data);
      }
    } catch (err) {
      console.error('Failed to load blast radius:', err);
    } finally {
      setBlastLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchGraph();
  }, [fetchGraph]);

  useEffect(() => {
    if (selectedServiceId !== null) {
      void fetchBlastRadius(selectedServiceId);
    }
  }, [selectedServiceId, fetchBlastRadius]);

  // Compute 2D node layout positions deterministically
  const nodePositions = useMemo(() => {
    if (!graphData) return {};
    const pos: Record<number, { x: number; y: number }> = {};
    
    // Custom balanced multi-tier DAG positions for clarity
    const layoutCoords: Record<string, { x: number; y: number }> = {
      'User-Portal': { x: 180, y: 140 },
      'Analytics-Pipeline': { x: 580, y: 140 },
      'Payment-Gateway': { x: 260, y: 290 },
      'Notification-Service': { x: 700, y: 290 },
      'Auth-Service': { x: 120, y: 440 },
      'Core-Database-Proxy': { x: 440, y: 440 },
    };

    graphData.nodes.forEach((n, idx) => {
      if (layoutCoords[n.name]) {
        pos[n.id] = layoutCoords[n.name];
      } else {
        // Fallback grid
        const col = idx % 3;
        const row = Math.floor(idx / 3);
        pos[n.id] = { x: 200 + col * 260, y: 150 + row * 160 };
      }
    });

    return pos;
  }, [graphData]);

  // Filtered nodes
  const visibleNodes = useMemo(() => {
    if (!graphData) return [];
    if (filterMode === 'CRITICAL_PATH') {
      const set = new Set(graphData.critical_path);
      return graphData.nodes.filter((n) => set.has(n.name));
    }
    if (filterMode === 'VULNERABLE') {
      return graphData.nodes.filter((n) => n.max_risk_score > 50 || n.has_vulnerable);
    }
    return graphData.nodes;
  }, [graphData, filterMode]);

  // Blast radius affected node IDs
  const blastAffectedIds = useMemo(() => {
    if (!blastRadius) return new Set<number>();
    const set = new Set<number>();
    set.add(blastRadius.service_id);
    blastRadius.dependent_services.forEach((d) => set.add(d.id));
    return set;
  }, [blastRadius]);

  const selectedNode = useMemo(() => {
    if (!graphData || selectedServiceId === null) return null;
    return graphData.nodes.find((n) => n.id === selectedServiceId) || null;
  }, [graphData, selectedServiceId]);

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="border border-[var(--border)] bg-[var(--surface)] p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-semibold">
              Capability 05 / 09
            </span>
            <span className="h-3 w-px bg-[var(--border)]" />
            <span className="font-mono text-xs text-[var(--text-muted)]">
              NetworkX Architecture & Blast Radius Engine
            </span>
          </div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-tight text-[var(--text-primary)] mt-1">
            Cryptographic Dependency Graph
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-3xl">
            Directed architectural topology displaying service dependencies, caller/callee relationships, and real-time blast-radius reachability analysis upon cryptographic compromise or PQC rollover.
          </p>
        </div>

        {/* Filter & Zoom Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="inline-flex border border-[var(--border)] bg-[var(--surface-raised)]">
            {(['ALL', 'CRITICAL_PATH', 'VULNERABLE'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => setFilterMode(mode)}
                className={`px-3 py-1.5 font-mono text-xs font-bold uppercase transition-colors ${
                  filterMode === mode
                    ? 'bg-[var(--text-primary)] text-[var(--surface)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                {mode === 'ALL' ? 'All Services' : mode === 'CRITICAL_PATH' ? 'Critical Path' : 'Vulnerable Only'}
              </button>
            ))}
          </div>

          <div className="flex items-center border border-[var(--border)] bg-[var(--surface-raised)] font-mono text-xs">
            <button
              onClick={() => setZoomLevel((z) => Math.max(0.7, z - 0.15))}
              className="px-2.5 py-1.5 hover:bg-[var(--surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-r border-[var(--border)]"
              title="Zoom Out"
            >
              −
            </button>
            <span className="px-2.5 py-1.5 text-[var(--text-primary)] font-bold">
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => setZoomLevel((z) => Math.min(1.4, z + 0.15))}
              className="px-2.5 py-1.5 hover:bg-[var(--surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-l border-[var(--border)]"
              title="Zoom In"
            >
              +
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="px-2.5 py-1.5 hover:bg-[var(--surface)] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-l border-[var(--border)] text-[11px]"
            >
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Interactive Canvas + Blast Radius Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Graph Canvas */}
        <div className="lg:col-span-8 border border-[var(--border)] bg-[var(--surface)] flex flex-col relative overflow-hidden min-h-[580px]">
          {/* Top Canvas Status */}
          <div className="border-b border-[var(--border)] px-4 py-2.5 bg-[var(--surface-raised)] flex items-center justify-between font-mono text-xs text-[var(--text-muted)]">
            <div className="flex items-center gap-4">
              <span>DAG Status: <strong className="text-[var(--text-primary)] font-bold">{graphData?.is_dag ? 'Directed Acyclic (Safe)' : 'Cyclic Detected'}</strong></span>
              <span>•</span>
              <span>Services: <strong className="text-[var(--text-primary)]">{graphData?.stats.total_nodes ?? 0}</strong></span>
              <span>•</span>
              <span>Dependencies: <strong className="text-[var(--text-primary)]">{graphData?.stats.total_edges ?? 0}</strong></span>
            </div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-[var(--accent)] inline-block border border-[var(--border)]" /> Selected / Root
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-[#f59e0b] inline-block border border-[var(--border)]" /> Blast Impact
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-[#10b981] inline-block border border-[var(--border)]" /> PQC Safe
              </span>
            </div>
          </div>

          {/* SVG Canvas */}
          <div className="flex-1 relative overflow-auto bg-[#f8f6f0] p-4 flex items-center justify-center">
            {loading ? (
              <div className="flex flex-col items-center justify-center p-12 text-[var(--text-muted)] font-mono text-sm">
                <div className="animate-spin w-6 h-6 border-2 border-[var(--accent)] border-t-transparent mb-3" />
                Compiling NetworkX graph dependencies...
              </div>
            ) : (
              <svg
                width="840"
                height="540"
                viewBox="0 0 840 540"
                style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'center center', transition: 'transform 0.2s ease-out' }}
                className="select-none"
              >
                <defs>
                  {/* Arrowhead marker */}
                  <marker
                    id="arrowhead-default"
                    markerWidth="8"
                    markerHeight="6"
                    refX="7"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="var(--border)" />
                  </marker>
                  <marker
                    id="arrowhead-active"
                    markerWidth="8"
                    markerHeight="6"
                    refX="7"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="var(--accent)" />
                  </marker>
                  <marker
                    id="arrowhead-blast"
                    markerWidth="8"
                    markerHeight="6"
                    refX="7"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="#f59e0b" />
                  </marker>
                </defs>

                {/* Grid guidelines */}
                <g opacity="0.07" stroke="#111111" strokeWidth="1">
                  {Array.from({ length: 9 }).map((_, i) => (
                    <line key={`gx-${i}`} x1={i * 100} y1="0" x2={i * 100} y2="540" />
                  ))}
                  {Array.from({ length: 6 }).map((_, i) => (
                    <line key={`gy-${i}`} x1="0" y1={i * 100} x2="840" y2={i * 100} />
                  ))}
                </g>

                {/* Edges */}
                <g className="edges">
                  {graphData?.edges.map((edge, idx) => {
                    const srcPos = nodePositions[edge.source];
                    const tgtPos = nodePositions[edge.target];
                    if (!srcPos || !tgtPos) return null;

                    const isSrcSelected = edge.source === selectedServiceId;
                    const isTgtSelected = edge.target === selectedServiceId;
                    const isBlastFlow = blastAffectedIds.has(edge.source) && blastAffectedIds.has(edge.target);
                    const isCriticalFlow =
                      graphData.critical_path.includes(edge.source_name) &&
                      graphData.critical_path.includes(edge.target_name);

                    // Dynamic stroke styling
                    let strokeColor = 'var(--border)';
                    let strokeWidth = 1.5;
                    let markerId = 'arrowhead-default';
                    let strokeDasharray = undefined;

                    if (isSrcSelected || isTgtSelected) {
                      strokeColor = 'var(--accent)';
                      strokeWidth = 2.5;
                      markerId = 'arrowhead-active';
                    } else if (isBlastFlow) {
                      strokeColor = '#f59e0b';
                      strokeWidth = 2;
                      markerId = 'arrowhead-blast';
                      strokeDasharray = '4,3';
                    } else if (isCriticalFlow) {
                      strokeColor = '#111111';
                      strokeWidth = 2;
                    }

                    // Calculate midpoint for quadratic bezier curve
                    const midX = (srcPos.x + tgtPos.x) / 2;
                    const midY = (srcPos.y + tgtPos.y) / 2;


                    return (
                      <g key={`edge-${idx}`}>
                        <path
                          d={`M ${srcPos.x} ${srcPos.y} Q ${midX} ${srcPos.y} ${tgtPos.x} ${tgtPos.y}`}
                          fill="none"
                          stroke={strokeColor}
                          strokeWidth={strokeWidth}
                          strokeDasharray={strokeDasharray}
                          markerEnd={`url(#${markerId})`}
                          className="transition-all duration-300"
                        />
                        {/* Edge label pill on hover */}
                        {(isSrcSelected || isTgtSelected || isBlastFlow) && (
                          <rect
                            x={midX - 28}
                            y={midY - 9}
                            width="56"
                            height="18"
                            fill="var(--surface)"
                            stroke={strokeColor}
                            strokeWidth="1"
                          />
                        )}
                        {(isSrcSelected || isTgtSelected || isBlastFlow) && (
                          <text
                            x={midX}
                            y={midY + 3}
                            textAnchor="middle"
                            fontFamily="monospace"
                            fontSize="9"
                            fill={strokeColor}
                            fontWeight="bold"
                          >
                            depends
                          </text>
                        )}
                      </g>
                    );
                  })}
                </g>

                {/* Nodes */}
                <g className="nodes">
                  {visibleNodes.map((node) => {
                    const pos = nodePositions[node.id];
                    if (!pos) return null;

                    const isSelected = node.id === selectedServiceId;
                    const isHovered = node.id === hoveredNode;
                    const isBlastImpacted = blastAffectedIds.has(node.id) && !isSelected;
                    const isCriticalPath = graphData?.critical_path.includes(node.name);

                    // Box dimensions
                    const width = 160;
                    const height = 72;
                    const x = pos.x - width / 2;
                    const y = pos.y - height / 2;

                    // Border & fill colors
                    let borderColor = 'var(--border)';
                    let bgColor = 'var(--surface)';
                    let badgeBg = 'var(--surface-raised)';
                    let badgeColor = 'var(--text-secondary)';

                    if (isSelected) {
                      borderColor = 'var(--accent)';
                      bgColor = '#fff5f2';
                      badgeBg = 'var(--accent)';
                      badgeColor = '#ffffff';
                    } else if (isBlastImpacted) {
                      borderColor = '#f59e0b';
                      bgColor = '#fefce8';
                      badgeBg = '#f59e0b';
                      badgeColor = '#ffffff';
                    } else if (node.max_risk_score > 60) {
                      borderColor = '#ef4444';
                    } else if (node.max_risk_score === 0) {
                      borderColor = '#10b981';
                    }

                    return (
                      <g
                        key={`node-${node.id}`}
                        onClick={() => setSelectedServiceId(node.id)}
                        onMouseEnter={() => setHoveredNode(node.id)}
                        onMouseLeave={() => setHoveredNode(null)}
                        className="cursor-pointer transition-transform duration-200"
                        style={{
                          transformOrigin: `${pos.x}px ${pos.y}px`,
                          transform: isHovered || isSelected ? 'scale(1.04)' : 'scale(1)',
                        }}
                      >
                        {/* Shadow box */}
                        <rect
                          x={x + 3}
                          y={y + 3}
                          width={width}
                          height={height}
                          fill="rgba(17, 17, 17, 0.12)"
                        />

                        {/* Main Node Card */}
                        <rect
                          x={x}
                          y={y}
                          width={width}
                          height={height}
                          fill={bgColor}
                          stroke={borderColor}
                          strokeWidth={isSelected ? '2.5' : isBlastImpacted ? '2' : '1.5'}
                        />

                        {/* Top Indicator Strip */}
                        <rect
                          x={x}
                          y={y}
                          width={width}
                          height="4"
                          fill={
                            isSelected
                              ? 'var(--accent)'
                              : isBlastImpacted
                              ? '#f59e0b'
                              : node.max_risk_score > 60
                              ? '#ef4444'
                              : '#10b981'
                          }
                        />

                        {/* Criticality Pill */}
                        <rect
                          x={x + 8}
                          y={y + 10}
                          width="24"
                          height="16"
                          fill={badgeBg}
                        />
                        <text
                          x={x + 20}
                          y={y + 21}
                          textAnchor="middle"
                          fontFamily="monospace"
                          fontSize="9"
                          fontWeight="bold"
                          fill={badgeColor}
                        >
                          {node.criticality}
                        </text>

                        {/* MWQRS Score Badge */}
                        <text
                          x={x + width - 10}
                          y={y + 22}
                          textAnchor="end"
                          fontFamily="monospace"
                          fontSize="10"
                          fontWeight="bold"
                          fill={node.max_risk_score > 60 ? '#b91c1c' : node.max_risk_score > 25 ? '#b45309' : '#047857'}
                        >
                          {node.max_risk_score.toFixed(1)}
                        </text>

                        {/* Service Name */}
                        <text
                          x={x + 10}
                          y={y + 44}
                          fontFamily="Syne, sans-serif"
                          fontSize="12"
                          fontWeight="bold"
                          fill="var(--text-primary)"
                        >
                          {node.name.length > 18 ? node.name.slice(0, 16) + '..' : node.name}
                        </text>

                        {/* Subtext info */}
                        <text
                          x={x + 10}
                          y={y + 60}
                          fontFamily="monospace"
                          fontSize="9"
                          fill="var(--text-muted)"
                        >
                          {node.asset_count} asset{node.asset_count !== 1 ? 's' : ''} • deg:{node.in_degree + node.out_degree}
                          {isCriticalPath ? ' • [CP]' : ''}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}
          </div>

          {/* Bottom Critical Path Bar */}
          {graphData && (
            <div className="border-t border-[var(--border)] p-3 bg-[var(--surface)] flex items-center justify-between text-xs font-mono">
              <span className="text-[var(--text-muted)] uppercase tracking-wider">
                Critical Dependency Path ({graphData.critical_path.length} hops):
              </span>
              <div className="flex items-center gap-1.5 overflow-x-auto text-[var(--text-primary)] font-bold">
                {graphData.critical_path.map((step, idx) => (
                  <React.Fragment key={step}>
                    <span className="px-2 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)]">
                      {step}
                    </span>
                    {idx < graphData.critical_path.length - 1 && (
                      <span className="text-[var(--accent)] font-bold">→</span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Blast Radius & Service Detail Drawer */}
        <div className="lg:col-span-4 border border-[var(--border)] bg-[var(--surface)] flex flex-col">
          <div className="border-b border-[var(--border)] p-4 bg-[var(--surface-raised)] flex items-center justify-between">
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--accent)] font-bold">
                Blast Radius Inspector
              </span>
              <h2 className="font-display text-lg font-bold uppercase text-[var(--text-primary)]">
                {selectedNode ? selectedNode.name : 'Select a Service'}
              </h2>
            </div>
            {selectedNode && (
              <span className="font-mono text-xs px-2 py-1 border border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] font-bold">
                {selectedNode.criticality} TIER
              </span>
            )}
          </div>

          {blastLoading ? (
            <div className="p-8 text-center font-mono text-xs text-[var(--text-muted)]">
              Computing topological blast radius reachability...
            </div>
          ) : blastRadius ? (
            <div className="p-5 space-y-5 overflow-y-auto max-h-[580px]">
              {/* Severity Gauge */}
              <div className="border border-[var(--border)] p-4 bg-[var(--surface-raised)]">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs uppercase text-[var(--text-muted)]">
                    Blast Radius Exposure
                  </span>
                  <span
                    className={`font-mono text-xs px-2 py-0.5 font-bold uppercase ${
                      blastRadius.severity === 'High'
                        ? 'bg-[#fee2e2] text-[#b91c1c] border border-[#ef4444]'
                        : blastRadius.severity === 'Medium'
                        ? 'bg-[#fef3c7] text-[#b45309] border border-[#f59e0b]'
                        : 'bg-[#ecfdf5] text-[#047857] border border-[#10b981]'
                    }`}
                  >
                    {blastRadius.severity} Severity
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mt-4 pt-3 border-t border-[var(--border)] text-center">
                  <div>
                    <div className="font-display text-2xl font-bold text-[var(--text-primary)]">
                      {blastRadius.blast_radius_count}
                    </div>
                    <div className="font-mono text-[10px] uppercase text-[var(--text-muted)] mt-0.5">
                      Services Impacted
                    </div>
                  </div>
                  <div>
                    <div className="font-display text-2xl font-bold text-[var(--accent)]">
                      {blastRadius.cumulative_risk_score.toFixed(1)}
                    </div>
                    <div className="font-mono text-[10px] uppercase text-[var(--text-muted)] mt-0.5">
                      Cumulative MWQRS
                    </div>
                  </div>
                </div>
              </div>

              {/* Description */}
              {selectedNode?.description && (
                <div className="text-xs text-[var(--text-secondary)] border-l-2 border-[var(--border)] pl-3 py-1">
                  {selectedNode.description}
                </div>
              )}

              {/* Downstream Dependent Services */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-mono text-xs uppercase tracking-wider font-bold text-[var(--text-primary)]">
                    Downstream Dependents ({blastRadius.dependent_count})
                  </h3>
                  <span className="font-mono text-[10px] text-[var(--text-muted)]">
                    Direct & Transitive
                  </span>
                </div>

                {blastRadius.dependent_services.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)] font-mono italic p-3 border border-[var(--border)] bg-[var(--surface-raised)]">
                    No downstream services depend on this endpoint (Leaf Node).
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {blastRadius.dependent_services.map((dep) => (
                      <div
                        key={dep.id}
                        className="p-2.5 border border-[var(--border)] bg-[var(--surface)] flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span
                            className={`w-2 h-2 ${
                              dep.is_direct ? 'bg-[var(--accent)]' : 'bg-[#f59e0b]'
                            }`}
                          />
                          <span className="font-bold text-[var(--text-primary)]">
                            {dep.name}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 font-mono text-[10px]">
                          <span className="px-1.5 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)]">
                            {dep.criticality}
                          </span>
                          <span className="text-[var(--text-muted)]">
                            {dep.is_direct ? 'Direct' : 'Transitive'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Upstream Dependencies */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-mono text-xs uppercase tracking-wider font-bold text-[var(--text-primary)]">
                    Upstream Dependencies ({blastRadius.upstream_count})
                  </h3>
                  <span className="font-mono text-[10px] text-[var(--text-muted)]">
                    Services Needed
                  </span>
                </div>

                {blastRadius.upstream_services.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)] font-mono italic p-3 border border-[var(--border)] bg-[var(--surface-raised)]">
                    Autonomous foundation service (No upstream dependencies).
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {blastRadius.upstream_services.map((u) => (
                      <div
                        key={u.id}
                        className="p-2.5 border border-[var(--border)] bg-[var(--surface)] flex items-center justify-between text-xs"
                      >
                        <span className="font-bold text-[var(--text-primary)]">{u.name}</span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 border border-[var(--border)] bg-[var(--surface-raised)]">
                          {u.criticality}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Attached Cryptographic Assets */}
              <div>
                <h3 className="font-mono text-xs uppercase tracking-wider font-bold text-[var(--text-primary)] mb-2">
                  Attached Crypto Assets ({blastRadius.impacted_asset_count})
                </h3>
                <div className="space-y-2">
                  {blastRadius.impacted_assets.map((asset) => (
                    <div
                      key={asset.id}
                      className="p-2.5 border border-[var(--border)] bg-[var(--surface-raised)] text-xs font-mono space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[var(--text-primary)]">
                          {asset.host}:{asset.port}
                        </span>
                        <span
                          className={`font-bold ${
                            asset.risk_score > 60
                              ? 'text-[#b91c1c]'
                              : asset.risk_score > 25
                              ? 'text-[#b45309]'
                              : 'text-[#047857]'
                          }`}
                        >
                          {asset.risk_score.toFixed(1)} MWQRS
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-[var(--text-muted)]">
                        <span>{asset.cert_key_type}</span>
                        <span className="italic">{asset.service_name}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center font-mono text-xs text-[var(--text-muted)]">
              Click any service node on the canvas to inspect its cryptographic blast radius.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
