import { useState } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  TrendingUp,
  Server,
  Search
} from 'lucide-react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip
} from 'recharts';

export interface DashboardData {
  mode: string;
  kpis: {
    total_scanned: number;
    critical_count: number;
    medium_count: number;
    safe_count: number;
    avg_mwqrs: number;
    sources_covered?: number;
  };
  public_scan_stats: {
    hosts_attempted: number;
    hosts_scanned: number;
    hosts_unreachable: number;
    quantum_vulnerable_percent: number;
    tls_assets?: number;
    non_tls_assets?: number;
  };
  risk_distribution: Array<{
    name: string;
    value: number;
    color: string;
  }>;
  sources_breakdown?: Record<string, number>;
  algorithm_breakdown?: Array<{
    algorithm: string;
    count: number;
  }>;
  criticality_distribution?: Array<{
    level: string;
    count: number;
  }>;
  data_lifetime_distribution?: Array<{
    lifetime: string;
    count: number;
  }>;
  key_type_breakdown: Array<{
    key_type: string;
    count: number;
  }>;
  top_vulnerable_assets: Array<{
    id: number;
    host: string;
    port: number;
    source?: string;
    business_criticality?: string;
    data_lifetime?: string;
    algorithm?: string;
    usage_context?: string;
    library?: string;
    file_path?: string;
    service_name: string;
    criticality: string;
    cert_key_type: string;
    cert_key_size_bits: number;
    tls_version: string;
    days_to_expiry: number;
    risk_score: number;
    risk_flags: string[];
  }>;
}

const SOURCE_BADGES: Record<string, { label: string; className: string }> = {
  source_code: { label: 'Source Code', className: 'text-violet-700 bg-violet-50 border-violet-200' },
  dependency: { label: 'Dependency', className: 'text-amber-700 bg-amber-50 border-amber-200' },
  container: { label: 'Container', className: 'text-emerald-700 bg-emerald-50 border-emerald-200' },
  binary: { label: 'Binary', className: 'text-gray-700 bg-gray-50 border-gray-200' },
  hsm: { label: 'Hardware HSM', className: 'text-purple-700 bg-purple-50 border-purple-200' },
  cloud_kms: { label: 'Cloud KMS', className: 'text-sky-700 bg-sky-50 border-sky-200' },
  tls: { label: 'TLS/Network', className: 'text-blue-700 bg-blue-50 border-blue-200' },
};

interface ExecutiveDashboardProps {
  data: DashboardData | null;
  loading: boolean;
  error: string | null;
  onNavigateToAsset?: (host: string, port: number) => void;
  onRetry?: () => void;
}

export const ExecutiveDashboard = ({
  data,
  loading,
  error,
  onNavigateToAsset,
  onRetry,
}: ExecutiveDashboardProps) => {
  const [queueSourceFilter, setQueueSourceFilter] = useState<'all' | 'tls' | 'non_tls'>('all');
  const [queueSearch, setQueueSearch] = useState('');

  if (loading || (!data && !error)) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <div className="border border-[#e5e5e5] bg-white p-12 text-center shadow-flat-sm">
          <div className="inline-block h-6 w-6 animate-spin border-2 border-primary border-t-transparent" />
          <p className="mt-4 font-mono text-xs text-tertiary uppercase tracking-wider">
            Loading cryptographic telemetry & MWQRS scores...
          </p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <div className="border border-severity-critical bg-white p-8 shadow-flat">
          <div className="flex items-center gap-3 text-severity-critical">
            <AlertTriangle className="h-6 w-6" />
            <h3 className="font-display text-lg font-bold uppercase">Telemetrics Pipeline Offline</h3>
          </div>
          <p className="mt-2 font-mono text-xs text-tertiary">
            {error || 'Failed to retrieve dashboard state from /api/dashboard/summary.'}
          </p>
          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-4 inline-flex items-center gap-2 border border-primary bg-primary px-4 py-2 font-mono text-xs font-bold uppercase text-white hover:bg-black transition-colors"
            >
              Retry Connection
            </button>
          )}
        </div>
      </div>
    );
  }

  const { kpis, public_scan_stats, risk_distribution, key_type_breakdown, top_vulnerable_assets } = data;

  const filteredAssets = (top_vulnerable_assets || []).filter((asset) => {
    if (queueSourceFilter === 'tls' && (asset.source || 'tls') !== 'tls') return false;
    if (queueSourceFilter === 'non_tls' && (asset.source || 'tls') === 'tls') return false;
    if (queueSearch) {
      const q = queueSearch.toLowerCase();
      const match = `${asset.host} ${asset.port} ${asset.service_name} ${asset.cert_key_type} ${asset.algorithm} ${asset.source} ${asset.file_path || ''}`.toLowerCase();
      if (!match.includes(q)) return false;
    }
    return true;
  });

  const getScoreBadge = (score: number) => {
    if (score >= 80) {
      return (
        <span className="inline-flex items-center gap-1 border border-severity-critical bg-white px-2 py-0.5 font-mono text-[11px] font-bold text-severity-critical">
          <span className="h-1.5 w-1.5 bg-severity-critical" />
          {score.toFixed(1)} CRITICAL
        </span>
      );
    }
    if (score >= 50) {
      return (
        <span className="inline-flex items-center gap-1 border border-severity-medium bg-white px-2 py-0.5 font-mono text-[11px] font-bold text-severity-medium">
          <span className="h-1.5 w-1.5 bg-severity-medium" />
          {score.toFixed(1)} MEDIUM
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 border border-severity-safe bg-white px-2 py-0.5 font-mono text-[11px] font-bold text-severity-safe">
        <span className="h-1.5 w-1.5 bg-severity-safe" />
        {score.toFixed(1)} SAFE
      </span>
    );
  };

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-[#e5e5e5] pb-6 gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
            <span className="inline-block h-2 w-2 bg-primary" />
            <span>EXECUTIVE DISCOVERY DASHBOARD</span>
            <span>·</span>
            <span>SIH26164 OPERATIONAL POSTURE</span>
          </div>
          <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
            Quantum Risk & Cryptographic Inventory
          </h1>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="border border-[#e5e5e5] bg-white px-3 py-1.5 shadow-flat-sm">
            <span className="text-tertiary">CURRENT MODE:</span>{' '}
            <span className="font-bold text-secondary">{data.mode}</span>
          </div>
          <div className="border border-[#e5e5e5] bg-white px-3 py-1.5 shadow-flat-sm">
            <span className="text-tertiary">MODEL:</span>{' '}
            <span className="font-bold text-primary">MWQRS v2.4</span>
          </div>
        </div>
      </div>

      {/* 4 Top KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* KPI 1 */}
        <div className="border border-[#e5e5e5] bg-white p-6 shadow-flat-sm">
          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-tertiary">
            <span>Total Endpoints</span>
            <Server className="h-4 w-4 text-secondary" />
          </div>
          <div className="mt-3 font-display text-4xl font-extrabold text-secondary">
            {kpis.total_scanned}
          </div>
          <div className="mt-2 text-xs font-mono text-tertiary">
            Public & Sovereign mesh assets
          </div>
        </div>

        {/* KPI 2 */}
        <div className="border border-secondary bg-white p-6 shadow-flat">
          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-severity-critical">
            <span className="font-bold">Critical Risk (≥80)</span>
            <ShieldAlert className="h-4 w-4 text-severity-critical" />
          </div>
          <div className="mt-3 font-display text-4xl font-extrabold text-severity-critical">
            {kpis.critical_count}
          </div>
          <div className="mt-2 text-xs font-mono text-tertiary">
            Harvest-Now-Decrypt-Later target
          </div>
        </div>

        {/* KPI 3 */}
        <div className="border border-[#e5e5e5] bg-white p-6 shadow-flat-sm">
          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-severity-medium">
            <span>Medium Risk (50-79)</span>
            <AlertTriangle className="h-4 w-4 text-severity-medium" />
          </div>
          <div className="mt-3 font-display text-4xl font-extrabold text-severity-medium">
            {kpis.medium_count}
          </div>
          <div className="mt-2 text-xs font-mono text-tertiary">
            Legacy asymmetric cipher usage
          </div>
        </div>

        {/* KPI 4 */}
        <div className="border border-[#e5e5e5] bg-white p-6 shadow-flat-sm">
          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-tertiary">
            <span>System Average MWQRS</span>
            <TrendingUp className="h-4 w-4 text-primary" />
          </div>
          <div className="mt-3 font-display text-4xl font-extrabold text-secondary">
            {kpis.avg_mwqrs}
            <span className="text-base text-tertiary font-normal"> /100</span>
          </div>
          <div className="mt-2 text-xs font-mono text-tertiary">
            Weighted composite risk score
          </div>
        </div>
      </div>

      {/* Aggregate Public Host Scan Statistics Row */}
      <div className="border border-secondary bg-[#ffffff] p-6 shadow-flat-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-primary font-bold">
              AGGREGATE PUBLIC HOST SCAN STATISTICS
            </div>
            <div className="mt-1 font-display text-lg font-bold text-secondary uppercase">
              Host Discovery & Quantum Exposure Profile
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 font-mono text-xs">
            <div className="border-l-2 border-secondary pl-3">
              <div className="text-tertiary">ATTEMPTED</div>
              <div className="mt-0.5 text-base font-bold text-secondary">{public_scan_stats.hosts_attempted}</div>
            </div>
            <div className="border-l-2 border-secondary pl-3">
              <div className="text-tertiary">CONFIRMED</div>
              <div className="mt-0.5 text-base font-bold text-secondary">{public_scan_stats.hosts_scanned}</div>
            </div>
            <div className="border-l-2 border-secondary pl-3">
              <div className="text-tertiary">UNREACHABLE</div>
              <div className="mt-0.5 text-base font-bold text-secondary">{public_scan_stats.hosts_unreachable}</div>
            </div>
            <div className="border-l-2 border-primary pl-3">
              <div className="text-primary font-bold">VULNERABLE %</div>
              <div className="mt-0.5 text-base font-bold text-primary">{public_scan_stats.quantum_vulnerable_percent}%</div>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Source Discovery Pipeline Coverage Strip */}
      {data.sources_breakdown && Object.keys(data.sources_breakdown).length > 0 && (
        <div className="border border-[#e5e5e5] bg-white p-4 shadow-flat-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="font-mono text-[10px] uppercase tracking-widest text-primary font-bold">
              UNIFIED DISCOVERY PIPELINE COVERAGE (7 SOURCES)
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(data.sources_breakdown).map(([src, count]) => {
                const b = SOURCE_BADGES[src] || SOURCE_BADGES.tls;
                return (
                  <span key={src} className={`border px-2.5 py-1 font-mono text-[11px] font-bold uppercase flex items-center gap-1.5 ${b.className}`}>
                    <span>{b.label}:</span>
                    <span className="font-extrabold">{count}</span>
                  </span>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Two Charts Side-by-Side */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Donut Chart: Quantum Risk Level Distribution */}
        <div className="lg:col-span-6 border border-[#e5e5e5] bg-white p-6 shadow-flat-sm">
          <div className="border-b border-[#e5e5e5] pb-3 flex items-center justify-between">
            <h3 className="font-display text-sm font-bold uppercase text-secondary">
              Quantum Risk Level Distribution
            </h3>
            <span className="font-mono text-[10px] text-tertiary uppercase">MWQRS CLASSIFICATION</span>
          </div>

          <div className="h-64 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={risk_distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {risk_distribution.map((entry, index) => {
                    const fillHex = 
                      entry.name.includes('Critical') ? '#b32100' :
                      entry.name.includes('Medium') ? '#d97706' : '#059669';
                    return <Cell key={`cell-${index}`} fill={fillHex} stroke="#111111" strokeWidth={1} />;
                  })}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#ffffff', 
                    border: '1px solid #111111', 
                    borderRadius: 0,
                    fontFamily: 'Geist Mono',
                    fontSize: '11px'
                  }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 flex flex-wrap justify-center gap-4 text-xs font-mono">
            {risk_distribution.map((item, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <span 
                  className="inline-block h-3 w-3 border border-secondary"
                  style={{
                    backgroundColor: 
                      item.name.includes('Critical') ? '#b32100' :
                      item.name.includes('Medium') ? '#d97706' : '#059669'
                  }}
                />
                <span className="text-secondary font-medium">{item.name}:</span>
                <span className="font-bold text-secondary">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bar Chart: Key Type & Bit Strength Breakdown */}
        <div className="lg:col-span-6 border border-[#e5e5e5] bg-white p-6 shadow-flat-sm">
          <div className="border-b border-[#e5e5e5] pb-3 flex items-center justify-between">
            <h3 className="font-display text-sm font-bold uppercase text-secondary">
              Key Type & Bit Strength Breakdown
            </h3>
            <span className="font-mono text-[10px] text-tertiary uppercase">ALGORITHM DISTRIBUTION</span>
          </div>

          <div className="h-64 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={key_type_breakdown} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                <XAxis 
                  dataKey="key_type" 
                  tick={{ fontSize: 10, fontFamily: 'Geist Mono' }} 
                  interval={0}
                  angle={-15}
                  textAnchor="end"
                />
                <YAxis tick={{ fontSize: 10, fontFamily: 'Geist Mono' }} allowDecimals={false} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#ffffff', 
                    border: '1px solid #111111', 
                    borderRadius: 0,
                    fontFamily: 'Geist Mono',
                    fontSize: '11px'
                  }} 
                />
                <Bar dataKey="count" fill="#ff3300" stroke="#111111" strokeWidth={1} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 text-center text-xs font-mono text-tertiary">
            Identified Asymmetric & Post-Quantum Key Instances
          </div>
        </div>
      </div>

      {/* 3-Column Multi-Source Analytics: Algorithm Families, Mosca Shelf-Life, Business Criticality */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Algorithm Families */}
        <div className="border border-[#e5e5e5] bg-white p-5 shadow-flat-sm">
          <div className="border-b border-[#e5e5e5] pb-2 flex items-center justify-between">
            <h4 className="font-display text-xs font-bold uppercase text-secondary">
              Algorithm Families
            </h4>
            <span className="font-mono text-[9px] text-tertiary uppercase">CRYPTO PRIMITIVES</span>
          </div>
          <div className="mt-3 space-y-2">
            {(data.algorithm_breakdown || []).slice(0, 5).map((item) => (
              <div key={item.algorithm} className="flex items-center justify-between font-mono text-xs">
                <span className="text-secondary font-medium">{item.algorithm}</span>
                <span className="border border-[#e5e5e5] bg-[#faf9f5] px-2 py-0.5 font-bold text-secondary text-[11px]">
                  {item.count}
                </span>
              </div>
            ))}
            {(!data.algorithm_breakdown || data.algorithm_breakdown.length === 0) && (
              <div className="text-xs font-mono text-tertiary">No algorithm distribution recorded.</div>
            )}
          </div>
        </div>

        {/* Mosca Data Shelf-Life */}
        <div className="border border-[#e5e5e5] bg-white p-5 shadow-flat-sm">
          <div className="border-b border-[#e5e5e5] pb-2 flex items-center justify-between">
            <h4 className="font-display text-xs font-bold uppercase text-secondary">
              Data Lifetime (Mosca Urgency)
            </h4>
            <span className="font-mono text-[9px] text-tertiary uppercase">SHELF-LIFE (X)</span>
          </div>
          <div className="mt-3 space-y-2">
            {(data.data_lifetime_distribution || []).map((item) => (
              <div key={item.lifetime} className="flex items-center justify-between font-mono text-xs">
                <span className="text-secondary font-medium">{item.lifetime} retention</span>
                <span className={`border px-2 py-0.5 font-bold text-[11px] ${
                  item.lifetime === '>10y' || item.lifetime === '5-10y'
                    ? 'border-severity-critical/40 bg-red-50 text-severity-critical'
                    : 'border-[#e5e5e5] bg-[#faf9f5] text-secondary'
                }`}>
                  {item.count}
                </span>
              </div>
            ))}
            {(!data.data_lifetime_distribution || data.data_lifetime_distribution.length === 0) && (
              <div className="text-xs font-mono text-tertiary">No data lifetime distribution recorded.</div>
            )}
          </div>
        </div>

        {/* Business Criticality Distribution */}
        <div className="border border-[#e5e5e5] bg-white p-5 shadow-flat-sm">
          <div className="border-b border-[#e5e5e5] pb-2 flex items-center justify-between">
            <h4 className="font-display text-xs font-bold uppercase text-secondary">
              Business Criticality Tiers
            </h4>
            <span className="font-mono text-[9px] text-tertiary uppercase">IMPACT WEIGHT</span>
          </div>
          <div className="mt-3 space-y-2">
            {(data.criticality_distribution || []).map((item) => (
              <div key={item.level} className="flex items-center justify-between font-mono text-xs">
                <span className="text-secondary font-medium uppercase">{item.level}</span>
                <span className={`border px-2 py-0.5 font-bold text-[11px] uppercase ${
                  item.level === 'critical'
                    ? 'border-severity-critical/40 bg-red-50 text-severity-critical'
                    : item.level === 'high'
                    ? 'border-severity-medium/40 bg-amber-50 text-severity-medium'
                    : 'border-[#e5e5e5] bg-[#faf9f5] text-secondary'
                }`}>
                  {item.count}
                </span>
              </div>
            ))}
            {(!data.criticality_distribution || data.criticality_distribution.length === 0) && (
              <div className="text-xs font-mono text-tertiary">No criticality distribution recorded.</div>
            )}
          </div>
        </div>
      </div>

      {/* Top Vulnerable Cryptographic Assets Table */}
      <div className="border border-secondary bg-white p-6 shadow-flat">
        <div className="border-b border-[#e5e5e5] pb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-primary font-bold">
              CRITICAL VULNERABILITY QUEUE
            </div>
            <h3 className="mt-0.5 font-display text-lg font-bold uppercase text-secondary">
              Top Vulnerable Cryptographic Assets
            </h3>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Source Filter Pills */}
            <div className="inline-flex border border-[#e5e5e5] bg-[#faf9f5] p-0.5 font-mono text-[10px]">
              <button
                onClick={() => setQueueSourceFilter('all')}
                className={`px-2 py-1 font-bold transition-colors ${
                  queueSourceFilter === 'all' ? 'bg-secondary text-white' : 'text-tertiary hover:text-secondary'
                }`}
              >
                All ({top_vulnerable_assets.length})
              </button>
              <button
                onClick={() => setQueueSourceFilter('tls')}
                className={`px-2 py-1 font-bold transition-colors ${
                  queueSourceFilter === 'tls' ? 'bg-secondary text-white' : 'text-tertiary hover:text-secondary'
                }`}
              >
                TLS / Web ({top_vulnerable_assets.filter(a => (a.source || 'tls') === 'tls').length})
              </button>
              <button
                onClick={() => setQueueSourceFilter('non_tls')}
                className={`px-2 py-1 font-bold transition-colors ${
                  queueSourceFilter === 'non_tls' ? 'bg-secondary text-white' : 'text-tertiary hover:text-secondary'
                }`}
              >
                Non-TLS ({top_vulnerable_assets.filter(a => (a.source || 'tls') !== 'tls').length})
              </button>
            </div>

            {/* Quick Filter Search */}
            <div className="relative">
              <input
                type="text"
                placeholder="Filter target..."
                value={queueSearch}
                onChange={(e) => setQueueSearch(e.target.value)}
                className="w-36 sm:w-44 border border-[#e5e5e5] bg-[#faf9f5] px-2 py-1 pl-6 text-[10px] font-mono outline-none focus:border-primary text-secondary"
              />
              <Search className="h-3 w-3 text-tertiary absolute left-2 top-2 pointer-events-none" />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-secondary bg-[#faf9f5] text-tertiary">
                <th className="py-2.5 px-3">ENDPOINT / TARGET</th>
                <th className="py-2.5 px-3">SOURCE</th>
                <th className="py-2.5 px-3">SERVICE</th>
                <th className="py-2.5 px-3">TIER</th>
                <th className="py-2.5 px-3">KEY SPECS</th>
                <th className="py-2.5 px-3">TLS</th>
                <th className="py-2.5 px-3">EXPIRY</th>
                <th className="py-2.5 px-3 text-right">MWQRS SCORE</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => {
                const badge = SOURCE_BADGES[asset.source || 'tls'] || SOURCE_BADGES.tls;
                const endpointDisplay = asset.port && asset.port > 0 ? `${asset.host}:${asset.port}` : asset.host;
                return (
                  <tr 
                    key={asset.id} 
                    onClick={() => onNavigateToAsset && onNavigateToAsset(asset.host, asset.port)}
                    className="border-b border-[#eeeeea] hover:bg-[#faf9f5] cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3 font-bold text-secondary max-w-[220px]" title={endpointDisplay}>
                      <div className="truncate">{endpointDisplay}</div>
                      {asset.file_path && (
                        <div className="text-[10px] text-tertiary truncate font-normal" title={asset.file_path}>
                          {asset.file_path}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`border px-2 py-0.5 font-bold text-[10px] uppercase ${badge.className}`}>
                        {badge.label}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-secondary">
                      <div>{asset.service_name}</div>
                      {asset.usage_context && (
                        <div className="text-[10px] text-tertiary truncate">
                          {asset.usage_context}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-secondary">
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-tertiary">
                      {asset.cert_key_type} {asset.cert_key_size_bits ? `${asset.cert_key_size_bits}b` : ''}
                    </td>
                    <td className="py-3 px-3 text-tertiary">
                      {asset.tls_version || 'N/A'}
                    </td>
                    <td className="py-3 px-3">
                      <span className={asset.days_to_expiry <= 30 ? 'text-severity-critical font-bold' : 'text-tertiary'}>
                        {asset.days_to_expiry} days
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      {getScoreBadge(asset.risk_score)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
