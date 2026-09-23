import { 
  AlertTriangle, 
  ShieldAlert, 
  TrendingUp,
  Server
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
  };
  public_scan_stats: {
    hosts_attempted: number;
    hosts_scanned: number;
    hosts_unreachable: number;
    quantum_vulnerable_percent: number;
  };
  risk_distribution: Array<{
    name: string;
    value: number;
    color: string;
  }>;
  key_type_breakdown: Array<{
    key_type: string;
    count: number;
  }>;
  top_vulnerable_assets: Array<{
    id: number;
    host: string;
    port: number;
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

interface ExecutiveDashboardProps {
  data: DashboardData | null;
  loading: boolean;
  error: string | null;
  onNavigateToAsset?: (host: string, port: number) => void;
}

export const ExecutiveDashboard = ({
  data,
  loading,
  error,
  onNavigateToAsset,
}: ExecutiveDashboardProps) => {
  if (loading) {
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
        </div>
      </div>
    );
  }

  const { kpis, public_scan_stats, risk_distribution, key_type_breakdown, top_vulnerable_assets } = data;

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

      {/* Top Vulnerable Cryptographic Assets Table */}
      <div className="border border-secondary bg-white p-6 shadow-flat">
        <div className="border-b border-[#e5e5e5] pb-4 flex items-center justify-between">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-primary font-bold">
              CRITICAL VULNERABILITY QUEUE
            </div>
            <h3 className="mt-0.5 font-display text-lg font-bold uppercase text-secondary">
              Top Vulnerable Cryptographic Assets
            </h3>
          </div>
          <span className="font-mono text-xs text-tertiary uppercase">
            RANKED BY MWQRS
          </span>
        </div>

        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-secondary bg-[#faf9f5] text-tertiary">
                <th className="py-2.5 px-3">ENDPOINT</th>
                <th className="py-2.5 px-3">SERVICE</th>
                <th className="py-2.5 px-3">TIER</th>
                <th className="py-2.5 px-3">KEY SPECS</th>
                <th className="py-2.5 px-3">TLS</th>
                <th className="py-2.5 px-3">EXPIRY</th>
                <th className="py-2.5 px-3 text-right">MWQRS SCORE</th>
              </tr>
            </thead>
            <tbody>
              {top_vulnerable_assets.map((asset) => (
                <tr 
                  key={asset.id} 
                  onClick={() => onNavigateToAsset && onNavigateToAsset(asset.host, asset.port)}
                  className="border-b border-[#eeeeea] hover:bg-[#faf9f5] cursor-pointer transition-colors"
                >
                  <td className="py-3 px-3 font-bold text-secondary">
                    {asset.host}:{asset.port}
                  </td>
                  <td className="py-3 px-3 text-secondary">
                    {asset.service_name}
                  </td>
                  <td className="py-3 px-3">
                    <span className="border border-[#e5e5e5] bg-white px-2 py-0.5 font-bold text-secondary">
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-tertiary">
                    {asset.cert_key_type} {asset.cert_key_size_bits}b
                  </td>
                  <td className="py-3 px-3 text-tertiary">
                    {asset.tls_version}
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
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
