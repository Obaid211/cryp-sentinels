import { useState, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { ExecutiveDashboard } from './components/ExecutiveDashboard';
import { CryptoAssetInventory } from './components/CryptoAssetInventory';
import { RemediationCenter } from './components/RemediationCenter';
import { ThreatTimeline } from './components/ThreatTimeline';
import { ComplianceReadiness } from './components/ComplianceReadiness';
import { CbomStudio } from './components/CbomStudio';
import { DependencyGraph } from './components/DependencyGraph';
import { PqcSimulator } from './components/PqcSimulator';
import { ScannerSuite } from './components/ScannerSuite';
import { ScanHistoryDiff } from './components/ScanHistoryDiff';
import { CryptographicAssistant } from './components/CryptographicAssistant';
import { TourWizard } from './components/TourWizard';
import { ErrorBoundary } from './components/ErrorBoundary';
import type { DashboardData } from './components/ExecutiveDashboard';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('landing');
  const [mode, setMode] = useState<'LIVE' | 'CACHED' | 'OFFLINE'>('LIVE');
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isTourOpen, setIsTourOpen] = useState<boolean>(false);

  const fetchDashboardData = useCallback(async (currentMode: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/dashboard/summary?mode=${currentMode}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} failed to fetch dashboard summary`);
      }
      const data: DashboardData = await response.json();
      setDashboardData(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown network failure';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleSelectTab = (tab: string) => {
    setCurrentTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (tab === 'dashboard') {
      void fetchDashboardData(mode);
    }
  };

  const handleModeChange = (newMode: 'LIVE' | 'CACHED' | 'OFFLINE') => {
    setMode(newMode);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    showToast(`✓ Switched operational mode to ${newMode}`);
    if (currentTab === 'dashboard') {
      void fetchDashboardData(newMode);
    }
  };

  const handleRefreshData = async () => {
    try {
      await fetch('http://127.0.0.1:8000/api/score/recalculate', { method: 'POST' });
      showToast('✓ MWQRS scores recalculated across all assets!');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      if (currentTab === 'dashboard') {
        void fetchDashboardData(mode);
      }
    } catch (err) {
      console.error('Failed to recalculate:', err);
      showToast('⚠️ Failed to recalculate scores.');
    }
  };

  const handleSeedDemo = async () => {
    try {
      await fetch('http://127.0.0.1:8000/api/demo/seed', { method: 'POST' });
      showToast('✓ Demo services and topological dependencies re-seeded!');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      if (currentTab === 'dashboard') {
        void fetchDashboardData(mode);
      }
    } catch (err) {
      console.error('Failed to seed demo:', err);
      showToast('⚠️ Failed to re-seed demo data.');
    }
  };

  const handleDownloadReport = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    window.open('/DETAILED_TEST_REPORT.md', '_blank');
  };

  return (
    <div className="min-h-screen bg-surface flex flex-col selection:bg-primary selection:text-white">
      <Navbar
        currentTab={currentTab}
        onSelectTab={handleSelectTab}
        mode={mode}
        onModeChange={handleModeChange}
        onRefreshData={handleRefreshData}
        onSeedDemo={handleSeedDemo}
        onDownloadReport={handleDownloadReport}
        onStartTour={() => setIsTourOpen(true)}
      />

      {mode === 'CACHED' && (
        <div className="w-full bg-amber-500/10 border-b border-amber-500/30 px-4 sm:px-6 py-2 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-amber-800">
          <div className="flex items-center gap-2">
            <span className="inline-block h-2 w-2 bg-amber-500 animate-pulse" />
            <span className="font-bold uppercase tracking-wider">⚡ CACHED OPERATIONAL MODE:</span>
            <span className="hidden sm:inline">Serving instant in-memory & local snapshot state (sub-millisecond latency, zero external network overhead).</span>
          </div>
          <button 
            onClick={() => handleModeChange('LIVE')}
            className="px-2 py-0.5 border border-amber-700 bg-amber-600 text-white font-bold text-[10px] uppercase hover:bg-amber-700 transition-colors"
          >
            Switch to LIVE
          </button>
        </div>
      )}

      {mode === 'OFFLINE' && (
        <div className="w-full bg-blue-500/10 border-b border-blue-500/30 px-4 sm:px-6 py-2 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-blue-900">
          <div className="flex items-center gap-2">
            <span className="inline-block h-2 w-2 bg-blue-600" />
            <span className="font-bold uppercase tracking-wider">🔒 AIR-GAPPED OFFLINE MODE:</span>
            <span className="hidden sm:inline">All outbound network sockets & external AI APIs blocked. Sovereign local intelligence & air-gapped simulation active.</span>
          </div>
          <button 
            onClick={() => handleModeChange('LIVE')}
            className="px-2 py-0.5 border border-blue-800 bg-blue-700 text-white font-bold text-[10px] uppercase hover:bg-blue-800 transition-colors"
          >
            Switch to LIVE
          </button>
        </div>
      )}

      <ErrorBoundary>
        <main className="flex-1">
          {currentTab === 'landing' ? (
            <LandingPage onExplore={(targetTab) => handleSelectTab(targetTab)} />
          ) : currentTab === 'dashboard' ? (
            <ExecutiveDashboard
              data={dashboardData}
              loading={loading}
              error={error}
              onNavigateToAsset={(host, port) => {
                console.log(`Navigate to asset ${host}:${port}`);
                handleSelectTab('inventory');
              }}
            />
          ) : currentTab === 'inventory' ? (
            <CryptoAssetInventory />
          ) : currentTab === 'remediation' ? (
            <RemediationCenter />
          ) : currentTab === 'threat-timeline' ? (
            <ThreatTimeline />
          ) : currentTab === 'dependency-graph' ? (
            <div className="mx-auto max-w-7xl p-8">
              <DependencyGraph />
            </div>
          ) : currentTab === 'pqc-simulator' ? (
            <div className="mx-auto max-w-7xl p-8">
              <PqcSimulator />
            </div>
          ) : currentTab === 'scanners' ? (
            <div className="mx-auto max-w-7xl p-8">
              <ScannerSuite mode={mode} />
            </div>
          ) : currentTab === 'history-diff' ? (
            <div className="mx-auto max-w-7xl p-8">
              <ScanHistoryDiff />
            </div>
          ) : currentTab === 'assistant' ? (
            <div className="mx-auto max-w-7xl p-8">
              <CryptographicAssistant mode={mode} />
            </div>
          ) : currentTab === 'compliance' ? (
            <ComplianceReadiness />
          ) : currentTab === 'cbom-studio' ? (
            <CbomStudio />
          ) : (
            <div className="mx-auto max-w-7xl p-8">
              <div className="border border-secondary bg-white p-8 shadow-flat">
                <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-4">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-widest text-primary font-bold">
                      ROUTE: /{currentTab}
                    </span>
                    <h2 className="font-display text-2xl font-bold uppercase text-secondary mt-1">
                      {currentTab.replace('-', ' ')}
                    </h2>
                  </div>
                  <button
                    onClick={() => handleSelectTab('landing')}
                    className="px-3 py-1.5 border border-secondary text-xs font-mono uppercase text-secondary hover:bg-secondary hover:text-white transition-colors"
                  >
                    ← Back to Overview
                  </button>
                </div>
              </div>
            </div>
          )}
        </main>
      </ErrorBoundary>

      {/* Guided Tour Wizard Modal */}
      <TourWizard
        isOpen={isTourOpen}
        onClose={() => setIsTourOpen(false)}
        onNavigateToTab={handleSelectTab}
      />

      {/* Floating System Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 border-2 border-secondary bg-white text-secondary px-4 py-3 font-mono text-xs font-bold shadow-flat">
          <span className="h-2.5 w-2.5 bg-primary animate-pulse inline-block" />
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}

export default App;

