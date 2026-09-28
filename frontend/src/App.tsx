import { useState, useCallback, useEffect, lazy, Suspense } from 'react';
import { apiFetch } from './lib/api';
import { Navbar } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { ExecutiveDashboard } from './components/ExecutiveDashboard';
import { CryptoAssetInventory } from './components/CryptoAssetInventory';
import { RemediationCenter } from './components/RemediationCenter';
import { ThreatTimeline } from './components/ThreatTimeline';
import { TourWizard } from './components/TourWizard';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoginPage } from './components/LoginPage';
import { createClient, getSession, signOut } from './lib/supabase';
import type { DashboardData } from './components/ExecutiveDashboard';

// Lazy-loaded heavy modules for optimal initial bundle footprint (< 300 kB)
const DependencyGraph = lazy(() => import('./components/DependencyGraph').then(m => ({ default: m.DependencyGraph })));
const PqcSimulator = lazy(() => import('./components/PqcSimulator').then(m => ({ default: m.PqcSimulator })));
const ScannerSuite = lazy(() => import('./components/ScannerSuite').then(m => ({ default: m.ScannerSuite })));
const ScanHistoryDiff = lazy(() => import('./components/ScanHistoryDiff').then(m => ({ default: m.ScanHistoryDiff })));
const CryptographicAssistant = lazy(() => import('./components/CryptographicAssistant').then(m => ({ default: m.CryptographicAssistant })));
const CbomStudio = lazy(() => import('./components/CbomStudio').then(m => ({ default: m.CbomStudio })));
const ComplianceReadiness = lazy(() => import('./components/ComplianceReadiness').then(m => ({ default: m.ComplianceReadiness })));

interface ToastState {
  message: string;
  type: 'info' | 'success' | 'error';
}

const TabFallback = () => (
  <div className="mx-auto max-w-7xl p-12 text-center">
    <div className="border border-[#e5e5e5] bg-white p-8 shadow-flat-sm inline-flex items-center gap-3 font-mono text-xs text-tertiary">
      <div className="h-4 w-4 animate-spin border-2 border-primary border-t-transparent inline-block" />
      <span>Loading module telemetry...</span>
    </div>
  </div>
);

const VALID_TABS = new Set([
  'landing',
  'login',
  'dashboard',
  'inventory',
  'remediation',
  'threat-timeline',
  'pqc-simulator',
  'scanners',
  'graph',
  'diff',
  'assistant',
  'cbom',
  'compliance',
  'cbom-studio',
  'history-diff',
  'dependency-graph',
]);

function getInitialTab(): string {
  if (typeof window === 'undefined') return 'landing';
  const path = window.location.pathname.replace(/^\/+/, '').split('/')[0].toLowerCase();
  const hash = window.location.hash.replace(/^#\/?/, '').split('?')[0].toLowerCase();
  
  if (VALID_TABS.has(path)) return path;
  if (VALID_TABS.has(hash)) return hash;
  return 'landing';
}

function getIntendedTab(): string {
  if (typeof window === 'undefined') return 'dashboard';
  try {
    const params = new URLSearchParams(window.location.search);
    const redirectParam = params.get('redirect')?.toLowerCase();
    if (redirectParam && VALID_TABS.has(redirectParam) && redirectParam !== 'login' && redirectParam !== 'landing') {
      return redirectParam;
    }
    const saved = sessionStorage.getItem('ecdat_intended_tab');
    if (saved && VALID_TABS.has(saved) && saved !== 'login' && saved !== 'landing') {
      sessionStorage.removeItem('ecdat_intended_tab');
      return saved;
    }
  } catch {
    // Ignore
  }
  return 'dashboard';
}

// ---------------------------------------------------------------------------
// Auth-aware routing.
// `isLoggedIn` mirrors the live Supabase session (localStorage-persisted):
//   • Bootstrapped once on mount via getSession().
//   • Kept in sync by supabase.auth.onAuthStateChange, which also catches
//     OAuth returns (Google/GitHub redirect back with a URL hash) and
//     SIGNED_OUT events from any tab.
// The dashboard route is gated so guests are bounced to the login page.
// ---------------------------------------------------------------------------
export function App() {
  const [currentTab, setCurrentTab] = useState<string>(getInitialTab);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [currentUserEmail, setCurrentUserEmail] = useState<string | null>(null);
  const [authChecked, setAuthChecked] = useState<boolean>(false);
  const [mode, setMode] = useState<'LIVE' | 'CACHED' | 'OFFLINE'>('LIVE');
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [isTourOpen, setIsTourOpen] = useState<boolean>(false);

  const showToast = useCallback((message: string, type: 'info' | 'success' | 'error' = 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3500);
  }, []);

  // ---- Live Supabase session bootstrap + subscription ----------------------
  useEffect(() => {
    let cancelled = false;

    const bootstrap = async () => {
      try {
        const session = await getSession();
        if (!cancelled) {
          setIsLoggedIn(Boolean(session?.user));
          setCurrentUserEmail(session?.user?.email ?? null);
        }
      } catch (err) {
        console.error('[App] session bootstrap failed:', err);
      } finally {
        if (!cancelled) setAuthChecked(true);
      }
    };

    void bootstrap();

    // Subscribe to auth changes: OAuth returns, token refreshes, sign-outs.
    const supabase = createClient();
    const { data } = supabase.auth.onAuthStateChange((event, session) => {
      if (cancelled) return;
      const user = session?.user;
      setIsLoggedIn(Boolean(user));
      setCurrentUserEmail(user?.email ?? null);
      if (event === 'SIGNED_IN' && user) {
        showToast(`✓ Welcome, ${user.email ?? 'Operator'}! Identity verified.`, 'success');
        const targetTab = getIntendedTab();
        setCurrentTab((prev) => (prev === 'landing' || prev === 'login' ? targetTab : prev));
        try {
          const newPath = targetTab === 'landing' ? '/' : `/${targetTab}`;
          if (window.location.pathname !== newPath) {
            window.history.pushState(null, '', newPath);
          }
        } catch {
          // Ignore
        }
      }
    });

    return () => {
      cancelled = true;
      const { subscription } = data as { subscription: { unsubscribe: () => void } };
      subscription.unsubscribe();
    };
  }, [showToast]);

  const fetchDashboardData = useCallback(async (currentMode: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiFetch(`/api/dashboard/summary?mode=${currentMode}`);
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

  // Ensure telemetry is automatically loaded when the user enters the dashboard
  useEffect(() => {
    if (currentTab === 'dashboard' && !dashboardData && !loading) {
      // eslint-disable-next-line react/set-state-in-effect
      void fetchDashboardData(mode);
    }
  }, [currentTab, dashboardData, loading, mode, fetchDashboardData]);

  const handleSelectTab = useCallback((tab: string) => {
    if (tab === 'login' && currentTab !== 'landing' && currentTab !== 'login') {
      try {
        sessionStorage.setItem('ecdat_intended_tab', currentTab);
      } catch {
        // Ignore
      }
    }
    setCurrentTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    try {
      const newPath = tab === 'landing' ? '/' : `/${tab}`;
      if (window.location.pathname !== newPath) {
        window.history.pushState(null, '', newPath);
      }
    } catch {
      // Ignore
    }
    if (tab === 'dashboard') {
      void fetchDashboardData(mode);
    }
  }, [currentTab, mode, fetchDashboardData]);

  // Synchronize browser forward / back button navigation
  useEffect(() => {
    const onPopState = () => {
      const tab = getInitialTab();
      setCurrentTab(tab);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const handleModeChange = useCallback((newMode: 'LIVE' | 'CACHED' | 'OFFLINE') => {
    setMode(newMode);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    showToast(`✓ Switched operational mode to ${newMode}`, 'success');
    if (currentTab === 'dashboard') {
      void fetchDashboardData(newMode);
    }
  }, [currentTab, fetchDashboardData, showToast]);

  const handleRefreshData = useCallback(async () => {
    try {
      await apiFetch('/api/score/recalculate', { method: 'POST' });
      showToast('✓ MWQRS scores recalculated across all assets!', 'success');
      if (currentTab === 'dashboard') {
        void fetchDashboardData(mode);
      }
    } catch (err) {
      console.error('Failed to recalculate:', err);
      showToast('⚠️ Failed to recalculate scores.', 'error');
    }
  }, [currentTab, mode, fetchDashboardData, showToast]);

  const handleSeedDemo = useCallback(async () => {
    try {
      await apiFetch('/api/demo/seed', { method: 'POST' });
      showToast('✓ Demo services and topological dependencies re-seeded!', 'success');
      if (currentTab === 'dashboard') {
        void fetchDashboardData(mode);
      }
    } catch (err) {
      console.error('Failed to seed demo:', err);
      showToast('⚠️ Failed to re-seed demo data.', 'error');
    }
  }, [currentTab, mode, fetchDashboardData, showToast]);

  const handleDownloadReport = useCallback(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    window.open('/DETAILED_TEST_REPORT.md', '_blank');
  }, []);

  // ---- Navbar auth action: log in (open portal) or sign out ----------------
  const handleAuthAction = useCallback(async () => {
    if (isLoggedIn) {
      const result = await signOut();
      if (result.success) {
        setIsLoggedIn(false);
        setCurrentUserEmail(null);
        showToast('✓ Signed out. Session cleared.', 'info');
        if (currentTab === 'dashboard') setCurrentTab('landing');
      } else {
        showToast('⚠️ Sign-out failed — try again.', 'error');
      }
    } else {
      if (currentTab !== 'landing' && currentTab !== 'login') {
        try {
          sessionStorage.setItem('ecdat_intended_tab', currentTab);
        } catch {
          // Ignore
        }
      }
      setCurrentTab('login');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      try {
        if (window.location.pathname !== '/login') {
          window.history.pushState(null, '', '/login');
        }
      } catch {
        // Ignore
      }
    }
  }, [isLoggedIn, currentTab, showToast]);

  // ---- Fired by LoginPage once a confirmed session exists ------------------
  const handleAuthSuccess = useCallback((email?: string) => {
    setIsLoggedIn(true);
    if (email) {
      setCurrentUserEmail(email);
    }
    const targetTab = getIntendedTab();
    setCurrentTab(targetTab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    try {
      const newPath = targetTab === 'landing' ? '/' : `/${targetTab}`;
      if (window.location.pathname !== newPath) {
        window.history.pushState(null, '', newPath);
      }
    } catch {
      // Ignore
    }
    if (targetTab === 'dashboard') {
      void fetchDashboardData(mode);
    }
  }, [mode, fetchDashboardData]);

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
        isLoggedIn={isLoggedIn}
        userEmail={currentUserEmail}
        onLogin={handleAuthAction}
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
          {/* Auth-aware routing: the login page is accessible to everyone;
               the dashboard is gated so guests are redirected there. */}
          {currentTab === 'landing' ? (
            <LandingPage onExplore={(targetTab) => handleSelectTab(targetTab)} />
          ) : currentTab === 'login' ? (
            <LoginPage
              customHeader="Post-Quantum Identity Portal"
              onAuthSuccess={handleAuthSuccess}
            />
          ) : currentTab === 'dashboard' ? (
            isLoggedIn ? (
              <ExecutiveDashboard
                data={dashboardData}
                loading={loading}
                error={error}
                onRetry={() => void fetchDashboardData(mode)}
                onNavigateToAsset={(host, port) => {
                  console.log(`Navigate to asset ${host}:${port}`);
                  handleSelectTab('inventory');
                }}
              />
            ) : (
              <div className="mx-auto max-w-7xl p-8 text-center">
                <div className="border border-[#e5e5e5] bg-white p-12 shadow-flat-sm">
                  <div className="flex flex-col items-center justify-center gap-4">
                    <div className="flex h-12 w-12 items-center justify-center rounded-none bg-[#faf9f5] border border-[#e5e5e5] text-2xl font-bold text-tertiary">
                      <span style={{ fontFamily: "'Syne', sans-serif" }}>E</span>
                    </div>
                    <h2 className="font-display text-2xl font-bold uppercase text-secondary">
                      Authenticated access required
                    </h2>
                    <p style={{ color: 'var(--text-tertiary)', margin: 0 }}>
                      {authChecked
                        ? 'Please sign in to continue.'
                        : 'Restoring your session…'}
                    </p>
                    <button
                      onClick={() => {
                        try {
                          sessionStorage.setItem('ecdat_intended_tab', 'dashboard');
                        } catch {
                          // Ignore
                        }
                        handleSelectTab('login');
                      }}
                      style={{
                        padding: '10px 16px',
                        borderRadius: 0,
                        border: '1px solid var(--accent)',
                        background: 'var(--accent)',
                        color: 'var(--on-primary)',
                        fontFamily: 'Geist Mono, monospace',
                        fontSize: '12px',
                        cursor: 'pointer',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                      }}
                    >
                      Open Login
                    </button>
                  </div>
                </div>
              </div>
            )
          ) : currentTab === 'inventory' ? (
            <CryptoAssetInventory />
          ) : currentTab === 'remediation' ? (
            <RemediationCenter />
          ) : currentTab === 'threat-timeline' ? (
            <ThreatTimeline />
          ) : currentTab === 'dependency-graph' ? (
            <Suspense fallback={<TabFallback />}>
              <div className="mx-auto max-w-7xl p-8">
                <DependencyGraph />
              </div>
            </Suspense>
          ) : currentTab === 'pqc-simulator' ? (
            <Suspense fallback={<TabFallback />}>
              <div className="mx-auto max-w-7xl p-8">
                <PqcSimulator />
              </div>
            </Suspense>
          ) : currentTab === 'scanners' ? (
            <Suspense fallback={<TabFallback />}>
              <div className="mx-auto max-w-7xl p-8">
                <ScannerSuite mode={mode} />
              </div>
            </Suspense>
          ) : currentTab === 'history-diff' ? (
            <Suspense fallback={<TabFallback />}>
              <div className="mx-auto max-w-7xl p-8">
                <ScanHistoryDiff />
              </div>
            </Suspense>
          ) : currentTab === 'assistant' ? (
            <Suspense fallback={<TabFallback />}>
              <div className="mx-auto max-w-7xl p-8">
                <CryptographicAssistant mode={mode} />
              </div>
            </Suspense>
          ) : currentTab === 'compliance' ? (
            <Suspense fallback={<TabFallback />}>
              <ComplianceReadiness />
            </Suspense>
          ) : currentTab === 'cbom-studio' ? (
            <Suspense fallback={<TabFallback />}>
              <CbomStudio />
            </Suspense>
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
      {toast && (
        <div className={`fixed bottom-6 right-6 z-50 flex items-center gap-2.5 border-2 bg-white px-4 py-3 font-mono text-xs font-bold shadow-flat ${
          toast.type === 'success' ? 'border-severity-safe text-secondary' :
          toast.type === 'error' ? 'border-severity-critical text-secondary' :
          'border-secondary text-secondary'
        }`}>
          <span className={`h-2.5 w-2.5 inline-block ${
            toast.type === 'success' ? 'bg-severity-safe' :
            toast.type === 'error' ? 'bg-severity-critical animate-pulse' :
            'bg-primary animate-pulse'
          }`} />
          <span>{toast.message}</span>
        </div>
      )}

      {/* Floating Network Error Banner */}
      {error && !toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 border-2 border-severity-critical bg-white text-secondary px-4 py-3 font-mono text-xs font-bold shadow-flat">
          <span className="h-2.5 w-2.5 bg-severity-critical animate-pulse inline-block" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

export default App;
