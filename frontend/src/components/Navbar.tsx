import { useRef, useState, useEffect, useCallback } from 'react';
import { 
  Shield, 
  Cpu, 
  Network, 
  Activity, 
  Lock, 
  Zap, 
  Database,
  Search,
  FileCode,
  FileCheck2,
  History,
  Bot,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  LogIn
} from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  mode: 'LIVE' | 'CACHED' | 'OFFLINE';
  onModeChange: (mode: 'LIVE' | 'CACHED' | 'OFFLINE') => void;
  onRefreshData?: () => void;
  onSeedDemo?: () => void;
  onDownloadReport?: () => void;
  onStartTour?: () => void;
  isLoggedIn?: boolean;
  userEmail?: string | null;
  onLogin?: () => void;
}

export const Navbar = ({
  currentTab,
  onSelectTab,
  mode,
  onModeChange,
  onRefreshData,
  onSeedDemo,
  onDownloadReport,
  onStartTour,
  isLoggedIn = false,
  userEmail,
  onLogin,
}: NavbarProps) => {
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const navItems = [
    { id: 'landing', label: 'Overview', icon: Shield },
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'inventory', label: 'Inventory', icon: Database },
    { id: 'remediation', label: 'Remediation', icon: Zap },
    { id: 'threat-timeline', label: 'Timeline', icon: Lock },
    { id: 'dependency-graph', label: 'Graph', icon: Network },
    { id: 'pqc-simulator', label: 'Simulator', icon: Cpu },
    { id: 'scanners', label: 'Scanners', icon: Search },
    { id: 'cbom-studio', label: 'CBOM', icon: FileCode },
    { id: 'compliance', label: 'Compliance', icon: FileCheck2 },
    { id: 'history-diff', label: 'Diff', icon: History },
    { id: 'assistant', label: 'Advisor', icon: Bot },
  ];

  const checkScroll = useCallback(() => {
    const el = scrollContainerRef.current;
    if (el) {
      setCanScrollLeft(el.scrollLeft > 6);
      setCanScrollRight(el.scrollLeft < el.scrollWidth - el.clientWidth - 6);
    }
  }, []);

  useEffect(() => {
    checkScroll();
    window.addEventListener('resize', checkScroll);
    return () => window.removeEventListener('resize', checkScroll);
  }, [checkScroll]);

  // Center/scroll active tab into view whenever currentTab changes
  useEffect(() => {
    const el = scrollContainerRef.current;
    if (el) {
      const activeEl = el.querySelector<HTMLElement>('[data-active="true"]');
      if (activeEl) {
        activeEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
      }
    }
    checkScroll();
  }, [currentTab, checkScroll]);

  const scroll = (direction: 'left' | 'right') => {
    const el = scrollContainerRef.current;
    if (el) {
      const scrollAmount = 260;
      el.scrollBy({ left: direction === 'left' ? -scrollAmount : scrollAmount, behavior: 'smooth' });
      setTimeout(checkScroll, 300);
    }
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-[#e5e5e5] bg-[#faf9f5]/95 backdrop-blur-sm shadow-sm select-none">
      {/* Row 1: Top Utility Bar */}
      <div className="flex h-8 sm:h-9 w-full items-center justify-between border-b border-[#e5e5e5] px-3 sm:px-6 text-[10px] sm:text-[11px] uppercase tracking-wider font-mono text-tertiary overflow-x-auto no-scrollbar">
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {isLoggedIn && userEmail ? (
            <div className="flex items-center gap-2 border border-emerald-600/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-900">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-600"></span>
              </span>
              <span className="font-semibold lowercase tracking-normal text-[11px] text-emerald-950">
                {userEmail}
              </span>
              <span className="border border-emerald-600/30 bg-white px-1 py-0.2 text-[9px] font-bold text-emerald-700">
                ONLINE
              </span>
            </div>
          ) : (
            <span className="flex items-center gap-1.5 text-secondary font-semibold">
              <span className="inline-block h-1.5 w-1.5 bg-primary animate-pulse" />
              NTRO SIH26164
            </span>
          )}
          <span className="hidden sm:inline text-tertiary">/</span>
          <span className="hidden md:inline text-tertiary">
            {isLoggedIn && userEmail ? 'NTRO SIH26164 · FIPS 203/204/205 PQC SUITE' : 'FIPS 203/204/205 PQC SUITE'}
          </span>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
          {/* Mode Switcher */}
          <div className="flex items-center border border-[#e5e5e5] bg-white p-0.5">
            <button
              onClick={() => onModeChange('LIVE')}
              className={`px-1.5 sm:px-2 py-0.5 text-[9px] sm:text-[10px] font-mono transition-colors ${
                mode === 'LIVE'
                  ? 'bg-secondary text-white font-bold'
                  : 'text-tertiary hover:text-secondary'
              }`}
            >
              LIVE
            </button>
            <button
              onClick={() => onModeChange('CACHED')}
              className={`px-1.5 sm:px-2 py-0.5 text-[9px] sm:text-[10px] font-mono transition-colors ${
                mode === 'CACHED'
                  ? 'bg-amber-600 text-white font-bold'
                  : 'text-tertiary hover:text-secondary'
              }`}
            >
              CACHED
            </button>
            <button
              onClick={() => onModeChange('OFFLINE')}
              className={`px-1.5 sm:px-2 py-0.5 text-[9px] sm:text-[10px] font-mono transition-colors ${
                mode === 'OFFLINE'
                  ? 'bg-blue-600 text-white font-bold'
                  : 'text-tertiary hover:text-secondary'
              }`}
            >
              OFFLINE
            </button>
          </div>

          {/* Quick Actions */}
          {onStartTour && (
            <button
              onClick={onStartTour}
              title="Launch Guided Tour Onboarding"
              className="inline-flex items-center px-1.5 sm:px-2 py-0.5 text-[9px] sm:text-[10px] font-mono border border-primary bg-primary text-white font-bold hover:bg-primary-deep transition-colors"
            >
              ★ TOUR
            </button>
          )}

          {onRefreshData && (
            <button
              onClick={onRefreshData}
              title="Recalculate MWQRS Scores"
              className="hidden lg:inline-flex items-center px-2 py-0.5 text-[10px] font-mono border border-[#e5e5e5] bg-white text-secondary hover:border-primary hover:text-primary transition-colors"
            >
              RECALCULATE
            </button>
          )}

          {onSeedDemo && (
            <button
              onClick={onSeedDemo}
              title="Seed Default Demo Services"
              className="hidden xl:inline-flex items-center px-2 py-0.5 text-[10px] font-mono border border-[#e5e5e5] bg-white text-secondary hover:border-primary hover:text-primary transition-colors"
            >
              RE-SEED
            </button>
          )}

          {onDownloadReport && (
            <button
              onClick={onDownloadReport}
              title="Download Full Report"
              className="hidden sm:inline-flex items-center px-2 py-0.5 text-[10px] font-mono border border-[#e5e5e5] bg-white text-secondary hover:border-secondary transition-colors"
            >
              REPORT .MD
            </button>
          )}

          {/* Auth action: login/logout */}
          {onLogin && (
            <button
              onClick={onLogin}
              title={isLoggedIn ? 'Sign out' : 'Sign in / open login'}
              className={`inline-flex items-center gap-1.5 px-2 sm:px-3 py-1.5 text-[10px] sm:text-xs font-mono border whitespace-nowrap shrink-0 transition-all duration-150 ${
                isLoggedIn
                  ? 'border-[#e5e5e5] bg-white text-secondary hover:border-error hover:text-error'
                  : 'border-primary bg-primary text-white font-bold hover:bg-primary-deep'
              }`}
            >
              <LogIn className="h-3.5 w-3.5" />
              <span className="hidden xs:inline">{isLoggedIn ? 'Sign out' : 'Log in'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Row 2: Brand & Primary Action */}
      <div className="flex h-14 sm:h-16 items-center justify-between px-3 sm:px-6 gap-3">
        {/* Brand / Logo */}
        <div 
          onClick={() => onSelectTab('landing')}
          className="flex cursor-pointer items-center gap-2.5 sm:gap-3 shrink-0 group"
        >
          <div className="flex h-8 w-8 sm:h-9 sm:w-9 items-center justify-center bg-secondary text-white font-bold text-sm border border-secondary shadow-flat-sm group-hover:bg-primary group-hover:border-primary transition-colors">
            E
          </div>
          <div>
            <div className="font-display text-base sm:text-lg font-extrabold tracking-tight text-secondary leading-none">
              ECDAT<span className="text-primary font-normal">.suite</span>
            </div>
            <div className="text-[9px] sm:text-[10px] font-mono uppercase tracking-widest text-tertiary mt-1">
              Cryptographic Discovery
            </div>
          </div>
        </div>

        {/* Right Controls: Console Button (logged-in users only) */}
        {isLoggedIn ? (
          <button
            onClick={() => onSelectTab('dashboard')}
            className="flex items-center gap-1.5 bg-primary px-3 sm:px-4 py-1.5 sm:py-2 text-[11px] sm:text-xs font-bold uppercase tracking-wider text-white hover:bg-primary-deep transition-all shadow-flat-sm hover:-translate-y-0.5"
          >
            <span>Console</span>
            <ArrowUpRight className="h-3.5 w-3.5 sm:h-4 sm:w-4" />
          </button>
        ) : null}
      </div>

      {/* Row 3: Dedicated Full-Width Persistent Navigation Bar (NEVER HIDDEN, ALWAYS VISIBLE ACROSS ALL SCREEN SIZES) */}
      <div className="relative w-full border-t border-[#e5e5e5] bg-white">
        {/* Left scroll chevron button (visible when scrollable to the left) */}
        {canScrollLeft && (
          <button
            onClick={() => scroll('left')}
            aria-label="Scroll navigation left"
            className="absolute left-0 top-0 bottom-0 z-20 flex w-7 items-center justify-center bg-white/95 border-r border-[#e5e5e5] text-secondary hover:text-primary hover:bg-[#faf9f5] transition-colors shadow-sm"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
        )}

        {/* Navigation Scroll Container — Centered Dock in the Middle */}
        <div
          ref={scrollContainerRef}
          onScroll={checkScroll}
          className="w-full overflow-x-auto scroll-smooth no-scrollbar flex justify-start md:justify-center"
        >
          <nav
            aria-label="Cryptographic Discovery Modules"
            className="flex w-max items-center gap-1 sm:gap-1.5 px-3 sm:px-6 py-1.5"
          >
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;

              return (
                <button
                  key={item.id}
                  data-active={isActive}
                  onClick={() => onSelectTab(item.id)}
                  className={`group relative flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 text-[11px] sm:text-xs font-medium uppercase tracking-wider font-mono border whitespace-nowrap shrink-0 transition-all duration-150 hover:-translate-y-0.5 ${
                    isActive
                      ? 'border-secondary bg-secondary text-white font-bold shadow-flat-sm'
                      : 'border-transparent text-secondary hover:border-primary hover:bg-[#faf9f5] hover:text-primary'
                  }`}
                >
                  <Icon className={`h-3.5 w-3.5 shrink-0 transition-colors ${isActive ? 'text-primary' : 'text-primary'}`} />
                  <span>{item.label}</span>
                  {isActive && (
                    <span className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-1.5 h-1.5 bg-primary" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Right scroll chevron button (visible when scrollable to the right) */}
        {canScrollRight && (
          <button
            onClick={() => scroll('right')}
            aria-label="Scroll navigation right"
            className="absolute right-0 top-0 bottom-0 z-20 flex w-7 items-center justify-center bg-white/95 border-l border-[#e5e5e5] text-secondary hover:text-primary hover:bg-[#faf9f5] transition-colors shadow-sm"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        )}
      </div>
    </header>
  );
};
