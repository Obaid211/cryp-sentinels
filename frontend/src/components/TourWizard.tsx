import React, { useState } from 'react';

interface TourStep {
  title: string;
  badge: string;
  description: string;
  keyHighlights: string[];
  recommendedAction: string;
  targetTab: string;
}

const TOUR_STEPS: TourStep[] = [
  {
    title: 'Executive Posture & MWQRS Scoring',
    badge: 'Step 1 of 5',
    description:
      'ECDAT provides unified sovereign visibility over enterprise cryptographic exposures using Dr. Michele Mosca’s quantum urgency model and the Mosca-Weighted Quantum Risk Score (MWQRS).',
    keyHighlights: [
      '4 core KPI metrics: Endpoint count, Critical risk count, Medium risk count, System average MWQRS',
      'Quantum risk distribution donut & key strength bar charts',
      'Plain-English vulnerability explanations with zero raw mathematical ambiguity'
    ],
    recommendedAction: 'Explore the Executive Dashboard',
    targetTab: 'dashboard'
  },
  {
    title: 'Cryptographic Asset Inventory & CBOM Studio',
    badge: 'Step 2 of 5',
    description:
      'Continuous discovery and cataloging of all TLS endpoints, certificate chains, and cipher suites with instant CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) generation.',
    keyHighlights: [
      'Searchable and filterable asset table with historical audit timelines',
      'NIST FIPS replacement recommendations (ML-KEM-768 / ML-DSA-65)',
      '1-click export of CycloneDX 1.6 CBOM in both JSON and XML specifications'
    ],
    recommendedAction: 'Inspect Crypto Inventory & CBOM',
    targetTab: 'inventory'
  },
  {
    title: 'NetworkX Dependency Graph & Blast Radius',
    badge: 'Step 3 of 5',
    description:
      'Dynamic directed acyclic graph (DAG) mapping microservice interdependencies and calculating cascading blast-radius reachability if an upstream component is compromised.',
    keyHighlights: [
      'Interactive SVG topology canvas with zoom, pan, and critical-path highlighting',
      'Blast Radius Inspector showing downstream service propagation and cumulative MWQRS risk',
      'Independent verification of DAG acyclicity and structural dependencies'
    ],
    recommendedAction: 'View Dependency Graph',
    targetTab: 'dependency-graph'
  },
  {
    title: 'PQC Migration Posture Simulator',
    badge: 'Step 4 of 5',
    description:
      'Simulate transitions across 3 strategic migration trajectories: Hybrid Classical+PQC (RFC 9370), Pure Post-Quantum (FIPS 203/204), or Classical Hardening.',
    keyHighlights: [
      'Side-by-side Before vs After posture delta forecast with critical risk elimination',
      'Engineering effort estimates and person-week projections',
      'Topologically sequenced 3-wave migration roadmap ensuring zero service disruption'
    ],
    recommendedAction: 'Launch PQC Simulator',
    targetTab: 'pqc-simulator'
  },
  {
    title: 'Multi-Vector Cryptographic Scanner Suite',
    badge: 'Step 5 of 5',
    description:
      'Real-time automated scanning across live TLS network endpoints, source code AST primitives, container Dockerfiles, and API JWT tokens with live SSE telemetry streaming.',
    keyHighlights: [
      'Live TLS handshake probing with automatic inventory commitment',
      'AST-based detection of broken hashing (MD5), legacy ciphers (DES), and embedded private keys',
      'API gateway JWT signature analysis for quantum vulnerabilities'
    ],
    recommendedAction: 'Try Cryptographic Scanners',
    targetTab: 'scanners'
  }
];

interface TourWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateToTab: (tab: string) => void;
}

export const TourWizard: React.FC<TourWizardProps> = ({ isOpen, onClose, onNavigateToTab }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  if (!isOpen) return null;

  const currentStep = TOUR_STEPS[currentStepIndex];

  const handleNext = () => {
    if (currentStepIndex < TOUR_STEPS.length - 1) {
      setCurrentStepIndex((prev) => prev + 1);
    } else {
      onClose();
    }
  };

  const handlePrev = () => {
    if (currentStepIndex > 0) {
      setCurrentStepIndex((prev) => prev - 1);
    }
  };

  const handleAction = () => {
    onNavigateToTab(currentStep.targetTab);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[var(--surface)] border-2 border-[var(--text-primary)] max-w-xl w-full p-6 shadow-[8px_8px_0px_#111111] space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-[var(--accent)] inline-block" />
            <span className="font-mono text-xs uppercase font-bold text-[var(--accent)]">
              ECDAT Guided Tour • {currentStep.badge}
            </span>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 border border-[var(--border)] font-mono text-xs hover:bg-[var(--text-primary)] hover:text-[var(--surface)] font-bold"
          >
            ✕
          </button>
        </div>

        {/* Step Progress Bar */}
        <div className="grid grid-cols-5 gap-1.5">
          {TOUR_STEPS.map((_, idx) => (
            <div
              key={idx}
              className={`h-1.5 transition-all ${
                idx === currentStepIndex
                  ? 'bg-[var(--accent)]'
                  : idx < currentStepIndex
                  ? 'bg-[var(--text-primary)]'
                  : 'bg-[var(--surface-raised)] border border-[var(--border)]'
              }`}
            />
          ))}
        </div>

        {/* Step Content */}
        <div className="space-y-4">
          <h2 className="font-display text-xl font-bold uppercase text-[var(--text-primary)]">
            {currentStep.title}
          </h2>
          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
            {currentStep.description}
          </p>

          <div className="p-4 border border-[var(--border)] bg-[var(--surface-raised)] space-y-2">
            <span className="font-mono text-[10px] uppercase font-bold text-[var(--text-muted)] block">
              Core Architectural Highlights:
            </span>
            <ul className="space-y-1.5 text-xs text-[var(--text-primary)]">
              {currentStep.keyHighlights.map((hl, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-[var(--accent)] font-bold">›</span>
                  <span>{hl}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Actions Footer */}
        <div className="flex items-center justify-between pt-2 border-t border-[var(--border)]">
          <div className="flex gap-2">
            <button
              onClick={handlePrev}
              disabled={currentStepIndex === 0}
              className="px-3 py-1.5 border border-[var(--border)] font-mono text-xs uppercase font-bold disabled:opacity-30 hover:bg-[var(--surface-raised)]"
            >
              ← Prev
            </button>
            <button
              onClick={handleNext}
              className="px-4 py-1.5 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs uppercase font-bold hover:bg-[var(--accent)] transition-colors"
            >
              {currentStepIndex === TOUR_STEPS.length - 1 ? 'Finish Tour' : 'Next →'}
            </button>
          </div>

          <button
            onClick={handleAction}
            className="px-4 py-1.5 border border-[var(--accent)] bg-[#fff7f5] text-[var(--accent)] font-mono text-xs uppercase font-bold hover:bg-[var(--accent)] hover:text-white transition-colors"
          >
            {currentStep.recommendedAction}
          </button>
        </div>
      </div>
    </div>
  );
};
