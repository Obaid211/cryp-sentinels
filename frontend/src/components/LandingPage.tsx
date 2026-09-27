import { 
  Shield, 
  Cpu, 
  Network, 
  Lock, 
  ArrowRight
} from 'lucide-react';

interface LandingPageProps {
  onExplore: (targetTab: string) => void;
}

export const LandingPage = ({ onExplore }: LandingPageProps) => {
  return (
    <div className="min-h-screen bg-[#faf9f5] text-secondary">
      {/* Hero Section — Architectural Constructivism */}
      <section className="relative border-b border-[#e5e5e5] px-6 py-16 sm:py-20 lg:px-12 xl:px-16 lg:py-24" style={{isolation: 'isolate'}}>
        <div className="mx-auto max-w-[1500px]">
          {/* Tagline Badge */}
          <div className="inline-flex items-center gap-2 border border-secondary bg-white px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-widest text-secondary shadow-flat-sm mb-8">
            <span className="h-2 w-2 bg-primary animate-pulse" />
            Post-Quantum Sovereign Pipeline · SIH26164
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 items-center relative">
            <div className="lg:col-span-7 xl:col-span-8 min-w-0 relative z-0">
              {/* Prominent WebApp Name Banner */}
              <div className="mb-4 inline-flex items-center gap-2.5 font-mono text-xs sm:text-sm uppercase tracking-widest text-primary font-extrabold flex-wrap">
                <span className="px-2 py-0.5 border border-primary bg-primary/10 text-primary">ECDAT.SUITE</span>
                <span className="text-secondary font-bold">Enterprise Cryptographic Discovery & Analysis Tool</span>
              </div>

              <h1 className="font-display text-3xl sm:text-4xl md:text-5xl lg:text-[2.65rem] xl:text-[3.25rem] 2xl:text-[3.75rem] font-extrabold tracking-tight uppercase leading-[1.08] text-secondary">
                Autonomous <br />
                <span className="text-primary underline decoration-[#e5e5e5] underline-offset-8 inline-block max-w-full">
                  Cryptographic
                </span> <br />
                Discovery & PQC.
              </h1>
              <p className="mt-6 max-w-2xl font-body text-base sm:text-lg text-tertiary leading-relaxed">
                Enterprise Cryptographic Discovery & Analysis Tool (<span className="text-secondary font-bold">ECDAT</span>). Mathematically driven by the 
                <span className="text-secondary font-semibold"> Mosca-Weighted Quantum Risk Score (MWQRS)</span>, 
                NetworkX dependency blast-radius graph, and automated NIST FIPS 203/204/205 transitions.
              </p>

              {/* Action Buttons */}
              <div className="mt-8 sm:mt-10 flex flex-wrap items-center gap-4">
                <button
                  onClick={() => onExplore('dashboard')}
                  className="flex items-center gap-3 bg-secondary px-6 py-3.5 font-mono text-xs font-bold uppercase tracking-wider text-white hover:bg-primary transition-colors shadow-flat"
                >
                  <span>Launch Executive Dashboard</span>
                  <ArrowRight className="h-4 w-4" />
                </button>

                <button
                  onClick={() => onExplore('login')}
                  className="flex items-center gap-3 border-2 border-primary bg-primary/10 px-6 py-3.5 font-mono text-xs font-bold uppercase tracking-wider text-primary hover:bg-primary hover:text-white transition-all shadow-flat"
                >
                  <Lock className="h-4 w-4" />
                  <span>Sign In / Identity Portal</span>
                </button>

                <button
                  onClick={() => onExplore('pqc-simulator')}
                  className="flex items-center gap-3 border border-secondary bg-white px-6 py-3.5 font-mono text-xs font-bold uppercase tracking-wider text-secondary hover:border-primary hover:text-primary transition-colors"
                >
                  <Cpu className="h-4 w-4 text-primary" />
                  <span>Run PQC Simulator</span>
                </button>

                <button
                  onClick={() => onExplore('threat-timeline')}
                  className="flex items-center gap-3 border border-[#e5e5e5] bg-[#faf9f5] px-6 py-3.5 font-mono text-xs font-medium uppercase tracking-wider text-tertiary hover:text-secondary hover:border-secondary transition-colors"
                >
                  <span>Mosca Timeline</span>
                </button>
              </div>
            </div>

            {/* Right Architectural Panel — mix-blend-mode lets orange text punch through */}
            <div className="lg:col-span-5 xl:col-span-4 flex justify-start lg:justify-end shrink-0 w-full relative z-10 lg:-ml-20 xl:-ml-28">
              {/* Outer wrapper carries the orange sketch shadow */}
              <div className="w-full max-w-sm relative" style={{boxShadow: '12px 12px 0px #ff3300'}}>

                {/* Layer 1: multiply-blend white bg — orange text bleeds through this */}
                <div className="absolute inset-0" style={{backgroundColor: '#ffffff', mixBlendMode: 'multiply'}} />

                {/* Layer 2: border frame (above blend, unaffected) */}
                <div className="absolute inset-0 border-2 border-[#111111] pointer-events-none" style={{zIndex: 1}} />

                {/* Layer 3: card content — fully opaque, above blend */}
                <div className="relative p-6" style={{zIndex: 2}}>
                <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-3 text-xs font-mono uppercase text-tertiary">
                  <span>POSTURE SPECIFICATION</span>
                  <span className="text-primary font-bold">FIPS READY</span>
                </div>

                <div className="mt-4 space-y-4 font-mono text-xs">
                  <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                    <span className="text-tertiary">Key Encapsulation</span>
                    <span className="font-bold text-secondary">ML-KEM-768</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                    <span className="text-tertiary">Digital Signature</span>
                    <span className="font-bold text-secondary">ML-DSA-65</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                    <span className="text-tertiary">Stateless Hash Sig</span>
                    <span className="font-bold text-secondary">SLH-DSA</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#eeeeea]">
                    <span className="text-tertiary">CBOM Format</span>
                    <span className="font-bold text-secondary">CycloneDX 1.6</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-tertiary">Quantum Scoring</span>
                    <span className="font-bold text-primary">MWQRS v2.4</span>
                  </div>
                </div>

                <div className="mt-6 border-t border-[#e5e5e5] pt-4">
                  <div className="text-[10px] font-mono uppercase text-tertiary">
                    Target Architecture
                  </div>
                  <div className="mt-1 text-sm font-semibold text-secondary">
                    Dual Hybrid Classical-PQC Transition
                  </div>
                </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Grid of 4 Architectural Pillars */}
      <section className="border-b border-[#e5e5e5] px-6 py-16 lg:px-16">
        <div className="mx-auto max-w-7xl">
          <div className="mb-12 border-b border-[#e5e5e5] pb-4 flex items-center justify-between">
            <h2 className="font-display text-2xl font-bold uppercase tracking-tight text-secondary">
              Core Capabilities
            </h2>
            <span className="font-mono text-xs text-tertiary uppercase">ENGINEERING PROTOCOL</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Pillar 1 */}
            <div 
              onClick={() => onExplore('inventory')}
              className="cursor-pointer border border-[#e5e5e5] bg-white p-6 hover:border-secondary transition-all hover:-translate-y-1 shadow-sm"
            >
              <div className="flex h-10 w-10 items-center justify-center bg-[#faf9f5] border border-secondary text-secondary mb-4">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-tertiary">MODULE 01</div>
              <h3 className="mt-1 font-display text-lg font-bold uppercase text-secondary">
                Asset Discovery & Inventory
              </h3>
              <p className="mt-2 text-xs font-body text-tertiary leading-relaxed">
                Automated continuous scanning of TLS certificates, cipher suites, key lengths, and algorithmic exposures.
              </p>
            </div>

            {/* Pillar 2 */}
            <div 
              onClick={() => onExplore('threat-timeline')}
              className="cursor-pointer border border-[#e5e5e5] bg-white p-6 hover:border-secondary transition-all hover:-translate-y-1 shadow-sm"
            >
              <div className="flex h-10 w-10 items-center justify-center bg-[#faf9f5] border border-secondary text-secondary mb-4">
                <Lock className="h-5 w-5 text-primary" />
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-tertiary">MODULE 02</div>
              <h3 className="mt-1 font-display text-lg font-bold uppercase text-secondary">
                MWQRS & Mosca Timeline
              </h3>
              <p className="mt-2 text-xs font-body text-tertiary leading-relaxed">
                Risk calculation evaluating algorithm exposure, key size, protocol versions, data shelf-life, and migration effort.
              </p>
            </div>

            {/* Pillar 3 */}
            <div 
              onClick={() => onExplore('dependency-graph')}
              className="cursor-pointer border border-[#e5e5e5] bg-white p-6 hover:border-secondary transition-all hover:-translate-y-1 shadow-sm"
            >
              <div className="flex h-10 w-10 items-center justify-center bg-[#faf9f5] border border-secondary text-secondary mb-4">
                <Network className="h-5 w-5 text-primary" />
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-tertiary">MODULE 03</div>
              <h3 className="mt-1 font-display text-lg font-bold uppercase text-secondary">
                Blast Radius Graph
              </h3>
              <p className="mt-2 text-xs font-body text-tertiary leading-relaxed">
                Directed dependency graph modeling service chains, blast radius propagation, and cascading cryptographic vulnerability.
              </p>
            </div>

            {/* Pillar 4 */}
            <div 
              onClick={() => onExplore('pqc-simulator')}
              className="cursor-pointer border border-[#e5e5e5] bg-white p-6 hover:border-secondary transition-all hover:-translate-y-1 shadow-sm"
            >
              <div className="flex h-10 w-10 items-center justify-center bg-[#faf9f5] border border-secondary text-secondary mb-4">
                <Cpu className="h-5 w-5 text-primary" />
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-tertiary">MODULE 04</div>
              <h3 className="mt-1 font-display text-lg font-bold uppercase text-secondary">
                PQC Simulation & CBOM
              </h3>
              <p className="mt-2 text-xs font-body text-tertiary leading-relaxed">
                Before-and-after simulation with NIST replacement mapping, topological migration ordering, and CycloneDX 1.6 export.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer Info */}
      <footer className="px-6 py-10 lg:px-16 border-t border-[#e5e5e5] bg-white">
        <div className="mx-auto max-w-7xl flex flex-col md:flex-row items-center justify-between gap-4 text-xs font-mono text-tertiary">
          <div>
            ECDAT © 2026 · Radical Monolith Architecture · Enterprise Cryptographic Discovery
          </div>
          <div className="flex items-center gap-6">
            <span>NIST FIPS 203/204/205</span>
            <span>CycloneDX CBOM 1.6</span>
            <span>NTRO / SIH26164</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
