import { useState, useEffect } from 'react';
import { Download, Copy, Check, FileCode } from 'lucide-react';
import { API_BASE_URL } from '../config';

export const CbomStudio = () => {
  const [cbomData, setCbomData] = useState<string>('');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchCbom = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE_URL}/api/cbom/export`);
        if (res.ok) {
          const json = await res.json();
          setCbomData(JSON.stringify(json, null, 2));
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    void fetchCbom();
  }, []);

  const handleCopy = () => {
    void navigator.clipboard.writeText(cbomData);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([cbomData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ecdat_cbom_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-7xl p-6 lg:p-10 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-[#e5e5e5] pb-6 gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-tertiary uppercase">
            <span className="inline-block h-2 w-2 bg-primary" />
            <span>CYCLONEDX SPECIFICATION 1.6</span>
            <span>·</span>
            <span>STANDARDIZED CBOM EXPORT</span>
          </div>
          <h1 className="mt-1 font-display text-3xl font-extrabold uppercase text-secondary">
            Cryptographic Bill of Materials (CBOM) Studio
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleCopy}
            disabled={!cbomData}
            className="flex items-center gap-2 border border-secondary bg-white px-4 py-2 font-mono text-xs font-bold uppercase text-secondary hover:border-primary hover:text-primary transition-colors shadow-flat-sm"
          >
            {copied ? <Check className="h-4 w-4 text-severity-safe" /> : <Copy className="h-4 w-4" />}
            <span>{copied ? 'Copied' : 'Copy JSON'}</span>
          </button>

          <button
            onClick={handleDownload}
            disabled={!cbomData}
            className="flex items-center gap-2 bg-primary px-4 py-2 font-mono text-xs font-bold uppercase text-white hover:bg-primary-deep transition-colors shadow-flat-sm"
          >
            <Download className="h-4 w-4" />
            <span>Download CBOM</span>
          </button>
        </div>
      </div>

      {/* JSON Viewer */}
      <div className="border border-secondary bg-white shadow-flat">
        <div className="flex items-center justify-between border-b border-[#e5e5e5] bg-[#faf9f5] px-4 py-2.5 font-mono text-xs text-tertiary">
          <div className="flex items-center gap-2">
            <FileCode className="h-4 w-4 text-primary" />
            <span className="font-bold text-secondary">cyclonedx-cbom-1.6.json</span>
          </div>
          <span>READ-ONLY SYNTAX VIEWER</span>
        </div>

        {loading ? (
          <div className="p-12 text-center font-mono text-xs text-tertiary">
            Generating CycloneDX 1.6 Cryptographic Bill of Materials...
          </div>
        ) : (
          <div className="p-4 bg-[#111111] text-[#f4f4f0] font-mono text-xs overflow-x-auto max-h-[650px] leading-relaxed">
            <pre>
              <code>{cbomData}</code>
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
