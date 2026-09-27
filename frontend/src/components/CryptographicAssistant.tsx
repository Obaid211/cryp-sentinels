import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Bot, Send, RefreshCw, Zap, Lock } from 'lucide-react';
import { API_BASE_URL } from '../config';

interface ChatMessage {
  sender: 'user' | 'assistant';
  text: string;
  source?: string;
  topic?: string;
  mode?: string;
  cached?: boolean;
  timestamp: string;
}

interface AssistantStatus {
  status: string;
  mode: string;
  primary_model: string;
  gemini_connected: boolean;
  keypool_size: number;
  sovereign_fallback_active: boolean;
}

interface CryptographicAssistantProps {
  mode?: 'LIVE' | 'CACHED' | 'OFFLINE';
}

const PROMPT_SUGGESTIONS = [
  'Explain NIST FIPS 203 ML-KEM-768 replacement',
  'What are our most vulnerable assets in inventory?',
  'What is the MWQRS score formula?',
  'Explain Mosca Quantum Urgency (X + Y > Z)',
  'How does hybrid classical + PQC transition work?',
  'What is CycloneDX 1.6 CBOM specification?'
];

export const CryptographicAssistant: React.FC<CryptographicAssistantProps> = ({ mode = 'LIVE' }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: 'assistant',
      text: "Welcome to the ECDAT Cryptographic Advisor. I am calibrated on NIST PQC standards (FIPS 203/204/205), the MWQRS quantitative scoring model, and enterprise post-quantum transition roadmaps. How may I advise your cryptographic migration?",
      source: mode === 'OFFLINE' ? 'sovereign-expert-engine' : 'gemini-ai (gemini-3.6-flash)',
      topic: 'System Welcome',
      mode: mode,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [inputPrompt, setInputPrompt] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<AssistantStatus | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll the chat window (not the page) to the latest message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, [messages, loading]);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/assistant/status?mode=${mode}`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch assistant status:', err);
    }
  }, [mode]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect
    void fetchStatus();
  }, [fetchStatus]);

  const handleSendMessage = async (textToSend?: string) => {
    const prompt = (textToSend || inputPrompt).trim();
    if (!prompt || loading) return;

    const userMsg: ChatMessage = {
      sender: 'user',
      text: prompt,
      mode: mode,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputPrompt('');
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE_URL}/api/assistant/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, mode }),
      });

      if (res.ok) {
        const data = await res.json();
        const assistantMsg: ChatMessage = {
          sender: 'assistant',
          text: data.response || 'No response generated.',
          source: data.source,
          topic: data.topic,
          mode: data.mode || mode,
          cached: data.cached,
          timestamp: new Date().toLocaleTimeString(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } else {
        const errorMsg: ChatMessage = {
          sender: 'assistant',
          text: 'Error contacting cryptographic advisor engine. Please check backend connection.',
          mode: mode,
          timestamp: new Date().toLocaleTimeString(),
        };
        setMessages((prev) => [...prev, errorMsg]);
      }
    } catch (err) {
      console.error('Assistant error:', err);
      const errorMsg: ChatMessage = {
        sender: 'assistant',
        text: 'Network failure communicating with advisory service: ' + String(err),
        mode: mode,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="border border-[var(--border)] bg-[var(--surface)] p-6 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[var(--accent)] font-semibold">
              Capability 09 / 09
            </span>
            <span className="h-3 w-px bg-[var(--border)]" />
            <span className="font-mono text-xs text-[var(--text-muted)]">
              Gemini 3.6 Flash & Sovereign Cryptographic AI Copilot
            </span>
          </div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-tight text-[var(--text-primary)] mt-1">
            Cryptographic Advisor Copilot
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-3xl">
            Interactive AI assistant calibrated on NIST FIPS 203/204/205 standards, MWQRS risk modeling, Mosca timeline inequality calculations, and real-time enterprise inventory posture.
          </p>
        </div>

        {/* Live Operational Engine Badge */}
        <div className="flex flex-col items-end gap-1.5 font-mono text-xs">
          <div className="flex items-center gap-2 border border-[#e5e5e5] bg-white px-3 py-1.5 shadow-flat-sm">
            {mode === 'LIVE' ? (
              <>
                <span className="inline-block h-2 w-2 bg-emerald-500 animate-pulse" />
                <span className="font-bold text-secondary">
                  {status?.gemini_connected ? 'GEMINI 3.6 FLASH (ONLINE)' : 'SOVEREIGN ENGINE (STANDBY)'}
                </span>
                <span className="text-tertiary">| Keypool: {status?.keypool_size || 1}</span>
              </>
            ) : mode === 'CACHED' ? (
              <>
                <Zap className="h-3.5 w-3.5 text-amber-500" />
                <span className="font-bold text-amber-600">CACHED MODE ACTIVE</span>
                <span className="text-tertiary">| Sub-ms Response</span>
              </>
            ) : (
              <>
                <Lock className="h-3.5 w-3.5 text-blue-600" />
                <span className="font-bold text-blue-700">AIR-GAPPED OFFLINE MODE</span>
                <span className="text-tertiary">| 0 External I/O</span>
              </>
            )}
          </div>
          <span className="text-[10px] text-tertiary uppercase">
            NIST SP 800-227 / FIPS 203/204/205 Calibrated
          </span>
        </div>
      </div>

      {/* Main Chat Interface */}
      <div className="border border-[var(--border)] bg-[var(--surface)] flex flex-col min-h-[580px] shadow-sm">
        {/* Chat Header */}
        <div className="border-b border-[var(--border)] p-4 bg-white flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-2.5">
            <Bot className="h-4 w-4 text-primary" />
            <span className="font-bold text-secondary uppercase tracking-wider">
              {mode === 'OFFLINE' 
                ? 'Sovereign Cryptographic Advisor (Air-Gapped)' 
                : mode === 'CACHED'
                ? 'High-Speed Cached Cryptographic Advisor'
                : 'ECDAT Post-Quantum Advisor (Gemini 3.6 Flash Active)'}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className={`px-2 py-0.5 text-[10px] font-bold border uppercase ${
              mode === 'LIVE' 
                ? 'border-emerald-600 bg-emerald-50 text-emerald-700' 
                : mode === 'CACHED' 
                ? 'border-amber-600 bg-amber-50 text-amber-700' 
                : 'border-blue-600 bg-blue-50 text-blue-700'
            }`}>
              MODE: {mode}
            </span>
            <button
              onClick={() => void fetchStatus()}
              title="Refresh Engine Status"
              className="text-tertiary hover:text-secondary transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Message Log */}
        <div className="flex-1 p-6 overflow-y-auto space-y-4 bg-[#faf9f5] max-h-[460px]">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div className="flex items-center gap-2 mb-1 font-mono text-[10px] text-tertiary">
                <span className="font-semibold">{msg.sender === 'user' ? 'Operator' : 'ECDAT Advisor'}</span>
                {msg.source && (
                  <span className={`px-1.5 py-0.2 border text-[9px] font-bold ${
                    msg.source.includes('gemini') 
                      ? 'border-emerald-500 bg-emerald-50 text-emerald-700' 
                      : msg.cached
                      ? 'border-amber-500 bg-amber-50 text-amber-700'
                      : 'border-secondary bg-white text-secondary'
                  }`}>
                    [{msg.source}]
                  </span>
                )}
                {msg.cached && <span className="text-amber-600 font-bold">⚡ CACHED</span>}
                <span>•</span>
                <span>{msg.timestamp}</span>
              </div>

              <div
                className={`max-w-2xl p-4 border text-xs leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-secondary text-white border-secondary font-mono shadow-flat-sm'
                    : 'bg-white text-secondary border-[#e5e5e5] shadow-flat-sm'
                }`}
              >
                {msg.topic && (
                  <div className="font-bold uppercase text-[10px] text-primary mb-1 tracking-wider">
                    {msg.topic}
                  </div>
                )}
                <div className="whitespace-pre-wrap font-mono text-sm">{msg.text}</div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-2.5 text-xs font-mono text-primary p-3 bg-white border border-[#e5e5e5] max-w-md shadow-flat-sm">
              <span className="inline-block h-2 w-2 bg-primary animate-ping" />
              <span>Analyzing cryptographic query with {mode === 'OFFLINE' ? 'Sovereign Engine' : 'Gemini 3.6 Flash'}...</span>
            </div>
          )}

          {/* Scroll anchor — scrollIntoView targets this, not the page */}
          <div ref={bottomRef} />
        </div>

        {/* Suggested Queries */}
        <div className="p-3 border-t border-[var(--border)] bg-white flex items-center gap-2 overflow-x-auto text-[11px] font-mono no-scrollbar">
          <span className="text-tertiary uppercase shrink-0 font-bold">Suggested:</span>
          {PROMPT_SUGGESTIONS.map((suggestion, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(suggestion)}
              className="px-2.5 py-1 border border-[#e5e5e5] bg-[#faf9f5] hover:border-primary hover:text-primary text-secondary shrink-0 transition-all hover:-translate-y-0.5"
            >
              {suggestion}
            </button>
          ))}
        </div>

        {/* Chat Input */}
        <div className="p-4 border-t border-[var(--border)] bg-white flex gap-3">
          <input
            type="text"
            value={inputPrompt}
            onChange={(e) => setInputPrompt(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Ask about NIST PQC standards, MWQRS formula, Mosca inequality, vulnerable assets..."
            className="flex-1 border border-[#e5e5e5] bg-[#faf9f5] p-3 font-mono text-xs text-secondary outline-none focus:border-primary transition-colors"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={loading || !inputPrompt.trim()}
            className="px-6 py-3 bg-secondary text-white font-mono text-xs font-bold uppercase tracking-wider hover:bg-primary transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-flat-sm flex items-center gap-2"
          >
            <span>Send</span>
            <Send className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
