import { useState } from 'react';
import InputPanel from './components/InputPanel';
import LogViewer from './components/LogViewer';
import InsightsPanel from './components/InsightsPanel';
import AIHelper from './components/AIHelper';
import { analyzeContent } from './services/api';

export default function App() {
  const [result, setResult] = useState(null);
  const [rawContent, setRawContent] = useState('');
  const [maskData, setMaskData] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanTs, setScanTs] = useState('--:--:--');

  const handleAnalyze = async (payload) => {
    setIsLoading(true);
    setError('');
    setResult(null);
    setRawContent(payload.rawContent || payload.content || '');
    setMaskData(payload.options?.mask ?? true);

    try {
      const data = await analyzeContent(payload);
      setResult(data);
      setScanTs(new Date().toLocaleTimeString('en-US', { hour12: false }));
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="soc-shell">
      {/* ── Global Header ── */}
      <header className="soc-header">
        <div className="soc-header-brand">
          <span className="soc-header-title">KYNETIC SENTRA v1.0.0</span>
          <span className="soc-header-version">· AI Gateway · Scanner · Log Analyzer · Risk Engine</span>
        </div>
        <div className="soc-header-status">
          <span>Compliance</span>
          <span>·</span>
          <span>Privacy</span>
          <span>·</span>
          <span>Security</span>
        </div>
      </header>

      {/* ── Main 3-Column Grid ── */}
      <div className="soc-grid">
        {/* ── Left Column: Input + Log stacked ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1px', overflow: 'hidden', minHeight: 0 }}>
          {/* Tile 1: Input Panel */}
          <div className="soc-tile" style={{ flex: '0 0 auto' }}>
            <div className="tile-header">
              <span className="tile-label">01 - DATA INGESTION</span>
              <span className="tile-meta">AI GATEWAY</span>
            </div>
            <div className="tile-body">
              <InputPanel onAnalyze={handleAnalyze} isLoading={isLoading} />
            </div>
          </div>

          {/* Tile 2: Log Viewer */}
          <div className="soc-tile" style={{ flex: 1, minHeight: 0 }}>
            <div className="tile-header">
              <span className="tile-label">02 - LOG TERMINAL</span>
              <span className="tile-meta">DATA SCANNER</span>
            </div>
            <div className="tile-body" style={{ padding: 0 }}>
              <LogViewer
                content={rawContent}
                findings={result?.findings}
                maskData={maskData}
                isLoading={isLoading}
              />
            </div>
          </div>
        </div>

        {/* ── Center Column: Insights (full height, only inner scrolls) ── */}
        <div className="soc-tile" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="tile-header">
            <span className="tile-label">03 - INTELLIGENCE HUB</span>
            <span className="tile-meta">RISK ENGINE</span>
          </div>
          <InsightsPanel
            data={result}
            error={error}
            isAnalyzing={isLoading}
            onFileDrop={({ content: fileContent, fileName: fName }) => {
              handleAnalyze({
                input_type: 'log',
                file_type: 'log',
                content: fileContent,
                rawContent: fileContent,
                file_name: fName,
                options: { mask: true, deep_ai: true },
              });
            }}
          />
        </div>

        {/* ── Right Column: AI Chat (full height) ── */}
        <div className="soc-tile">
          <div className="tile-header">
            <span className="tile-label">04 - AI ANALYST BRIEFING</span>
            <div className="status-pill">
              <span className="dot" />
              <span style={{ fontSize: '0.55rem', letterSpacing: '0.1em' }}>LIVE</span>
            </div>
          </div>
          <AIHelper data={result} isLoading={isLoading} />
        </div>
      </div>

      {/* ── Footer Status Bar ── */}
      <footer className="soc-footer">
        <div className="footer-ticker">
          <span>IN A WORLD WHERE DATA IS JUST ANOTHER STREAM TO BE SECURED...</span>
          {result && <span style={{ color: 'var(--cyan)' }}>SCAN COMPLETE · {result.findings?.length ?? 0} FINDINGS · RISK: {result.risk_level?.toUpperCase()}</span>}
          {error && <span style={{ color: 'var(--risk-critical)' }}>⚠ {error}</span>}
        </div>
        <span style={{ color: 'var(--cyan)' }}>/// SISA HACKATHON 2026</span>
      </footer>
    </div>
  );
}
