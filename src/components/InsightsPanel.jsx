import { useState, useEffect, useRef } from 'react';

const RISK_COLORS = {
  critical: 'var(--risk-critical)',
  high:     'var(--risk-high)',
  medium:   'var(--risk-medium)',
  low:      'var(--risk-low)',
};

/** Simple reveal on scroll hook */
function useReveal() {
  const ref = useRef(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setIsVisible(true);
        observer.unobserve(entry.target);
      }
    }, { threshold: 0.1 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  return [ref, isVisible];
}

/** AI Typewriter effect component */
function Typewriter({ text, speed = 10 }) {
  const [displayed, setDisplayed] = useState('');
  
  useEffect(() => {
    let i = 0;
    setDisplayed('');
    if (!text) return;
    
    const timer = setInterval(() => {
      setDisplayed(text.substring(0, i + 1));
      i++;
      if (i >= text.length) clearInterval(timer);
    }, speed);
    
    return () => clearInterval(timer);
  }, [text, speed]);

  return <span>{displayed}</span>;
}

function SummaryRibbon({ risk_score, risk_level, findings_count, action }) {
  return (
    <div className="summary-ribbon">
      <div className="ribbon-item">
        <span className="ribbon-label">RISK SCORE:</span>
        <span className="ribbon-value" style={{ color: RISK_COLORS[risk_level?.toLowerCase()] }}>
          {risk_score} ({risk_level?.toUpperCase()})
        </span>
      </div>
      <div className="ribbon-divider" />
      <div className="ribbon-item">
        <span className="ribbon-label">TOTAL FINDINGS:</span>
        <span className="ribbon-value">{findings_count}</span>
      </div>
      <div className="ribbon-divider" />
      <div className="ribbon-item">
        <span className="ribbon-label">STATUS:</span>
        <span className="ribbon-value" style={{ color: action === 'blocked' ? 'var(--risk-critical)' : 'var(--cyan)' }}>
          {action?.toUpperCase() || 'NORMAL'}
        </span>
      </div>
    </div>
  );
}

function ExtractedEntitiesPanel({ data }) {
  const [ref, visible] = useReveal();
  const entities = data?.extracted_entities || {};
  const fields = [
    { label: 'TIMESTAMP', value: entities.timestamp || 'Mar 24 07:30:01', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> },
    { label: 'LOG TYPE',  value: entities.log_type  || 'Application', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg> },
    { label: 'DEVICE',    value: entities.device_type|| 'Workstation', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg> },
    { label: 'SOURCE IP', value: entities.source_ip || '193.17.57.108', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><polyline points="9 18 15 12 9 6"/></svg> },
    { label: 'DEST IP',   value: entities.dest_ip   || '172.16.30.43', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg> },
    { label: 'DST PORT',  value: entities.dst_port  || '443', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg> },
    { label: 'TARGET',    value: entities.uri_target|| '/api/v1/auth', icon: <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" strokeWidth="2" fill="none"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> },
  ];

  return (
    <div ref={ref} className={`entities-section reveal-hidden ${visible ? 'reveal-visible' : ''}`}>
      <div className="section-title">EXTRACTED NETWORK ENTITIES</div>
      <div className="entities-grid adaptive">
        {fields.map((f, i) => (
          <div key={i} className="entity-cell-modern">
            <span className="entity-label">
              <span className="entity-icon">{f.icon}</span>
              {f.label}
            </span>
            <span className="entity-value">{f.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AIIntelligenceSection({ summary, risks, recommendations, fix_instructions }) {
  const [ref, visible] = useReveal();
  return (
    <div ref={ref} className={`ai-section soc-terminal reveal-hidden ${visible ? 'reveal-visible' : ''}`}>
      <div className="section-title">
        <span className="ai-badge">AI</span> SECURITY INTELLIGENCE
      </div>
      <div className="ai-summary-box">
        <div className="card-header executive">EXECUTIVE SUMMARY</div>
        <p className="summary-text">
          <Typewriter text={summary} />
        </p>
      </div>
      <div className="ai-grid-modern">
        <div className="ai-card">
          <div className="card-header">CORE SECURITY RISKS</div>
          <ul className="ai-list">
            {(risks || []).map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
        <div className="ai-card">
          <div className="card-header">REMEDIATION STEPS</div>
          <ul className="ai-list">
            {(recommendations || []).map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      </div>
      {fix_instructions && (
        <div className="ai-fix-box">
          <div className="card-header">DEVELOPER FIX INSTRUCTIONS</div>
          <div className="fix-content">
            {fix_instructions.split('\n').filter(l => l.trim()).map((line, idx) => (
               <p key={idx}>{line.startsWith('>') ? line.substring(1).trim() : line}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function RiskVectorSection({ riskCounts, riskPct }) {
  const [ref, visible] = useReveal();
  return (
    <div ref={ref} className={`risk-vector-section reveal-hidden ${visible ? 'reveal-visible' : ''}`}>
        <div className="section-title">RISK VECTOR DISTRIBUTION</div>
        <div className="stacked-bar-v2">
          {['critical', 'high', 'medium', 'low'].map(level => (
             riskCounts[level] > 0 && (
              <div 
                key={level}
                className="bar-segment" 
                style={{ 
                  width: visible ? riskPct(level) : '0', 
                  background: level === 'low' ? 'var(--cyan)' : `var(--risk-${level})` 
                }}
              >
                <span className="bar-label">{riskCounts[level]}</span>
              </div>
            )
          ))}
        </div>
        <div className="risk-legend">
          {['critical', 'high', 'medium', 'low'].map(level => (
            <div key={level} className="legend-item">
              <div className={`legend-box ${level === 'low' ? 'var-low' : `var-${level}`}`}></div>
              <span className="legend-text">{level.toUpperCase()}: {riskCounts[level]}</span>
            </div>
          ))}
        </div>
      </div>
  );
}

export default function InsightsPanel({ data, error, isAnalyzing, onFileDrop }) {
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && onFileDrop) {
      const reader = new FileReader();
      reader.onload = (ev) => onFileDrop({ content: ev.target.result, fileName: file.name });
      reader.readAsText(file);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file && onFileDrop) {
      const reader = new FileReader();
      reader.onload = (ev) => onFileDrop({ content: ev.target.result, fileName: file.name });
      reader.readAsText(file);
    }
  };

  if (isAnalyzing) {
    return (
      <div className="hub-loading">
        <div className="spinner-ring" />
        <span className="spinner-text">COMPUTING RISK VECTORS</span>
      </div>
    );
  }

  if (!data && !error) {
    return (
      <div
        className={`hub-empty-state ${dragging ? 'dragging' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input ref={fileInputRef} type="file" hidden onChange={handleFileSelect} />
        <div className="hub-empty-icon">
          <svg viewBox="0 0 24 24" width="48" height="48" stroke="currentColor" strokeWidth="1" fill="none" style={{ color: 'var(--cyan)' }}>
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
        </div>
        <div className="hub-empty-title">DROP YOUR FILES HERE TO BEGIN ANALYSIS</div>
        <div className="hub-empty-formats">PDF · LOG · SQL · TXT · CSV · JSON · SYSLOG</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="insights-error">
        <svg viewBox="0 0 24 24" width="48" height="48" stroke="var(--risk-critical)" strokeWidth="1" fill="none">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <div className="error-title">CONNECTION FAILED</div>
        <div className="error-text">{error}<br/>Status: OFFLINE</div>
      </div>
    );
  }

  const { findings = [], risk_score = 0, risk_level = 'low', action = 'allowed', summary = '' } = data || {};
  
  const mockRisks = data?.risks || ["No risks detected."];
  const mockRecs = data?.recommendations || ["No recommendations available."];
  const mockFix = data?.fix_instructions || "No fix instructions.";

  const riskCounts = findings.reduce((acc, f) => {
    const r = f.risk?.toLowerCase() || 'low';
    acc[r] = (acc[r] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const totalFindings = findings.length || 1;
  const riskPct = (key) => `${Math.round((riskCounts[key] / totalFindings) * 100)}%`;

  return (
    <div className="insights-center animate-fade-in" key={data?.id || 'new-scan'}>
      <SummaryRibbon risk_score={risk_score} risk_level={risk_level} findings_count={findings.length} action={action} />
      <AIIntelligenceSection summary={summary} risks={mockRisks} recommendations={mockRecs} fix_instructions={mockFix} />
      <ExtractedEntitiesPanel data={data} />
      <RiskVectorSection riskCounts={riskCounts} riskPct={riskPct} />
      
      <div className="vuln-section">
        <div className="section-title">Vulnerability Detail</div>
        <table className="vuln-table">
          <thead>
            <tr><th>LINE</th><th>THREAT</th><th>SEVERITY</th><th>STATUS</th></tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '20px' }}>No findings detected</td></tr>
            ) : (
              findings.map((f, i) => (
                <tr key={i}>
                  <td>{f.line}</td>
                  <td>{f.type}</td>
                  <td><span className={`severity-pill ${f.risk}`}>{f.risk}</span></td>
                  <td><span className={`status-tag ${f.risk === 'critical' || f.risk === 'high' ? 'blocked' : 'allowed'}`}>{f.risk === 'critical' || f.risk === 'high' ? 'BLOCKED' : 'ALLOWED'}</span></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
