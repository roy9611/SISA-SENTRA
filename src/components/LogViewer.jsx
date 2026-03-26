import { useState } from 'react';

export default function LogViewer({ content, findings, maskData, isLoading }) {
  const lines = content?.split('\n') || [];

  if (isLoading) {
    return (
      <div className="terminal-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="spinner-ring" style={{ margin: '0 auto 12px' }} />
          <div className="spinner-text">SCANNING LOG DATA</div>
        </div>
      </div>
    );
  }

  return (
    <div className="terminal-container stagger-reveal" key={content?.length || 0}>
      {lines.map((line, idx) => {
        const finding = findings?.find(f => f.line === idx + 1);
        let maskedLine = line;
        if (maskData) {
          maskedLine = line.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[**MASKED**]')
                           .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[**MASKED**]');
        }

        const riskClass = finding ? finding.risk : '';

        return (
          <div key={idx} className={`log-line ${riskClass}`}>
            <span className="line-num">{idx + 1}</span>
            <span className="line-text" style={{ display: 'flex', flexDirection: 'column' }}>
              <span>{maskedLine}</span>
              {finding && (
                <span style={{ 
                  marginTop: '4px', 
                  fontSize: '0.65rem', 
                  fontWeight: 'bold', 
                  color: `var(--risk-${riskClass})`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" strokeWidth="2" fill="none">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                  [THREAT: {finding.type?.toUpperCase()}]
                </span>
              )}
            </span>
          </div>
        );
      })}
      {!content && (
        <div className="no-data-msg">
          No data stream loaded. Upload a file or paste content in Tile 01.
        </div>
      )}
    </div>
  );
}
