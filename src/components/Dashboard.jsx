import React from 'react';
import InputPanel from './InputPanel';
import LogViewer from './LogViewer';
import InsightsPanel from './InsightsPanel';
import ResultDisplay from './ResultDisplay';

export default function Dashboard({ result, isLoading, error, inputContent, onAnalyze }) {
  return (
    <div className="dashboard-grid">
      {/* 
          1. Sidebar/Left Column: Input Handling
          This is where users upload logs, paste strings, or configure analysis.
      */}
      <div className="dashboard-sidebar">
        <InputPanel onAnalyze={onAnalyze} isLoading={isLoading} />
        
        {/* Optional quick stats or context panel could go here */}
      </div>

      {/* 
          2. Primary Workspace: Visualization & Evidence
          Displays the logs being analyzed with highlighted findings.
      */}
      <div className="dashboard-main">
        {error && (
          <div className="error-banner slide-up">
            <span className="icon">⚠️</span>
            <div className="error-content">
              <strong>Analysis Error</strong>
              <p>{error}</p>
            </div>
          </div>
        )}

        {!result && !isLoading && !error && (
          <div className="vivid-placeholder">
            <div className="placeholder-art">🛡️</div>
            <h2>Awaiting Data Stream</h2>
            <p>Upload a log file or paste text in the analysis panel to begin scanning for threats.</p>
          </div>
        )}

        {isLoading && (
          <div className="vivid-placeholder">
            <div className="spinner-orbit">
              <div className="spinner-core"></div>
            </div>
            <h2>Scanning Intelligence</h2>
            <p>Processing text patterns, scoring risks, and generating AI insights...</p>
          </div>
        )}

        {result && (
          <>
            <InsightsPanel data={result} />
            <LogViewer content={inputContent} findings={result.findings} />
            <ResultDisplay data={result} />
          </>
        )}
      </div>

      {/* 
          3. Right Column / Intelligence Layer
          In v1, this was shared or floating. We'll stick to the layout used in App.jsx.
      */}
    </div>
  );
}
