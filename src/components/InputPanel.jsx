import { useState, useRef } from 'react';

const SAMPLE_LOG = `<134>Mar 24 07:30:01 ABCD
ASM:unit_hostname="ABCD",management_ip_address="173.65.22.11",management_ip_address_2="N/A"
http_class_name="N/A",web_application_name="N/A"
policy_name="N/A",policy_apply_date="N/A",violations="N/A"
support_id="N/A",request_status="N/A",response_code="N/A"
ip_client="193.17.57.108",route_domain="0",method="GET",protocol="HTTPS"
query_string="N/A",action="blocked"`;

export default function InputPanel({ onAnalyze, isLoading }) {
  const [fileType, setFileType] = useState('log');     // display label
  const [backendType, setBackendType] = useState('log'); // actual API type
  const [content, setContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [dragging, setDragging] = useState(false);
  const [options, setOptions] = useState({
    mask: true,
    deep_ai: true,
  });
  const fileInputRef = useRef(null);

  const handleFileRead = (file) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => setContent(e.target.result);
    reader.readAsText(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  };

  const toggleOption = (key) =>
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));

  const handleSubmit = () => {
    if (!content.trim() || isLoading) return;
    onAnalyze({
      input_type: backendType,
      file_type: backendType,
      content,
      rawContent: content,
      file_name: fileName,
      options,
    });
  };

  return (
    <div className="module-station">
      {/* 01. Source Ingestion */}
      <div
        className={`compact-drop ${dragging ? 'active' : ''} ${content ? 'has-content' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="compact-drop-text">
          <div className="drop-main-text" style={{ color: fileName ? 'var(--cyan)' : undefined }}>
             {fileName ? fileName.toUpperCase() : 'DRAG & DROP FILE'}
          </div>
          <div className="drop-sub-text">
            (.LOG, .TXT, .PDF, .DOC, .SQL)
          </div>
        </div>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        hidden
        onChange={(e) => { const f = e.target.files[0]; if (f) handleFileRead(f); }}
      />

      {/* Context Grid — labels are display-only; backend_type is the actual API value */}
      <div className="context-grid">
        {[
          { display: 'log',     backend: 'log',  label: 'Structured Log',    icon: '{ }' },
          { display: 'syslog',  backend: 'log',  label: 'Syslog',            icon: '>_'  },
          { display: 'text',    backend: 'text', label: 'Unstructured Text', icon: '='   },
          { display: 'network', backend: 'text', label: 'Network Packet',    icon: '🌐'  },
          { display: 'sql',     backend: 'sql',  label: 'SQL Trace',         icon: '⬢'  },
        ].map((t) => (
          <button
            key={t.display}
            className={`context-btn ${fileType === t.display ? 'active' : ''}`}
            onClick={() => { setFileType(t.display); setBackendType(t.backend); }}
            title={t.label}
          >
            {t.icon}
          </button>
        ))}
      </div>

      {/* Module Arming — 2 options */}
      <div className="module-matrix prominent">
        <div className="matrix-label">// MODULE ARMING STATION</div>
        <div className="matrix-grid vert">
          <button 
            className={`module-tile large ${options.mask ? 'armed' : ''}`}
            onClick={() => toggleOption('mask')}
          >
            <div className="module-icon">
              <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="1.5" fill="none">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div className="module-text-stack">
              <div className="module-label">DATA PRIVACY</div>
              <div className="module-sub">HASHING + SALTING</div>
            </div>
            <div className="module-status-indicator" />
          </button>
          <button 
            className={`module-tile large ${options.deep_ai ? 'armed' : ''}`}
            onClick={() => toggleOption('deep_ai')}
          >
            <div className="module-icon">
              <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="1.5" fill="none">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
              </svg>
            </div>
            <div className="module-text-stack">
              <div className="module-label">DEEP AI</div>
              <div className="module-sub">HIGHER MODEL</div>
            </div>
            <div className="module-status-indicator" />
          </button>
        </div>
      </div>

      {/* Workspace Area */}
      <div className="execution-zone">
        <textarea
          className="hidden-textarea"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste log data here..."
        />
        <div className="execution-actions">
           <button onClick={() => setContent(SAMPLE_LOG)} className="sample-link-btn">USE SAMPLE</button>
           <button
            className="big-execute-btn"
            disabled={!content.trim() || isLoading}
            onClick={handleSubmit}
          >
            {isLoading ? 'ANALYZING...' : 'EXECUTE SCAN'}
          </button>
        </div>
      </div>
    </div>
  );
}
