export default function ResultDisplay({ data }) {
  if (!data) return null;

  const { findings } = data;

  const getBadgeClass = (risk) => {
    return `risk-badge ${risk}`;
  };

  return (
    <div className="slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 24, marginTop: 8 }}>
      
      {/* Findings Table OS Window */}
      {findings.length > 0 && (
        <div className="glass-card" style={{ padding: 0 }}>
          <div className="card-title">
            Vulnerabilities.xml
          </div>
          <div style={{ padding: 12 }}>
            <div style={{ overflowX: 'auto', border: '1px solid var(--accent-gray)' }}>
              <table className="findings-table" id="findings-table">
                <thead>
                  <tr>
                    <th>Line</th>
                    <th>Type Signature</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, idx) => (
                    <tr key={idx}>
                      <td style={{ color: 'var(--text-muted)' }}>{String(f.line)}</td>
                      <td>
                        <span className="finding-type">{f.type}</span>
                      </td>
                      <td>
                        <span className={getBadgeClass(f.risk)}>{f.risk}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Raw JSON Notepad */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div className="card-title">
          Protocol.json - Notepad
        </div>
        <div style={{ padding: 12 }}>
          <div className="json-display" id="json-display" style={{ border: '2px inset rgba(0,0,0,0.1)', background: '#FFF' }}>
            <pre>{JSON.stringify(data, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
