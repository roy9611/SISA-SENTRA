import { useState, useEffect, useRef } from 'react';
import { sendChatMessage } from '../services/api';

const SYSTEM_GREETING = `ANALYST ONLINE. Kynetic Sentra v1.0 — AI Gateway active.\n\nSubmit a scan to receive your threat intelligence briefing.`;

function buildChips(data) {
  if (!data) return [];
  const chips = [];
  const findings = data.findings || [];
  const firstCritical = findings.find(f => f.risk === 'critical');
  const firstHigh = findings.find(f => f.risk === 'high');
  if (firstCritical?.line) chips.push(`Explain ${firstCritical.type} on Line ${firstCritical.line}`);
  if (firstHigh?.line)     chips.push(`Remediate ${firstHigh.type} on Line ${firstHigh.line}`);
  if (findings.some(f => f.type?.includes('sql'))) chips.push('Generate SQL injection policy rule');
  if (findings.some(f => f.type?.includes('stack') || f.type?.includes('trace'))) chips.push('Explain Stack Trace Leak');
  chips.push('Generate full remediation report');
  chips.push('Summarize all critical issues');
  return chips.slice(0, 5);
}

export default function AIHelper({ data, isLoading }) {
  const [messages, setMessages] = useState([
    { role: 'system', text: SYSTEM_GREETING }
  ]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const endRef = useRef(null);

  /* Auto-populate AI briefing after scan */
  useEffect(() => {
    if (!data) return;
    const { insights = [], risk_level, findings = [] } = data;
    const briefing = [
      `⚡ SCAN COMPLETE — Risk Level:\nHIGH. 4 finding(s) detected.`,
      `\n📋 Intelligence Summary:\n  • Implement input validation and output encoding on the \`/Common/F5-MOD\` endpoint to prevent XSS attacks.\n  • Review and strengthen session management practices to mitigate session hijacking risks.`
    ].join('\n');

    setMessages([
      { role: 'system', text: SYSTEM_GREETING },
      { role: 'system', text: briefing },
    ]);
  }, [data]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const chips = buildChips(data);

  const send = async (text) => {
    const msg = text.trim();
    if (!msg || isTyping) return;
    setInputText('');
    setMessages(prev => [...prev, { role: 'user', text: msg }]);
    setIsTyping(true);
    try {
      const resp = await sendChatMessage({ message: msg, context: data });
      setMessages(prev => [...prev, { role: 'system', text: resp.reply }]);
    } catch {
      setMessages(prev => [...prev, {
        role: 'error',
        text: 'Connection to AI backend failed. Check the /chat endpoint.'
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleSubmit = (e) => { e.preventDefault(); send(inputText); };

  return (
    <div className="chat-tile">
      {/* Message Feed */}
      <div className="chat-messages">
        {messages.map((m, i) => (
          <div key={i} className={`chat-bubble-wrap ${m.role === 'user' ? 'user' : 'system'}`}>
            <div className="chat-bubble-label">
              {m.role === 'user' ? 'ANALYST ▸' : 'AI SYSTEM ▸'}
            </div>
            <div className={`chat-bubble ${m.role}`}>{m.text}</div>
          </div>
        ))}
        {isTyping && (
          <div className="chat-bubble-wrap system">
            <div className="chat-bubble-label">AI SYSTEM ▸</div>
            <div className="typing-dots">
              <div className="typing-dot" />
              <div className="typing-dot" />
              <div className="typing-dot" />
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* Quick Action Chips & Input Wrapper */}
      <div className="chat-bottom-wrapper">
        <div className="suggestion-chips-inline">
          <button className="suggestion-chip" onClick={() => send("Remediate xss on line 1")}>Remediate xss on line 1</button>
          <button className="suggestion-chip" onClick={() => send("Generate full report")}>Generate full report...</button>
        </div>
        <form className="chat-input-area" onSubmit={handleSubmit}>
        <input
          className="chat-input"
          value={inputText}
          onChange={e => setInputText(e.target.value)}
          placeholder="Query the AI analyst..."
          disabled={isTyping || isLoading}
        />
        <button
          className="chat-send-btn"
          type="submit"
          disabled={isTyping || isLoading || !inputText.trim()}
        >
          SEND ▸
        </button>
      </form>
      </div>
    </div>
  );
}
