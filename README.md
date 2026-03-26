# KYNETIC SENTRA v1.0.0 — Platinum Edition
**AI Secure Data Intelligence Platform**

🔴 **Live Demo:** [https://sisa-project.vercel.app/](https://sisa-project.vercel.app/)

Welcome to **Kynetic Sentra** — an advanced Forensic-First Security Operations Center (SOC) designed to act as a centralized **AI Gateway, Data Scanner, Log Analyzer, and Risk Engine**. 

Built from the ground up for high-stakes enterprise environments, Kynetic Sentra bridges the gap between deterministic rule-based scanning and generative AI threat modeling, utilizing the blazing-fast **Llama 3 70B Model powered by Groq's LPU™ AI Inference Technology**.

---

## 👁️ 1. Overview & Objective

Modern security pipelines suffer from log pollution, data exfiltration via chat, and correlation blindspots. The objective of Kynetic Sentra is to support multi-source data ingestion and intelligent analysis to intercept vulnerabilities *before* they proliferate.

### Supported Input Types
The platform provides robust ingestion for:
- **Text input**
- **Files:** `.pdf`, `.docx`, `.txt`
- **Log files:** `.log`, `.txt`
- **SQL / Structured data traces**
- **Live chat input**

---

## ⚙️ 2. Core Modules & End-to-End Flow

### The Processing Architecture

```text
Input (Text / File / SQL / Log / Chat)
        ↓
Validation Layer
        ↓
Extraction (Multimodal Parser)
        ↓
Detection Engine
   ├── Regex Signatures
   ├── Groq AI Semantic Analysis
   └── Log Analyzer (NEW)
        ↓
Risk Engine (Critical / High / Medium / Low)
        ↓
Policy Engine (Allow / Mask / Block)
        ↓
Response Payload
```

---

## 📊 3. Deep Log File Processing (MANDATORY)

Kynetic Sentra places a heavy emphasis on parsing server logs, API responses, errors, and debug traces. 

### 3.1 Log Analyzer Detection Layer
1. **Sensitive Data Detection (PII & Secrets):**
   - Extracts: Emails (Low Risk), API keys (High Risk), Passwords (Critical Risk), and Tokens.
2. **Security Issue Detection (CRITICAL):**
   - Flags hardcoded secrets, exposed credentials, and error leaks (e.g., Stack Traces - Medium Risk).
3. **Advanced Anomaly Detection (Optional/Bonus):**
   - Identifies repeated failures (Brute-force detection), suspicious IP activity, and debug mode leaks.

### 3.2 AI-Based Log Insights (Powered by Groq Llama-3)
After deterministic scanning, the data is pushed to Groq for sub-second, intelligent insight generation:
- Summaries of log activity.
- Contextual warnings (e.g., *"API key exposed in logs"*, *"Multiple failed login attempts detected"*).
- Developer remediation instructions.

---

## 🔌 4. API Design

### POST `/analyze`

Provides a unified, high-reliability endpoint for all analysis tasks.

**Request Payload:**
```json
{
  "input_type": "text | file | sql | chat | log",
  "content": "2026-03-10 10:00:01 INFO User login\nemail=admin@company.com\npassword=admin123\napi_key=sk-prod-xyz\nERROR stack trace: NullPointerException",
  "options": {
    "mask": true,
    "block_high_risk": true,
    "log_analysis": true
  }
}
```

**Response Payload:**
```json
{
  "summary": "Log contains sensitive credentials and errors",
  "content_type": "logs",
  "findings": [
    { "type": "api_key", "risk": "high", "line": 4 },
    { "type": "password", "risk": "critical", "line": 3 }
  ],
  "risk_score": 12,
  "risk_level": "high",
  "action": "masked",
  "insights": [
    "Sensitive credentials exposed in logs",
    "Stack trace reveals internal system details"
  ]
}
```

---

## 💻 5. Frontend & UI Capabilities

Designed with a custom "Silent Cyberpunk" dark-mode glassmorphic UI using React 18 + Vite.

- **Log Upload UI:** Drag & Drop support for batch `.log` and `.txt` processing.
- **Log Visualization (BONUS):** High-fidelity terminal view displaying logs with highlighted sensitive lines, accurate line numbers, and strict risk markers.
- **Insights Panel (NEW):** Modular display for Groq AI-generated log summaries, security warnings, and risk breakdowns.

---

## 🏆 6. Hackathon Evaluation Mapping

| Category | Score Weight | Kynetic Sentra Implementation |
| :--- | :---: | :--- |
| **Backend Design** | 18 | FastAPI, async processing, Pydantic validation, modular architecture. |
| **AI Integration** | 15 | **Groq API** + Llama-3.3-70B integration for instant, intelligent analysis. |
| **Log Analysis** | 15 | Dedicated `LogAnalyzer` service evaluating velocities, errors, and PII in chunked logs. |
| **Multi-Input Handling** | 12 | Support for Text, Logs, Chat, SQL, and heavy document processing (`PyPDF2`, `python-docx`). |
| **Detection + Risk Engine** | 12 | Regex validation mapped to normalized risk scores and entity extractions. |
| **Frontend UI** | 10 | Real-time React dashboard with Drag & Drop, Terminal Visualization, and Insights. |
| **Policy Engine** | 8 | Configurable Allow/Mask/Block actions. Rejects requests automatically on CRITICAL threshold. |
| **Security** | 5 | Built-in `slowapi` rate limiting, CORS configuration, local PII masking (Zero-Trust). |
| **Observability** | 3 | Health check endpoints, root routing API documentation. |
| **Bonus Mechanics** | 2 | Real-time brute-force detection across log events. Efficient chunking for massive sizes. |

---

## 🚦 7. Deployment & Operations

Kynetic Sentra is entirely production-ready.

### Environment Preparation
Create a `.env` file in the `backend/` directory. Get your **Groq API Key** at [console.groq.com](https://console.groq.com).

```env
APP_NAME="Kynetic Sentra"
GROQ_API_KEY="your-groq-api-key"
GROQ_MODEL="llama-3.3-70b-versatile"
ALLOWED_ORIGINS="*"
MAX_FILE_SIZE_MB=10
```

### Option A: Local Bare Metal (Development)
**Backend API:**
```bash
cd backend
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Frontend Dashboard:**
```bash
cd frontend
npm install
npm run dev
```

### Option B: Cloud (Vercel)
The repository contains native `vercel.json` and Python wrappers. Run `npx vercel --prod` and deploy directly as a serverless monolithic application with static frontend routing. Ensure `GROQ_API_KEY` is added to your Vercel Environment Variables.
