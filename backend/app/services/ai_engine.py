"""
AI Engine — Groq-based security insight generator.
Analyzes findings to produce natural language summaries, risk breakdowns, and recommendations.
"""

import os
import json
import asyncio
import re
from typing import List, Dict

import httpx
from app.core.config import settings
from app.core.logging_config import logger
from app.models.schemas import Finding


class AIEngine:
    """
    Centralized inference interface using Groq (OpenAI-compatible).
    Handles prompt construction, API calling, and structured output parsing.
    """

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY") or settings.GROQ_API_KEY
        self.model_name = os.getenv("GROQ_MODEL") or settings.GROQ_MODEL
        self.base_url = "https://api.groq.com/openai/v1"
        
        if self.api_key:
            logger.info(f"AI Engine initialized with Groq model: {self.model_name}")
        else:
            logger.warning("GROQ_API_KEY is missing. AI insights will use fallback.")

    async def _call_groq(self, prompt: str, timeout: float = 45.0) -> str | None:
        """Send a prompt to Groq and return the raw text response."""
        if not self.api_key:
            return None

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.4,
            "top_p": 0.8,
            "max_tokens": 1024,
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, headers=headers, json=payload)

            if response.status_code != 200:
                logger.error(f"Groq API error ({response.status_code}): {response.text}")
                return None

            data = response.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "").strip() or None
            return None

        except httpx.TimeoutException:
            logger.warning("Groq request timed out")
            return None
        except Exception as e:
            logger.error(f"Groq communication error: {e}")
            return None

    async def generate_insights(
        self,
        findings: List[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        raw_content: str = "",
    ) -> Dict:
        """
        Generate security insights from structured findings and raw data.
        Returns a dict with 'summary', 'risks', 'recommendations', and 'fix_instructions'.
        """
        if not self.api_key or (not findings and not raw_content):
            return self._get_fallback_response(findings, risk_level, content_type)

        try:
            prompt = self._build_prompt(findings, risk_score, risk_level, content_type, raw_content)
            text = await asyncio.wait_for(self._call_groq(prompt), timeout=50.0)

            if not text:
                return self._get_fallback_response(findings, risk_level, content_type)

            # Robust JSON extraction: look for the first '{' and last '}'
            json_match = re.search(r'(\{.*\})', text, re.DOTALL)
            if json_match:
                text = json_match.group(1)

            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                cleaned_text = re.sub(r'(?<=: ")(.*?)(?=",?\n)', lambda m: m.group(1).replace('\n', '\\n'), text, flags=re.DOTALL)
                parsed = json.loads(cleaned_text)

            return {
                "summary": parsed.get("summary", "Analysis complete."),
                "risks": parsed.get("risks", []),
                "recommendations": parsed.get("recommendations", []),
                "fix_instructions": parsed.get("fix_instructions", "See recommendations.")
            }

        except Exception as e:
            logger.error(f"Groq insight generation failed: {e}")
            return self._get_fallback_response(findings, risk_level, content_type)

    def _build_prompt(self, findings: List[Finding], risk_score: int, risk_level: str, content_type: str, raw_content: str = "") -> str:
        """Construct a high-quality prompt that includes both deterministic findings and raw data."""
        ai_findings = findings[:10]
        findings_json = json.dumps([f.model_dump() for f in ai_findings], indent=2)
        raw_context = raw_content[:1500] if raw_content else "No raw input data provided."

        return f"""You are a Lead Cybersecurity Analyst at Kynetic Sentra.

Analyze a potential security incident in a {content_type} file.

### DETERMINISTIC FINDINGS
{findings_json}

### RAW CONTENT FOR DEEP ANALYSIS
{raw_context}

### TASK
1. Review the findings and the raw content carefully.
2. Flag any ADDITIONAL threats missed by the deterministic engine (e.g. XSS, shellcode, anomalous URIs).
3. If an attack is present in the raw content but NOT in findings, raise its risk to CRITICAL in your summary.

Respond ONLY in JSON:
{{
  "summary": "one sentence executive summary",
  "risks": ["concise threat 1", "concise threat 2"],
  "recommendations": ["remediation 1", "remediation 2"],
  "fix_instructions": "technical step-by-step fix guide"
}}
"""

    def _get_fallback_response(self, findings: List[Finding], risk_level: str, content_type: str) -> Dict:
        """Deterministic safety response when AI is unavailable or findings are empty."""
        if not findings:
            return {
                "summary": f"No high-risk issues were detected in this {content_type}.",
                "risks": ["No significant vulnerabilities found"],
                "recommendations": ["Continue standard monitoring"],
                "fix_instructions": "No fixes required. The system configuration and codebase look secure."
            }

        logger.info("Using rule-based fallback summary.")
        return {
            "summary": "AI analysis unavailable, using rule-based summary.",
            "risks": [f"Detected {len(findings)} issues with {risk_level} risk level"],
            "recommendations": ["Review report for specific line numbers", "Implement standard security hardening"],
            "fix_instructions": "Groq Engine Unavailable. Please add a valid GROQ_API_KEY to your .env file to enable the Summary Bot insights. Manual inspection of reported lines is recommended in the meantime."
        }

    async def chat_with_context(self, message: str, context: dict) -> str:
        """Process an interactive chat dialogue using the provided analysis context."""
        if not self.api_key:
            return "AI Engine is unavailable. Please check your GROQ_API_KEY in the `.env` file."
            
        prompt = f"""You are an advanced cybersecurity analyst helping a developer fix vulnerabilities.
Below is the context of the recent vulnerability scan of their system/log file:

--- CONTEXT ---
{json.dumps(context, indent=2)}
--- END CONTEXT ---

The developer is asking you a question directly.
Respond professionally, specifically addressing their issue, using standard markdown. Keep it concise, helpful, and technically accurate.

User: {message}

Security Analyst:
"""
        response = await self._call_groq(prompt, timeout=45.0)
        return response or "I'm sorry, I could not generate a response. Please try again."
