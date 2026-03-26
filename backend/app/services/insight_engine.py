"""
Insight Engine — generates meaningful, actionable security insights.
Uses Ollama LLM when available, falls back to deterministic rule-based generation.
"""

from collections import Counter

from app.core.logging_config import logger
from app.models.schemas import Finding
from app.services.ai_client import AIClient


class InsightEngine:
    """
    Generates human-readable security insights from analysis findings.
    Two modes:
    1. AI-enhanced: Uses Ollama local LLM for natural language summaries
    2. Rule-based fallback: Deterministic insight generation from findings
    """

    def __init__(self):
        self.ai_client = AIClient()

    async def generate(
        self,
        findings: list[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        log_stats: dict | None = None,
    ) -> dict:
        """
        Generate summary and insights.
        Returns dict with 'summary' and 'insights' keys.
        """
        # Try AI-enhanced generation first
        ai_result = await self._try_ai_generation(
            findings, risk_score, risk_level, content_type, log_stats
        )
        if ai_result:
            return ai_result

        # Fall back to rule-based generation
        logger.info("Using rule-based insight generation")
        return self._rule_based_generation(
            findings, risk_score, risk_level, content_type, log_stats
        )

    async def chat(self, message: str, context: dict | None = None) -> str:
        """
        Interactive chat for contextual security analysis.
        Uses the provided scan context to answer user queries.
        """
        # If no context, respond as a general security analyst
        if not context:
            prompt = (
                f"You are a cybersecurity analyst. Answer the user's scan "
                f"and security-related query: '{message}'\n\n"
                f"Be professional, concise, and helpful. Keep responses "
                f"under 50 words."
            )
        else:
            # Build a prompt with scan context
            findings = context.get('findings', [])
            risk_level = context.get('risk_level', 'unknown')
            risk_score = context.get('risk_score', 0)
            summary = context.get('summary', 'No summary available')
            
            prompt = (
                f"You are a cybersecurity analyst. Answer a query about the "
                f"following scan result:\n\n"
                f"Scan Summary: {summary}\n"
                f"Risk Level: {risk_level} ({risk_score})\n"
                f"Total Findings: {len(findings)}\n\n"
                f"User Question: '{message}'\n\n"
                f"Be specific, professional, and reference the scan data when "
                f"relevant. Keep responses under 50 words."
            )

        response = await self.ai_client.generate(prompt)
        if response:
            return response
        
        # Rule-based fallback for chat if AI is exhausted or failing
        if context:
            summary = context.get('summary', 'the recent scan')
            risk = context.get('risk_level', 'unknown')
            findings = context.get('findings', [])
            return (
                f"I am operating in telemetry-only mode (AI engine load is high). "
                f"Summary: {summary}. Risk Level: {risk.upper()}. "
                f"I detected {len(findings)} specific findings. "
                f"How else can I assist with this data?"
            )
        
        return "The AI engine is currently under high load. Please try again in a few moments."

    async def _try_ai_generation(
        self,
        findings: list[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        log_stats: dict | None,
    ) -> dict | None:
        """Attempt to generate insights using Ollama LLM."""
        if not findings:
            return None

        # Build context for the LLM
        finding_summary = self._build_finding_summary(findings)
        stats_text = ""
        if log_stats:
            stats_text = (
                f"\nLog statistics: {log_stats['total_lines']} lines, "
                f"{log_stats['failed_logins']} failed logins, "
                f"{log_stats['error_leaks']} error leaks, "
                f"brute force detected: {log_stats['brute_force_detected']}"
            )

        prompt = (
            f"You are a cybersecurity analyst. Analyze these findings from a "
            f"{content_type} scan and provide a concise security summary and "
            f"3-5 actionable insights.\n\n"
            f"Findings: {finding_summary}\n"
            f"Risk Score: {risk_score} ({risk_level}){stats_text}\n\n"
            f"Respond in this exact JSON format:\n"
            f'{{"summary": "one sentence summary", '
            f'"insights": ["insight 1", "insight 2", "insight 3"]}}\n'
            f"Keep each insight under 15 words. Be specific, not generic."
        )

        response = await self.ai_client.generate(prompt)
        if not response:
            return None

        # Parse AI response
        try:
            import json
            # Try to extract JSON from the response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(response[start:end])
                summary = parsed.get("summary", "")
                insights = parsed.get("insights", [])
                if summary and insights:
                    logger.info("AI-generated insights parsed successfully")
                    return {
                        "summary": summary,
                        "insights": insights[:5],
                    }
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to parse AI response: {e}")

        return None

    def _rule_based_generation(
        self,
        findings: list[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        log_stats: dict | None,
    ) -> dict:
        """Generate deterministic insights from findings."""
        if not findings:
            return {
                "summary": f"No security issues detected in {content_type} content",
                "insights": ["Content appears clean with no detected vulnerabilities"],
            }

        # Count findings by type
        type_counts = Counter(f.type for f in findings)
        risk_counts = Counter(f.risk for f in findings)

        # Build summary
        summary_parts = []
        if "password" in type_counts or "secret" in type_counts:
            summary_parts.append("sensitive credentials exposed")
        if "api_key" in type_counts:
            summary_parts.append("API keys detected")
        if "token" in type_counts:
            summary_parts.append("authentication tokens found")
        if "stack_trace" in type_counts or "error_leak" in type_counts:
            summary_parts.append("error information leaked")
        if "debug_mode" in type_counts:
            summary_parts.append("debug mode enabled")
        if "brute_force" in type_counts:
            summary_parts.append("brute-force attack pattern detected")
        if "email" in type_counts:
            summary_parts.append("email addresses exposed")
        if "failed_login" in type_counts:
            summary_parts.append("failed login attempts detected")
        if "suspicious_ip" in type_counts:
            summary_parts.append("suspicious IP activity found")
        if "hardcoded_credential" in type_counts:
            summary_parts.append("hardcoded credentials in source")
        if "sql_injection" in type_counts:
            summary_parts.append("SQL injection patterns detected")

        if not summary_parts:
            summary_parts.append("security issues detected")

        content_label = content_type.replace("_", " ")
        summary = f"{content_label.capitalize()} contains {', '.join(summary_parts)}"

        # Build insights
        insights = []

        if risk_counts.get("critical", 0) > 0:
            insights.append(
                f"{risk_counts['critical']} critical-severity issues require immediate attention"
            )
        if risk_counts.get("high", 0) > 0:
            insights.append(
                f"{risk_counts['high']} high-risk findings should be remediated urgently"
            )

        if "password" in type_counts:
            insights.append("Passwords must be removed from logs and rotated immediately")
        if "api_key" in type_counts:
            insights.append("API keys should be revoked and replaced with vault-based secrets")
        if "token" in type_counts:
            insights.append("Exposed tokens should be invalidated and regenerated")
        if "hardcoded_credential" in type_counts:
            insights.append("Replace hardcoded credentials with environment variables or secrets manager")
        if "stack_trace" in type_counts or "error_leak" in type_counts:
            insights.append("Error details and stack traces should not be exposed in production")
        if "debug_mode" in type_counts:
            insights.append("Debug mode must be disabled in production environments")
        if "email" in type_counts:
            insights.append("Consider masking email addresses to comply with privacy regulations")

        # Log-specific insights
        if log_stats:
            if log_stats.get("brute_force_detected"):
                insights.append(
                    f"Brute-force pattern: {log_stats['failed_logins']} failed logins detected — implement rate limiting"
                )
            if log_stats.get("suspicious_ips", 0) > 0:
                insights.append(
                    f"{log_stats['suspicious_ips']} suspicious IPs detected — consider IP blocking"
                )
            if log_stats.get("error_leaks", 0) > 5:
                insights.append(
                    "High volume of error leaks suggests misconfigured error handling"
                )

        if "sql_injection" in type_counts:
            insights.append("SQL injection patterns found — use parameterized queries")

        # Ensure at least one insight
        if not insights:
            insights.append(
                f"{len(findings)} security findings detected with {risk_level} overall risk"
            )

        # Cap at 5 insights
        insights = insights[:5]

        return {
            "summary": summary,
            "insights": insights,
        }

    @staticmethod
    def _build_finding_summary(findings: list[Finding]) -> str:
        """Build a compact text summary of findings for the AI prompt."""
        type_counts = Counter(f.type for f in findings)
        parts = [f"{count}x {ftype}" for ftype, count in type_counts.items()]
        return ", ".join(parts)
