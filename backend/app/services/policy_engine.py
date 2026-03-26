"""
Policy Engine — masking, blocking, and response shaping based on options.
"""

from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.masking import mask_content


class PolicyEngine:
    """
    Applies security policies to analyzed content:
    - mask: redact detected sensitive content
    - block_high_risk: block or flag critical/high-risk findings
    """

    def apply(
        self,
        content: str,
        findings: list[Finding],
        risk_level: str,
        mask: bool = False,
        block_high_risk: bool = False,
    ) -> dict:
        """
        Apply policies and determine the action taken.
        Returns dict with action and optionally modified content.
        """
        action = "allowed"
        modified_content = content

        # Check for blocking first (takes precedence)
        if block_high_risk:
            has_critical = any(f.risk in ("critical", "high") for f in findings)
            if has_critical or risk_level in ("critical", "high"):
                action = "blocked"
                logger.info(
                    f"Policy: BLOCKED — risk_level={risk_level}, "
                    f"high/critical findings present"
                )

        # Apply masking
        if mask:
            modified_content = mask_content(content)
            if action == "allowed":
                action = "masked"
            elif action == "blocked":
                action = "blocked"  # blocking takes precedence
            logger.info("Policy: Content masked")

        if action == "allowed":
            logger.info("Policy: Content allowed without modification")

        return {
            "action": action,
            "content": modified_content,
        }
