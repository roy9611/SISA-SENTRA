"""
Risk Engine — weighted scoring system producing deterministic,
explainable risk scores and levels.
"""

from app.core.logging_config import logger
from app.models.schemas import Finding


class RiskEngine:
    """
    Weighted risk scoring engine.
    Produces a numeric risk_score and a categorical risk_level.
    """

    # Severity weights for risk score calculation
    SEVERITY_WEIGHTS: dict[str, int] = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    }

    # Risk level thresholds
    RISK_THRESHOLDS = [
        (0, "low"),
        (5, "medium"),
        (15, "high"),
        (30, "critical"),
    ]

    def calculate(self, findings: list[Finding]) -> dict:
        """
        Calculate weighted risk score from findings.
        Returns dict with risk_score and risk_level.
        """
        if not findings:
            return {"risk_score": 0, "risk_level": "low"}

        # Calculate weighted score
        total_score = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in findings:
            risk = finding.risk.lower()
            weight = self.SEVERITY_WEIGHTS.get(risk, 1)
            total_score += weight
            if risk in severity_counts:
                severity_counts[risk] += 1

        # Cap score at a reasonable maximum for display
        risk_score = min(total_score, 100)

        # Determine risk level
        risk_level = "low"
        for threshold, level in self.RISK_THRESHOLDS:
            if risk_score >= threshold:
                risk_level = level

        # Override to critical if any critical finding exists
        if severity_counts["critical"] > 0:
            risk_level = "critical"

        logger.info(
            f"Risk calculation: score={risk_score}, level={risk_level}, "
            f"counts={severity_counts}"
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
        }
