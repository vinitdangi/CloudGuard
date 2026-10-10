"""Backward-compatible facade for security posture calculations."""

from cloudguard.risk_aggregator import RiskAggregator
from cloudguard.security_score import calculate_security_score


class SecurityPosture:
    """Legacy dict-shaped adapter backed by the authoritative score model."""

    @classmethod
    def calculate(cls, findings):
        findings = list(findings)
        result = calculate_security_score(findings)
        return {
            **result.to_dict(),
            # Retained for older CLI consumers; this is a separate risk total,
            # not an input to the 0-100 security score.
            "total_risk": round(RiskAggregator.total_risk(findings), 1),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
        }
