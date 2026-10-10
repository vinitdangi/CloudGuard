class SecurityPosture:
    RISK_BUDGET = 40.0
    CRITICAL_PENALTY = 15.0

    @classmethod
    def calculate(cls, findings):
        total_risk = sum(finding.risk_score or 0.0 for finding in findings if not finding.passed
        )

        critical_count = sum(
            1 for finding in findings if not finding.passed
            and str(finding.severity).upper() == "CRITICAL"
        )

        base_score = max(
            0.0,
            100.0 * (1.0 - total_risk / cls.RISK_BUDGET)
        )

        critical_penalty = critical_count * cls.CRITICAL_PENALTY

        final_score = max(
            0.0,
            base_score - critical_penalty
        )

        return {
            "score": round(final_score, 1),
            "total_risk": round(total_risk, 1),
            "critical": critical_count,
            "high": sum(
                1 for f in findings
                if not f.passed
                and str(f.severity).upper() == "HIGH"
            ),
            "medium": sum(
                1 for f in findings
                if not f.passed
                and str(f.severity).upper() == "MEDIUM"
            ),
            "low": sum(
                1 for f in findings
                if not f.passed
                and str(f.severity).upper() == "LOW"
            ),
        }