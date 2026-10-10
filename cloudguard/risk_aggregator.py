class RiskAggregator:
    @staticmethod
    def total_risk(findings):
        return sum(
            finding.risk_score or 0.0 for finding in findings if not finding.passed
        )