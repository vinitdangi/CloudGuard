from cloudguard.findings import Finding
from cloudguard.risk_aggregator import RiskAggregator


def test_total_risk():
    findings = [
        Finding(
            check="MFA",
            resource="User: test",
            passed=False,
            severity="HIGH",
        ),
        Finding(
            check="Public Bucket",
            resource="bucket-test",
            passed=False,
            severity="CRITICAL",
        ),
        Finding(
            check="Encryption",
            resource="bucket-test",
            passed=True,
            severity="HIGH",
        ),
    ]


    assert RiskAggregator.total_risk(findings) == 18.0