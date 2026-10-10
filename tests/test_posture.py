from cloudguard.findings import Finding
from cloudguard.posture import SecurityPosture


def test_no_risk():
    findings = [
        Finding(
            check="Encryption",
            resource="bucket",
            passed=True,
            severity="HIGH",
        )
    ]

    result = SecurityPosture.calculate(findings)

    assert result["score"] == 100.0
    assert result["total_risk"] == 0.0


def test_one_high():
    findings = [
        Finding(
            check="MFA",
            resource="user",
            passed=False,
            severity="HIGH",
        )
    ]

    result = SecurityPosture.calculate(findings)

    assert result["total_risk"] == 8.0
    assert result["score"] == 80.0


def test_one_critical():
    findings = [
        Finding(
            check="Public Access",
            resource="bucket",
            passed=False,
            severity="CRITICAL",
        )
    ]

    result = SecurityPosture.calculate(findings)

    assert result["total_risk"] == 10.0
    assert result["score"] == 60.0
    assert result["critical"] == 1