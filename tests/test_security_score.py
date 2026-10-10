"""Deterministic tests for CloudGuard's authoritative security score."""

import json

from cloudguard.findings import Finding
from cloudguard.reporting.json_exporter import build_json_payload
from cloudguard.security_score import (
    RATING_THRESHOLDS,
    calculate_security_score,
    rating_for_score,
)


def failed(severity=None, **overrides):
    finding = {
        "finding_id": f"id-{severity}",
        "check": f"{severity or 'missing'} control",
        "category": "IAM",
        "resource": "user-a",
        "passed": False,
        "severity": severity,
    }
    finding.update(overrides)
    return finding


def test_empty_and_all_passed_findings_return_clean_score():
    empty = calculate_security_score([])
    passed = calculate_security_score([
        Finding(check="MFA enabled", category="IAM", resource="user-a", passed=True),
        Finding(check="Encryption enabled", category="S3", resource="bucket-a", passed=True),
    ])

    assert (empty.score, empty.rating, empty.total_findings) == (100.0, "Excellent", 0)
    assert empty.maximum_penalty == 0
    assert (passed.score, passed.passed_count, passed.total_findings) == (100.0, 2, 2)


def test_each_severity_uses_its_weight_and_expected_score():
    expectations = {
        "LOW": (90.0, "Excellent", 2),
        "MEDIUM": (75.0, "Good", 5),
        "HIGH": (50.0, "Poor", 10),
        "CRITICAL": (0.0, "Critical", 20),
    }
    for severity, (score, rating, penalty) in expectations.items():
        result = calculate_security_score([failed(severity)])
        assert (result.score, result.rating, result.total_penalty) == (score, rating, penalty)


def test_mixed_severities_normalize_against_all_applicable_checks():
    result = calculate_security_score([
        failed("CRITICAL"), failed("HIGH"), failed("MEDIUM"),
        failed("LOW"),
        {"check": "Passed check", "category": "S3", "resource": "bucket", "passed": True},
    ])

    assert result.score == 63.0
    assert result.rating == "Needs Improvement"
    assert result.total_penalty == 37
    assert result.maximum_penalty == 100
    assert result.severity_summary == {
        "critical": 1, "high": 1, "medium": 1, "low": 1, "passed": 1,
    }
    assert result.penalty_breakdown == {
        "CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2,
    }


def test_multiple_critical_findings_and_score_bounds():
    multiple_critical = calculate_security_score([
        failed("CRITICAL", finding_id="c1", check="c1"),
        failed("CRITICAL", finding_id="c2", check="c2"),
        {"check": "Pass", "resource": "r", "passed": True},
    ])
    extremely_poor = calculate_security_score([
        failed("CRITICAL", finding_id=f"critical-{index}", check=f"check-{index}")
        for index in range(20)
    ])

    assert multiple_critical.score == 33.3
    assert multiple_critical.critical_count == 2
    assert 0 <= extremely_poor.score <= 100
    assert extremely_poor.score == 0


def test_missing_and_unknown_severity_default_to_high():
    result = calculate_security_score([
        failed(None, finding_id="missing", check="missing"),
        failed("UNRECOGNIZED", finding_id="unknown", check="unknown"),
    ])

    assert result.high_count == 2
    assert result.score == 50.0


def test_identical_findings_are_counted_once_but_distinct_controls_are_not():
    duplicate = failed("HIGH", finding_id="same", check="MFA")
    distinct = failed("HIGH", finding_id="other", check="Key rotation")
    result = calculate_security_score([duplicate, dict(duplicate), distinct])

    assert result.total_findings == 2
    assert result.high_count == 2
    assert result.score == 50.0


def test_ratings_follow_centralized_boundaries():
    assert [(threshold, rating_for_score(threshold)) for threshold, _ in RATING_THRESHOLDS] == [
        (90, "Excellent"),
        (75, "Good"),
        (60, "Needs Improvement"),
        (40, "Poor"),
        (0, "Critical"),
    ]


def test_same_findings_always_return_same_security_score():
    findings = [failed("HIGH"), failed("LOW")]
    assert calculate_security_score(findings) == calculate_security_score(findings)


def test_json_metadata_receives_the_authoritative_score():
    score = calculate_security_score([failed("MEDIUM")])
    payload = build_json_payload(
        [Finding(check="Database encryption", passed=False, severity="MEDIUM")],
        ["All"],
        score,
    )
    encoded = json.dumps(payload)
    metadata = payload["scan_metadata"]

    assert metadata["security_score"] == score.score
    assert metadata["security_rating"] == score.rating
    assert metadata["severity_summary"] == score.severity_summary
    assert json.loads(encoded)["findings"]
