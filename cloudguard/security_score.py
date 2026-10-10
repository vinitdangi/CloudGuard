"""Authoritative, severity-weighted CloudGuard security posture score."""

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping

SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}
MAX_SEVERITY_WEIGHT = SEVERITY_WEIGHTS["CRITICAL"]
RATING_THRESHOLDS = (
    (90, "Excellent"),
    (75, "Good"),
    (60, "Needs Improvement"),
    (40, "Poor"),
    (0, "Critical"),
)


@dataclass(frozen=True)
class SecurityScore:
    """A score and explainable breakdown calculated from a scan's findings."""

    score: float
    rating: str
    total_findings: int
    passed_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    severity_weights: dict[str, int]
    penalty_breakdown: dict[str, int]
    total_penalty: int
    maximum_penalty: int

    @property
    def severity_summary(self) -> dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "passed": self.passed_count,
        }

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity_summary"] = self.severity_summary
        return result


def _field(finding: Any, key: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(key, default)
    if hasattr(finding, "to_dict"):
        return finding.to_dict().get(key, getattr(finding, key, default))
    return getattr(finding, key, default)


def _severity(finding: Any, passed: bool) -> str:
    if passed:
        return "PASS"
    severity = str(_field(finding, "severity") or "HIGH").strip().upper()
    return severity if severity in SEVERITY_WEIGHTS else "HIGH"


def _fingerprint(finding: Any, passed: bool, severity: str) -> tuple[Any, ...] | None:
    """Identify repeated control results without merging unrelated anonymous rows."""
    finding_id = _field(finding, "finding_id")
    check = _field(finding, "check")
    category = _field(finding, "category")
    resource = _field(finding, "resource")
    if not any((finding_id, check, category, resource)):
        return None
    return (
        str(finding_id or "").strip(),
        str(check or "").strip().casefold(),
        str(category or "").strip().casefold(),
        str(resource or "").strip().casefold(),
        passed,
        severity,
    )


def deduplicate_findings(findings: Iterable[Any]) -> list[Any]:
    """Return findings with repeated identified control results included once."""
    unique: list[Any] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        passed = bool(_field(finding, "passed", False))
        severity = _severity(finding, passed)
        fingerprint = _fingerprint(finding, passed, severity)
        if fingerprint is not None:
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
        unique.append(finding)
    return unique


def rating_for_score(score: float) -> str:
    for threshold, label in RATING_THRESHOLDS:
        if score >= threshold:
            return label
    return "Critical"


def calculate_security_score(findings: Iterable[Any]) -> SecurityScore:
    """Calculate a deterministic 0-100 score from unique scan findings.

    Each unique finding is one applicable control. Its severity penalty is
    divided by the maximum possible penalty (20) times the number of unique
    findings, then converted to a percentage:

        score = max(0, 100 * (1 - total_penalty / (20 * total_findings)))

    Passed checks contribute no penalty but remain in the denominator, so they
    improve posture by demonstrating covered controls. An empty scan has no
    penalties and returns 100; callers should make its zero coverage clear.
    Missing or unknown severity on a failed finding defaults to HIGH.
    Exact duplicate control results (same ID/check/category/resource/outcome)
    are counted once. Findings without any identifying fields remain distinct.
    """
    unique_findings = [
        (bool(_field(finding, "passed", False)),
         _severity(finding, bool(_field(finding, "passed", False))))
        for finding in deduplicate_findings(findings)
    ]

    counts = {severity: 0 for severity in (*SEVERITY_WEIGHTS, "PASS")}
    for _, severity in unique_findings:
        counts[severity] += 1

    penalty_breakdown = {
        severity: counts[severity] * weight
        for severity, weight in SEVERITY_WEIGHTS.items()
    }
    total_penalty = sum(penalty_breakdown.values())
    total_findings = len(unique_findings)
    maximum_penalty = total_findings * MAX_SEVERITY_WEIGHT
    if maximum_penalty == 0:
        score = 100.0
    else:
        score = round(max(0.0, 100.0 * (1 - total_penalty / maximum_penalty)), 1)

    return SecurityScore(
        score=score,
        rating=rating_for_score(score),
        total_findings=total_findings,
        passed_count=counts["PASS"],
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        severity_weights=dict(SEVERITY_WEIGHTS),
        penalty_breakdown=penalty_breakdown,
        total_penalty=total_penalty,
        maximum_penalty=maximum_penalty,
    )
