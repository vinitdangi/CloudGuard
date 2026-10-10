"""PDF report generation tests using local Finding fixtures only."""

from io import BytesIO

from pypdf import PdfReader

from cloudguard.findings import Finding
from cloudguard.reporting.pdf_exporter import generate_pdf_report
from cloudguard.security_score import calculate_security_score

FAKE_SECRET = "FAKE_TEST_" + "SECRET_DO_NOT_USE"


def extract_text(pdf_bytes: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf_bytes)).pages)


def finding(severity="HIGH", **kwargs):
    values = dict(
        finding_id=f"TEST-{severity}",
        check=f"{severity.title()} configuration check",
        category="IAM",
        resource="User: demo-user",
        passed=False,
        severity=severity,
        issue="The setting does not meet the expected security configuration.",
        evidence={"setting": "disabled"},
        recommendation="Enable the required security configuration.",
        risk_score=7.5,
    )
    values.update(kwargs)
    return Finding(**values)


def test_pdf_generation_contains_report_summary_and_finding_details():
    pdf = generate_pdf_report(
        [finding()],
        {
            "aws_account_id": "123456789012",
            "region": "ap-southeast-2",
            "scan_timestamp": "2026-10-10T10:00:00Z",
            "scan_duration_seconds": 12.5,
            "plugins_executed": 9,
        },
    )
    text = extract_text(pdf)

    assert pdf.startswith(b"%PDF-")
    assert "AWS Cloud Security Assessment Report" in text
    assert "Executive Summary" in text
    assert "Findings Summary" in text
    assert "Detailed Findings" in text
    assert "TEST-HIGH" in text
    assert "123456789012" in text
    assert "ap-southeast-2" in text
    assert "12.50 seconds" in text
    assert "Enable the required security configuration." in text
    assert "Plugins/checks executed" in text


def test_pdf_generation_supports_zero_findings_and_missing_metadata():
    pdf = generate_pdf_report([])
    text = extract_text(pdf)

    assert "Total Findings" in text
    assert "No findings were returned by the scan." in text
    assert "Not provided" in text
    assert "Security Score" not in text


def test_pdf_generation_counts_all_severities_and_compacts_passed_checks():
    findings = [
        finding("CRITICAL"),
        finding("HIGH"),
        finding("MEDIUM"),
        finding("LOW"),
        Finding(check="S3 encryption", category="S3", resource="bucket-a", passed=True),
    ]
    text = extract_text(generate_pdf_report(findings))

    assert "Critical" in text
    assert "High" in text
    assert "Medium" in text
    assert "Low" in text
    assert "Passed Checks" in text
    assert "S3 encryption" in text
    assert "No action required" not in text


def test_pdf_displays_the_precalculated_score_rating_and_penalty_breakdown():
    findings = [
        Finding(check="MFA", resource="user-a", passed=False, severity="HIGH"),
        Finding(check="S3 encryption", resource="bucket-a", passed=True),
    ]
    score = calculate_security_score(findings)
    text = extract_text(generate_pdf_report(findings, security_score=score))

    assert "SECURITY SCORE" in text
    assert f"{score.score:g} / 100" in text
    assert score.rating in text
    assert "Penalty Breakdown" in text
    assert "High: 1 x 10 = 10 points" in text
    assert "Weighted penalty: 10 / 40" in text


def test_pdf_redacts_credentials_from_findings_metadata_and_evidence():
    pdf = generate_pdf_report(
        [
            Finding(
                check="Credential safety",
                passed=False,
                severity="HIGH",
                issue=f"Unexpected value: {FAKE_SECRET}",
                evidence={"aws_secret_access_key": FAKE_SECRET, "detail": FAKE_SECRET},
                recommendation="Rotate the exposed key.",
            )
        ],
        {
            "region": "ap-southeast-2",
            "aws_secret_access_key": FAKE_SECRET,
            "environment_values": {"AWS_SESSION_TOKEN": FAKE_SECRET},
        },
        sensitive_values=[FAKE_SECRET, "AKIAFAKEACCESSKEY123"],
    )
    text = extract_text(pdf)

    assert FAKE_SECRET not in text
    assert b"FAKE_TEST_SECRET_DO_NOT_USE" not in pdf
    assert "[REDACTED]" in text
    assert "AKIAFAKEACCESSKEY123" not in text


def test_pdf_escapes_dynamic_markup_and_includes_available_cis_information():
    sample = Finding(
        check="<script>not markup</script>",
        passed=False,
        severity="MEDIUM",
        issue="Example <untrusted> evidence",
        recommendation="Review & correct the setting.",
        cis_control="1.1",
        cis_title="Protect <root>",
    )
    text = extract_text(generate_pdf_report([sample]))

    assert "<script>not markup</script>" in text
    assert "Example <untrusted> evidence" in text
    assert "1.1" in text
    assert "Protect <root>" in text


def test_long_report_repeats_table_headers_and_adds_page_numbers():
    findings = [
        finding("HIGH", finding_id=f"TEST-{index}", check=f"Security check {index}")
        for index in range(45)
    ]
    pages = PdfReader(BytesIO(generate_pdf_report(findings))).pages
    page_text = [page.extract_text() or "" for page in pages]

    assert len(pages) > 1
    assert "Page 1" in page_text[0]
    assert f"Page {len(pages)}" in page_text[-1]
    assert any("Finding ID" in text for text in page_text[1:])
