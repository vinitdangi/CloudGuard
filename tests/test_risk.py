from cloudguard.findings import Finding
from cloudguard.risk import RiskScorer

def test_high_finding_score():
    finding=Finding(
        check="IAM USER MFA",
        resource="User: noni",
        passed=False,
        issue="MFA  is  not enabled",
        recommendation="Enable MFA",
        severity="HIGH",
        category="IAM "
    )
    score=RiskScorer.score(finding)
    
    assert score==8.0
    
def test_critical_finding_Score():
    finding=Finding(
        check="S3 Public Access",
        resource="my-bucket",
        passed=False,
        severity="CRITICAL",
        category="S3",
    )
    assert RiskScorer.score(finding)==10.0
    
def test_pass_Score():
    finding=Finding(
        check="Bucket Encryption",
        resource="my-bucket",
        passed=True,
        severity="HIGH",
        category="S3",
    )
    assert RiskScorer.score(finding)==0.0