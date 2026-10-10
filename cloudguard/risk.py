class RiskScorer:
    SEVERITY_SCORES={
        
        "CRITICAL":10.0,
        "HIGH":8.0,
        "MEDIUM":5.0,
        "LOW":2.0,
        "PASS":0.0
    }
    
    @classmethod
    def score(cls,finding):
        if finding.passed:
            return 0.0
        severity=str(finding.severity).upper()
        return cls.SEVERITY_SCORES.get(severity,5.0)