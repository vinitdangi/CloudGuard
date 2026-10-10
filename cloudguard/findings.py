from typing import Optional, List, Dict, Any
from cloudguard.risk import RiskScorer
COLORS = {
    "BLUE": "\033[94m",           # Used for Resource names
    "GREEN": "\033[92m",          # Used for [PASS]
    "YELLOW": "\033[93m",         # Used for [Medium] severity
    "RED": "\033[91m",            # Used for [High] severity
    "CYAN": "\033[96m",           # Used for FIX -> recommendations
    "BOLD": "\033[1m",            # Used for Headers
    "RESET": "\033[0m",           # Resets color back to default
    "PURPLE": "\033[95m",         # Used for [CRITICAL] severity
    "WHITE_BRIGHT": "\033[97m",   # Text highlight
    "GRAY": "\033[90m",           # Fallback/Low severity
    "GREEN_DARK": "\033[32m",     
    "YELLOW_LIGHT": "\033[33m" 
}


class Finding:
    def __init__(
        self,
        finding_id:Optional[str]=None,
        risk_score:Optional[float]=None,
        impact:Optional[str]="",
        evidence:Optional[dict[str,Any]]=None,
        remediation: Optional[str] = "",
        check: Optional[str]="", 
        resource: Optional[str]="", 
        passed: Optional[bool]=True, 
        issue: Optional[str] = "", 
        recommendation: str = "",
        cis_control:Optional[str]="",
        cis_title:Optional[str]="",
        cis_benchmark:Optional[str]="CIS AWS Foundation",
        cis_version:Optional[str]='7.0.0',
        severity: Optional[str] = "HIGH", 
        category: Optional[str] = "GENERAL",
        compliance: Optional[List[Dict[str, Any]]] = None
    ):
        self.check = check
        self.resource = resource
        self.passed = passed
        self.issue = issue
        self.severity = severity
        self.category = category
        self.finding_id=finding_id
        self.impact=impact
        self.evidence=evidence or{}
        self.remediation=remediation
        self.recommendation = recommendation
        self.cis_control=cis_control
        self.cis_title=cis_title
        self.cis_benchmark=cis_benchmark
        self.cis_version=cis_version
        self.compliance = compliance or []
        if risk_score is not None:
            self.risk_score=risk_score
        else:
            self.risk_score=RiskScorer.score(self)
            
    


    def __str__(self):
        if self.passed:
            pass_badge = f"{COLORS['GREEN']}[PASS]{COLORS['RESET']}"
            msg = self.issue if self.issue else "Secure and compliant"
            return f"  ↳ {pass_badge} {self.check}: {msg}"
        
        sev_val = str(self.severity).upper() if self.severity else "HIGH"
        
        if sev_val == 'CRITICAL':
            sev_badge = f"{COLORS['PURPLE']}[CRITICAL]{COLORS['RESET']}"
        elif sev_val == 'HIGH':
            sev_badge = f"{COLORS['RED']}[HIGH]{COLORS['RESET']}"
        elif sev_val == 'MEDIUM':
            sev_badge = f"{COLORS['YELLOW']}[MEDIUM]{COLORS['RESET']}"
        elif sev_val == 'LOW':
            sev_badge = f"{COLORS['GRAY']}[LOW]{COLORS['RESET']}"
        else:
            sev_badge = f"{COLORS['BLUE']}[{sev_val}]{COLORS['RESET']}"

        fix_pointer = f"{COLORS['CYAN']}FIX ->{COLORS['RESET']}"
        issue_pointer = f"{COLORS['CYAN']}ISSUE:{COLORS['RESET']}"
        
        return (
            f"  ↳ {sev_badge} {COLORS['BOLD']}{self.check}{COLORS['RESET']}\n"
            f"      {issue_pointer} {self.issue}\n"
            f"      {fix_pointer} {self.recommendation}"
        )

    def __repr__(self):
        return self.__str__()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":self.finding_id,
            "risk_score":self.risk_score,
            "impact":self.impact,
            "evidence":self.evidence,
            "check": self.check,
            "category": self.category,
            "resource": self.resource,
            "passed": self.passed,
            "severity": self.severity if not self.passed else "None",
            "issue": self.issue if not self.passed else "Secure and compliant",
            "recommendation":self.recommendation if not self.passed else "No action required",
            "remediation":self.remediation if not self.passed else "",
            "compliance": self.compliance,
        
        }