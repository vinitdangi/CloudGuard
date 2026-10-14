import json
from datetime import datetime
from collections.abc import Mapping
from cloudguard.findings import COLORS 
from cloudguard.utils.logger import feeder
from cloudguard.utils.sanitization import sanitize_sensitive_data

def build_json_payload(all_findings, running_tasks, security_score=None, sensitive_values=()):
    """Build the established JSON report structure, optionally with score data."""
    findings_list = [
        finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        if isinstance(finding, Mapping)
        else {"check": str(finding)}
        for finding in all_findings
    ]
    
    json_payload = {
        "scan_metadata": {
            "engine": "CloudGuard",
            "version": "v1.0.0",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tasks_run": running_tasks if running_tasks else ["All"]
        },
        "findings": findings_list
    }
    if security_score is not None:
        score_data = (
            security_score.to_dict()
            if hasattr(security_score, "to_dict")
            else dict(security_score)
            if isinstance(security_score, Mapping)
            else None
        )
        if score_data is None:
            raise TypeError("security_score must be a SecurityScore or mapping")
        json_payload["scan_metadata"].update({
            "security_score": score_data["score"],
            "security_rating": score_data["rating"],
            "severity_summary": score_data["severity_summary"],
        })
    return sanitize_sensitive_data(json_payload, tuple(sensitive_values))


def export_to_json(all_findings, running_tasks, security_score=None, sensitive_values=()):
    json_payload = build_json_payload(all_findings, running_tasks, security_score, sensitive_values)
    
    report_filename = "cloudguard_report.json"
    with open(report_filename, 'w', encoding='utf-8') as json_file:
        json.dump(json_payload, json_file, indent=4)
        
    feeder(f"\n{COLORS['GREEN']}JSON report exported successfully to {report_filename}!{COLORS['RESET']}")
