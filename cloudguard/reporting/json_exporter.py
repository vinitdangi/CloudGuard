import json
from datetime import datetime
from cloudguard.findings import COLORS 
from cloudguard.utils.logger import feeder

def export_to_json(all_findings, running_tasks):
    findings_list = [finding.to_dict() for finding in all_findings]    
    
    json_payload = {
        "scan_metadata": {
            "engine": "CloudGuard",
            "version": "v1.0.0",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tasks_run": running_tasks if running_tasks else ["All"]
        },
        "findings": findings_list
    } 
    
    report_filename = "cloudguard_report.json"
    with open(report_filename, 'w', encoding='utf-8') as json_file:
        json.dump(json_payload, json_file, indent=4)
        
    feeder(f"\n{COLORS['GREEN']}JSON report exported successfully to {report_filename}!{COLORS['RESET']}")