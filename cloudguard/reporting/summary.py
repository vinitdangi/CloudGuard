from cloudguard.findings import COLORS

def print_summary(findings, bucket_count, start, end):
    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    
    total_checks = len(findings)
    score = 100
    passed = 0
    failed = 0

    for finding in findings:
        if getattr(finding, 'passed', False):
            passed += 1
        else:
            failed += 1
            severity = str(getattr(finding, 'severity', 'HIGH')).upper()
            if severity in severity_count:
                severity_count[severity] += 1  

    critical_weightage = severity_count['CRITICAL'] * 25         
    high_weightage = severity_count['HIGH'] * 10                
    medium_weightage = severity_count['MEDIUM'] * 5      
    low_weightage = severity_count['LOW'] * 2                  
    total_deduction = critical_weightage + high_weightage + medium_weightage + low_weightage    
    score = max(0, score - total_deduction)

    # Determine Risk Label
    if score >= 90:
        risk_level = f"{COLORS['GREEN']}LOW RISK{COLORS['RESET']}"
    elif score >= 70:
        risk_level = f"{COLORS['YELLOW']}MEDIUM RISK{COLORS['RESET']}"
    else:
        risk_level = f"{COLORS['RED']}HIGH RISK{COLORS['RESET']}"

    print(f'''
============================================================
                    {COLORS['GREEN']}SCAN SUMMARY{COLORS['RESET']}
                    {COLORS['GREEN']}CloudGuard v1.0.0{COLORS['RESET']}
            Start: {start.strftime('%I:%M:%S %p')} | End: {end.strftime('%I:%M:%S %p')}
============================================================
Total Scan Time : {COLORS['BOLD']}{(end - start).total_seconds():.2f}s{COLORS['RESET']}
Security Score  : {score}/100
Risk level      : {risk_level}

Buckets Scanned : {bucket_count}
Checks Executed : {total_checks}
Passed          : {passed}
Failed          : {failed}

Critical        : {COLORS['PURPLE']}{severity_count["CRITICAL"]}{COLORS['RESET']}
High            : {COLORS['RED']}{severity_count["HIGH"]}{COLORS['RESET']}
Medium          : {COLORS['YELLOW']}{severity_count["MEDIUM"]}{COLORS['RESET']}
Low             : {COLORS['BLUE']}{severity_count["LOW"]}{COLORS['RESET']}
''')