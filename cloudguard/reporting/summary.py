from cloudguard.findings import COLORS
from cloudguard.security_score import calculate_security_score

def print_summary(findings, bucket_count, start, end, security_score=None):
    score_result = security_score or calculate_security_score(findings)
    failed = score_result.total_findings - score_result.passed_count
    risk_color = COLORS["GREEN"] if score_result.score >= 90 else (
        COLORS["YELLOW"] if score_result.score >= 75 else COLORS["RED"]
    )
    risk_level = f"{risk_color}{score_result.rating.upper()}{COLORS['RESET']}"

    print(f'''
============================================================
                    {COLORS['GREEN']}SCAN SUMMARY{COLORS['RESET']}
                    {COLORS['GREEN']}CloudGuard v1.0.0{COLORS['RESET']}
            Start: {start.strftime('%I:%M:%S %p')} | End: {end.strftime('%I:%M:%S %p')}
============================================================
Total Scan Time : {COLORS['BOLD']}{(end - start).total_seconds():.2f}s{COLORS['RESET']}
Security Score  : {score_result.score:g}/100
Risk level      : {risk_level}

Buckets Scanned : {bucket_count}
Checks Executed : {score_result.total_findings}
Passed          : {score_result.passed_count}
Failed          : {failed}

Critical        : {COLORS['PURPLE']}{score_result.critical_count}{COLORS['RESET']}
High            : {COLORS['RED']}{score_result.high_count}{COLORS['RESET']}
Medium          : {COLORS['YELLOW']}{score_result.medium_count}{COLORS['RESET']}
Low             : {COLORS['BLUE']}{score_result.low_count}{COLORS['RESET']}
''')
