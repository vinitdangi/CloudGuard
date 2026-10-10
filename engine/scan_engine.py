from collections import defaultdict
from plugin_manager import PluginRegistry, load_all_plugins
from cloudguard.findings import COLORS
SEVERITY_ORDER={
    "CRITICAL":1,
    "HIGH":2,
    "MEDIUM":3,
    "LOW":4,
    "PASS":5
}

class ScanEngine:
    def __init__(self, session, plugins_to_run=None, disable_plugins=False):
        self.session = session
        self.plugins_to_run = plugins_to_run
        self.disable_plugins = disable_plugins

    def run(self):
        all_findings = []

        if not self.disable_plugins:
            registry = PluginRegistry()
            load_all_plugins(registry)

            context = {
                "session": self.session,
                "s3_client": self.session.client("s3"),
                "iam_client": self.session.client("iam"),
            }

            for name, plugin in registry._registry.items():
                if self.plugins_to_run and name not in self.plugins_to_run:
                    continue

                plugin_findings = plugin.execute(context)
                if plugin_findings:
                    all_findings.extend(plugin_findings)

        if all_findings:
            category_grouped = defaultdict(list)
            for f in all_findings:
                cat = getattr(f, 'category', None)
                if not cat:
                    if hasattr(f,'resource') and f.resource.startswith("User:"):
                        cat="IAM"
                    else:
                        cat="S3"
                category_grouped[cat.upper()].append(f)

            for cat, findings in category_grouped.items():
                print("\n" + "-" * 60)
                print(f"{cat} SECURITY ASSESSMENT")
                print("-" * 60)

                resource_grouped = defaultdict(list)
                for f in findings:
                    res = getattr(f, 'resource', 'Global')
                    resource_grouped[res].append(f)

                for resource, res_findings in resource_grouped.items():
                    print(f"\n{COLORS['BLUE']}[RESOURCE]{COLORS['RESET']} {resource}\n")
                    sorted_severity=sorted(res_findings,key=lambda f: SEVERITY_ORDER.get(
                            "PASS" if getattr(f, 'passed', False) else str(getattr(f, 'severity', 'HIGH')).upper(),
                            99
                        ))
                    for f in sorted_severity:
                        passed = getattr(f, 'passed', False)
                        check_name = getattr(f, 'check', 'Check')
                        severity = str(getattr(f, 'severity', 'HIGH')).upper()
                        issue = getattr(f, 'issue', '')
                        recommendation = getattr(f, 'recommendation', '')

                        if not passed:
                            risk_score=getattr(f,"risk_score",None)
                            
                            print(f"  ↳ {COLORS['RED']}[{severity}]{COLORS['RESET']} "
                                f"{check_name}"
                                )
                            if risk_score is not None:
                                print(f"    Risk Score: {risk_score:.1f}/10"    
                                )
                            print(f"  {COLORS["YELLOW"]}ISSUE:{COLORS['RESET']} {issue}")
                            print(f"  {COLORS['GREEN']}FIX ->{COLORS['RESET']} {recommendation}")
                        
                        else:
                            msg = issue if issue else "Secure and compliant"
                            print(f"  ↳ {COLORS['GREEN']}[PASS]{COLORS['RESET']} {check_name}: {msg}")
        unique_buckets = {
            f.resource for f in all_findings 
            if hasattr(f, 'resource') and f.resource and not f.resource.startswith("User:")
        }

        metadata = {
            "bucket_count": len(unique_buckets)
        }

        return all_findings, metadata