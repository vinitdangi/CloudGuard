from cloudguard.constants import SEPARATOR
from cloudguard.findings import COLORS
from cloudguard.utils.logger import feeder
from typing import Optional


def scan_iam(session, registry, plugins_to_run: Optional[list] = None):

    iam_client = session.client("iam")
    findings = []

    feeder("\n" + SEPARATOR)
    feeder(f"{COLORS['BOLD']}IAM SECURITY ASSESSMENT{COLORS['RESET']}")
    feeder(SEPARATOR)

    iam_plugins = []
    for key, plugin in registry._registry.items():
        meta = plugin.get_metadata()
        is_iam_plugin = "iam" in [s.lower() for s in meta.get("supported_services", [])]

        if is_iam_plugin:
            if plugins_to_run is None or key in plugins_to_run:
                iam_plugins.append(plugin)

    context = {
        "session": session,
        "iam_client": iam_client
    }

    for plugin in iam_plugins:
        try:
            plugin_findings = plugin.execute(context)
            if plugin_findings:
                for finding in plugin_findings:
                    feeder(finding)
                    findings.append(finding)
        except Exception as e:
            feeder(f"  {COLORS['RED']} Plugin execution failed ({plugin.name}): {e}{COLORS['RESET']}")

    return findings