from typing import Optional

from cloudguard.constants import SEPARATOR
from cloudguard.findings import COLORS
from cloudguard.utils.logger import feeder


def list_buckets(s3_client) -> list:
    """Return a list of all S3 bucket names."""
    try:
        response = s3_client.list_buckets()
        return [bucket["Name"] for bucket in response.get("Buckets", [])]
    except Exception as e:
        feeder(f"{COLORS['RED']}[!] Failed to list S3 buckets: {e}{COLORS['RESET']}")
        return []


def scan_s3_buckets(session, registry, plugins_to_run: Optional[list] = None) -> tuple:
    """
    Scans every S3 bucket by executing registered S3 plugins from the PluginRegistry.

    Args:
        session: Active boto3 session.
        registry: Loaded PluginRegistry instance.
        plugins_to_run (list, optional): Filtered list of plugin names/IDs to run.

    Returns:
        tuple: (findings, metadata_dict)
    """
    s3_client = session.client("s3")
    findings = []
    buckets = list_buckets(s3_client)
    bucket_count = len(buckets)

    feeder("\n" + SEPARATOR)
    feeder(f"{COLORS['BOLD']}S3 SECURITY ASSESSMENT{COLORS['RESET']}")
    feeder(SEPARATOR)

    if not buckets:
        feeder("No S3 buckets found to assess.\n")
        return findings, {"bucket_count": 0}

    # Extract all S3-supported plugins from registry
    s3_plugins = []
    for key, plugin in registry._registry.items():
        meta = plugin.get_metadata()
        is_s3_plugin = "s3" in [s.lower() for s in meta.get("supported_services", [])]
        
        # Apply selective filter if user passed specific plugin/service flags
        if is_s3_plugin:
            if plugins_to_run is None or key in plugins_to_run:
                s3_plugins.append(plugin)

    context = {
        "session": session,
        "s3_client": s3_client
    }

    # Execute plugins grouped by resource
    for bucket in buckets:
        feeder(f"\n{COLORS['BLUE']}[RESOURCE]{COLORS['RESET']} {bucket}\n")
        
        for plugin in s3_plugins:
            try:
                plugin_findings = plugin.execute(context)
                for finding in plugin_findings:
                    if getattr(finding, "resource", "") == bucket:
                        feeder(finding)
                        findings.append(finding)
            except Exception as e:
                feeder(f"  {COLORS['RED']}[!] Plugin execution failed ({plugin.name}): {e}{COLORS['RESET']}")

    return findings, {"bucket_count": bucket_count}