import argparse
from datetime import datetime

from cloudguard.aws.session import create_session
from cloudguard.reporting.html_exporter import export_to_html
from cloudguard.reporting.json_exporter import export_to_json
from cloudguard.reporting.summary import print_summary
from cloudguard.utils.logger import write_log
from engine.scan_engine import ScanEngine
from plugin_manager import PluginRegistry, load_all_plugins


def handle_plugins_list(args):
    """Displays all installed plugins with metadata."""
    registry = PluginRegistry()
    load_all_plugins(registry)
    registry.list_metadata()


def handle_scan(args):
    """Executes security scan with optional category/service filtering."""
    write_log("Initializing CloudGuard security scan...")

    # 1. Track start time for report summary metrics
    start_time = datetime.now()
    session = create_session(
    endpoint_url=getattr(args, "endpoint", None)
)

    # Load registry to support filtering flags
    registry = PluginRegistry()
    load_all_plugins(registry)

    plugins_to_run = None
    running_tasks = []

    # Filter plugins by user-specified Category or Service
    if args.category or args.service:
        plugins_to_run = []
        target_cat = args.category.upper() if args.category else None
        target_svc = args.service.lower() if args.service else None

        for name, plugin in registry._registry.items():
            meta = plugin.get_metadata()
            cat_match = target_cat and meta["category"].upper() == target_cat
            svc_match = target_svc and target_svc in [
                s.lower() for s in meta["supported_services"]
            ]

            if cat_match or svc_match:
                plugins_to_run.append(name)
                running_tasks.append(meta["name"])

        if not plugins_to_run:
            print(
                f"\n[!] No plugins found matching filter -> Category: {args.category} | Service: {args.service}\n"
            )
            return

        print(
            f"\n Selective Scan Active: Running {len(plugins_to_run)} matched plugin(s)..."
        )

    # Run Scan Engine
    engine = ScanEngine(session=session, plugins_to_run=plugins_to_run)
    all_findings, metadata = engine.run()

    end_time = datetime.now()

    # 2. Trigger Reporting Engine if --report flag is passed
    if args.report:
        bucket_count = metadata.get("bucket_count", 0)

        # Terminal Summary Table
        print_summary(all_findings, bucket_count, start_time, end_time)

        # HTML & JSON Exporters
        export_to_html(all_findings, running_tasks)
        export_to_json(all_findings, running_tasks)


def main():
    help_epilog = """
Examples:
  # Execute full scan across all services and generate reports:
  python3 cloudguard.py scan --report

  # Run scan filtered specifically for S3 service checks:
  python3 cloudguard.py scan --service s3 --report

  # Run scan filtered specifically for Identity category plugins:
  python3 cloudguard.py scan --category Identity --report

  # Inspect all loaded plugins, IDs, and metadata:
  python3 cloudguard.py plugins list
    """

    parser = argparse.ArgumentParser(
        prog="cloudguard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=" CloudGuard - Modular AWS Security Assessment Scanner",
        epilog=help_epilog,
    )

    subparsers = parser.add_subparsers(
        dest="subcommand", help="Available CloudGuard subcommands"
    )

    # --- SUBCOMMAND: scan ---
    scan_parser = subparsers.add_parser(
        "scan", help="Execute AWS infrastructure security assessment"
    )
    scan_parser.add_argument(
        "--report",
        action="store_true",
        help="Print summary risk metrics table and export HTML/JSON reports",
    )
    scan_parser.add_argument(
        "--category",
        type=str,
        metavar="<cat>",
        help="Filter scan by category (e.g., S3, IAM, Storage, Identity)",
    )
    scan_parser.add_argument(
        "--service",
        type=str,
        metavar="<svc>",
        help="Filter scan by AWS service (e.g., s3, iam)",
    )
    scan_parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help="AWS-compatible endpoint URL, e.g. LocalStack http://localhost:4566"
        
    )

    # --- SUBCOMMAND GROUP: plugins ---
    plugins_parser = subparsers.add_parser(
        "plugins", help="Manage and inspect CloudGuard plugins"
    )
    plugins_subparsers = plugins_parser.add_subparsers(dest="plugin_command")

    # cloudguard plugins list
    plugins_subparsers.add_parser(
        "list", help="List all registered plugins and their metadata"
    )

    # Backwards compatibility support for top-level `--scan` flag
    parser.add_argument(
        "--scan", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--report", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--category", type=str, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--service", type=str, help=argparse.SUPPRESS
    )

    args = parser.parse_args()

    # Dispatch subcommand logic
    if args.subcommand == "plugins":
        if args.plugin_command == "list":
            handle_plugins_list(args)
        else:
            plugins_parser.print_help()
    elif args.subcommand == "scan" or args.scan:
        handle_scan(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()