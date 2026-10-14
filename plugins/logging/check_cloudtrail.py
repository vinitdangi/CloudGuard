from cloudguard.findings import Finding
from plugin_manager import PluginInterface


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "CloudTrail Logging Check"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Vinit Dangi"

    @property
    def description(self) -> str:
        return "Checks whether AWS CloudTrail logging is enabled."

    @property
    def category(self) -> str:
        return "Logging"

    @property
    def supported_services(self) -> list[str]:
        return ["cloudtrail"]

    @property
    def default_severity(self) -> str:
        return "HIGH"

    def execute(self, context: dict) -> list:
        session = context["session"]
        cloudtrail_client = session.client("cloudtrail")

        findings = []

        try:
            trails = cloudtrail_client.describe_trails(
                includeShadowTrails=False
            ).get("trailList", [])

            if not trails:
                findings.append(
                    Finding(
                        finding_id="CLOUDTRAIL-001",
                        check="CloudTrail Logging",
                        resource="AWS Account",
                        passed=False,
                        severity="HIGH",
                        category="Logging",
                        issue="No CloudTrail trail is configured.",
                        recommendation=(
                            "Create and enable an AWS CloudTrail trail "
                            "to record API activity and security events."
                        ),
                        impact=(
                            "Without CloudTrail logging, security events "
                            "and suspicious API activity may not be recorded."
                        ),
                        evidence={"trail_count": 0},
                    )
                )
                return findings

            active_trails = []

            for trail in trails:
                trail_arn = trail.get("TrailARN")

                if not trail_arn:
                    continue

                status = cloudtrail_client.get_trail_status(
                    Name=trail_arn
                )

                if status.get("IsLogging"):
                    active_trails.append(trail_arn)

            if active_trails:
                findings.append(
                    Finding(
                        finding_id="CLOUDTRAIL-002",
                        check="CloudTrail Logging",
                        resource="AWS Account",
                        passed=True,
                        severity="HIGH",
                        category="Logging",
                        issue="CloudTrail logging is enabled.",
                        recommendation="No action required.",
                        impact="CloudTrail is recording AWS API activity.",
                        evidence={
                            "trail_count": len(trails),
                            "active_trails": len(active_trails),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        finding_id="CLOUDTRAIL-003",
                        check="CloudTrail Logging",
                        resource="AWS Account",
                        passed=False,
                        severity="HIGH",
                        category="Logging",
                        issue="CloudTrail trails exist, but logging is disabled.",
                        recommendation=(
                            "Enable logging for at least one CloudTrail trail "
                            "to continuously record AWS API activity."
                        ),
                        impact=(
                            "Disabled CloudTrail logging reduces visibility "
                            "into security events and API activity."
                        ),
                        evidence={
                            "trail_count": len(trails),
                            "active_trails": 0,
                        },
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    finding_id="CLOUDTRAIL-004",
                    check="CloudTrail Logging",
                    resource="AWS Account",
                    passed=False,
                    severity="HIGH",
                    category="Logging",
                    issue="Unable to check CloudTrail logging because AWS returned an error.",
                    recommendation=(
                        "Verify CloudTrail permissions and AWS account configuration."
                    ),
                    impact="CloudTrail logging status could not be verified.",
                    evidence={"error_type": type(e).__name__},
                )
            )

        return findings
