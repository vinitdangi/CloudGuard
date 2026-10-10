from cloudguard.aws.s3_scanner import list_buckets
from cloudguard.findings import Finding
from plugin_manager import PluginInterface


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "S3 Server Access Logging Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Checks whether S3 Server Access Logging is configured."

    @property
    def category(self) -> str:
        return "S3"

    @property
    def supported_services(self) -> list:
        return ["s3"]

    @property
    def default_severity(self) -> str:
        return "HIGH"

    def execute(self, context: dict) -> list:
        s3_client = context.get("s3_client")
        if not s3_client and "session" in context:
            s3_client = context["session"].client("s3")

        if not s3_client:
            return []

        buckets = list_buckets(s3_client) or []
        findings = []

        for bucket_name in buckets:
            finding = self.check_bucket_logging(bucket_name, s3_client)
            if finding:
                findings.append(finding)

        return findings

    def check_bucket_logging(self, bucket_name: str, s3_client):
        try:
            response = s3_client.get_bucket_logging(Bucket=bucket_name)
        except Exception as e:
            return Finding(
                check="Bucket Logging",
                category="S3",
                resource=bucket_name,
                passed=False,
                severity="MEDIUM",
                issue=f"Failed to fetch configuration: {str(e)}",
                recommendation="Verify IAM permissions for s3:GetBucketLogging.",
            )

        if not response or "LoggingEnabled" not in response:
            return Finding(
                check="Bucket Logging",
                category="S3",
                resource=bucket_name,
                passed=False,
                severity="HIGH",
                issue="Server access logging is not enabled on this bucket.",
                recommendation="Enable S3 Server Access Logging and configure a dedicated log bucket.",
            )

        return Finding(
            check="Bucket Logging",
            category="S3",
            resource=bucket_name,
            passed=True,
            severity=None,
            issue="Bucket logging is configured correctly.",
            recommendation="No action required.",
        )