from cloudguard.aws.s3_scanner import list_buckets
from cloudguard.findings import Finding
from plugin_manager import PluginInterface


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "S3 Bucket Versioning Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Checks whether S3 bucket versioning is active."

    @property
    def category(self) -> str:
        return "S3"

    @property
    def supported_services(self) -> list:
        return ["s3"]

    @property
    def default_severity(self) -> str:
        return "MEDIUM"

    def execute(self, context: dict) -> list:
        s3_client = context.get("s3_client")
        if not s3_client and "session" in context:
            s3_client = context["session"].client("s3")

        if not s3_client:
            return []

        buckets = list_buckets(s3_client) or []
        findings = []

        for bucket_name in buckets:
            finding = self.check_bucket_versioning(bucket_name, s3_client)
            if finding:
                findings.append(finding)

        return findings

    def check_bucket_versioning(self, bucket_name: str, s3_client):
        try:
            response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "Disabled")

            if status != "Enabled":
                return Finding(
                    check="Bucket Versioning",
                    category="S3",
                    resource=bucket_name,
                    passed=False,
                    severity="MEDIUM",
                    issue="Bucket Versioning Disabled or Suspended",
                    recommendation="Enable S3 Versioning to protect against accidental deletion and ransomware.",
                )

            return Finding(
                check="Bucket Versioning",
                category="S3",
                resource=bucket_name,
                passed=True,
                severity=None,
                issue="Versioning is secure and compliant.",
                recommendation="No action required.",
            )

        except Exception as e:
            return Finding(
                check="Bucket Versioning",
                category="S3",
                resource=bucket_name,
                passed=False,
                severity="MEDIUM",
                issue=f"Failed to check versioning: {str(e)}",
                recommendation="Verify s3:GetBucketVersioning permissions.",
            )