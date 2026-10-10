from botocore.exceptions import ClientError
from cloudguard.aws.s3_scanner import list_buckets
from cloudguard.findings import Finding
from plugin_manager import PluginInterface


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "S3 Bucket Encryption Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Checks S3 default server-side encryption settings."

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
            finding = self.check_bucket_encryption(bucket_name, s3_client)
            if finding:
                findings.append(finding)

        return findings

    def check_bucket_encryption(self, bucket_name: str, s3_client):
        try:
            response = s3_client.get_bucket_encryption(Bucket=bucket_name)

            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )

            if not rules:
                return Finding(
                    check="Bucket Encryption",
                    category="S3",
                    resource=bucket_name,
                    passed=False,
                    severity="HIGH",
                    issue="Bucket Encryption Disabled",
                    recommendation="Enable S3 Default Encryption (SSE-S3 or SSE-KMS).",
                )

            return Finding(
                check="Bucket Encryption",
                category="S3",
                resource=bucket_name,
                passed=True,
                severity=None,
                issue="Bucket encryption is enabled and active.",
                recommendation="No action required.",
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                return Finding(
                    check="Bucket Encryption",
                    category="S3",
                    resource=bucket_name,
                    passed=False,
                    severity="HIGH",
                    issue="Bucket Encryption Disabled",
                    recommendation="Enable S3 Default Encryption (SSE-S3 or SSE-KMS).",
                )

            elif error_code == "NoSuchBucket":
                return None

            else:
                raise