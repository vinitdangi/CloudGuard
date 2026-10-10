import json
from botocore.exceptions import ClientError
from cloudguard.aws.s3_scanner import list_buckets
from cloudguard.findings import Finding
from plugin_manager import PluginInterface


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "S3 Bucket Policy Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Audits S3 bucket policies for overly permissive public exposure."

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
            finding = self.check_bucket_policy(bucket_name, s3_client)
            if finding:
                findings.append(finding)

        return findings

    def check_bucket_policy(self, bucket_name: str, s3_client):
        try:
            response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response["Policy"])

            for statement in policy.get("Statement", []):
                principal = statement.get("Principal", {})
                effect = statement.get("Effect", "")

                is_public_principal = (
                    principal == "*"
                    or (isinstance(principal, dict) and principal.get("AWS") == "*")
                    or (
                        isinstance(principal, dict)
                        and "*" in principal.get("AWS", [])
                    )
                )

                if is_public_principal and effect == "Allow":
                    condition = statement.get("Condition", {})

                    if not condition:
                        return Finding(
                            check="Bucket Policy",
                            category="S3",
                            resource=bucket_name,
                            passed=False,
                            severity="CRITICAL",
                            issue="Bucket policy allows unauthenticated public access",
                            recommendation="Restrict Principal to specific IAM identities or implement strict Conditions.",
                        )

            return Finding(
                check="Bucket Policy",
                category="S3",
                resource=bucket_name,
                passed=True,
                severity=None,
                issue="Bucket policy is safe or contains secure restrictions.",
                recommendation="No action needed.",
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return Finding(
                    check="Bucket Policy",
                    category="S3",
                    resource=bucket_name,
                    passed=True,
                    severity=None,
                    issue="No explicit bucket policy attached (Safe by default if public access blocks are active).",
                    recommendation="No action needed.",
                )
            raise e