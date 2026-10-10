from cloudguard.findings import Finding
from plugin_manager import PluginInterface
from cloudguard.aws.s3_scanner import list_buckets


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "S3 Bucket ACL Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Checks S3 default Access Control Lists for public exposures."

    @property
    def category(self) -> str:
        return "S3"

    @property
    def supported_services(self) -> list:
        return ["s3"]

    @property
    def default_severity(self) -> str:
        return "HIGH"

    @property
    def dependencies(self) -> list:
        return []

    def execute(self, context: dict) -> list:
        # Extract s3_client from context
        s3_client = context.get("s3_client")
        if not s3_client and "session" in context:
            s3_client = context["session"].client("s3")

        if not s3_client:
            return []

        buckets = list_buckets(s3_client) or []
        findings = []

        for bucket_name in buckets:
            finding = self.check_bucket_acl(bucket_name, s3_client)
            if finding:
                findings.append(finding)

        return findings

    def check_bucket_acl(self, bucket_name, s3_client) -> Finding:
        try:
            response = s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response.get("Grants", [])

            for grant in grants:
                if not isinstance(grant, dict):
                    continue
                grantee = grant.get("Grantee", {})

                if grantee.get("Type") == "Group":
                    group_uri = grantee.get("URI", "")

                    if "AllUsers" in group_uri:
                        return Finding(
                            check="Bucket ACL",
                            category="S3",
                            resource=bucket_name,
                            passed=False,
                            severity="HIGH",
                            issue="Insecure ACL exposed to Public Anonymous Access (AllUsers)",
                            recommendation="Disable ACLs entirely by enabling S3 Object Ownership."
                        )
                    elif "AuthenticatedUsers" in group_uri:
                        return Finding(
                            check="Bucket ACL",
                            category="S3",
                            resource=bucket_name,
                            passed=False,
                            severity="MEDIUM",
                            issue="Insecure ACL exposed to Any Authenticated AWS User",
                            recommendation="Restrict ACL permissions to specific AWS principals."
                        )

            return Finding(
                check="Bucket ACL",
                category="S3",
                resource=bucket_name,
                passed=True,
                severity=None,
                issue="ACL secure. Only owner has access.",
                recommendation="No action required."
            )

        except Exception as e:
            return Finding(
                check="Bucket ACL",
                category="S3",
                resource=bucket_name,
                passed=False,
                severity="MEDIUM",
                issue=f"Failed to evaluate ACL: {str(e)}",
                recommendation="Verify s3:GetBucketAcl permissions."
            )