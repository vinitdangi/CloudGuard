from botocore.exceptions import ClientError
from cloudguard.aws.s3_scanner import list_buckets
from cloudguard.findings import Finding
from plugin_manager import PluginInterface
from cloudguard.compliance.cis_aws import cis_reference


class Plugin(PluginInterface):
    @property
    def name(self) -> str:
        return "S3 Public Access Block Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Verifies S3 Public Access Block settings."

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
            finding = self.check_public_access_block(bucket_name, s3_client)
            if finding:
                findings.append(finding)

        return findings

    def check_public_access_block(self, bucket_name: str, s3_client):
        try:
            response = s3_client.get_public_access_block(Bucket=bucket_name)
            PAB_config = response["PublicAccessBlockConfiguration"]

            block_acls = PAB_config.get("BlockPublicAcls", False)
            ignore_acls = PAB_config.get("IgnorePublicAcls", False)
            block_policy = PAB_config.get("BlockPublicPolicy", False)
            restrict_buckets = PAB_config.get("RestrictPublicBuckets", False)

            if not (
                block_acls and ignore_acls and block_policy and restrict_buckets
            ):
                return Finding(
                    check="Public Access Block",
                    category="S3",
                    resource=bucket_name,
                    passed=False,
                    severity="HIGH",
                    issue="Public Access block is incomplete or disabled.",
                    recommendation="Enable all 4 Public Access Block settings.",
                    compliance=[cis_reference("s3_public_access_block")]
                )

            return Finding(
                check="Public Access Block",
                category="S3",
                resource=bucket_name,
                passed=True,
                severity=None,
                issue="Public access block settings are secure and complete.",
                recommendation="No action required.",
                compliance=[cis_reference("s3_public_access_block")]
            )

        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                return Finding(
                    check="Public Access Block",
                    category="S3",
                    resource=bucket_name,
                    passed=False,
                    severity="HIGH",
                    issue="Public Access block configuration is entirely missing.",
                    recommendation="Deploy standard AWS Public Access Block controls.",
                    compliance=[cis_reference("s3_public_access_block")]
                )
            raise e