from cloudguard.compliance.cis_aws import cis_reference
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from plugin_manager import PluginInterface
from cloudguard.findings import Finding


class Plugin(PluginInterface):
    # --- METADATA PROPERTIES ---
    @property
    def name(self) -> str:
        return "IAM Security Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Scans IAM users for active access key age/usage and MFA compliance."

    @property
    def category(self) -> str:
        return "Identity"

    @property
    def supported_services(self) -> list:
        return ["iam"]

    @property
    def default_severity(self) -> str:
        return "HIGH"

    @property
    def dependencies(self) -> list:
        return []

    # --- EXECUTION ENGINE ---
    def execute(self, context: dict) -> list:
        iam_client = context.get("iam_client") or context["session"].client("iam")
        return self.check_user_mfa(iam_client)
        all_findings = []
        
        # 1. Run Access Key Age/Usage Checks
        all_findings.extend(self.check_access_key_last_used(iam_client))
        
        # 2. Run User MFA Checks
        all_findings.extend(self.check_user_mfa(iam_client))

        return all_findings

    def check_access_key_last_used(self, iam_client) -> list:
        findings = []
        try:
            users_response = iam_client.list_users()
            users = users_response.get('Users', [])

            for user in users:
                username = user['UserName']
                keys_response = iam_client.list_access_keys(UserName=username)
                access_keys = keys_response.get('AccessKeyMetadata', [])

                for key in access_keys:
                    key_id = key['AccessKeyId']
                    if key['Status'] != 'Active':
                        continue

                    usage_response = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                    key_data = usage_response.get('AccessKeyLastUsed', {})
                    last_used_date = key_data.get('LastUsedDate')

                    resource_id = f"User: {username} | Key: {key_id}"

                    if not last_used_date:
                        findings.append(
                            Finding(
                                check="IAM Access Key Usage",
                                category="IAM",
                                resource=resource_id,
                                passed=False,
                                severity="HIGH",
                                issue=f"Active Access Key {key_id} has NEVER been used",
                                recommendation="Deactivate or delete unused IAM access keys to reduce attack surface",
                                compliance=[cis_reference("iam_user_mfa")]
                            )
                        )
                    else:
                        days_unused = (datetime.now(timezone.utc) - last_used_date).days
                        if days_unused > 90:
                            findings.append(
                                Finding(
                                    check="IAM Access Key Usage",
                                    category="IAM",
                                    resource=resource_id,
                                    passed=False,
                                    severity="MEDIUM",
                                    issue=f"Access key inactive for {days_unused} days (Threshold: 90 days)",
                                    recommendation="Rotate or disable stale credentials",
                                    compliance=[cis_reference("iam_user_mfa")]
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check="IAM Access Key Usage",
                                    category="IAM",
                                    resource=resource_id,
                                    passed=True,
                                    severity=None,
                                    issue=f"Key active and used recently ({days_unused} days ago)",
                                    recommendation="No action required",
                                    compliance=[cis_reference("iam_user_mfa")]
                                )
                            )

        except Exception as e:
            findings.append(
                Finding(
                    check="IAM Access Key Usage",
                    category="IAM",
                    resource="IAM Service",
                    passed=False,
                    severity="HIGH",
                    issue=f"Failed to scan IAM access keys: {str(e)}",
                    recommendation="Verify iam:ListUsers and iam:GetAccessKeyLastUsed permissions",
                    compliance=[cis_reference("iam_user_mfa")]
                )
            )

        return findings

    def check_user_mfa(self, iam_client) -> list:
        """Check whether IAM users have MFA enabled."""
        findings = []

        try:
            users = iam_client.list_users().get("Users", [])

        except ClientError as e:
            return [
                Finding(
                    check="IAM User MFA",
                    category="IAM",
                    resource="IAM Service",
                    passed=False,
                    severity="HIGH",
                    issue=f"AWS API Error: {e.response['Error']['Message']}",
                    recommendation="Grant 'iam:ListUsers' permission to the CloudGuard IAM user",
                    compliance=[cis_reference("iam_user_mfa")]
                    
                )
            ]

        for user in users:
            username = user["UserName"]
            resource_id = f"User: {username}"

            try:
                mfa_devices = iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])

                if mfa_devices:
                    findings.append(
                        Finding(
                            check="IAM User MFA",
                            category="IAM",
                            resource=resource_id,
                            passed=True,
                            severity=None,
                            issue="MFA is enabled and active",
                            recommendation="No action required",
                            compliance=[cis_reference("iam_user_mfa")]
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check="IAM User MFA",
                            category="IAM",
                            resource=resource_id,
                            passed=False,
                            severity="HIGH",
                            issue=f"MFA is not enabled for IAM user '{username}'",
                            recommendation="Enable MFA for this IAM user",
                            compliance=[cis_reference("iam_user_mfa")]
                        )
                    )

            except ClientError as e:
                findings.append(
                    Finding(
                        check="IAM User MFA",
                        category="IAM",
                        resource=resource_id,
                        passed=False,
                        severity="HIGH",
                        issue=f"Could not check MFA status: {e.response['Error']['Message']}",
                        recommendation="Grant 'iam:ListMFADevices' permission",
                        compliance=[cis_reference("iam_user_mfa")]
                    )
                )

        return findings