from datetime import datetime, timezone
from plugin_manager import PluginInterface
from cloudguard.findings import Finding



class Plugin(PluginInterface):
    # --- METADATA PROPERTIES ---
    @property
    def name(self) -> str:
        return "IAM Access Key Usage Audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Scans active IAM user access keys to flag unused credentials or keys inactive > 90 days."

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
        iam_client = context.get("iam_client") or context["session"].client('iam')

        return self.check_access_key_last_used(iam_client)

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

                    resource_id = f"User: {username} "

                    if not last_used_date:
                        findings.append(
                            Finding(
                                check="IAM Access Key Usage",
                                category="IAM",
                                resource=resource_id,
                                passed=False,
                                severity="HIGH",
                                issue=f"Active Access Key {key_id} has NEVER been used.",
                                recommendation="Deactivate or delete unused IAM access keys to reduce attack surface."
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
                                    issue=f"Access key inactive for {days_unused} days (Threshold: 90 days).",
                                    recommendation="Rotate or disable stale credentials."
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
                                    issue=f"Key active and used recently ({days_unused} days ago).",
                                    recommendation="No action required."
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
                    recommendation="Verify iam:ListUsers and iam:GetAccessKeyLastUsed permissions."
                )
            )

        return findings