"""Temporary AWS connection configuration for the CloudGuard dashboard."""

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ReadTimeoutError,
)

from cloudguard.aws.session import create_session

AUTH_METHOD_ACCESS_KEY = "Access Key"
AUTH_METHOD_ENVIRONMENT = "Existing AWS Environment Credentials"
AUTH_METHODS = (AUTH_METHOD_ACCESS_KEY, AUTH_METHOD_ENVIRONMENT)

AWS_REGIONS = (
    "ap-southeast-2",
    "ap-southeast-1",
    "ap-southeast-3",
    "ap-south-1",
    "ap-south-2",
    "ca-central-1",
    "eu-central-1",
    "eu-north-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "me-central-1",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
)

AWS_SESSION_STATE_KEYS = (
    "aws_auth_method",
    "aws_region",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_connection_verified",
    "aws_account_id",
)


class AWSConfigurationError(ValueError):
    """Raised when AWS connection inputs are incomplete or unsupported."""


def validate_aws_configuration(
    auth_method: str,
    region: str,
    access_key_id: str = "",
    secret_access_key: str = "",
) -> None:
    """Validate the selected AWS authentication mode and region."""
    if auth_method not in AUTH_METHODS:
        raise AWSConfigurationError("Choose a supported AWS authentication method.")
    if region not in AWS_REGIONS:
        raise AWSConfigurationError("Choose a supported AWS region.")
    if auth_method == AUTH_METHOD_ACCESS_KEY:
        if not access_key_id.strip():
            raise AWSConfigurationError("Enter an AWS Access Key ID.")
        if not secret_access_key:
            raise AWSConfigurationError("Enter an AWS Secret Access Key.")


def create_aws_session(
    auth_method: str,
    region: str,
    access_key_id: str = "",
    secret_access_key: str = "",
):
    """Build a CloudGuard session without persisting supplied credentials."""
    validate_aws_configuration(auth_method, region, access_key_id, secret_access_key)
    if auth_method == AUTH_METHOD_ACCESS_KEY:
        return create_session(
            region=region,
            aws_access_key_id=access_key_id.strip(),
            aws_secret_access_key=secret_access_key,
        )
    return create_session(region=region)


def test_aws_connection(session) -> str:
    """Validate AWS authentication with STS and return the safe account ID."""
    identity = session.client("sts").get_caller_identity()
    account_id = identity.get("Account")
    if not account_id:
        raise RuntimeError("AWS did not return an account identifier.")
    return str(account_id)


def safe_connection_error(error: Exception) -> str:
    """Map AWS errors to user-safe messages without exposing exception text."""
    if isinstance(error, NoCredentialsError):
        return "No AWS credentials were found. Configure credentials or choose Access Key mode."
    if isinstance(error, (ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError)):
        return "Could not reach AWS. Check the network and selected region, then try again."
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code in {
            "InvalidClientTokenId",
            "SignatureDoesNotMatch",
            "UnrecognizedClientException",
            "ExpiredToken",
            "AuthFailure",
        }:
            return "Unable to authenticate with AWS. Verify the credentials and region."
        if code in {"AccessDenied", "AccessDeniedException"}:
            return "AWS credentials could not call STS GetCallerIdentity. Check the account policy."
    if error.__class__.__name__ in {"InvalidRegionError", "UnknownEndpointError"}:
        return "The selected AWS region is unavailable. Choose a supported region."
    return "AWS connection failed. Verify credentials, region, network access, and permissions."


def clear_aws_session_state(session_state) -> None:
    """Remove AWS credentials and connection status from Streamlit state."""
    for key in AWS_SESSION_STATE_KEYS:
        session_state.pop(key, None)
