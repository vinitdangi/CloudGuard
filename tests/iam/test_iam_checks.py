import os

import boto3
import pytest
from moto import mock_aws

from plugins.iam.check_user_mfa import Plugin as MfaPlugin
from plugins.iam.check_access_last_used import Plugin as AccessKeyPlugin


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def iam_client():
    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")



def test_iam_user_without_mfa_is_flagged(iam_client):

    test_user = "vulnerable-no-mfa-user"

    iam_client.create_user(UserName=test_user)

    plugin = MfaPlugin()

    context = {
        "iam_client": iam_client
    }

    findings = plugin.execute(context)

    target_finding = next(
        (finding for finding in findings if test_user in str(finding.resource)),
        None,
    )

    assert target_finding is not None
    assert target_finding.passed is False


def test_iam_user_with_mfa_passes(iam_client):
    test_user = "secure-mfa-user"

    iam_client.create_user(UserName=test_user)

    iam_client.enable_mfa_device(
        UserName=test_user,
        SerialNumber=f"arn:aws:iam::123456789012:mfa/{test_user}",
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    plugin = MfaPlugin()

    context = {
        "iam_client": iam_client
    }

    findings = plugin.execute(context)

    target_finding = next(
        (finding for finding in findings if test_user in str(finding.resource)),
        None,
    )

    assert target_finding is not None
    assert target_finding.passed is True

@mock_aws
def test_unused_access_key_is_flagged(monkeypatch):
    iam_client = boto3.client("iam", region_name="us-east-1")

    test_user = "stale-key-user"

    iam_client.create_user(UserName=test_user)

    key_response = iam_client.create_access_key(
        UserName=test_user
    )

    access_key_id = key_response["AccessKey"]["AccessKeyId"]

    def mock_get_access_key_last_used(*args, **kwargs):
        return {
            "UserName": test_user,
            "AccessKeyLastUsed": {}
        }

    monkeypatch.setattr(iam_client,"get_access_key_last_used",mock_get_access_key_last_used,)

    plugin = AccessKeyPlugin()

    context = {
        "iam_client": iam_client
    }

    findings = plugin.execute(context)

    target_finding = next(
        (
            finding
            for finding in findings
            if test_user in str(finding.resource)
        ),
        None,
    )

    assert target_finding is not None
    assert target_finding.passed is False
    assert target_finding.severity == "HIGH"
    assert access_key_id in target_finding.issue

def test_iam_user_without_keys_passes(iam_client):

    test_user = "keyless-user"

    iam_client.create_user(UserName=test_user)

    plugin = AccessKeyPlugin()

    context = {
        "iam_client": iam_client
    }

    findings = plugin.execute(context)

    target_finding = next(
        (
            finding
            for finding in findings
            if test_user in str(finding.resource)
        ),
        None,
    )

    if target_finding is not None:
        assert target_finding.passed is True
