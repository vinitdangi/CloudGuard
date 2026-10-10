import os
import pytest
import boto3
from moto import mock_aws
from plugins.s3.check_bucket_encryption import Plugin as EncryptionPlugin
from plugins.s3.check_bucket_versioning import Plugin as VersioningPlugin

@pytest.fixture(scope="function", autouse=True)
def aws_credentials():
    """Sets dummy environment variables so Boto3 never hits real AWS."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@mock_aws
def test_encryption_check_with_fake_aws():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-vulnerable-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    
    plugin = EncryptionPlugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is False

@mock_aws
def test_versioning_disabled_is_flagged():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-unversioned-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)

    plugin = VersioningPlugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)

    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is False

@mock_aws
def test_versioning_enabled_passes():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-versioned-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    fake_s3.put_bucket_versioning(
        Bucket=fake_bucket,
        VersioningConfiguration={"Status": "Enabled"}
    )

    plugin = VersioningPlugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)

    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is True