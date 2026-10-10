import boto3
from moto import mock_aws
from plugins.s3.check_bucket_public_block import Plugin

@mock_aws
def test_public_block_missing_is_flagged():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-no-block-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)

    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)

    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is False

@mock_aws
def test_public_block_enabled_passes():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-blocked-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    
    fake_s3.put_public_access_block(
        Bucket=fake_bucket,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)

    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is True