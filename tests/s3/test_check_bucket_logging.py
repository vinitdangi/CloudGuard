import boto3
from moto import mock_aws
from plugins.s3.check_bucket_logging import Plugin

@mock_aws
def test_logging_disabled_is_flagged():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-unlogged-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    
    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is False

@mock_aws
def test_logging_enabled_passes():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-logged-bucket"
    target_bucket = "my-fake-target-log-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    fake_s3.create_bucket(Bucket=target_bucket)

    fake_s3.put_bucket_acl(
        Bucket=target_bucket,
        AccessControlPolicy={
            "Owner": {"ID": "owner-id"},
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "WRITE"
                },
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "READ_ACP"
                }
            ]
        }
    )

    fake_s3.put_bucket_logging(
        Bucket=fake_bucket,
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": target_bucket,
                "TargetPrefix": "logs/"
            }
        }
    )
    
    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is True