import json
import boto3
from moto import mock_aws
from plugins.s3.check_bucket_policy import Plugin

@mock_aws
def test_policy_public_is_flagged():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-public-policy-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{fake_bucket}/*"
        }]
    }
    fake_s3.put_bucket_policy(Bucket=fake_bucket, Policy=json.dumps(public_policy))
    
    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is False

@mock_aws
def test_policy_missing_passes():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-no-policy-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    
    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target = next((f for f in findings if f.resource == fake_bucket), None)
    assert target is not None
    assert target.passed is True