import boto3
from moto import mock_aws
from plugins.s3.check_bucket_acl import Plugin

@mock_aws
def test_acl_public_allusers_is_flagged():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-public-acl-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    fake_s3.put_bucket_acl(
        Bucket=fake_bucket,
        AccessControlPolicy={
            "Owner": {"ID": "owner-id"},
            "Grants": [{
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                },
                "Permission": "READ"
            }]
        }
    )
    
    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target_finding = next((f for f in findings if f.resource == fake_bucket), None)
    assert target_finding is not None
    assert target_finding.passed is False

@mock_aws
def test_acl_private_passes():
    fake_s3 = boto3.client("s3", region_name="us-east-1")
    fake_bucket = "my-fake-private-acl-bucket"
    fake_s3.create_bucket(Bucket=fake_bucket)
    
    plugin = Plugin()
    context = {"s3_client": fake_s3}
    findings = plugin.execute(context)
    
    target_finding = next((f for f in findings if f.resource == fake_bucket), None)
    assert target_finding is not None
    assert target_finding.passed is True