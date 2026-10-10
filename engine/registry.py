from cloudguard.aws.s3_scanner import scan_s3_buckets
from cloudguard.aws.iam_scanner import scan_iam

SCANNERS = {
    "s3": scan_s3_buckets,
    "iam": scan_iam,
}