CIS_BENCHMARK = {
    "name": "CIS Amazon Web Services Foundations Benchmark",
    "version": "7.0.0",
}

CIS_CONTROLS = {
    "iam_user_mfa": {
        "control_id": "2.10",
        "title": (
            "Ensure multi-factor authentication (MFA) is enabled "
            "for all IAM users that have a console password"
        ),
        "mapping": "partial",
        "note": (
            "The current CloudGuard check evaluates all IAM users. "
            "It does not yet restrict the assessment to users with a console password."
        ),
    },

    "s3_public_access_block": {
        "control_id": "3.1.4",
        "title": (
            "Ensure that S3 is configured with "
            "'Block Public Access' enabled"
        ),
        "mapping": "exact",
        "note": "",
    },

    "nacl_remote_admin_ipv4": {
        "control_id": "6.2",
        "title": (
            "Ensure no Network ACLs allow ingress from 0.0.0.0/0 "
            "to remote server administration ports"
        ),
        "mapping": "exact",
        "note": "",
    },

    "sg_remote_admin_ipv4": {
        "control_id": "6.3",
        "title": (
            "Ensure no security groups allow ingress from 0.0.0.0/0 "
            "to remote server administration ports"
        ),
        "mapping": "exact",
        "note": "",
    },

    "sg_remote_admin_ipv6": {
        "control_id": "6.4",
        "title": (
            "Ensure no security groups allow ingress from ::/0 "
            "to remote server administration ports"
        ),
        "mapping": "exact",
        "note": "",
    },
}


def get_cis_control(control_key):
    return CIS_CONTROLS.get(control_key)


def cis_reference(control_key):
    control = get_cis_control(control_key)

    if control is None:
        raise KeyError(f"Unknown CIS control: {control_key}")

    return {
        "framework": CIS_BENCHMARK["name"],
        "version": CIS_BENCHMARK["version"],
        "control_id": control["control_id"],
        "title": control["title"],
        "mapping": control["mapping"],
        "note": control["note"],
    }

