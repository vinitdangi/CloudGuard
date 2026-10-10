from unittest.mock import MagicMock

from plugins.vpc.check_network_Acl_traffic import Plugin


def make_nacl(entries):
    fake_ec2 = MagicMock()

    fake_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "Associations": [
                    {
                        "NetworkAclAssociationId": "nacla-123",
                        "NetworkAclId": "acl-123",
                        "SubnetId": "subnet-123",
                    }
                ],
                "Entries": entries,
                "IsDefault": True,
                "NetworkAclId": "acl-123",
            }
        ]
    }

    return fake_ec2


def make_rule(
    rule_number,
    action="allow",
    protocol="-1",
    cidr_ipv4="",
    cidr_ipv6="",
    egress=False,
    from_port=80,
    to_port=80,
):
    return {
        "CidrBlock": cidr_ipv4,
        "Egress": egress,
        "IcmpTypeCode": {
            "Code": 123,
            "Type": 123,
        },
        "Ipv6CidrBlock": cidr_ipv6,
        "PortRange": {
            "From": from_port,
            "To": to_port,
        },
        "Protocol": protocol,
        "RuleAction": action,
        "RuleNumber": rule_number,
    }


# 1. Public IPv4 ALLOW → finding

def test_public_ipv4_allow_is_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False


# 2. Public IPv4 DENY → no finding
def test_public_ipv4_deny_is_not_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="deny",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 0


# 3. IPv4 DENY before IPv4 ALLOW
#    First matching rule wins
def test_ipv4_deny_before_allow_is_not_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="deny",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        ),
        make_rule(
            200,
            action="allow",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        ),
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 0


# 4. IPv4 ALLOW before IPv4 DENY
#    First matching rule wins
def test_ipv4_allow_before_deny_is_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        ),
        make_rule(
            200,
            action="deny",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        ),
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False


# 5. IPv6 ALLOW → finding

def test_public_ipv6_allow_is_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv6="::/0",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False


# 6. IPv6 DENY → no finding
def test_public_ipv6_deny_is_not_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="deny",
            protocol="-1",
            cidr_ipv6="::/0",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 0


# 7. IPv4 DENY + IPv6 ALLOW
#    Families must be evaluated independently
def test_ipv4_deny_does_not_block_ipv6_allow():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="deny",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        ),
        make_rule(
            200,
            action="allow",
            protocol="-1",
            cidr_ipv6="::/0",
        ),
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False


# 8. IPv4 ALLOW + IPv6 DENY

def test_ipv4_allow_does_not_block_ipv6_deny():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        ),
        make_rule(
            200,
            action="deny",
            protocol="-1",
            cidr_ipv6="::/0",
        ),
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False


# 9. Private IPv4 CIDR → no public finding

def test_private_ipv4_cidr_is_not_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv4="10.0.1.0/24",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 0


# 10. Non-public IPv6 CIDR → no public finding

def test_non_public_ipv6_cidr_is_not_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv6="2001:db8:1234::/48",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 0


# 11. Egress rule → ignored

def test_public_egress_rule_is_not_flagged():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
            egress=True,
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 0


# 12. Protocol -1 → CRITICAL

def test_unrestricted_protocol_is_critical():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="-1",
            cidr_ipv4="0.0.0.0/0",
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


# 13. Public TCP 22 → CRITICAL

def test_public_ssh_is_critical():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="6",
            cidr_ipv4="0.0.0.0/0",
            from_port=22,
            to_port=22,
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


# 14. Public TCP 80 → LOW

def test_public_http_is_low():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="6",
            cidr_ipv4="0.0.0.0/0",
            from_port=80,
            to_port=80,
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].severity == "LOW"


# 15. Public database port → HIGH

def test_public_database_port_is_high():

    fake_ec2 = make_nacl([
        make_rule(
            100,
            action="allow",
            protocol="6",
            cidr_ipv4="0.0.0.0/0",
            from_port=3306,
            to_port=3306,
        )
    ])

    findings = Plugin().network_acl_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"