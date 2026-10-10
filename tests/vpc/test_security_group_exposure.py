from unittest.mock import MagicMock

from plugins.vpc.check_security_group_exposure import Plugin


def test_public_ssh_is_detected():
    # Arrange
    fake_ec2 = MagicMock()

    fake_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test-001",
                "GroupName": "test-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ],
                        "Ipv6Ranges": [],
                    }
                ],
            }
        ]
    }

    plugin = Plugin()

    # Act
    findings =plugin.get_all_security_groups(fake_ec2)

    # Assert
    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].severity == "CRITICAL"
    assert "22" in findings[0].issue

def test_private_ssh_is_not_public_exposure():
    # Arrange
    fake_ec2 = MagicMock()
    fake_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test-001",
                "GroupName": "test-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "10.0.0.0/16"}
                        ],
                        "Ipv6Ranges": [],
                    }
                ],
            }
        ]
    }

    plugin = Plugin()
    # Act
    findings = plugin.get_all_security_groups(fake_ec2)
    # Assert
    assert findings==[]