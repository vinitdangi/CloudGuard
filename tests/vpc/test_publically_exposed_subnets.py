from unittest.mock import MagicMock

from plugins.vpc.check_publically_subnet_available import Plugin
# first TRUE TRUE
def test_public_subnet_is_flagged():
    fake_ec2 = MagicMock()
    fake_ec2.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-03f0f8d47ff17ce12",
                "MapPublicIpOnLaunch": True,
                "CidrBlock": "172.31.80.0/20",
                "VpcId": "vpc-0eec66f9f63f75712",
            }
        ]
    }
    fake_ec2.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-12345",
                "Associations": [
                    {
                        "SubnetId": "subnet-03f0f8d47ff17ce12",
                        "RouteTableId": "rtb-12345",
                    }
                ],
                "Routes": [
                    {
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-12345",
                    }
                ],
            }
        ]
    }

    plugin = Plugin()
    findings = plugin.subnet_exposure_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False

# TRUE FALSE
def test_public_ip_mapping_without_internet_route_is_not_flagged():
    fake_ec2 = MagicMock()
    fake_ec2.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-03f0f8d47ff17ce12",
                "MapPublicIpOnLaunch": True,
                "CidrBlock": "172.31.80.0/20",
                "VpcId": "vpc-0eec66f9f63f75712",
            }
        ]
    }

    fake_ec2.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-12345",
                "Associations": [
                    {
                        "SubnetId": "subnet-03f0f8d47ff17ce12",
                        "RouteTableId": "rtb-12345",
                    }
                ],
                "Routes": [
                    {
                        # "DestinationCidrBlock": "0.0.0.0/0",
                        # "GatewayId": "igw-12345",
                    }
                ],
            }
        ]
    }

    plugin = Plugin()
    findings = plugin.subnet_exposure_checker(fake_ec2)

    assert len(findings) == 0
    #FALSE TRUE
def test_internet_route_without_public_ip_mapping_is_not_flagged():
    fake_ec2 = MagicMock()
    fake_ec2.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-03f0f8d47ff17ce12",
                "MapPublicIpOnLaunch": False,
                "CidrBlock": "172.31.80.0/20",
                "VpcId": "vpc-0eec66f9f63f75712",
            }
        ]
    }

    fake_ec2.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-12345",
                "Associations": [
                    {
                    "SubnetId": "subnet-03f0f8d47ff17ce12",
                    "RouteTableId": "rtb-12345",
                    }
                ],
                "Routes": [
                    {
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-12345",
                    }
                ],
            }
        ]
    }

    plugin = Plugin()
    findings = plugin.subnet_exposure_checker(fake_ec2)

    assert len(findings) == 0
    #FALSE FALSE
def test_private_subnet_without_internet_route_is_not_flagged():
    fake_ec2 = MagicMock()
    fake_ec2.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-03f0f8d47ff17ce12",
                "MapPublicIpOnLaunch": False,
                "CidrBlock": "172.31.80.0/20",
                "VpcId": "vpc-0eec66f9f63f75712",
            }
        ]
    }

    fake_ec2.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-12345",
                "Associations": [
                    {
                        "SubnetId": "subnet-03f0f8d47ff17ce12",
                        "RouteTableId": "rtb-12345",
                    }
                ],
                "Routes": [
                    {
                        # "DestinationCidrBlock": "0.0.0.0/0",
                        # "GatewayId": "igw-12345",
                    }
                ],
            }
        ]
    }

    plugin = Plugin()
    findings = plugin.subnet_exposure_checker(fake_ec2)

    assert len(findings) == 0
def test_main_route_table_public_subnet_is_flagged():
    fake_ec2 = MagicMock()
    fake_ec2.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-03f0f8d47ff17ce12",
                "MapPublicIpOnLaunch": True,
                "CidrBlock": "172.31.80.0/20",
                "VpcId": "vpc-0eec66f9f63f75712",
            }
        ]
    }

    fake_ec2.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-12345",
                "Associations": [
                    {
                        "Main": True,
                        "RouteTableId": "rtb-12345",
                    }
                ],
                "Routes": [
                    {
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-12345",
                    }
                ],
            }
        ]
    }

    plugin = Plugin()
    findings = plugin.subnet_exposure_checker(fake_ec2)

    assert len(findings) == 1
    assert findings[0].passed is False
