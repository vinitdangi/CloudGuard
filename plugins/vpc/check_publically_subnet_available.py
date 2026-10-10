from plugin_manager import PluginInterface
from cloudguard.findings import Finding

class Plugin(PluginInterface):
    # --- METADATA PROPERTIES ---
    @property
    def name(self) -> str:
        return "Public Subnet Exposure Check"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Check whether subnets have both public IP auto-assignment and an Internet Gateway route"

    @property
    def category(self) -> str:
        return "VPC"

    @property
    def supported_services(self) -> list:
        return ["vpc"]

    @property
    def default_severity(self) -> str:
        return "HIGH"

    @property
    def dependencies(self) -> list:
        return []
    # --- EXECUTION ENGINE ---
    def execute(self, context: dict) -> list:
        ec2_client = context.get("ec2") or context["session"].client('ec2')
        return self.subnet_exposure_checker(ec2_client)
    def check_map_on_launch(self,subnets,route_table_subnet_id='SubnetId'):
        for map_on_launch in subnets:
            subnet_id=map_on_launch.get('SubnetId')
            if route_table_subnet_id==subnet_id:
                return map_on_launch.get("MapPublicIpOnLaunch",False)
    def subnet_list(self,subnets):
        subnets_ids=[]
        for single_subnet in subnets:
            subnets_ids.append(single_subnet.get("SubnetId",''))
        return subnets_ids
    def subnet_exposure_checker(self,ec2_client):
        routes_tables=ec2_client.describe_route_tables()['RouteTables']
        subnets=ec2_client.describe_subnets()["Subnets"]
        findings=[]
        subnets_ids=self.subnet_list(subnets)
        for subnet_id in subnets_ids:
            explicit_route_table=None
            main_route_table=None
            route_table_id=None
            has_internet_route = False
            for single_rt_id in routes_tables:
                for association in single_rt_id.get("Associations",[]):
                    if association.get("SubnetId")==subnet_id:
                        explicit_route_table=association.get("RouteTableId",'')
                        break
                    if association.get("Main")==True:
                        main_route_table=association.get("RouteTableId","")
            if explicit_route_table:
                route_table_id = explicit_route_table
            elif main_route_table:
                route_table_id = main_route_table
            for single_route_table in routes_tables:
                if single_route_table.get("RouteTableId")==route_table_id:
                    for route in single_route_table.get("Routes",[]):
                        cidr=route.get("DestinationCidrBlock")
                        gateway=route.get("GatewayId")
                        if cidr== '0.0.0.0/0' and gateway and gateway.startswith('igw-'):
                            has_internet_route = True
                            is_publically_map=self.check_map_on_launch(subnets,subnet_id)
                            if has_internet_route and is_publically_map: #true true
                                findings.append(Finding(
                                    check="Route to an Internet Gateway",
                                    category="VPC",
                                    resource=f"SubnetId: {subnet_id} RouteTableId: {route_table_id}",
                                    passed=False,
                                    issue=f''' Subnet: [{subnet_id}] has a route to an Internet Gateway and enables automatic public IPv4 assignment''',
                                    recommendation='''
                                    Disable auto-assign public IP by setting MapPublicIpOnLaunch to False
                                    Move backend services/databases to a private subnet routed to a NAT Gateway
                                    Restrict inbound Security Group rules to specific trusted CIDRs instead of 0.0.0.0/0''',
                                    severity="CRITICAL"
                                ))
        return findings
