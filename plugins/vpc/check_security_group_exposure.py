from plugin_manager import PluginInterface
from cloudguard.findings import Finding
from cloudguard.constants import PORTS, ADMIN_PORTS,DATABASE_PORTS,PUBLIC_WEB_PORTS
from rich import print
from cloudguard.compliance.cis_aws import cis_reference

class Plugin(PluginInterface):
    # --- METADATA PROPERTIES ---
    @property
    def name(self) -> str:
        return "VPC Security Group Exposure Check"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Check the exposure of VPC Security Groups."

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

        return self.get_all_security_groups(ec2_client)



    def get_all_security_groups(self,ec2_client)->list:
        sg_audit=ec2_client.describe_security_groups().get("SecurityGroups",[])
        findings=[]

        for sg in sg_audit:
            sg_id=sg.get("GroupId",'')
            sg_name=sg.get("GroupName",'')
            inbound_rules=sg.get("IpPermissions",[])
            # iteration through each Security Rule
            for rule in inbound_rules:
                ip_protocol=rule.get("IpProtocol",'')
                from_port=rule.get("FromPort")
                to_port=rule.get("ToPort")
                # get all cidrs
                ipv4_sources=[r.get("CidrIp") for r in rule.get("IpRanges",[])]
                ipv6_sources=[r.get("CidrIpv6") for r in rule.get("Ipv6Ranges",[])]
                is_ipv4_public='0.0.0.0/0' in ipv4_sources
                is_ipv6_public='::/0' in ipv6_sources

                is_all_traffic=ip_protocol=='-1'


                if is_ipv4_public and (is_all_traffic):

                    findings.append(
                        Finding(

                            check="Security Group Exposure",
                            category="VPC",
                            resource=f"SecurityGroup: {sg_id} [{sg_name}]",
                            passed=False,
                            severity="CRITICAL",
                            issue=f"Entire inbound IPv4 space and  all protocols",
                            recommendation=""" 0.0.0.0/0->-1
                            -Delete it immediately—restrict traffic strictly to required ports (443/80)
                            -Lock down management access (SSH/RDP) to your VPN or private IPs
                            -Terminate public traffic behind a load balancer""" ),
                        
                        
                        )
                            

                if is_ipv6_public and (is_all_traffic):

                    findings.append(
                        Finding(
                            check="Security Group Exposure",
                            category="VPC",
                            resource=f"SecurityGroupId: {sg_id} [{sg_name}]",
                            passed=False,
                            severity="CRITICAL",
                            issue=f"Entire IPv6 space  and  all protocols",
                            recommendation=""" ::/0 ->-1
                            -Delete immediately
                            -Apply the same strict per-port rules
                            -Block direct global inbound routing to backend resources using Egress-Only -Internet -Gateways
                            -Eliminate untracked dual-stack exposure
                            """))
                matched_ports=[]
                if ip_protocol=='tcp' and from_port is not None and to_port is not None:
                    if is_ipv4_public or is_ipv6_public:
                        matched_ports=[ p for p  in PORTS if from_port <= p <= to_port]

                for port in matched_ports:
                    if port in DATABASE_PORTS:
                        findings.append(Finding(
                            check="Security Group Exposure",
                            category="VPC",
                            resource=f"SecurityGroupId: {sg_id} [{sg_name}]",
                            passed=False,
                            severity="CRITICAL",
                            issue=f"Public database access [Port:{port}]",
                            recommendation=f""" 0.0.0.0/0 → Database
                            -Remove it immediately
                            -Place the database in a private subnet
                            -Restrict ingress strictly to your application tier's security group or internal -CIDR (port 3306/5432) with no public IP assigned
                            """))
                    elif port in ADMIN_PORTS:
                        compliance_refs = []
                        
                        if is_ipv4_public:
                            compliance_refs.append(cis_reference("sg_remote_admin_ipv4"))
                        if is_ipv6_public:
                            compliance_refs.append(cis_reference("sg_remote_admin_ipv6"))
                        findings.append(Finding(
                            check="Security Group Exposure",
                            category="VPC",
                            resource=f"SecurityGroupId: {sg_id} [{sg_name}]",
                            passed=False,
                            severity="CRITICAL",
                            issue=f" Public administrative access [Port:{port}]",
                            recommendation=f""" 0.0.0.0/0 → Port {port}
                            -Delete public access immediately to prevent automated brute-force
                            -Credential stuffing
                            -Zero-day exploits on your administrative interfaces.
                            """,compliance=compliance_refs
                            ))
                    else:
                        # by default
                        pass_status=False
                        issue_status=''
                        severity_status=''
                        if port in PUBLIC_WEB_PORTS:
                            if port ==80:
                                pass_status=False
                                issue_status=f'Common public application endpoint [Port:{port}]'
                                severity_status='LOW'
                            else:
                                pass_status=True
                                issue_status='No Security Group misconfiguration detected by this rule'
                                severity_status=''
                        findings.append(Finding(
                            check="Security Group Exposure",
                            category="VPC",
                            resource=f"SecurityGroupId: {sg_id} [{sg_name}]",
                            passed=pass_status,
                            severity=severity_status,
                            issue=issue_status,
                            recommendation=f""" 0.0.0.0/0 → Port {port}
                            -No Action Needed
                            """,))
        return findings

