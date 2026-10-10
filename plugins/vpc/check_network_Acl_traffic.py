from cloudguard.findings import Finding
from plugin_manager import PluginInterface
from cloudguard.compliance.cis_aws import cis_reference
from cloudguard.constants import ADMIN_PORTS,DATABASE_PORTS,PUBLIC_WEB_PORTS ,PORTS
class Plugin(PluginInterface):
    # --- METADATA PROPERTIES ---
    @property
    def name(self) -> str:
        return "Network ACL Analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Mohsan"

    @property
    def description(self) -> str:
        return "Network ACL Analyzer for any open world protocol or unbounded traffic detection"

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
        return self.network_acl_checker(ec2_client)

    def network_acl_checker(self,ec2_client):
        nacls=ec2_client.describe_network_acls()["NetworkAcls"]
        findings=[]
        for nacl in nacls:
            NetworkAclId=nacl.get("Associations")[0].get("NetworkAclId")
            # one complete network ACL
            entries= sorted(
                nacl.get("Entries",[]),
                key=lambda entry:entry["RuleNumber"]
            )
            ipv4_evaluated = False
            ipv6_evaluated = False
            for entry in entries:
                protocol=entry.get("Protocol")
                egress=entry.get("Egress",True)
                rule_action=entry.get("RuleAction","deny")
                rule_number=(entry.get("RuleNumber"))
                cidripv4=entry.get("CidrBlock","")
                cidripv6=entry.get("Ipv6CidrBlock","")
                is_public_ipv4_source='0.0.0.0/0' == cidripv4 
                is_public_ipv6_source='::/0'==cidripv6
                
                inbound_message=''
                compliance_refs = []
                if not egress  and (is_public_ipv4_source  and not  ipv4_evaluated ) or (is_public_ipv6_source and  not ipv6_evaluated):
                    if is_public_ipv4_source and  not ipv4_evaluated:
                        ipv4_evaluated=True
                    if is_public_ipv6_source and  not ipv6_evaluated:
                        ipv6_evaluated=True
                    if rule_action=="deny":
                        continue
                    if rule_action=="allow":
                        ipv4_msg='Unrestricted Public ipv4 Inbound'
                        ipv6_msg='Unrestricted Public ipv6 Inbound'
                        if protocol=='-1':
                            if ipv4_evaluated:
                                inbound_message=f'{ipv4_msg} '
                            elif ipv6_evaluated:
                                inbound_message=f'{ipv6_msg} '
                                
                            severity = "CRITICAL"
                        else:
                            port_range=entry.get("PortRange",{})
                            from_port=port_range.get("From",'')
                            to_port=port_range.get("To",'')
                            matched_ports=[p for p in PORTS if from_port<=p<=to_port]
                            
                            admin_port=next((port for port in matched_ports if port in ADMIN_PORTS),None)
                            db_port=next((port for  port in matched_ports if port in DATABASE_PORTS),None)
                            web_port=next((port for port in matched_ports if port in PUBLIC_WEB_PORTS),None)
                            if  admin_port is not None:
                                inbound_message=f'ADMIN USAGE PROTOCOL FOUND\n{protocol} {admin_port}  '
                                severity = "CRITICAL"
                                
                                if is_public_ipv4_source :
                                    compliance_refs.append(
                                        cis_reference("nacl_remote_admin_ipv4"))
                            elif db_port is not None:
                                inbound_message=f'DATABASE USAGE PROTOCOL FOUND\n{protocol} {db_port}'
                                severity = "HIGH"
                            elif web_port is  not None:
                                inbound_message=f'PUBLIC WEB  PORT\n{protocol} {web_port}'
                                severity = "LOW"
                            else:
                                inbound_message="Unbound /Unclassified PORT"
                                severity = "MEDIUM"    
                        findings.append(Finding(
                            check="Network ACL Analyzer",
                            category="VPC",
                            resource=f"NetworkAclId: {NetworkAclId}",
                            passed=False,
                            severity=severity,
                            issue=inbound_message,
                            recommendation='''
                            1. [Restrict Ports]: Replace -1 (All) with required ports (e.g., TCP 443)
                            2. [Narrow CIDR]: Replace 0.0.0.0/0 with trusted IP ranges
                            3. Allow required ephemeral return-traffic ports in the appropriate direction
                            while restricting the source/destination CIDRs as tightly as practical.'''.strip(),
                            compliance=compliance_refs,
                        ))
                        break     
                
        return findings


