before touching VPC Implementation We must be able to answer to these questions

-------------------1-What makes a subnet public?
--in Vpc  a subnet is becomes public when the routing table is pointing directly to the IGW(Internal Gateway). it poiunts to IGW instead of NAT(NetworkAddressTranslator).it allows  resources  to  send receive  staright from the public internet..

--How we can check in AWS is this Subnet public?
    Usually  we have to check attached route Table
    command--> aws ec2 describe-route-tables
    and check for destination starting from igw xxxx
    0.0.0.0/0 or ::/0

-------------------2-What makes a subnet private?
   this is same as public checking but there is no IPV4 is attached , 
   no in bound route--> outseider not initiate connection
     usually used in databases

No internet connection->  routing table does not send traffic to the internet gateway

-------------------3-What is the role of an Internet Gateway
--IGW  is the  virtual router thet enables to communicate to the public  internet 
   connects cloud network (VPC) to the  network.
   it handles 2 way connection outsider to acces and internal to  the outsider

   like Physical Router handles Address  translator sam eit handles . connects private to the public internet
-------------------4-What is the role of a NAT Gateway?
NAT is Network Address translator is a one way system  thet helps in translating private ip to public ip
it blocks outsider to the internal system a access
it hides private ip and replaces private with public
-------------------5-How does a route table determine Internet reachability?

 when prvt network sends request to access to something outside it uses routing table , like 0.0.0.0/0   means router can commnunicate with public internet a..
-----------------6-What is the difference between a Security Group and Network ACL?
security group  means rules or  regulatiopns/restriction applies to specific group where as Network defines as  Address Control list like who can access the service or or from which  protocol

-----------------7-What does 0.0.0.0/0 actually mean?
 it means everyone on the internet    simply all public network

-----------------8-Why is 0.0.0.0/0 → TCP/22 dangerous?

as this is invitation to all persons on the  internet to come and access the SSh service 
-----------------9-What are VPC Flow Logs?
it is aws service to capture all coming or out going traffic from VPC
it has types like:
1-->All VPC 
2-->Specific Subnet
3--> INdividiual elastic Interface0I EI

Types:
ACcept--> ALlow specific  Subnet Traffic
Block/reject-->only blocked/dropped traffic
 All-->Both accepted and rejected traffic
Tools Used--> cloudwatch  Amamzon firehose
-----------------10How can CloudGuard determine whether a resource is actually exposed?
Directly Exposed	Public IP assigned + Route to IGW + SG/NACL allows 0.0.0.0/0 on an open port.	Critical / High
Indirectly Exposed	Resource is in a private subnet, but mapped via an internet-facing Load Balancer or reverse proxy.	Medium
Isolated / Misconfigured Internal	Security Group allows 0.0.0.0/0, but resource lacks a Public IP or sits in a private subnet with no IGW route.	Low / Hygiene Issue
Protected / Inspected	Traffic passes through an inline security appliance (e.g., Next-Gen Firewall, CloudGuard Network) before reaching the workload.	Managed