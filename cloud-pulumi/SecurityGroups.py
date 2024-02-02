import pulumi
import pulumi_aws as aws
import ipaddress

config = pulumi.Config()
data = config.require_object("data")
vpc = data.get("vpc")
destination_cidr_block = vpc.get("destination_cidr_block")
db = data.get("db")
postgres_port = db.get("port")


# Load Balancer Security Group with port 80 and 443 ingress rule
def create_load_balancer_security_group(vpc_id):

    lb_sec_grp = aws.ec2.SecurityGroup("LoadBalancerSecurityGroup",
                                 name="LoadBalancerSecurityGroup",
                                 description="Load Balancer security group",
                                 vpc_id=vpc_id,
                                 ingress=[
                                     {
                                         'Description': 'HTTP from VPC for port 80',
                                         'FromPort': 80,
                                         'ToPort': 80,
                                         'Protocol': 'tcp',
                                         'CidrBlocks': [destination_cidr_block],
                                         'Ipv6CidrBlocks': ['::/0'],
                                     },
                                     {
                                         'Description': 'HTTPS from VPC for port 443',
                                         'FromPort': 443,
                                         'ToPort': 443,
                                         'Protocol': 'tcp',
                                         'CidrBlocks': [destination_cidr_block],
                                         'Ipv6CidrBlocks': ['::/0'],
                                     },
                                 ],
                                 tags={
                                     "Name": "LoadBalancerSecurityGroup",
                                 },

                                 )
    aws.ec2.SecurityGroupRule("LoadBalancerSecurityGroupEgress",
                              description="Allow all outbound traffic by default",
                              from_port=0,
                              to_port=0,
                              protocol="-1",
                              type="egress",
                              cidr_blocks=[destination_cidr_block],
                              security_group_id=lb_sec_grp.id,
                              # destination_security_group_id=security_group.id,
                              )

    return lb_sec_grp


def ApplicationSecurityGroup(vpc_id, load_balancer_security_group):
    return aws.ec2.SecurityGroup("AppSecurityGrp",
                                 name="AppSecurityGrp",
                                 description='Application security group',
                                 vpc_id=vpc_id,
                                 ingress=[aws.ec2.SecurityGroupIngressArgs(
                                     description="TLS from VPC for port 22",
                                     from_port=22,
                                     to_port=22,
                                     protocol='tcp',
                                     cidr_blocks=['0.0.0.0/0'],
                                     ipv6_cidr_blocks=['::/0'],
                                 ),
                                     aws.ec2.SecurityGroupIngressArgs(
                                         description="TLS from VPC for port 22",
                                         from_port=8080,
                                         to_port=8080,
                                         protocol='tcp',
                                         security_groups=[load_balancer_security_group.id],
                                     ),
                                 ],
                                 egress=[{
                                     "cidr_blocks": ["0.0.0.0/0"],
                                     "from_port": 0,
                                     "to_port": 0,
                                     "protocol": "-1",  # 'all'
                                 }],
                                 tags={
                                     "Name": "AppSecurityGrp",
                                 },

                                 )


def DatabaseSecurityGroup(vpc_id, application_security_group):
    return aws.ec2.SecurityGroup("DatabaseSecurityGroup1",
                                 name="DatabaseSecurityGroup",
                                 description="Database security group for PostgreSQL",
                                 vpc_id=vpc_id,
                                 ingress=[
                                     {
                                         'description': 'PostgreSQL traffic from application security group',
                                         'fromPort': postgres_port,
                                         'toPort': postgres_port,
                                         'protocol': 'tcp',
                                         'securityGroups': [application_security_group.id]
                                         # Refer to your application security group here
                                     }
                                 ],
                                 tags={
                                     "Name": "DatabaseSecurityGroup",
                                 },

                                 )
