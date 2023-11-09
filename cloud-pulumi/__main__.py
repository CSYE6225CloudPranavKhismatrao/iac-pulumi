import pulumi
import pulumi_aws as aws
import ipaddress
import os


def calculate_subnets(vpc_cidr, num_subnets):
    try:
        vpc_network = ipaddress.IPv4Network(vpc_cidr)
    except ValueError:
        print("Invalid VPC CIDR format. Example format: 10.0.0.0/16")
        return []

    subnet_bits = vpc_network.max_prefixlen - num_subnets

    subnets = list(vpc_network.subnets(new_prefix=subnet_bits))

    return subnets


# Fetch the configuration values
config = pulumi.Config()
data = config.require_object("data")

# ======================================= Extract key configuration values==============================================
vpc_name = data.get("vpcName")
vpc_cidr = data.get("vpcCidr")
destination_cidr_block = data.get("destination_cidr_block")
postgres_port = data.get("postgres_port")

private_subnet_group_name = data.get("private-subnet-group")
db_name = data.get("db_name")
db_username = data.get("db_username")
db_password = data.get("db_password")
db_instance_class = data.get("db_instance_class")
db_engine = data.get("db_engine")
ami_id = data.get("ami_id")
domain_name = data.get("domain_name")
# ========================================================================

# Create the VPC using the fetched config values
Virtual_private_cloud = aws.ec2.Vpc(vpc_name,
                                    cidr_block=vpc_cidr,
                                    instance_tenancy="default",
                                    tags={
                                        "Name": vpc_name,
                                    })

vpc_id = Virtual_private_cloud.id
# Define availability zones
azs = aws.get_availability_zones().names
num_azs = len(azs)

no_of_subnets = 3  # max

print(num_azs)

if (num_azs < 3):
    no_of_subnets = num_azs
# Create 3 public and 3 private subnets
public_subnets = []
private_subnets = []

subnet_cidrs = calculate_subnets(vpc_cidr, no_of_subnets * 2)

k = 0
# print(subnet_strings)
# print("IP 0 ", ip_list[0])

for i in range(no_of_subnets):
    az_index = i % num_azs
    public_subnet = aws.ec2.Subnet(f"{vpc_name}-public-subnet-{i}",
                                   cidr_block=str(subnet_cidrs[k]),  # data.get(f'publicSubnetCidr{i}'),
                                   availability_zone=azs[az_index],
                                   vpc_id=Virtual_private_cloud.id,
                                   map_public_ip_on_launch=True,
                                   tags={
                                       "Name": f"{vpc_name}-public-subnet-{i}",
                                   })

    k += 1

    private_subnet = aws.ec2.Subnet(f"{vpc_name}-private-subnet-{i}",
                                    cidr_block=str(subnet_cidrs[k]),  # data.get(f'privateSubnetCidr{i}'),
                                    availability_zone=azs[az_index],
                                    vpc_id=Virtual_private_cloud.id,
                                    tags={
                                        "Name": f"{vpc_name}-private-subnet-{i}",
                                    })
    k += 1

    public_subnets.append(public_subnet)
    private_subnets.append(private_subnet)

# Create an Internet Gateway and attach it to the VPC
internet_gateway = aws.ec2.InternetGateway(f"{vpc_name}-internet-gateway",
                                           vpc_id=Virtual_private_cloud.id,
                                           tags={
                                               "Name": f"{vpc_name}-internet-gateway",
                                           })

# Create a public route table
public_route_table = aws.ec2.RouteTable(f"{vpc_name}-public-route-table",
                                        vpc_id=Virtual_private_cloud.id,
                                        tags={
                                            "Name": f"{vpc_name}-public-route-table",
                                        })

# Associate public subnets with the public route table
for subnet in public_subnets:
    aws.ec2.RouteTableAssociation(f"{subnet._name}-association",
                                  subnet_id=subnet.id,
                                  route_table_id=public_route_table.id)

# Create a private route table
private_route_table = aws.ec2.RouteTable(f"{vpc_name}-private-route-table",
                                         vpc_id=Virtual_private_cloud.id,
                                         tags={
                                             "Name": f"{vpc_name}-private-route-table",
                                         })

# Associate private subnets with the private route table
for subnet in private_subnets:
    aws.ec2.RouteTableAssociation(f"{subnet._name}-association",
                                  subnet_id=subnet.id,
                                  route_table_id=private_route_table.id)

# Create a public route in the public route table
public_route = aws.ec2.Route(f"{vpc_name}-public-route",
                             route_table_id=public_route_table.id,
                             destination_cidr_block=destination_cidr_block,
                             gateway_id=internet_gateway.id)


def create_security_group(vpc_id, destination_block):
    """Creates a new security group with the specified ingress rules.

    Args:
      vpc_id: The ID of the VPC to create the security group in.
      destination_block: The CIDR block of the destination network.

    Returns:
      The newly created security group.
    """
    security_group = aws.ec2.SecurityGroup("AppSecurityGrp",
                                           description='Application security group',
                                           vpc_id=vpc_id,
                                           ingress=[
                                               {
                                                   'Description': 'TLS from VPC for port 22',
                                                   'FromPort': 22,
                                                   'ToPort': 22,
                                                   'Protocol': 'tcp',
                                                   'CidrBlocks': [destination_block],
                                                   'Ipv6CidrBlocks': ['::/0'],
                                               },
                                               {
                                                   'Description': 'TLS from VPC for port 80',
                                                   'FromPort': 80,
                                                   'ToPort': 80,
                                                   'Protocol': 'tcp',
                                                   'CidrBlocks': [destination_block],
                                                   'Ipv6CidrBlocks': ['::/0'],
                                               },
                                               {
                                                   'Description': 'TLS from VPC for port 443',
                                                   'FromPort': 443,
                                                   'ToPort': 443,
                                                   'Protocol': 'tcp',
                                                   'CidrBlocks': [destination_block],
                                                   'Ipv6CidrBlocks': ['::/0'],
                                               },
                                               {
                                                   'Description': 'TLS from VPC for port 8080',
                                                   'FromPort': 8080,
                                                   'ToPort': 8080,
                                                   'Protocol': 'tcp',
                                                   'CidrBlocks': [destination_block],
                                                   'Ipv6CidrBlocks': ['::/0'],
                                               },
                                           ],
                                           egress=[{
                                               "cidr_blocks": ["0.0.0.0/0"],
                                               "from_port": 0,
                                               "to_port": 0,
                                               "protocol": "-1",  # 'all'
                                           }],
                                           )

    return security_group


# Assignment 6 Code
def create_database_security_group(vpc_id, security_group):
    """Creates a security group for RDS instances and allows PostgreSQL traffic from the application security group."""

    database_security_group = aws.ec2.SecurityGroup("DatabaseSecurityGroup",
                                                    description="Database security group for PostgreSQL",
                                                    vpc_id=vpc_id,
                                                    ingress=[
                                                        {
                                                            'description': 'PostgreSQL traffic from application security group',
                                                            'fromPort': postgres_port,
                                                            'toPort': postgres_port,
                                                            'protocol': 'tcp',
                                                            'securityGroups': [security_group.id]
                                                            # Refer to your application security group here
                                                        }
                                                    ],
                                                    egress=[{
                                                        'fromPort': 0,
                                                        'toPort': 65535,
                                                        'protocol': 'tcp',
                                                        'cidrBlocks': ['0.0.0.0/0']  # Restrict egress access as needed
                                                    }]
                                                    )

    return database_security_group


rds_parameter_grp = data.get("rds_parameter_grp")


# Assignment 6 Code
def create_db_parameter_group(db_instance_name):
    """Create a custom parameter group for your PostgreSQL RDS instance."""

    db_parameter_group = aws.rds.ParameterGroup(db_instance_name,
                                                family="postgres12",  # Adjust this to match your PostgreSQL version
                                                description="Custom parameter group for PostgreSQL RDS instance",
                                                # resource_name="RDS_Parameter_Group",
                                                name=rds_parameter_grp
                                                )

    return db_parameter_group


def create_private_subnet_group(subnet_ids, subnet_group_name):
    """Create a DB subnet group for RDS instances using private subnets."""

    db_subnet_group = aws.rds.SubnetGroup("private_subnet_group_name",
                                          subnet_ids=subnet_ids,
                                          name=subnet_group_name,
                                          description="DB Subnet Group for private RDS instances",
                                          tags={
                                              "Name": subnet_group_name,
                                          }
                                          )
    return db_subnet_group


def create_instance(ami_id, subnet_id, security_group_id, rds_instance_for_ec2, role):

    """Creates a new EC2 instance.

    Args:
      ami_id: The ID of the AMI to launch the instance from.
      subnet_id: The ID of the subnet to launch the instance in.
      security_group_id: The ID of the security group to associate with the instance.

    Returns:
      The newly created instance.
    """

    # ec2 = boto3.resource('ec2')
    # ami_id = 'ami-0541f6be93c08c0f7'
    app_properties = "/tmp/application.properties"
    user_data = [
        "#!/bin/bash",
        f"echo 'spring.jpa.hibernate.ddl-auto=update' >> {app_properties}",
        f"echo 'spring.datasource.username=csye6225' >> {app_properties}",
        f"echo 'spring.datasource.password=mypassword' >> {app_properties}",
        f"echo 'env.CSV_PATH=/opt/users.csv' >> {app_properties}",
        f"echo 'env.domain=localhost' >> {app_properties}",
        f"echo 'logging.file.name=my-app.log' >> {app_properties}",
        # f"echo 'logging.file.path=/var/log' >> {app_properties}",
    ]
    rds_instance_hostname = pulumi.Output.concat(
        "jdbc:postgresql://",
        rds_instance_for_ec2.address,

        ":5432/",
        "csye6225"
    )

    user_data = pulumi.Output.concat(
        "\n".join(user_data),
        "\n",
        rds_instance_hostname.apply(func=lambda x: f"echo 'spring.datasource.url={x}' >> {app_properties}"))

    user_data = pulumi.Output.concat(user_data, f"\nsudo mv {app_properties} /opt/webapp/application.properties", "\n")
    user_data = pulumi.Output.concat(user_data, "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/cloudwatch-config.json \
    -s", "\n")
    outp = pulumi.Output.concat("EC2 Security Group ID ", security_group_id)
    outp.apply(lambda id: print(f"Hello, {id}!"))

    # You need to refer to the role's name
    instance_profile = aws.iam.InstanceProfile('myInstanceProfile',
                                           role = role.name
                                           )

    ec2_instance = aws.ec2.Instance("EC2Instance",
                                    ami=ami_id,
                                    instance_type="t2.micro",
                                    subnet_id=subnet_id,
                                    key_name="ec2-key",
                                    user_data=user_data,
                                    iam_instance_profile=instance_profile.name,
                                    root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(
                                        volume_type=data.get("root_volume_type"),
                                        volume_size=data.get("root_volume_size"),
                                        delete_on_termination=True
                                    ),
                                    disable_api_termination=False,
                                    vpc_security_group_ids=[security_group_id])

    return ec2_instance


def create_rds_instance(db_instance_name, db_engine, db_instance_class, username, password, subnet_group_name,
                        security_group_id):
    """Create an RDS instance with the specified configuration."""
    # Create a new parameter group
    parameter_group = create_db_parameter_group(db_instance_name)
    outp = pulumi.Output.concat("EC2 RDS Security Group ID ", security_group_id)
    outp.apply(lambda id: print(f"Hello, {id}!"))
    rdsInstance = aws.rds.Instance("rds-instance",
                                   identifier=db_instance_name,
                                   skip_final_snapshot=True,
                                   allocated_storage=20,
                                   storage_type="gp2",
                                   engine=db_engine,
                                   engine_version="12",
                                   parameter_group_name=parameter_group,
                                   instance_class=db_instance_class,
                                   name=db_instance_name,
                                   multi_az=False,
                                   username=username,
                                   password=password,
                                   db_subnet_group_name=subnet_group_name,
                                   vpc_security_group_ids=[security_group_id]
                                   )

    return rdsInstance


# ============================ Route53 Code - Assignment 7 =======================================
def route53_record(name, zone_id, type, records, ttl=60):
    return aws.route53.Record(name,
                              zone_id=zone_id,
                              name=name,
                              type=type,
                              ttl=ttl,
                              records=records)


# ===============================================================================================

def demo():
    """
    :rtype: object
    """

    destination_block = '0.0.0.0/0'

    # Create the security group.
    security_group = create_security_group(vpc_id, destination_block)

    database_security_group = create_database_security_group(vpc_id, security_group)

    # Look up the latest AMI for the csye6225-debian-instance-ami AMI family.
    # ami_id = lookup_ami()

    private_subnet_ids = [privateSubnet.id for privateSubnet in private_subnets]
    outp = pulumi.Output.concat("Private Subnet Ids ", private_subnet_ids)
    outp.apply(lambda id: print(f"Hello, {id}!"))

    private_subnet_group = create_private_subnet_group(private_subnet_ids, private_subnet_group_name)

    # Create the RDS instance with the specified configuration.
    rds_instance_demo = create_rds_instance(
        db_instance_name=db_name,
        db_engine=db_engine,  # Use "mysql" for MySQL, "mariadb" for MariaDB, "postgres" for PostgreSQL
        db_instance_class=db_instance_class,  # Use the cheapest class available
        username=db_username,
        password=db_password,
        subnet_group_name=private_subnet_group,  # Replace with the name of your private subnet group
        security_group_id=database_security_group.id
    )
    #
    # Creating IAM Role and policy for CloudWatch Logs and attaching to EC2 Instance
    role = aws.iam.Role("my-role",
                        assume_role_policy="""{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                "Action": "sts:AssumeRole",
                                "Principal": {
                                    "Service": "ec2.amazonaws.com"
                                },
                                "Effect": "Allow",
                                "Sid": ""
                                }
                            ]
                            }""")

    # Attaching CloudWatchLogsFullAccess Policy to the role
    aws.iam.RolePolicyAttachment("my-policy",
                                 role=role.name,
                                 policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy")

    # Create the EC2 instance.
    instance_demo = create_instance(ami_id, public_subnets[0], security_group.id, rds_instance_demo, role)
    public_ip = pulumi.Output.concat("EC2 Instance Public IP ", instance_demo.public_ip)
    public_ip.apply(lambda ip: print(f"Hello, {ip}!"))

    # Configure a Route53 record for the EC2 instance.
    selected = aws.route53.get_zone(name=domain_name)
    # dev = aws.route53.Zone("dev", tags={
    #     "Environment": "dev",
    # })
    # record = route53_record("dev-A", selected.zone_id, "A", dev.name_servers)
    zoneId = pulumi.Output.concat("ZONE ", selected.zone_id)
    zoneId.apply(lambda id: print(f"Hello, {id}!"))

    print("Create Route53 Record")
    aws.route53.Record("www",
                       zone_id=selected.zone_id,
                       name=selected.name,
                       type="A",
                       ttl=60,
                       records=[instance_demo.public_ip])

    #
    # # Attaching the role to EC2 Instance
    # role_attachment = aws.ec2.InstanceRoleAttachment("role-attachment",
    #                                                   instance_id=instance_demo.id,
    #                                                   role=role.name)


    return rds_instance_demo, instance_demo


rds_instance, instance = demo()
