import pulumi
import pulumi_aws as aws
import ipaddress
import os


# import boto3


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

# Extract key configuration values
vpc_name = data.get("vpcName")
vpc_cidr = data.get("vpcCidr")

# Create the VPC using the fetched config values
Virtual_private_cloud = aws.ec2.Vpc(vpc_name,
                                    cidr_block=vpc_cidr,
                                    instance_tenancy="default",
                                    tags={
                                        "Name": vpc_name,
                                    })

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
                             destination_cidr_block="0.0.0.0/0",
                             gateway_id=internet_gateway.id)


# pdb.set_trace()


def create_security_group(vpc_id, destination_block):
    """Creates a new security group with the specified ingress rules.

    Args:
      vpc_id: The ID of the VPC to create the security group in.
      destination_block: The CIDR block of the destination network.

    Returns:
      The newly created security group.
    """

    # ec2 = boto3.resource('ec2')

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
                                           egress=[],
                                           )

    return security_group


def lookup_ami():
    """Looks up the latest AMI for the csye6225-debian-instance-ami AMI family.

    Returns:
      The AMI ID.
    """

    # ec2 = boto3.resource('ec2')

    ami = aws.ec2.get_ami(
        executable_users=["self"],
        filters=[
            aws.ec2.GetAmiFilterArgs(
                name="name",
                values=["csye6225_2023_*"],
            ),
            aws.ec2.GetAmiFilterArgs(
                name="root-device-type",
                values=["ebs"],
            ),
            aws.ec2.GetAmiFilterArgs(
                name="virtualization-type",
                values=["hvm"],
            ),
        ],
        most_recent=True,
        name_regex="csye6225_2023_*",
        owners=["self"])

    return ami.id


def create_instance(ami_id, subnet_id, security_group_id):
    """Creates a new EC2 instance.

    Args:
      ami_id: The ID of the AMI to launch the instance from.
      subnet_id: The ID of the subnet to launch the instance in.
      security_group_id: The ID of the security group to associate with the instance.

    Returns:
      The newly created instance.
    """

    # ec2 = boto3.resource('ec2')
    ami_id = 'ami-0541f6be93c08c0f7'

    instance = aws.ec2.Instance("instance",
                                ami=ami_id,
                                instance_type="t2.micro",
                                subnet_id=subnet_id,
                                key_name="ec2-key",
                                root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(
                                    volume_type=data.get("root_volume_type"),
                                    volume_size=data.get("root_volume_size"),
                                    delete_on_termination=True
                                ),
                                disable_api_termination=False,
                                vpc_security_group_ids=[security_group_id])
    # DisableApiTermination=True)


    # instance = aws.ec2.create_instance(
    #     ImageId=ami_id,
    #     InstanceType='t2.micro',
    #     SubnetId=subnet_id,
    #     KeyName='demo_ssh_key',
    #     DisableApiTermination=True,
    #     RootBlockDevice={
    #         'VolumeSize': 25,
    #         'VolumeType': 'gp2',
    #     },
    #     VpcSecurityGroupIds=[security_group_id],
    #     Tags={
    #         'Name': 'HelloWorld',
    #     },
    # )

    return instance


def demo():
    """

    :rtype: object
    """
    vpc_id = Virtual_private_cloud.id
    destination_block = '0.0.0.0/0'

    # Create the security group.
    security_group = create_security_group(vpc_id, destination_block)

    # Look up the latest AMI for the csye6225-debian-instance-ami AMI family.
    # ami_id = lookup_ami()

    # Create the EC2 instance.
    instance = create_instance("ami_id", public_subnets[0], security_group.id)


demo()

# application_security_group = aws.ec2.SecurityGroup("application_security_group",
#                                                    description="Security group for EC2 instances hosting web applications",
#                                                    ingress=[
#                                                        # Allow TCP traffic on ports 22, 80, 443, and the port on which your application runs from anywhere in the world.
#                                                        aws.ec2.SecurityGroupRule(
#                                                            "sg-rule-1",
#                                                            protocol="tcp",
#                                                            from_port=22,
#                                                            to_port=22,
#                                                            cidr_blocks=["0.0.0.0/0"],
#                                                        ),
#                                                        aws.ec2.SecurityGroupRule(
#                                                            "sg-rule-2",
#                                                            protocol="tcp",
#                                                            from_port=80,
#                                                            to_port=80,
#                                                            cidr_blocks=["0.0.0.0/0"],
#                                                        ),
#                                                        aws.ec2.SecurityGroupRule(
#                                                            "sg-rule-3",
#                                                            protocol="tcp",
#                                                            from_port=443,
#                                                            to_port=443,
#                                                            cidr_blocks=["0.0.0.0/0"],
#                                                        ),
#                                                        # Add a rule to allow traffic on the port on which your application runs.
#                                                        aws.ec2.SecurityGroupRule(
#                                                            "sg-rule-4",
#                                                            protocol="tcp",
#                                                            from_port=os.environment["PORT"],
#                                                            to_port=os.environment["PORT"],
#                                                            cidr_blocks=["0.0.0.0/0"],
#                                                        ),
#                                                    ],
#                                                    )
# Create an EC2 instance.
# ec2_instance = aws.ec2.Instance("web_server",
#                                 ami="ami-0599146fa6dd05c5f",
#                                 instance_type="t2.micro",
#                                 resource_name="my-web-server",
#                                 vpc_security_group_ids=[application_security_group.id],
#                                 vpc_subnet_id=pulumi.get_stack_resource_output("subnet", "id"),
#                                 associate_public_ip_address=True,
#                                 terminate_ebs_volumes_on_instance_termination=True,
#                                 )
#
# # Export the public IP address of the EC2 instance.
# pulumi.export("public_ip", ec2_instance.public_ip)
