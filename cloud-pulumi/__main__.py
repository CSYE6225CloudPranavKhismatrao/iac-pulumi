import pulumi
import pulumi_aws as aws
import ipaddress

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

no_of_subnets = 3 # max

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
        cidr_block= str(subnet_cidrs[k]), #data.get(f'publicSubnetCidr{i}'),
        availability_zone=azs[az_index],
        vpc_id = Virtual_private_cloud.id,
        map_public_ip_on_launch=True,
        tags={
            "Name": f"{vpc_name}-public-subnet-{i}",
        })

    k += 1

    private_subnet = aws.ec2.Subnet(f"{vpc_name}-private-subnet-{i}",
        cidr_block= str(subnet_cidrs[k]), #data.get(f'privateSubnetCidr{i}'),
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
