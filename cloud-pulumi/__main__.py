import pulumi
import pulumi_aws as aws
import ipaddress
import base64
import VPC as vpc_class
import pulumi_gcp as gcp
import SecurityGroups as scgrps
import AWSInstanceManager as aws_instance_manager
import Route53 as awsRoute53
import GCPManager as gcp_manager
import LambdaFunction as lambda_manager
from utility.UserData import getUserData

# Fetch the configuration values
config = pulumi.Config()
data = config.require_object("data")
vpc = data.get("vpc")
db = data.get("db")
rds = data.get("rds")
root_volume = data.get("root_volume")
launch_template = data.get("launch_template")
auto_scaling_group = data.get("auto_scaling_group")
auto_scaling_policy = data.get("auto_scaling_policy")

# ======================================= Extract key configuration values==============================================
vpc_name = vpc.get("name")
print(vpc_name)
vpc_cidr = vpc.get("cidr")
destination_cidr_block = vpc.get("destination_cidr_block")
postgres_port = db.get("port")
private_subnet_group_name = vpc.get("private-subnet-group")
rds_parameter_grp = rds.get("rds_parameter_grp")
db_name = db.get("name")
db_username = db.get("username")
db_password = db.get("password")
db_instance_class = db.get("instance_class")
db_engine = db.get("engine")
db_port = db.get("port")
ami_id = data.get("ami_id")
domain_name = data.get("domain_name")
print("Domain Name ", domain_name)
root_volume_type = root_volume.get("type")
root_volume_size = root_volume.get("size")
launch_template_name = launch_template.get("name")
launch_template_key = launch_template.get("key")
launch_template_instance_type = launch_template.get("instance_type")
auto_scaling_group_name = auto_scaling_group.get("name")
auto_scaling_group_min_size = auto_scaling_group.get("min_size")
auto_scaling_group_max_size = auto_scaling_group.get("max_size")
auto_scaling_group_desired_capacity = auto_scaling_group.get("desired_capacity")
auto_scaling_group_default_cooldown = auto_scaling_group.get("default_cooldown")
auto_scaling_group_health_check_type = auto_scaling_group.get("health_check_type")
auto_scaling_group_health_check_grace_period = auto_scaling_group.get("health_check_grace_period")
auto_scaling_up_policy_name = auto_scaling_policy.get("up_policy_name")
auto_scaling_down_policy_name = auto_scaling_policy.get("down_policy_name")
auto_scaling_policy_adjustment_type = auto_scaling_policy.get("adjustment_type")
auto_scaling_policy_policy_type = auto_scaling_policy.get("policy_type")


# ========================================================================

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





def create_rds_instance(db_instance_name, db_engine, db_instance_class, username, password, subnet_group_name,
                        security_group_id):
    """Create an RDS instance with the specified configuration."""
    # Create a new parameter group
    parameter_group = create_db_parameter_group(db_instance_name)
    outp = pulumi.Output.concat("EC2 RDS Security Group ID ", security_group_id)
    outp.apply(lambda id: print(f"Hello, {id}!"))
    rds_instance = aws.rds.Instance("rds-instance",
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
                                    publicly_accessible=False,
                                    username=username,
                                    password=password,
                                    db_subnet_group_name=subnet_group_name,
                                    vpc_security_group_ids=[security_group_id]
                                    )

    return rds_instance



def demo():
    """
    :rtype: object
    """

    destination_block = '0.0.0.0/0'
    # Create the VPC using the fetched config values
    vpc_network, public_subnets, private_subnets, internet_gateway, public_route_table, private_route_table, public_route = vpc_class.create_vpc_network()

    load_balancer_security_group = scgrps.create_load_balancer_security_group(vpc_network.id)

    app_security_group = scgrps.ApplicationSecurityGroup(vpc_network.id, load_balancer_security_group)

    # Create egress rule for loadbalancer security group

    # Database Security Group for RDS Instance
    database_security_group = scgrps.DatabaseSecurityGroup(vpc_network.id, app_security_group)

    aws.ec2.SecurityGroupRule("AppSecurityGroupEgress",
                              description="Allow all inbound traffic by default",
                              from_port=postgres_port,
                              to_port=postgres_port,
                              protocol="tcp",
                              type="egress",
                              source_security_group_id=database_security_group.id,
                              security_group_id=app_security_group.id,
                              )

    # Look up the latest AMI for the csye6225-debian-instance-ami AMI family.
    # ami_id = lookup_ami()
    #
    # Create the private subnet group.
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

    # # Create Amazon Simple Notification Service (Amazon SNS) topic creation with Pulumi
    sns_topic = aws.sns.Topic("sns_topic_submission",
                              display_name="Assignment Submission Topic",
                              name="sns_topic_submission",
                              tags={
                                  "Name": "sns_topic_submission",
                              }
                              )
    #
    # Create a base64 encoded string for the user data.
    user_data = getUserData(rds_instance_demo, sns_topic, domain_name)

    # Converting Output to String
    # data_string = pulumi.Output.concat(user_data)
    # print(type(data_string), " Data String ", data_string)

    base_userData = user_data.apply(lambda x: base64.b64encode(x.encode()).decode())
    # print(base_userData, " Base User Data ", type(base_userData))

    # # Create a target group for the load balancer to route requests to.
    target_group = aws_instance_manager.create_target_group(vpc_network.id)

    instance_profile = aws_instance_manager.create_iam_role_for_launch_template()
    # Create Launch Template for EC2 Instances
    launch_template = aws_instance_manager.create_launch_template(instance_profile, app_security_group, base_userData)

    # Create Auto Scaling Group for EC2 Instances
    auto_scaling_group = aws_instance_manager.auto_scaling_group(public_subnets, target_group, launch_template)

    # Create Auto Scaling Policy for EC2 Instances
    auto_scaling_UP_policy = aws_instance_manager.auto_scaling_up_policy(auto_scaling_group)

    auto_scaling_DOWN_policy = aws_instance_manager.auto_scaling_down_policy(auto_scaling_group)

    # Create a CloudWatch metric alarm for scaling up.
    scaling_up_alarm = aws_instance_manager.scaling_up_alarm(auto_scaling_UP_policy)
    # Create a CloudWatch metric alarm for scaling down.
    scaling_down_alarm = aws_instance_manager.scaling_down_alarm(auto_scaling_DOWN_policy)

    #  Create load balancer for EC2 Instances to accept traffic on PORT 80 and forward to PORT 8080
    load_balancer = aws_instance_manager.create_load_balancer(load_balancer_security_group, public_subnets)

    # Lookup arn for SSL Certificate for Load Balancer
    ssl_certificate = aws.acm.get_certificate(domain=domain_name,
                                              most_recent=True,
                                              )

    # Create a listener for the load balancer.
    listener = aws_instance_manager.create_listener(load_balancer, ssl_certificate, target_group)

    # Create a Route53 ALIAS record for the Load Balancer.
    awsRoute53.create_alias_record(load_balancer)

    # GCP Bucket
    bucket = gcp_manager.create_gcp_bucket()

    # GCP Service Account
    service_account_keys = gcp_manager.create_service_account_keys(bucket)

    # Create DynamoDB Table in AWS
    dynamodb_table = lambda_manager.create_dynamoDB()

    # Create Lambda Function
    lambda_function = lambda_manager.create_lambda_function(sns_topic, service_account_keys, bucket, dynamodb_table)


# rds_instance = demo()
demo()
