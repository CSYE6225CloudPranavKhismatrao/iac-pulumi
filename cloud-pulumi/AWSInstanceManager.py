import pulumi
import pulumi_aws as aws

config = pulumi.Config()
data = config.require_object("data")
launch_template = data.get("launch_template")
launch_template_name = launch_template.get("name")
launch_template_instance_type = launch_template.get("instance_type")
launch_template_key = launch_template.get("key")
ami_id = data.get("ami_id")

auto_scaling_group = data.get("auto_scaling_group")
auto_scaling_policy = data.get("auto_scaling_policy")

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


def create_iam_role_for_launch_template():
    # Creating IAM Role and policy for CloudWatch Logs and attaching to EC2 Instance
    role = aws.iam.Role("my-role",
                        name="my-role",
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

    # Attaching sns Full Access Policy to the role
    aws.iam.RolePolicyAttachment("sns-policy",
                                 role=role.name,
                                 policy_arn="arn:aws:iam::aws:policy/AmazonSNSFullAccess")

    instance_profile = aws.iam.InstanceProfile('myInstanceProfile',
                                               name='myInstanceProfile',
                                               role=role.name
                                               )
    return instance_profile


def create_launch_template(instance_profile, app_security_group, base_userData):
    return aws.ec2.LaunchTemplate("Launch_Template",
                                  name=launch_template_name,
                                  image_id=ami_id,
                                  instance_type=launch_template_instance_type,
                                  key_name=launch_template_key,
                                  user_data=base_userData,
                                  iam_instance_profile=aws.ec2.LaunchTemplateIamInstanceProfileArgs(
                                      name=instance_profile.name
                                  ),
                                  vpc_security_group_ids=[app_security_group.id],
                                  disable_api_termination=False,

                                  )


def create_target_group(vpc_id):
    return aws.lb.TargetGroup("TargetGroup",
                              port=8080,
                              protocol="HTTP",
                              target_type="instance",
                              vpc_id=vpc_id,
                              health_check=aws.lb.TargetGroupHealthCheckArgs(
                                  path="/healthz",
                                  port="8080",
                                  protocol="HTTP",
                                  enabled=True,
                                  interval=60,
                                  timeout=5,
                              ),
                              )


def auto_scaling_group(public_subnets, target_group, launch_template):
    return aws.autoscaling.Group("AutoScalingGroup",
                                 name=auto_scaling_group_name,
                                 vpc_zone_identifiers=[public_subnets[0].id, public_subnets[1].id],
                                 launch_template=aws.autoscaling.GroupLaunchTemplateArgs(
                                     id=launch_template.id,
                                     version="$Latest"
                                 ),
                                 target_group_arns=[target_group.arn],
                                 min_size=auto_scaling_group_min_size,
                                 max_size=auto_scaling_group_max_size,
                                 desired_capacity=auto_scaling_group_desired_capacity,
                                 default_cooldown=auto_scaling_group_default_cooldown,
                                 health_check_type=auto_scaling_group_health_check_type,
                                 health_check_grace_period=auto_scaling_group_health_check_grace_period,
                                 tags=[
                                     aws.autoscaling.GroupTagArgs(
                                         key="Name",
                                         value="EC2Instance",
                                         propagate_at_launch=True,
                                     ),
                                 ],
                                 # target_group_arns=[target_group.arn],
                                 )


def auto_scaling_up_policy(auto_scaling_group):
    return aws.autoscaling.Policy("AutoScalingPolicyUp",
                                  name=auto_scaling_up_policy_name,
                                  adjustment_type=auto_scaling_policy_adjustment_type,
                                  policy_type=auto_scaling_policy_policy_type,
                                  autoscaling_group_name=auto_scaling_group.name,
                                  scaling_adjustment=1,
                                  )


def auto_scaling_down_policy(auto_scaling_group):
    return aws.autoscaling.Policy("AutoScalingPolicyDown",
                                  name=auto_scaling_down_policy_name,
                                  adjustment_type=auto_scaling_policy_adjustment_type,
                                  policy_type=auto_scaling_policy_policy_type,
                                  autoscaling_group_name=auto_scaling_group.name,
                                  scaling_adjustment=-1,
                                  )


def scaling_up_alarm(auto_scaling_UP_policy):
    return aws.cloudwatch.MetricAlarm("ScalingUpAlarm",
                                      comparison_operator="GreaterThanOrEqualToThreshold",
                                      evaluation_periods=2,
                                      metric_name="CPUUtilization",
                                      namespace="AWS/EC2",
                                      period=60,
                                      statistic="Average",
                                      threshold=5.0,
                                      alarm_actions=[auto_scaling_UP_policy.arn],
                                      )


def scaling_down_alarm(auto_scaling_DOWN_policy):
    return aws.cloudwatch.MetricAlarm("ScalingDownAlarm",
                                      comparison_operator="LessThanOrEqualToThreshold",
                                      evaluation_periods=2,
                                      metric_name="CPUUtilization",
                                      namespace="AWS/EC2",
                                      period=60,
                                      statistic="Average",
                                      threshold=3.0,
                                      alarm_actions=[auto_scaling_DOWN_policy.arn],
                                      )


def create_load_balancer(load_balancer_security_group, public_subnets):
    return aws.lb.LoadBalancer("LoadBalancer",
                               name="LoadBalancerForEC21",
                               security_groups=[load_balancer_security_group.id],
                               subnets=[public_subnets[0].id, public_subnets[1].id],
                               load_balancer_type="application",
                               enable_deletion_protection=False,
                               internal=False,
                               )


def create_listener(load_balancer, ssl_certificate, target_group):
    return aws.lb.Listener("Listener",
                           load_balancer_arn=load_balancer.arn,
                           port=443,
                           protocol="HTTPS",
                           certificate_arn=ssl_certificate.arn,
                           default_actions=[{
                               "type": "forward",
                               "target_group_arn": target_group.arn,
                           }],
                           )
