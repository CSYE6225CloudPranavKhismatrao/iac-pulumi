import pulumi
import pulumi_aws as aws

config = pulumi.Config()
data = config.require_object("data")
domain_name = data.get("domain_name")


def create_lambda_function(sns_topic, service_account_key, bucket, dynamodb_table):
    lambda_role = aws.iam.Role("lambda_role",
                               assume_role_policy="""{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                "Action": "sts:AssumeRole",
                                "Principal": {
                                    "Service": "lambda.amazonaws.com"
                                },
                                "Effect": "Allow",
                                "Sid": ""
                                }
                            ]
                            }""")

    aws.iam.RolePolicyAttachment("lambda_policy",
                                 role=lambda_role.name,
                                 policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")

    aws.iam.RolePolicyAttachment("lambda_policy-dynamoDB",
                                 role=lambda_role.name,
                                 policy_arn="arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess")

    lambda_function = aws.lambda_.Function("lambda_function",
                                           role=lambda_role.arn,
                                           runtime="python3.10",
                                           handler="main.lambda_handler",
                                           code=pulumi.FileArchive("/Users/pranavkhismatrao/Northeastern/Fall_Sem_2023/Cloud/serverless/deployment-package.zip"),
                                           environment=aws.lambda_.FunctionEnvironmentArgs(
                                               variables={
                                                   "SNS_TOPIC_ARN": sns_topic.arn,
                                                   "GOOGLE_CREDENTIALS": service_account_key.private_key,
                                                   "GCP_BUCKET_NAME": bucket.name,
                                                   "FROM_ADDRESS": "mailgun@" + domain_name,
                                                   "DYNAMO_TABLE_NAME": dynamodb_table.name,
                                               }
                                           ),
                                           timeout=60,
                                           tags={
                                               "Name": "lambda_function",
                                           },
                                           )

    aws.lambda_.Permission("lambda_permission",
                           action="lambda:InvokeFunction",
                           function=lambda_function.name,
                           principal="sns.amazonaws.com",
                           source_arn=sns_topic.arn,
                           )

    aws.sns.TopicSubscription("lambda_subscription",
                              endpoint=lambda_function.arn,
                              protocol="lambda",
                              topic=sns_topic.arn,
                              )

    return lambda_function


def create_dynamoDB():
    return aws.dynamodb.Table("csye6225_dynamodb_table",
                              attributes=[aws.dynamodb.TableAttributeArgs(
                                  name="id",
                                  type="S",
                              )],
                              hash_key="id",
                              read_capacity=5,
                              write_capacity=5,
                              )
