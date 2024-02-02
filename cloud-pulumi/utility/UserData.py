import pulumi
import pulumi_aws as aws


def getUserData(rds_instance_for_ec2, topic, name):
    app_properties = "/tmp/application.properties"
    user_data = [
        "#!/bin/bash",
        f"echo 'spring.jpa.hibernate.ddl-auto=update' >> {app_properties}",
        f"echo 'spring.datasource.username=csye6225' >> {app_properties}",
        f"echo 'spring.datasource.password=mypassword' >> {app_properties}",
        f"echo 'env.CSV_PATH=/opt/users.csv' >> {app_properties}",
        f"echo 'env.domain=localhost' >> {app_properties}",
        f"echo 'logging.file.name=my-app.log' >> {app_properties}",
        f"echo 'management.endpoints.enabled-by-default=false' >> {app_properties}",
        f"echo 'management.endpoint.info.enabled=true' >> {app_properties}",
        f"echo 'management.endpoint.health.enabled=true' >> {app_properties}",
        f"echo 'management.endpoint.health.show-details=always' >> {app_properties}",
        f"echo 'management.endpoint.metrics.enabled=true' >> {app_properties}",
        f"echo 'management.endpoints.web.base-path=' >> {app_properties}",
        f"echo 'management.endpoints.web.path-mapping.health=/healthz' >> {app_properties}",
        f"echo 'management.endpoints.web.path-mapping.metrics=/metrics' >> {app_properties}",
        f"echo 'management.endpoints.web.exposure.include=health,info,metrics' >> {app_properties}",
        f"echo 'DOMAIN_NAME={name}' >> {app_properties}",

    ]
    rds_instance_hostname = pulumi.Output.concat(
        "jdbc:postgresql://",
        rds_instance_for_ec2.address,
        ":5432/",
        "csye6225"
    )
    topic_arn = pulumi.Output.concat("", topic.arn)

    user_data = pulumi.Output.concat(
        "\n".join(user_data),
        "\n",
        rds_instance_hostname.apply(func=lambda x: f"echo 'spring.datasource.url={x}' >> {app_properties}"),
        "\n",
        topic_arn.apply(func=lambda x: f"echo 'TOPIC_ARN={x}' >> {app_properties}"))

    user_data = pulumi.Output.concat(user_data, f"\nsudo mv {app_properties} /opt/webapp/application.properties", "\n")
    user_data = pulumi.Output.concat(user_data, "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/cloudwatch-config.json \
    -s", "\n")

    return user_data
