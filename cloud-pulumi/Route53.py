import pulumi
import pulumi_aws as aws

config = pulumi.Config()
data = config.require_object("data")
domain_name = data.get("domain_name")


def create_alias_record(load_balancer):
    selected = aws.route53.get_zone(name=domain_name)

    alias = aws.route53.Record("LoadBalancerAlias",
                               zone_id=selected.zone_id,
                               name=selected.name,
                               type="A",
                               aliases=[{
                                   "name": load_balancer.dns_name,
                                   "zoneId": load_balancer.zone_id,
                                   "evaluateTargetHealth": True,
                               }],
                               )
