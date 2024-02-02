import pulumi
import pulumi_gcp as gcp

config = pulumi.Config()
data = config.require_object("data")
gcp_config = data.get("gcp")
project = gcp_config.get("project")


def create_gcp_bucket():
    return gcp.storage.Bucket("csye6225-bucket",
                              location="US-EAST1",
                              project=project,
                              force_destroy=True,
                              )


def create_service_account_keys(bucket):
    service_account = gcp.serviceaccount.Account("csye6225-service-account",
                                                 account_id="csye6225-service-account",
                                                 display_name="csye6225-service-account",
                                                 )

    gcp.storage.BucketIAMMember("member",
                                bucket=bucket.name,
                                role="roles/storage.admin",
                                member=service_account.member)

    return gcp.serviceaccount.Key("csye6225-service-account-key",
                                  service_account_id=service_account.name,
                                  public_key_type="TYPE_X509_PEM_FILE",
                                  private_key_type="TYPE_GOOGLE_CREDENTIALS_FILE",
                                  )
