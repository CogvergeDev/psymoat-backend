"""Provision only AdminAuditLogs; never changes existing application records."""
import os
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from admin_audit import KEY_SCHEMA, TABLE_NAME


def provision(resource, name=TABLE_NAME):
    client = resource.meta.client
    try:
        description = client.describe_table(TableName=name)["Table"]
        if description["KeySchema"] != KEY_SCHEMA:
            raise RuntimeError("Existing audit table has an incompatible schema; no changes made")
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        table = resource.create_table(
            TableName=name, BillingMode="PAY_PER_REQUEST", KeySchema=KEY_SCHEMA,
            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"} for key in ("pk", "sk")])
        table.wait_until_exists()
    backups = client.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
    if backups.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") != "ENABLED":
        client.update_continuous_backups(TableName=name, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True})
    return client.describe_table(TableName=name)["Table"]


def main():
    load_dotenv(Path(__file__).with_name(".env"))
    name = os.getenv("ADMIN_AUDIT_TABLE", TABLE_NAME)
    resource = boto3.resource("dynamodb", region_name=os.getenv("REGION_NAME", "us-east-1").strip(),
                              aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                              aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                              config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2}))
    # Explicitly constrain this script to its one new table and infrastructure
    # operations. It cannot Put/Update/Delete any application data.
    def guard(model, params, **kwargs):
        import json
        allowed = {"DescribeTable", "CreateTable", "DescribeContinuousBackups", "UpdateContinuousBackups"}
        if model.name not in allowed or json.loads(params["body"])["TableName"] != name:
            raise RuntimeError("Audit provisioner blocked an unrelated operation")
    resource.meta.client.meta.events.register("before-call.dynamodb.*", guard)
    description = provision(resource, name)
    print(f'{description["TableName"]}: {description["TableStatus"]}; audit table ready.')


if __name__ == "__main__":
    main()
