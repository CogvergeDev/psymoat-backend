"""Create the additive table only. Never alters Lecture, Module or existing data."""
import os
from dotenv import load_dotenv
from botocore.exceptions import ClientError


def main():
    load_dotenv()
    import controller
    name = os.getenv("LECTURE_CATALOG_TABLE", "LectureCatalog")
    resource = controller.dynamodb_resource
    try:
        description = resource.meta.client.describe_table(TableName=name)["Table"]
        if description["KeySchema"] != [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}]:
            raise RuntimeError("Existing table has a different key schema; no changes made")
        print(f"{name} already exists. No changes made.")
        return
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    table = resource.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}])
    table.wait_until_exists()
    resource.meta.client.update_continuous_backups(TableName=name, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True})
    print(f"{name} is ready with point-in-time recovery enabled.")


if __name__ == "__main__":
    main()
