"""Safely provision the DynamoDB table required by the activity-map feature.

Run this once from the psymoat-backend directory after deploying the Phase 1
code. It is deliberately a script instead of a public Flask route, so table
creation is not exposed through the application API.
"""

import sys

from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()
import controller


TABLE_NAME = 'UserActivity'


def main() -> int:
    try:
        controller.dynamodb_resource.meta.client.describe_table(TableName=TABLE_NAME)
        print(f'{TABLE_NAME} already exists; no changes made.')
        return 0
    except ClientError as error:
        error_code = error.response.get('Error', {}).get('Code')
        if error_code != 'ResourceNotFoundException':
            print(f'Could not inspect {TABLE_NAME}: {error}', file=sys.stderr)
            return 1

    try:
        table = controller.create_user_activity_table()
        table.wait_until_exists()
        print(f'{TABLE_NAME} created and ready.')
        return 0
    except ClientError as error:
        print(f'Could not create {TABLE_NAME}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
