"""Provision only the durable checkout-intent table and its pending-user index."""
import json
import os
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from payment_routes import ORDER_TABLE, ORDER_INDEX

KEY_SCHEMA = [{'AttributeName': 'order_id', 'KeyType': 'HASH'}]
INDEX_KEYS = [{'AttributeName': 'pending_user', 'KeyType': 'HASH'},
              {'AttributeName': 'created_at', 'KeyType': 'RANGE'}]


def provision(resource):
    client = resource.meta.client
    try:
        desc = client.describe_table(TableName=ORDER_TABLE)['Table']
        indexes = {index['IndexName']: index for index in desc.get('GlobalSecondaryIndexes', [])}
        if desc['KeySchema'] != KEY_SCHEMA or ORDER_INDEX not in indexes or indexes[ORDER_INDEX]['KeySchema'] != INDEX_KEYS or indexes[ORDER_INDEX]['Projection']['ProjectionType'] != 'ALL':
            raise RuntimeError('Existing checkout table has an incompatible schema; no changes made')
    except ClientError as error:
        if error.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        table = resource.create_table(TableName=ORDER_TABLE, BillingMode='PAY_PER_REQUEST',
            KeySchema=KEY_SCHEMA, AttributeDefinitions=[{'AttributeName': key, 'AttributeType': 'S'}
                for key in ('order_id', 'pending_user', 'created_at')],
            GlobalSecondaryIndexes=[{'IndexName': ORDER_INDEX, 'KeySchema': INDEX_KEYS,
                                     'Projection': {'ProjectionType': 'ALL'}}])
        table.wait_until_exists()
    client.update_continuous_backups(TableName=ORDER_TABLE,
        PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True})
    return client.describe_table(TableName=ORDER_TABLE)['Table']


def main():
    load_dotenv(Path(__file__).with_name('.env'))
    resource = boto3.resource('dynamodb', region_name=os.getenv('REGION_NAME', 'us-east-1').strip(),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        config=Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 2}))
    def guard(model, params, **kwargs):
        if model.name not in {'DescribeTable', 'CreateTable', 'UpdateContinuousBackups'} or json.loads(params['body'])['TableName'] != ORDER_TABLE:
            raise RuntimeError('Checkout provisioner blocked an unrelated operation')
    resource.meta.client.meta.events.register('before-call.dynamodb.*', guard)
    desc = provision(resource)
    print(desc['TableName'] + ': ' + desc['TableStatus'])


if __name__ == '__main__':
    main()
