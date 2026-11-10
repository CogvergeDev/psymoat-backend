"""Explicitly provision the account email/rate-limit table; never runs at startup."""
import os
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from account_mail import TABLE_NAME, QUEUE_INDEX


def provision(resource, name=None):
    name = name or os.getenv('ACCOUNT_OPERATIONS_TABLE', TABLE_NAME)
    client = resource.meta.client
    keys = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    index_keys = [{'AttributeName': 'queue', 'KeyType': 'HASH'}, {'AttributeName': 'next_attempt', 'KeyType': 'RANGE'}]
    try:
        desc = client.describe_table(TableName=name)['Table']
        index = next((i for i in desc.get('GlobalSecondaryIndexes', []) if i['IndexName'] == QUEUE_INDEX), {})
        if desc['KeySchema'] != keys or index.get('KeySchema') != index_keys or index.get('Projection', {}).get('ProjectionType') != 'ALL':
            raise RuntimeError('Incompatible account operations table; no changes made')
    except ClientError as error:
        if error.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        created = resource.create_table(TableName=name, BillingMode='PAY_PER_REQUEST', KeySchema=keys,
            AttributeDefinitions=[{'AttributeName': key, 'AttributeType': kind} for key, kind in [('pk', 'S'), ('queue', 'S'), ('next_attempt', 'N')]],
            GlobalSecondaryIndexes=[{'IndexName': QUEUE_INDEX, 'KeySchema': index_keys, 'Projection': {'ProjectionType': 'ALL'}}])
        created.wait_until_exists()
    ttl = client.describe_time_to_live(TableName=name)['TimeToLiveDescription']
    if ttl.get('TimeToLiveStatus') not in ('ENABLED', 'ENABLING'):
        client.update_time_to_live(TableName=name, TimeToLiveSpecification={'Enabled': True, 'AttributeName': 'ttl'})
    elif ttl.get('AttributeName') != 'ttl':
        raise RuntimeError('Existing TTL attribute does not match; no TTL changes made')
    return client.describe_table(TableName=name)['Table']


if __name__ == '__main__':
    load_dotenv(Path(__file__).with_name('.env'))
    resource = boto3.resource('dynamodb', region_name=os.getenv('REGION_NAME', 'us-east-1'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
    result = provision(resource)
    print(result['TableName'] + ': ' + result['TableStatus'])
