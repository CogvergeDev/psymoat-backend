"""Bounded account-email retry command; suitable for an external scheduled job."""
import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import boto3
from dotenv import load_dotenv

from account_mail import drain


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, choices=range(1, 3), default=2)
    args = parser.parse_args()
    load_dotenv(Path(__file__).with_name('.env'))
    resource = boto3.resource('dynamodb', region_name=os.getenv('REGION_NAME', 'us-east-1'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
    db = SimpleNamespace(dynamodb_resource=resource, UserTable=resource.Table('User'))
    print(json.dumps(drain(db, args.limit)))


if __name__ == '__main__':
    main()
