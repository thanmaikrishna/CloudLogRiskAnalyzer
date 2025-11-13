import boto3
import json

def fetch_logs_from_aws(access_key, secret_key, bucket, path):
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    obj = s3.get_object(Bucket=bucket, Key=path)
    logs = json.loads(obj['Body'].read().decode('utf-8'))
    return logs