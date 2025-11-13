import boto3
import botocore
import json

def fetch_aws_logs_securely(access_key, secret_key, region, bucket, path):
    """
    Fetch AWS CloudTrail or similar logs stored as JSON or NDJSON files from an S3 bucket.

    Params:
        access_key (str): AWS Access Key ID
        secret_key (str): AWS Secret Access Key
        region (str): AWS region of the bucket
        bucket (str): S3 bucket name
        path (str): prefix path inside the bucket

    Returns:
        logs (list): list of parsed JSON log entries
        error (str or None): error message if any error occurred
    """
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=botocore.client.Config(signature_version='s3v4')
        )

        response = s3.list_objects_v2(Bucket=bucket, Prefix=path)
        if 'Contents' not in response:
            return [], 'No logs found at specified path'

        logs = []
        for obj in response['Contents']:
            try:
                file_obj = s3.get_object(Bucket=bucket, Key=obj['Key'])
                file_content = file_obj['Body'].read()

                # Try parsing full content as JSON array or object
                try:
                    json_logs = json.loads(file_content)
                    if isinstance(json_logs, list):
                        logs.extend(json_logs)
                    else:
                        logs.append(json_logs)

                # If that fails, try parsing as NDJSON (one JSON object per line)
                except json.JSONDecodeError:
                    lines = file_content.decode('utf-8').splitlines()
                    for line in lines:
                        if line.strip():
                            logs.append(json.loads(line))

            except Exception as e:
                # Ignore individual file errors but log here if needed
                print(f"Error reading {obj['Key']}: {e}")
                continue

        return logs, None

    except Exception as e:
        return [], str(e)
