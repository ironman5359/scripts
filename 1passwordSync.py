import boto3
import json
import hashlib
import logging
import time
from botocore.exceptions import ClientError
from onepasswordconnector import OnePasswordConnector

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
secrets_manager = boto3.client('secretsmanager')

BUCKET_NAME = 'your-bucket-name'
STATE_FILE_KEY = 'state.json'
MAX_RUNTIME = 300  # 5 minutes in seconds

def lambda_handler(event, context):
    start_time = time.time()
    state = load_state_from_s3()

    try:
        op_connector = OnePasswordConnector('your-1password-api-key')
        secrets = op_connector.get_secrets()

        for secret in secrets:
            secret_name = secret['name']
            secret_value = secret['value']
            secret_hash = calculate_hash(secret_value)

            if secret_name not in state or state[secret_name] != secret_hash:
                update_secret_in_secrets_manager(secret_name, secret_value)
                state[secret_name] = secret_hash
                log_secret_change(secret_name)

        save_state_to_s3(state)
        logger.info('Password sync completed successfully')

    except ClientError as e:
        logger.error(f'Error occurred while interacting with AWS services: {str(e)}')
    except Exception as e:
        logger.error(f'Error occurred during password sync: {str(e)}')

    end_time = time.time()
    execution_time = end_time - start_time

    if execution_time > MAX_RUNTIME:
        logger.warning(f'Lambda execution time exceeded {MAX_RUNTIME} seconds')

    return {
        'statusCode': 200,
        'body': json.dumps('Password sync completed')
    }

def load_state_from_s3():
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=STATE_FILE_KEY)
        state = json.loads(response['Body'].read().decode('utf-8'))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            state = {}
        else:
            raise
    return state

def save_state_to_s3(state):
    s3.put_object(Bucket=BUCKET_NAME, Key=STATE_FILE_KEY, Body=json.dumps(state))

def calculate_hash(secret_value):
    return hashlib.sha256(secret_value.encode('utf-8')).hexdigest()

def update_secret_in_secrets_manager(secret_name, secret_value):
    try:
        secrets_manager.update_secret(SecretId=secret_name, SecretString=secret_value)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            secrets_manager.create_secret(Name=secret_name, SecretString=secret_value)
        else:
            raise

def log_secret_change(secret_name):
    logger.info(json.dumps({'message': f'Secret {secret_name} updated in Secrets Manager'}))