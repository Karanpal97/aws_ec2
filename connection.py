import boto3
from dotenv import load_dotenv
import os

load_dotenv()

access_key = os.getenv("AWS_ACCESS_KEY_ID")
secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

ec2 = boto3.client(
    "ec2",
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name=region,
)

response = ec2.describe_instances()
print(response)
