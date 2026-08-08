# Puts the buckets and objects the S3 scenario reads, with an ordinary S3
# client, so what the proxy serves is an ordinary object rather than something
# arranged to suit it.
#
# acme-archive is the bucket the proxy is configured for. tenant-42-archive is
# not, and is reachable only through the credentials backend-s3 states on the
# entry naming it.
import time

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

s3 = boto3.client(
    "s3",
    endpoint_url="http://minio:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
)

deadline = time.monotonic() + 60
while True:
    try:
        s3.list_buckets()
        break
    except (BotoCoreError, ClientError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)

for bucket in ("acme-archive", "tenant-42-archive"):
    try:
        s3.create_bucket(Bucket=bucket)
    except ClientError as error:
        if error.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise

with open("/fixtures/seed.txt", "rb") as source:
    s3.put_object(Bucket="acme-archive", Key="outbound/seed.txt", Body=source.read())
with open("/fixtures/hello.txt", "rb") as source:
    s3.put_object(Bucket="tenant-42-archive", Key="2026/hello.txt", Body=source.read())

# inbound/ is left with nothing under it: a prefix with no objects is what an
# empty directory is here, and the proxy must present it as one.
