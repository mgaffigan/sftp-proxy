import stat
import time

import boto3
import paramiko
from botocore.config import Config

# An ordinary S3 client, used only to read back what the proxy stored. What the
# store was told is not something SFTP can ask about.
store = boto3.client(
    "s3",
    endpoint_url="http://minio:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
)


def connect():
    deadline = time.monotonic() + 30
    while True:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect("proxy-s3", port=2222, username="acme", password="secret", timeout=3)
            return client
        except (OSError, paramiko.SSHException):
            client.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def refused(action):
    try:
        action()
    except IOError:
        return True
    return False


client = connect()
sftp = client.open_sftp()

assert sorted(sftp.listdir("/")) == ["Inbound", "Outbound", "ReadOnly", "Tenant"]

# A seeded object is a file with the size the store reports, not a guess.
assert sftp.listdir("/Outbound") == ["seed.txt"]
seeded = sftp.stat("/Outbound/seed.txt")
assert seeded.st_size == len(b"seed data")
with sftp.open("/Outbound/seed.txt", "rb") as source:
    assert source.read() == b"seed data"

# A prefix with no objects under it is an empty directory, not a missing one.
assert sftp.listdir("/Inbound") == []

original = b"paramiko upload\n"
updated = b"paramiko update\n"
upload = "/Inbound/paramiko.txt"
renamed = "/Inbound/paramiko-renamed.txt"

with sftp.open(upload, "wb") as destination:
    destination.write(original)
assert sftp.listdir("/Inbound") == ["paramiko.txt"]
with sftp.open(upload, "rb") as source:
    assert source.read() == original
    # Match the speculative read pattern used by pipelined desktop clients.
    source.seek(32768)
    assert source.read(32768) == b""

with sftp.open(upload, "wb") as destination:
    destination.write(updated)
with sftp.open(upload, "rb") as source:
    assert source.read() == updated

# The user states no headers, so the object carries the defaults, signed and
# stored by a real object store rather than a fake one.
stamp = {"user-agent": "sftp-proxy", "user-agent-id": "acme"}
assert store.head_object(Bucket="acme-archive", Key="inbound/paramiko.txt")["Metadata"] == stamp

sftp.rename(upload, renamed)
assert sftp.listdir("/Inbound") == ["paramiko-renamed.txt"]
# A rename copies the object and keeps what its upload was stamped with.
assert store.head_object(Bucket="acme-archive", Key="inbound/paramiko-renamed.txt")["Metadata"] == stamp
sftp.remove(renamed)
assert sftp.listdir("/Inbound") == []
assert refused(lambda: sftp.remove(renamed))

# A directory in a bucket is the prefix its members share, so there is none to
# make and none to unmake.
assert refused(lambda: sftp.mkdir("/Inbound/directory"))
assert refused(lambda: sftp.rmdir("/Outbound"))

# allowedMethods withholding PutObject/DeleteObject/CopyObject projects to
# read-only POSIX bits, and is inherited by everything beneath the node.
assert sftp.listdir("/ReadOnly") == ["seed.txt"]
assert not stat.S_IMODE(sftp.stat("/ReadOnly/seed.txt").st_mode) & 0o222
assert refused(lambda: sftp.open("/ReadOnly/blocked.txt", "wb"))
assert refused(lambda: sftp.remove("/ReadOnly/seed.txt"))

# A bucket the proxy was never configured for, reached with the credentials the
# HTTP backend stated on the entry naming it.
assert sorted(sftp.listdir("/Tenant")) == ["Archive", "ReadOnly"]
assert sftp.listdir("/Tenant/Archive") == ["hello.txt"]
with sftp.open("/Tenant/Archive/hello.txt", "rb") as source:
    assert source.read() == b"hello from OpenSSH"

# Those credentials are inherited by everything found beneath the entry, so a
# nested write works with nothing further stated.
nested = "/Tenant/Archive/tenant.txt"
with sftp.open(nested, "wb") as destination:
    destination.write(b"tenant upload\n")
assert sorted(sftp.listdir("/Tenant/Archive")) == ["hello.txt", "tenant.txt"]
sftp.remove(nested)

# The same bucket behind allowedMethods the backend stated as read-only, which
# is that restriction travelling down a subtree it did not configure.
assert refused(lambda: sftp.remove("/Tenant/ReadOnly/hello.txt"))

sftp.close()
client.close()
