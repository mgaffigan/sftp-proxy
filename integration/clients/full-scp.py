import os
import time

import paramiko
from scp import SCPClient, SCPException


def connect():
    deadline = time.monotonic() + 30
    while True:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect("proxy-full", port=2222, username="acme", password="secret", timeout=3)
            return client
        except (OSError, paramiko.SSHException):
            client.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def write(path, contents):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as destination:
        destination.write(contents)


def read(path):
    with open(path, "rb") as source:
        return source.read()


client = connect()
original = b"scp client upload\n"
updated = b"scp client update\n"
write("/tmp/scpclient/original.txt", original)

with SCPClient(client.get_transport()) as scp:
    # Into a directory, where the file keeps its own name.
    scp.put("/tmp/scpclient/original.txt", "/Workspace/")
    scp.get("/Workspace/original.txt", "/tmp/scpclient/downloaded.txt")
    assert read("/tmp/scpclient/downloaded.txt") == original

    # To a path that does not exist, which names the file itself.
    scp.put("/tmp/scpclient/original.txt", "/Workspace/scpclient.txt")
    scp.get("/Workspace/scpclient.txt", "/tmp/scpclient/renamed.txt")
    assert read("/tmp/scpclient/renamed.txt") == original

    write("/tmp/scpclient/updated.txt", updated)
    scp.put("/tmp/scpclient/updated.txt", "/Workspace/scpclient.txt")
    scp.get("/Workspace/scpclient.txt", "/tmp/scpclient/updated-downloaded.txt")
    assert read("/tmp/scpclient/updated-downloaded.txt") == updated

with SCPClient(client.get_transport()) as scp:
    write("/tmp/scpclient/tree/top.txt", b"top\n")
    write("/tmp/scpclient/tree/nested/deep.txt", b"deep\n")
    scp.put("/tmp/scpclient/tree", "/Workspace/", recursive=True, preserve_times=True)
    os.makedirs("/tmp/scpclient/back", exist_ok=True)
    scp.get("/Workspace/tree", "/tmp/scpclient/back", recursive=True, preserve_times=True)
    assert read("/tmp/scpclient/back/tree/top.txt") == b"top\n"
    assert read("/tmp/scpclient/back/tree/nested/deep.txt") == b"deep\n"

with SCPClient(client.get_transport()) as scp:
    # A file that is not there is refused, not answered with something else.
    try:
        scp.get("/Workspace/absent.txt", "/tmp/scpclient/absent.txt")
    except SCPException:
        pass
    else:
        raise AssertionError("downloading an absent file succeeded")

sftp = client.open_sftp()
# What SCP wrote is what SFTP sees: one filesystem, two protocols over it.
assert "original.txt" in sftp.listdir("/Workspace")
for path in ("/Workspace/original.txt", "/Workspace/scpclient.txt",
             "/Workspace/tree/nested/deep.txt", "/Workspace/tree/top.txt"):
    sftp.remove(path)
sftp.rmdir("/Workspace/tree/nested")
sftp.rmdir("/Workspace/tree")
sftp.close()
client.close()
