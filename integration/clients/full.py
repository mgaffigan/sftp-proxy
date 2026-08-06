import time

import paramiko


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


client = connect()
sftp = client.open_sftp()
assert sftp.listdir("/") == ["Workspace"]
assert "seed.txt" in sftp.listdir("/Workspace")

original = b"paramiko upload\n"
updated = b"paramiko update\n"
upload = "/Workspace/paramiko.txt"
renamed = "/Workspace/paramiko-renamed.txt"
directory = "/Workspace/paramiko-directory"

with sftp.open(upload, "wb") as destination:
    destination.write(original)
assert "paramiko.txt" in sftp.listdir("/Workspace")
with sftp.open(upload, "rb") as source:
    assert source.read() == original
    # Match the speculative read pattern used by pipelined desktop clients.
    source.seek(32768)
    assert source.read(32768) == b""
with sftp.open(upload, "wb") as destination:
    destination.write(updated)
with sftp.open(upload, "rb") as source:
    assert source.read() == updated
sftp.rename(upload, renamed)
assert "paramiko-renamed.txt" in sftp.listdir("/Workspace")
assert "paramiko.txt" not in sftp.listdir("/Workspace")
sftp.remove(renamed)
assert "paramiko-renamed.txt" not in sftp.listdir("/Workspace")
sftp.mkdir(directory)
assert "paramiko-directory" in sftp.listdir("/Workspace")
sftp.rmdir(directory)
assert "paramiko-directory" not in sftp.listdir("/Workspace")
sftp.close()
client.close()