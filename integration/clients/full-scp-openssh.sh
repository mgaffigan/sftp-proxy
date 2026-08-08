#!/bin/sh
set -eu

# -O forces the legacy SCP protocol. Without it OpenSSH 9 and later run the
# transfer over the SFTP subsystem instead, which would test the other half.
run_scp() {
	sshpass -p secret scp -O -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 "$@"
}

run_sftp() {
	sshpass -p secret sftp -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-full
}

printf 'openssh scp upload\n' > /tmp/scp-original.txt

# Upload into a directory, which the file keeps its own name in.
run_scp /tmp/scp-original.txt acme@proxy-full:/Workspace/
run_scp acme@proxy-full:/Workspace/scp-original.txt /tmp/scp-downloaded.txt
cmp /tmp/scp-original.txt /tmp/scp-downloaded.txt

# Upload to a path that does not exist, which names the file itself.
run_scp /tmp/scp-original.txt acme@proxy-full:/Workspace/scp-renamed.txt
run_scp acme@proxy-full:/Workspace/scp-renamed.txt /tmp/scp-renamed-downloaded.txt
cmp /tmp/scp-original.txt /tmp/scp-renamed-downloaded.txt

# Overwrite an existing file.
printf 'openssh scp update\n' > /tmp/scp-updated.txt
run_scp /tmp/scp-updated.txt acme@proxy-full:/Workspace/scp-renamed.txt
run_scp acme@proxy-full:/Workspace/scp-renamed.txt /tmp/scp-updated-downloaded.txt
cmp /tmp/scp-updated.txt /tmp/scp-updated-downloaded.txt

# A whole tree, up and back down again.
mkdir -p /tmp/scp-tree/nested
printf 'top\n' > /tmp/scp-tree/top.txt
printf 'deep\n' > /tmp/scp-tree/nested/deep.txt
run_scp -r /tmp/scp-tree acme@proxy-full:/Workspace/
mkdir -p /tmp/scp-back
run_scp -pr acme@proxy-full:/Workspace/scp-tree /tmp/scp-back/
cmp /tmp/scp-tree/top.txt /tmp/scp-back/scp-tree/top.txt
cmp /tmp/scp-tree/nested/deep.txt /tmp/scp-back/scp-tree/nested/deep.txt

# What SCP wrote is what SFTP sees: one filesystem, two protocols over it.
printf 'ls /Workspace\n' | run_sftp | grep -F 'scp-original.txt'

# A file that is not there is refused rather than downloaded as something else.
if run_scp acme@proxy-full:/Workspace/absent.txt /tmp/scp-absent.txt 2>/dev/null; then exit 1; fi

# Clean up, so a rerun against a live backend starts where this one did.
printf 'rm /Workspace/scp-original.txt\nrm /Workspace/scp-renamed.txt\n' | run_sftp
printf 'rm /Workspace/scp-tree/nested/deep.txt\nrmdir /Workspace/scp-tree/nested\n' | run_sftp
printf 'rm /Workspace/scp-tree/top.txt\nrmdir /Workspace/scp-tree\n' | run_sftp
