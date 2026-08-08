#!/bin/sh
set -eu

host_key=$(ssh-keygen -lf /hostkey/host_key | awk '{print $2}')

# -scp forces the SCP protocol; pscp prefers SFTP when the server offers it.
run_pscp() {
	pscp -scp -batch -hostkey "$host_key" -P 2222 -l acme -pw secret "$@"
}

run_sftp() {
	sshpass -p secret sftp -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-full
}

printf 'pscp upload\n' > /tmp/pscp-original.txt

run_pscp /tmp/pscp-original.txt proxy-full:/Workspace/pscp.txt
run_pscp proxy-full:/Workspace/pscp.txt /tmp/pscp-downloaded.txt
cmp /tmp/pscp-original.txt /tmp/pscp-downloaded.txt

printf 'pscp update\n' > /tmp/pscp-updated.txt
run_pscp /tmp/pscp-updated.txt proxy-full:/Workspace/pscp.txt
run_pscp proxy-full:/Workspace/pscp.txt /tmp/pscp-updated-downloaded.txt
cmp /tmp/pscp-updated.txt /tmp/pscp-updated-downloaded.txt

mkdir -p /tmp/pscp-tree/nested
printf 'top\n' > /tmp/pscp-tree/top.txt
printf 'deep\n' > /tmp/pscp-tree/nested/deep.txt
run_pscp -r /tmp/pscp-tree proxy-full:/Workspace/
mkdir -p /tmp/pscp-back
run_pscp -r proxy-full:/Workspace/pscp-tree /tmp/pscp-back/
cmp /tmp/pscp-tree/top.txt /tmp/pscp-back/pscp-tree/top.txt
cmp /tmp/pscp-tree/nested/deep.txt /tmp/pscp-back/pscp-tree/nested/deep.txt

if run_pscp proxy-full:/Workspace/absent.txt /tmp/pscp-absent.txt 2>/dev/null; then exit 1; fi

printf 'rm /Workspace/pscp.txt\n' | run_sftp
printf 'rm /Workspace/pscp-tree/nested/deep.txt\nrmdir /Workspace/pscp-tree/nested\n' | run_sftp
printf 'rm /Workspace/pscp-tree/top.txt\nrmdir /Workspace/pscp-tree\n' | run_sftp
