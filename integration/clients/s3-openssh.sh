#!/bin/sh
set -eu

run_sftp() {
	sshpass -p secret sftp -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-s3
}

# -O forces the legacy SCP protocol, which states a file's length before sending
# it and so needs the size the object store reports.
run_scp() {
	sshpass -p secret scp -O -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 "$@"
}

list_inbound() {
	printf 'ls Inbound\n' | run_sftp 2>&1
}

printf 'openssh upload\n' > /tmp/s3-original.txt
printf 'openssh update\n' > /tmp/s3-updated.txt

printf 'ls /\nls Outbound\n' | run_sftp
printf 'get Outbound/seed.txt /tmp/s3-seed.txt\n' | run_sftp
printf 'seed data' | cmp - /tmp/s3-seed.txt

printf 'put /tmp/s3-original.txt Inbound/openssh.txt\n' | run_sftp
list_inbound | grep -F 'Inbound/openssh.txt'
printf 'get Inbound/openssh.txt /tmp/s3-downloaded.txt\n' | run_sftp
cmp /tmp/s3-original.txt /tmp/s3-downloaded.txt

printf 'put /tmp/s3-updated.txt Inbound/openssh.txt\nget Inbound/openssh.txt /tmp/s3-updated-downloaded.txt\n' | run_sftp
cmp /tmp/s3-updated.txt /tmp/s3-updated-downloaded.txt

printf 'rename Inbound/openssh.txt Inbound/openssh-renamed.txt\n' | run_sftp
list_inbound | grep -F 'Inbound/openssh-renamed.txt'
if list_inbound | grep -F 'Inbound/openssh.txt'; then exit 1; fi

# A name a client may give is a name the store may hold, whatever is in it.
printf 'put /tmp/s3-original.txt "Inbound/an odd name.txt"\n' | run_sftp
list_inbound | grep -F 'an odd name.txt'
printf 'get "Inbound/an odd name.txt" /tmp/s3-odd.txt\n' | run_sftp
cmp /tmp/s3-original.txt /tmp/s3-odd.txt
printf 'rm "Inbound/an odd name.txt"\n' | run_sftp

# SCP over the same filesystem, which needs the object's exact length.
run_scp /tmp/s3-original.txt acme@proxy-s3:/Inbound/
run_scp acme@proxy-s3:/Inbound/s3-original.txt /tmp/s3-scp-downloaded.txt
cmp /tmp/s3-original.txt /tmp/s3-scp-downloaded.txt
printf 'rm Inbound/s3-original.txt\n' | run_sftp

# There is no directory to make in a bucket, and no empty one to remove.
if printf 'mkdir Inbound/openssh-directory\n' | run_sftp 2>/dev/null; then exit 1; fi

printf 'rm Inbound/openssh-renamed.txt\n' | run_sftp
if list_inbound | grep -F 'Inbound/openssh-renamed.txt'; then exit 1; fi
