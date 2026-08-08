#!/bin/sh
set -eu

run_sftp() {
	sftp -i /keys/acme -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-pubkey
}

list_outbound() {
	printf 'ls Outbound\n' | run_sftp 2>&1
}

printf 'ls /\nls Inbound\nput /fixtures/hello.txt Inbound/hello.txt\n' | run_sftp
list_outbound | grep -F 'Outbound/seed.txt'
printf 'get Outbound/seed.txt /tmp/pubkey-seed.txt\n' | run_sftp
printf 'public-key outbound seed\n' | cmp - /tmp/pubkey-seed.txt
printf 'rm Outbound/seed.txt\n' | run_sftp
list_outbound | grep -F 'Outbound/seed.txt'