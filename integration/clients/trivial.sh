#!/bin/sh
set -eu

run_sftp() {
	sshpass -p secret sftp -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-trivial
}

assert_public_key_denied() {
	if printf 'ls /\n' | sftp -i /keys/acme -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-trivial >/dev/null 2>&1; then
		echo "public-key authentication unexpectedly succeeded" >&2
		exit 1
	fi
}

list_outbound() {
	printf 'ls Outbound\n' | run_sftp 2>&1
}

assert_public_key_denied
printf 'ls /\nls Inbound\nput /fixtures/hello.txt Inbound/hello.txt\n' | run_sftp
list_outbound | grep -F 'Outbound/seed.txt'
printf 'get Outbound/seed.txt /tmp/trivial-seed.txt\n' | run_sftp
printf 'trivial outbound seed\n' | cmp - /tmp/trivial-seed.txt
printf 'rm Outbound/seed.txt\n' | run_sftp
list_outbound | grep -F 'Outbound/seed.txt'