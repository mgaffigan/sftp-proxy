#!/bin/sh
set -eu

run_sftp() {
	sshpass -p secret sftp -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222 -b - acme@proxy-full
}

list_workspace() {
	printf 'ls Workspace\n' | run_sftp 2>&1
}

printf 'openssh upload\n' > /tmp/openssh-original.txt
printf 'openssh update\n' > /tmp/openssh-updated.txt
printf 'ls /\nls Workspace\n' | run_sftp
printf 'put /tmp/openssh-original.txt Workspace/openssh.txt\n' | run_sftp
list_workspace | grep -F 'Workspace/openssh.txt'
printf 'get Workspace/openssh.txt /tmp/openssh-downloaded.txt\n' | run_sftp
cmp /tmp/openssh-original.txt /tmp/openssh-downloaded.txt
printf 'put /tmp/openssh-updated.txt Workspace/openssh.txt\nget Workspace/openssh.txt /tmp/openssh-updated-downloaded.txt\n' | run_sftp
cmp /tmp/openssh-updated.txt /tmp/openssh-updated-downloaded.txt
printf 'rename Workspace/openssh.txt Workspace/openssh-renamed.txt\n' | run_sftp
list_workspace | grep -F 'Workspace/openssh-renamed.txt'
if list_workspace | grep -F 'Workspace/openssh.txt'; then exit 1; fi
printf 'rm Workspace/openssh-renamed.txt\n' | run_sftp
if list_workspace | grep -F 'Workspace/openssh-renamed.txt'; then exit 1; fi
printf 'mkdir Workspace/openssh-directory\n' | run_sftp
list_workspace | grep -F 'Workspace/openssh-directory'
printf 'rmdir Workspace/openssh-directory\n' | run_sftp
if list_workspace | grep -F 'Workspace/openssh-directory'; then exit 1; fi