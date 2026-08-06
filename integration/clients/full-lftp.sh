#!/bin/sh
set -eu

run_lftp() {
	lftp -c "set cmd:fail-exit true; set net:max-retries 5; set net:timeout 5; set sftp:auto-confirm yes; open -u acme,secret sftp://proxy-full:2222; $1"
}

printf 'lftp upload\n' > /tmp/lftp-original.txt
printf 'lftp update\n' > /tmp/lftp-updated.txt
run_lftp 'cls /; cls /Workspace'
run_lftp 'put /tmp/lftp-original.txt -o /Workspace/lftp.txt'
run_lftp 'cls /Workspace' | grep -F '/Workspace/lftp.txt'
run_lftp 'get /Workspace/lftp.txt -o /tmp/lftp-downloaded.txt'
cmp /tmp/lftp-original.txt /tmp/lftp-downloaded.txt
run_lftp 'put /tmp/lftp-updated.txt -o /Workspace/lftp.txt; get /Workspace/lftp.txt -o /tmp/lftp-updated-downloaded.txt'
cmp /tmp/lftp-updated.txt /tmp/lftp-updated-downloaded.txt
run_lftp 'mv /Workspace/lftp.txt /Workspace/lftp-renamed.txt'
run_lftp 'cls /Workspace' | grep -F '/Workspace/lftp-renamed.txt'
if run_lftp 'cls /Workspace' | grep -F '/Workspace/lftp.txt'; then exit 1; fi
run_lftp 'rm /Workspace/lftp-renamed.txt'
if run_lftp 'cls /Workspace' | grep -F '/Workspace/lftp-renamed.txt'; then exit 1; fi
run_lftp 'mkdir /Workspace/lftp-directory'
run_lftp 'cls /Workspace' | grep -F '/Workspace/lftp-directory'
run_lftp 'rmdir /Workspace/lftp-directory'
if run_lftp 'cls /Workspace' | grep -F '/Workspace/lftp-directory'; then exit 1; fi