#!/bin/sh
set -eu

host_key=$(ssh-keygen -lf /hostkey/host_key | awk '{print $2}')

run_psftp() {
	batch=$(mktemp)
	cat > "$batch"
	psftp -batch -hostkey "$host_key" -b "$batch" -P 2222 -l acme -pw secret proxy-full
	rm -f "$batch"
}

printf 'psftp upload\n' > /tmp/psftp-original.txt
printf 'psftp update\n' > /tmp/psftp-updated.txt
run_psftp <<'EOF'
ls /
ls /Workspace
quit
EOF
run_psftp <<'EOF'
put /tmp/psftp-original.txt /Workspace/psftp.txt
quit
EOF
run_psftp <<'EOF' | grep -F 'psftp.txt'
ls /Workspace
quit
EOF
run_psftp <<'EOF'
get /Workspace/psftp.txt /tmp/psftp-downloaded.txt
quit
EOF
cmp /tmp/psftp-original.txt /tmp/psftp-downloaded.txt
run_psftp <<'EOF'
put /tmp/psftp-updated.txt /Workspace/psftp.txt
get /Workspace/psftp.txt /tmp/psftp-updated-downloaded.txt
quit
EOF
cmp /tmp/psftp-updated.txt /tmp/psftp-updated-downloaded.txt
run_psftp <<'EOF'
mv /Workspace/psftp.txt /Workspace/psftp-renamed.txt
quit
EOF
run_psftp <<'EOF' | grep -F 'psftp-renamed.txt'
ls /Workspace
quit
EOF
if run_psftp <<'EOF' | grep -F 'psftp.txt'; then exit 1; fi
ls /Workspace
quit
EOF
run_psftp <<'EOF'
rm /Workspace/psftp-renamed.txt
quit
EOF
if run_psftp <<'EOF' | grep -F 'psftp-renamed.txt'; then exit 1; fi
ls /Workspace
quit
EOF
run_psftp <<'EOF'
mkdir /Workspace/psftp-directory
quit
EOF
run_psftp <<'EOF' | grep -F 'psftp-directory'
ls /Workspace
quit
EOF
run_psftp <<'EOF'
rmdir /Workspace/psftp-directory
quit
EOF
if run_psftp <<'EOF' | grep -F 'psftp-directory'; then exit 1; fi
ls /Workspace
quit
EOF