#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SCENARIO=${1:-all}

case "$SCENARIO" in
  trivial|full|s3) SCENARIOS=$SCENARIO ;;
  all) SCENARIOS="trivial full s3" ;;
  *) echo "usage: $0 [trivial|full|s3|all]" >&2; exit 2 ;;
esac

for scenario in $SCENARIOS; do
  project="sftpproxy_${scenario}"
  cleanup() {
    docker compose --project-name "$project" -f "$ROOT/integration/compose.yml" --profile "$scenario" down --volumes --remove-orphans
  }
  trap cleanup EXIT INT TERM
  docker compose --project-name "$project" -f "$ROOT/integration/compose.yml" --profile "$scenario" up --build --abort-on-container-exit --exit-code-from "clients-$scenario"
  cleanup
  trap - EXIT INT TERM
done