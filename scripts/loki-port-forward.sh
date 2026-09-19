#!/usr/bin/env bash
# Start a Loki port-forward for logtriage.py and keep it in the foreground.
# Usage: scripts/loki-port-forward.sh [namespace] [service] [local_port]
set -euo pipefail

NAMESPACE="${1:-monitoring}"
SERVICE="${2:-loki}"
PORT="${3:-3100}"

echo "port-forwarding ${NAMESPACE}/svc/${SERVICE} -> 127.0.0.1:${PORT}" >&2
kubectl port-forward -n "${NAMESPACE}" "svc/${SERVICE}" "${PORT}:3100"