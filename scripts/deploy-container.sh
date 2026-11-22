#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

# Duvora — container deploy (one command): podman or docker on the remote host, no Kubernetes.
#
#   ./scripts/deploy-container.sh user@10.0.1.5
#   ./scripts/deploy-container.sh user@10.0.1.5 --dry-run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi
exec "${SCRIPT_DIR}/deploy-remote.sh" "$@" --docker
