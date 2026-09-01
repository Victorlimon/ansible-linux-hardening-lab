#!/usr/bin/env bash
# Read-only Section 6 validation. Run only from ansible-control.
set -euo pipefail

if [[ "$(hostname -s)" != "ansible-control" ]]; then
  echo "ERROR: run this script only inside ansible-control." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INVENTORY="$PROJECT_ROOT/inventories/local/hosts.yml"
PLAYBOOK="$PROJECT_ROOT/playbooks/cis_ubuntu_2404_hardening.yml"
TARGET="ubuntu24"

cd "$PROJECT_ROOT"

echo "[1/3] Syntax"
ansible-playbook -i "$INVENTORY" "$PLAYBOOK" --limit "$TARGET" --syntax-check

echo "[2/3] Section tag discovery"
TAG_OUTPUT="$(mktemp)"
trap 'rm -f "$TAG_OUTPUT"' EXIT
ansible-playbook -i "$INVENTORY" "$PLAYBOOK" \
  --limit "$TARGET" --tags cis_sec6 --list-tasks >"$TAG_OUTPUT"
if ! grep -q 'SECTION 6' "$TAG_OUTPUT"; then
    echo "ERROR: cis_sec6 did not select the Section 6 entry point." >&2
    exit 1
fi

echo "[3/3] Check mode"
ansible-playbook -i "$INVENTORY" "$PLAYBOOK" \
  --limit "$TARGET" --tags cis_sec6 \
  -e cis_section6_logging_audit=true --check --diff

echo "Section 6 read-only validation passed."
