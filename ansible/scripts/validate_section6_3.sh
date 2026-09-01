#!/usr/bin/env bash
# Read-only AIDE validation. It never installs, initializes, or promotes a DB.
set -euo pipefail

TOOLCHAIN_BIN="/home/vagrant/.venvs/ansible-cis/bin"
if [[ -d "$TOOLCHAIN_BIN" ]]; then
    export PATH="$TOOLCHAIN_BIN:$PATH"
fi

if [[ "$(hostname -s)" != "ansible-control" ]]; then
  echo "ERROR: run this script only inside ansible-control." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INVENTORY="$PROJECT_ROOT/inventories/local/hosts.yml"
PLAYBOOK="$PROJECT_ROOT/playbooks/cis_ubuntu_2404_hardening.yml"
TARGET="ubuntu24"
TAG="cis_6_3"
PROFILE="$PROJECT_ROOT/profiles/ubuntu_2404_aide_lab.yml"

cd "$PROJECT_ROOT"

ansible-playbook -i "$INVENTORY" "$PLAYBOOK" --limit "$TARGET" --syntax-check
TASK_OUTPUT="$(mktemp)"
trap 'rm -f "$TASK_OUTPUT"' EXIT
ansible-playbook -i "$INVENTORY" "$PLAYBOOK" \
  --limit "$TARGET" --tags "$TAG" -e "@$PROFILE" --list-tasks >"$TASK_OUTPUT"
if ! grep -q 'Install AIDE packages' "$TASK_OUTPUT"; then
    echo "ERROR: the safe AIDE profile did not select installation checks." >&2
    exit 1
fi
ansible-playbook -i "$INVENTORY" "$PLAYBOOK" \
  --limit "$TARGET" --tags "$TAG" -e "@$PROFILE" --check --diff

echo "AIDE read-only validation passed; initialization requires a separate approved run."
