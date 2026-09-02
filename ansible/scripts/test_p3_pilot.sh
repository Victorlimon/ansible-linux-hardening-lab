#!/usr/bin/env bash
set -euo pipefail

if [[ "$(hostname -s)" != "ansible-control" ]]; then
  printf '%s\n' "ERROR: run this script only inside ansible-control." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_BIN="/home/vagrant/.venvs/ansible-cis/bin"

if [[ -d "$TOOLCHAIN_BIN" ]]; then
  export PATH="$TOOLCHAIN_BIN:$PATH"
fi

cd "$PROJECT_ROOT"

audit_output="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/audit/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_1)"
printf '%s\n' "$audit_output"

for expected_recap in "changed=0" "unreachable=0" "failed=0"; do
  if [[ "$audit_output" != *"$expected_recap"* ]]; then
    printf 'ERROR: P3 audit recap does not contain %s.\n' \
      "$expected_recap" >&2
    exit 1
  fi
done

ansible-playbook -i inventories/local/hosts.yml \
  playbooks/verify/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_1

ansible debian12 -i inventories/local/hosts.yml \
  --limit debian12 -m ansible.builtin.ping

printf '%s\n' "P3 pilot audit and independent verification passed."
