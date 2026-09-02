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

for platform in ubuntu_2404 debian_12; do
  if [[ "$platform" == "ubuntu_2404" ]]; then
    limit="ubuntu24"
    playbook_platform="cis_ubuntu_2404"
  else
    limit="debian12"
    playbook_platform="cis_debian_12"
  fi

  audit_output="$(ansible-playbook -i inventories/local/hosts.yml \
    "playbooks/audit/$playbook_platform.yml" \
    --limit "$limit" --tags cis_3_3_10)"
  printf '%s\n' "$audit_output"

  for expected in '"control": "3.3.10"' '"classification": "PASS"' \
    '"running_value": "1"' '"persistent_value": "1"' \
    'changed=0' 'unreachable=0' 'failed=0'; do
    if [[ "$audit_output" != *"$expected"* ]]; then
      printf 'ERROR: %s sysctl audit output does not contain %s.\n' \
        "$platform" "$expected" >&2
      exit 1
    fi
  done

  ansible-playbook -i inventories/local/hosts.yml \
    "playbooks/verify/$playbook_platform.yml" \
    --limit "$limit" --tags cis_3_3_10
  ansible "$limit" -i inventories/local/hosts.yml \
    --limit "$limit" -m ansible.builtin.ping
done

printf '%s\n' "P4 common CIS 3.3.10 read-only gate passed on both platforms."
