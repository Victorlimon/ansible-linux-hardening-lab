#!/usr/bin/env bash
set -euo pipefail

if [[ "$(hostname -s)" != "ansible-control" ]]; then
  printf '%s\n' "ERROR: run this script only inside ansible-control." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

assert_contains() {
  local value="$1"
  local expected="$2"
  local description="$3"
  if [[ "$value" != *"$expected"* ]]; then
    printf 'ERROR: %s; expected %s\n' "$description" "$expected" >&2
    exit 1
  fi
}

assert_not_contains() {
  local value="$1"
  local unexpected="$2"
  local description="$3"
  if [[ "$value" == *"$unexpected"* ]]; then
    printf 'ERROR: %s; found unexpected %s\n' "$description" "$unexpected" >&2
    exit 1
  fi
}

ubuntu_hosts="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --list-hosts)"
assert_contains "$ubuntu_hosts" "ubuntu24" "Ubuntu entry point did not select ubuntu24"
assert_not_contains "$ubuntu_hosts" "debian12" "Ubuntu entry point selected Debian"

ubuntu_wrong_limit="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/cis_ubuntu_2404_hardening.yml --limit debian12 --list-hosts 2>&1)"
assert_contains "$ubuntu_wrong_limit" "hosts (0)" "Ubuntu entry point accepted Debian limit"

debian_hosts="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/cis_debian_12_hardening.yml --limit debian12 --list-hosts)"
assert_contains "$debian_hosts" "debian12" "Debian entry point did not select debian12"
assert_not_contains "$debian_hosts" "ubuntu24" "Debian entry point selected Ubuntu"

debian_wrong_limit="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/cis_debian_12_hardening.yml --limit ubuntu24 --list-hosts 2>&1)"
assert_contains "$debian_wrong_limit" "hosts (0)" "Debian entry point accepted Ubuntu limit"

compatibility_hosts="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/cis_hardening.yml --limit ubuntu24 --list-hosts)"
assert_contains "$compatibility_hosts" "ubuntu24" "Compatibility entry point changed host selection"
assert_not_contains "$compatibility_hosts" "debian12" "Compatibility entry point selected Debian"

printf '%s\n' "Inventory and playbook isolation contracts passed."
