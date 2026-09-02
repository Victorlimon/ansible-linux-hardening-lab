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
  --limit debian12 --tags cis_7_1_5)"
printf '%s\n' "$audit_output"

for expected in 'classification": "PASS' 'content_redacted": true' \
  'changed=0' 'unreachable=0' 'failed=0'; do
  if [[ "$audit_output" != *"$expected"* ]]; then
    printf 'ERROR: Debian CIS 7.1.5 audit output does not contain %s.\n' \
      "$expected" >&2
    exit 1
  fi
done

disabled_output="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_5 --check --diff)"
printf '%s\n' "$disabled_output"

if [[ "$disabled_output" != *'changed=0'* ]]; then
  printf '%s\n' 'ERROR: disabled CIS 7.1.5 remediation predicted a change.' >&2
  exit 1
fi

if gate_output="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_5 --check --diff \
  -e cis_debian_12_remediation_enabled=true 2>&1)"; then
  printf '%s\n' "$gate_output"
  printf '%s\n' 'ERROR: CIS 7.1.5 accepted remediation without canary confirmation.' >&2
  exit 1
fi
printf '%s\n' "$gate_output"

if [[ "$gate_output" != *'cis_debian_12_canary_confirmed=true'* ]]; then
  printf '%s\n' 'ERROR: CIS 7.1.5 rejection did not identify the canary gate.' >&2
  exit 1
fi

ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_5 --check --diff \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true

first_output="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_5 \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true)"
printf '%s\n' "$first_output"

second_output="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_5 \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true)"
printf '%s\n' "$second_output"

if [[ "$second_output" != *'changed=0'* ]]; then
  printf '%s\n' 'ERROR: second CIS 7.1.5 remediation was not idempotent.' >&2
  exit 1
fi

ansible-playbook -i inventories/local/hosts.yml \
  playbooks/verify/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_5
ansible debian12 -i inventories/local/hosts.yml \
  --limit debian12 -m ansible.builtin.ping

printf '%s\n' 'P4 Debian CIS 7.1.5 independent-interface gate passed.'
