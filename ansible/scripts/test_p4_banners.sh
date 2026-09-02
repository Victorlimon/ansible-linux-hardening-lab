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
  --limit debian12 --tags cis_1_6_2)"
printf '%s\n' "$audit_output"

for expected in '"control": "1.6.2"' '"classification": "FAIL"' \
  '"prohibited_os_information_detected": true' \
  '"content_redacted": true' 'changed=0' 'unreachable=0' 'failed=0'; do
  if [[ "$audit_output" != *"$expected"* ]]; then
    printf 'ERROR: banner audit output does not contain %s.\n' "$expected" >&2
    exit 1
  fi
done

disabled_output="$(ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_1_6_2 --check --diff)"
printf '%s\n' "$disabled_output"

for expected in 'changed=0' 'unreachable=0' 'failed=0'; do
  if [[ "$disabled_output" != *"$expected"* ]]; then
    printf 'ERROR: disabled banner remediation output does not contain %s.\n' \
      "$expected" >&2
    exit 1
  fi
done

if ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags cis_1_6_2 --check --diff \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true \
  -e cis_debian_12_banner_remediation_enabled=true; then
  printf '%s\n' "ERROR: banner remediation accepted unapproved empty text." >&2
  exit 1
else
  remediation_status=$?
  if [[ "$remediation_status" -ne 2 ]]; then
    printf 'ERROR: unexpected banner remediation status: %s.\n' \
      "$remediation_status" >&2
    exit 1
  fi
fi

if ansible-playbook -i inventories/local/hosts.yml \
  playbooks/verify/cis_debian_12.yml \
  --limit debian12 --tags cis_1_6_2; then
  printf '%s\n' "ERROR: banner verification passed without approved text." >&2
  exit 1
else
  verify_status=$?
  if [[ "$verify_status" -ne 2 ]]; then
    printf 'ERROR: unexpected banner verification status: %s.\n' \
      "$verify_status" >&2
    exit 1
  fi
fi

ansible debian12 -i inventories/local/hosts.yml \
  --limit debian12 -m ansible.builtin.ping

printf '%s\n' "P4 banner read-only audit and legal-policy gate passed."
