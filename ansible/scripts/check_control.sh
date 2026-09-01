#!/usr/bin/env bash
set -euo pipefail

if [[ "$(hostname -s)" != "ansible-control" ]]; then
  printf '%s\n' "ERROR: run this script only inside ansible-control." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPOSITORY_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"
cd "$PROJECT_ROOT"

for command_name in ansible ansible-inventory ansible-playbook; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'ERROR: required command is missing: %s\n' "$command_name" >&2
    exit 1
  fi
done

ansible --version
ansible-inventory -i inventories/local/hosts.yml --graph

playbooks=(
  playbooks/cis_hardening.yml
  playbooks/cis_ubuntu_2404_hardening.yml
  playbooks/cis_debian_12_preflight.yml
  playbooks/cis_debian_12_audit.yml
  playbooks/cis_debian_12_hardening.yml
)

for playbook in "${playbooks[@]}"; do
  ansible-playbook -i inventories/local/hosts.yml "$playbook" --syntax-check
done

strict="${CIS_STRICT_QUALITY_TOOLS:-false}"
for quality_tool in ansible-lint yamllint; do
  if ! command -v "$quality_tool" >/dev/null 2>&1; then
    if [[ "$strict" == "true" ]]; then
      printf 'ERROR: strict mode requires %s.\n' "$quality_tool" >&2
      exit 1
    fi
    printf 'WARN: %s is not installed; its check was skipped.\n' "$quality_tool" >&2
  fi
done

if command -v ansible-lint >/dev/null 2>&1; then
  (
    cd "$REPOSITORY_ROOT"
    ANSIBLE_CONFIG="$PROJECT_ROOT/ansible.cfg" \
      ANSIBLE_ROLES_PATH="$PROJECT_ROOT/roles" \
      ansible-lint ansible/playbooks ansible/roles
  )
fi

if command -v yamllint >/dev/null 2>&1; then
  (
    cd "$REPOSITORY_ROOT"
    yamllint .
  )
fi

printf '%s\n' "Control-node static checks completed; no target was remediated."
