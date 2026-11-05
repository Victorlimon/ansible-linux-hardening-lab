#!/usr/bin/env bash
set -euo pipefail

# Select a trusted, absolute executable from the institutional Ansible 2.21.2 venv.
: "${ANSIBLE_PLAYBOOK_BIN:?Set ANSIBLE_PLAYBOOK_BIN to the absolute venv ansible-playbook path}"
case "$ANSIBLE_PLAYBOOK_BIN" in
  /*) ;;
  *) echo 'ANSIBLE_PLAYBOOK_BIN must be an absolute path' >&2; exit 1 ;;
esac
if [[ ! -x "$ANSIBLE_PLAYBOOK_BIN" ]]; then
  echo 'The selected ansible-playbook is not executable' >&2
  exit 1
fi

ansible_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$ansible_dir"

extra_args=()
if (($# != 0)); then
  if (($# != 2)) || [[ "$1" != '--critical' || "$2" != /* ]]; then
    echo 'Usage: run_ansible_control_hardening.sh [--critical /absolute/root-owned/policy.yml]' >&2
    exit 1
  fi
  if ! sudo test -f "$2" || sudo test -L "$2"; then
    echo 'Critical policy must be an existing regular file, not a symlink' >&2
    exit 1
  fi
  policy_permissions=$(sudo stat -c '%u:%g:%a' "$2")
  if [[ "$policy_permissions" != '0:0:600' && "$policy_permissions" != '0:0:400' ]]; then
    echo 'Critical policy must be root:root with mode 0600 or 0400' >&2
    exit 1
  fi
  extra_args=(-e "@$2" -e controller_critical_enabled=true)
fi

# Check the executable under the same privilege used for the playbook. sudo
# prompts for the administrator password when required; no NOPASSWD is assumed.
version_output=$(sudo "$ANSIBLE_PLAYBOOK_BIN" --version)
version_line=${version_output%%$'\n'*}
if [[ "$version_line" != *'[core 2.21.2]'* ]]; then
  echo "Expected Ansible Core 2.21.2, got: $version_line" >&2
  exit 1
fi

if sudo test -L /var || ! sudo test -d /var || sudo test -L /var/log || ! sudo test -d /var/log; then
  echo '/var and /var/log must be real directories' >&2
  exit 1
fi
for parent_dir in /var /var/log; do
  parent_metadata=$(sudo stat -c '%u:%g:%a' "$parent_dir")
  IFS=: read -r parent_uid parent_gid parent_mode <<< "$parent_metadata"
  if [[ "$parent_uid" != 0 || "$parent_gid" != 0 ]] || (( (8#$parent_mode & 8#22) != 0 )); then
    echo "$parent_dir must be root-owned and not group/world writable" >&2
    exit 1
  fi
done

log_dir=/var/log/ansible-control
log_file=$log_dir/ansible.log
if sudo test -L "$log_dir"; then
  echo 'Refusing a symlinked Ansible log directory' >&2
  exit 1
fi
if sudo test -e "$log_dir"; then
  if ! sudo test -d "$log_dir" || [[ $(sudo stat -c '%u:%g:%a' "$log_dir") != '0:0:700' ]]; then
    echo 'Existing Ansible log directory must be root:root 0700' >&2
    exit 1
  fi
else
  sudo install -d -o root -g root -m 0700 "$log_dir"
fi

if sudo test -L "$log_file"; then
  echo 'Refusing a symlinked Ansible log file' >&2
  exit 1
fi
if sudo test -e "$log_file"; then
  if ! sudo test -f "$log_file" || [[ $(sudo stat -c '%u:%g:%a' "$log_file") != '0:0:600' ]]; then
    echo 'Existing Ansible log file must be regular and root:root 0600' >&2
    exit 1
  fi
else
  sudo install -o root -g root -m 0600 /dev/null "$log_file"
fi

sudo env ANSIBLE_LOG_PATH="$log_file" \
  "$ANSIBLE_PLAYBOOK_BIN" \
  -i inventories/ansible_control/hosts.yml \
  playbooks/hardening/ansible_control_ubuntu_2404.yml \
  "${extra_args[@]}"
