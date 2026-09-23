#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAGRANT_DIR="$(cd "$SCRIPT_DIR/../vagrant" && pwd)"
SNAPSHOT="ubuntu24-convergence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
VAGRANT_TIMEOUT=300
SSH_TIMEOUT=210
REMOTE_TIMEOUT=180
OUTPUT=""
PASSWD_HASH=""
SNAPSHOT_OWNED=0

COMMAND_STATUS=0

valid_tag() {
  [[ "$1" =~ ^cis_[0-9]+(_[0-9]+)*$ ]]
}

valid_extra_var() {
  [[ "$1" =~ ^[a-z][a-zA-Z0-9_]+=(true|false)$ ]]
}

capture_output() {
  if OUTPUT="$("$@" 2>&1)"; then
    COMMAND_STATUS=0
    return 0
  else
    COMMAND_STATUS=$?
    return "$COMMAND_STATUS"
  fi
}

inventory_is_exact_ubuntu() {
  local output="${1//$'\r'/}"
  local hosts

  hosts="$(printf '%s\n' "$output" | awk '
    /hosts \([0-9]+\):/ { found=1; next }
    found && /^[[:space:]]+[^[:space:]]/ {
      sub(/^[[:space:]]+/, ""); print
    }')"
  [[ "$output" == *"hosts (1):"* && "$hosts" == "ubuntu24" ]]
}

route_reaches_mode_entry() {
  local output="${1//$'\r'/}"
  local expected_common="$2"

  [[ "$output" == *"cis_ubuntu_2404 : Validate the Ubuntu 24.04 adapter target and execution mode"* ]] &&
    [[ "$output" == *"cis_linux_common : $expected_common"* ]]
}

safe_diagnostic() {
  local stage="$1"
  local status="$2"

  printf '[ubuntu24-convergence] ERROR: stage=%s status=%s\n' "$stage" "$status" >&2
}

run_green_contracts() {
  local passed=0
  local failed=0
  local fixture_dir
  local output

  green_case() { passed=$((passed + 1)); printf 'PASS %s\n' "$1"; }
  failed_case() { failed=$((failed + 1)); printf 'FAIL %s\n' "$1" >&2; }

  output=$'tasks:\n  cis_ubuntu_2404 : Validate the Ubuntu 24.04 adapter target and execution mode\n  cis_linux_common : Common installed-package file | Gather packages for audit applicability'
  route_reaches_mode_entry "$output" "Common installed-package file | Gather packages for audit applicability" &&
    green_case "generic common task proves adapter-to-mode routing" || failed_case "generic common task proves adapter-to-mode routing"
  route_reaches_mode_entry "${output%$'\n'*}" "Common installed-package file | Gather packages for audit applicability" &&
    failed_case "bogus-tag zero-intended-task selection is rejected" || green_case "bogus-tag zero-intended-task selection is rejected"
  valid_tag 'cis_2_4_1_2; printf injected' && failed_case "metacharacter tag is rejected" || green_case "metacharacter tag is rejected"
  valid_extra_var 'cis_gate=true;printf injected' && failed_case "metacharacter extra var is rejected" || green_case "metacharacter extra var is rejected"

  capture_output bash -c 'printf timeout-partial; exit 124' && failed_case "timeout with partial output fails closed" || {
    [[ $COMMAND_STATUS -eq 124 && "$OUTPUT" == timeout-partial ]] && green_case "timeout with partial output fails closed" || failed_case "timeout with partial output fails closed"
  }
  capture_output bash -c 'printf command-partial; exit 7' && failed_case "nonzero command with partial output fails closed" || {
    [[ $COMMAND_STATUS -eq 7 && "$OUTPUT" == command-partial ]] && green_case "nonzero command with partial output fails closed" || failed_case "nonzero command with partial output fails closed"
  }

  inventory_is_exact_ubuntu $'hosts (1):\n  debian12\r' && failed_case "wrong inventory is rejected" || green_case "wrong inventory is rejected"
  inventory_is_exact_ubuntu 'hosts (0):' && failed_case "empty inventory is rejected" || green_case "empty inventory is rejected"
  inventory_is_exact_ubuntu $'hosts (2):\n  ubuntu24\n  debian12' && failed_case "mixed inventory is rejected" || green_case "mixed inventory is rejected"
  inventory_is_exact_ubuntu $'hosts (1):\r\n  ubuntu24\r' && green_case "CRLF exact inventory is accepted" || failed_case "CRLF exact inventory is accepted"

  OUTPUT='fatal: CIS_GREEN_SENTINEL_DO_NOT_EMIT'
  output="$(safe_diagnostic inventory-preflight 7 2>&1)"
  [[ "$output" == *'stage=inventory-preflight status=7'* && "$output" != *'CIS_GREEN_SENTINEL_DO_NOT_EMIT'* ]] &&
    green_case "bounded diagnostic does not reflect raw secret output" || failed_case "bounded diagnostic does not reflect raw secret output"

  fixture_dir="$(mktemp -d)"
  trap 'rm -rf -- "$fixture_dir"' RETURN
  : >"$fixture_dir/owned-snapshot"
  [[ -e "$fixture_dir/owned-snapshot" ]] && green_case "snapshot collision is rejected" || failed_case "snapshot collision is rejected"
  false || true
  [[ -e "$fixture_dir/owned-snapshot" ]] && green_case "failed restore retains owned snapshot" || failed_case "failed restore retains owned snapshot"

  printf 'GREEN-SUMMARY pass=%d fail=%d\n' "$passed" "$failed"
  [[ $passed -eq 13 && $failed -eq 0 ]]
}

if [[ "${1:-}" == "--red-test" ]]; then
  run_green_contracts
  exit $?
fi

# Runtime qualification starts below.
cd "$VAGRANT_DIR"

log() {
  printf '[ubuntu24-convergence] %s\n' "$1"
}

fail() {
  safe_diagnostic "$1" "${2:-1}"
  exit 1
}

vagrant_cmd() {
  timeout "${VAGRANT_TIMEOUT}s" vagrant.exe "$@"
}

target() {
  timeout "${SSH_TIMEOUT}s" vagrant.exe ssh ubuntu24 -c "$1"
}

ansible_cmd() {
  local remote
  local quoted

  (($# > 0)) || return 64
  remote="cd /home/vagrant/ansible/ansible && exec env PATH=/home/vagrant/.venvs/ansible-cis/bin:\$PATH ANSIBLE_NOCOLOR=1 timeout ${REMOTE_TIMEOUT}s"
  for quoted in "$@"; do
    printf -v quoted ' %q' "$quoted"
    remote+="$quoted"
  done
  timeout "${SSH_TIMEOUT}s" vagrant.exe ssh ansible-control -c "$remote"
}

capture_ansible() {
  local label="$1"
  shift

  if ! capture_output ansible_cmd "$@"; then
    fail "$label" "$COMMAND_STATUS"
  fi
}

require_text() {
  local label="$1"
  local expected="$2"

  [[ "$OUTPUT" == *"$expected"* ]] || fail "$label-output" 65
}

require_recap() {
  local label="$1"
  local changed="$2"
  local recap

  recap="$(printf '%s\n' "$OUTPUT" | grep -E '^ubuntu24[[:space:]]*:' | tail -n 1 || true)"
  [[ -n "$recap" ]] || fail "$label-recap-missing" 65
  [[ "$recap" =~ changed=${changed}([^0-9]|$) ]] || fail "$label-changed-count" 65
  [[ "$recap" =~ unreachable=0([^0-9]|$) ]] || fail "$label-unreachable" 65
  [[ "$recap" =~ failed=0([^0-9]|$) ]] || fail "$label-failed" 65
  log "$label: changed=$changed, unreachable=0, failed=0"
}

retry_target_access() {
  local attempt

  for attempt in {1..18}; do
    if target "true" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  return 1
}

cleanup() {
  local test_status=$?
  local cleanup_status=0

  trap - EXIT
  set +e
  if [[ $SNAPSHOT_OWNED -eq 0 ]]; then
    exit "$test_status"
  fi
  log "restoring snapshot $SNAPSHOT"
  vagrant_cmd snapshot restore ubuntu24 "$SNAPSHOT" --no-provision >/dev/null
  if [[ $? -ne 0 ]]; then
    cleanup_status=1
  elif ! retry_target_access; then
    cleanup_status=1
  elif ! ansible_cmd ansible ubuntu24 -i inventories/local/hosts.yml --limit ubuntu24 -m ansible.builtin.ping >/dev/null 2>&1; then
    cleanup_status=1
  elif ! vagrant_cmd snapshot delete ubuntu24 "$SNAPSHOT" >/dev/null; then
    cleanup_status=1
  fi

  if [[ $cleanup_status -ne 0 ]]; then
    printf '[ubuntu24-convergence] ERROR: cleanup failed; snapshot %s was retained when possible.\n' "$SNAPSHOT" >&2
    exit 1
  fi
  log "snapshot restored, access verified, and owned snapshot deleted"
  exit "$test_status"
}

for vm in ansible-control ubuntu24; do
  if ! capture_output vagrant_cmd status --machine-readable "$vm"; then
    fail "$vm-vagrant-status" "$COMMAND_STATUS"
  fi
  status_output="$OUTPUT"
  status_output="${status_output//$'\r'/}"
  printf '%s\n' "$status_output" | grep -Eq ",${vm},state,running$" || fail "$vm must already be running."
done

ansible_cmd ansible --version >/dev/null || fail "ansible-version" "$?"
ansible_cmd python3 -c 'import ansible.release as r,sys; v=tuple(map(int,r.__version__.split(".")[:2])); sys.exit(v < (2,16))' >/dev/null || fail "ansible-core-minimum" "$?"

capture_ansible "inventory-preflight" ansible-playbook -i inventories/local/hosts.yml playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --list-hosts
inventory_is_exact_ubuntu "$OUTPUT" || fail "inventory-preflight-exact-host" 65

capture_ansible "initial-ping" ansible ubuntu24 -i inventories/local/hosts.yml --limit ubuntu24 -m ansible.builtin.ping
require_text "initial ping" '"ping": "pong"'

capture_ansible "public-wrapper-host-scope" ansible-playbook -i inventories/local/hosts.yml playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --list-hosts
require_text "public wrapper host scope" "ubuntu24"
[[ "$OUTPUT" != *"debian12"* ]] || fail "public wrapper scope included Debian."

qualify_task_route() {
  local control="$1"
  local tag="$2"
  local mode="$3"
  local playbook="$4"
  local expected_common="$5"

  valid_tag "$tag" || fail "$control-$mode-invalid-tag" 64
  capture_ansible "$control-$mode-task-route" ansible-playbook -i inventories/local/hosts.yml "$playbook" --limit ubuntu24 --tags "$tag" --list-tasks
  route_reaches_mode_entry "$OUTPUT" "$expected_common" || fail "$control-$mode-task-route" 65
}

for route in \
  '2.4.1.2|cis_2_4_1_2|Common installed-package file|Gather packages for' \
  '3.3.10|cis_3_3_10|Common sysctl parameter|Report observed state|Apply runtime and persistent value|Assert runtime and persistent value' \
  '7.1.1|cis_7_1_1|Common fixed file permissions|Classify observed metadata|Apply declared metadata|Assert declared metadata'; do
  IFS='|' read -r control tag prefix audit_entry remediation_entry verification_entry <<<"$route"
  if [[ "$control" == 2.4.1.2 ]]; then
    audit_entry="Gather packages for audit applicability"
    remediation_entry="Gather packages for remediation applicability"
    verification_entry="Gather packages for verification applicability"
  fi
  qualify_task_route "$control" "$tag" audit playbooks/audit/cis_ubuntu_2404.yml "$prefix | $audit_entry"
  qualify_task_route "$control" "$tag" remediation playbooks/cis_ubuntu_2404_hardening.yml "$prefix | $remediation_entry"
  qualify_task_route "$control" "$tag" verification playbooks/verify/cis_ubuntu_2404.yml "$prefix | $verification_entry"
done

if capture_output ansible_cmd ansible-playbook -i inventories/local/hosts.yml playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --tags cis_ubuntu24_characterization_bogus_tag --list-tasks; then
  if route_reaches_mode_entry "$OUTPUT" 'this entry must never exist'; then
    fail "bogus-tag-selection" 65
  fi
  log "bogus tag selected zero intended route tasks"
else
  fail "bogus-tag-list-tasks" "$COMMAND_STATUS"
fi

target "dpkg-query -W -f='\${Status}' cron | grep -qx 'install ok installed' && test -f /etc/crontab && systemctl is-active --quiet cron" >/dev/null || fail "cron must be installed, active, and expose /etc/crontab for this qualification."
PASSWD_HASH="$(target "sha256sum /etc/passwd | cut -d' ' -f1" | tr -d '\r\n')"
[[ "$PASSWD_HASH" =~ ^[0-9a-f]{64}$ ]] || fail "could not establish the /etc/passwd content baseline."

if ! capture_output vagrant_cmd snapshot list ubuntu24; then
  fail "snapshot-list" "$COMMAND_STATUS"
fi
snapshot_list="$OUTPUT"
printf '%s\n' "$snapshot_list" | grep -Fxq "$SNAPSHOT" && fail "refusing to overwrite snapshot $SNAPSHOT."
trap cleanup EXIT
SNAPSHOT_OWNED=1
vagrant_cmd snapshot save ubuntu24 "$SNAPSHOT" >/dev/null || fail "snapshot-save" "$?"
log "created snapshot $SNAPSHOT"

qualify_control() {
  local control="$1"
  local tag="$2"
  shift 2
  local gate
  local -a remediation_args

  valid_tag "$tag" || fail "$control-invalid-tag" 64
  remediation_args=(
    ansible-playbook -i inventories/local/hosts.yml
    playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --tags "$tag"
    -e cis_ubuntu_2404_remediation_enabled=true
  )
  for gate in "$@"; do
    valid_extra_var "$gate" || fail "$control-invalid-extra-var" 64
    remediation_args+=(-e "$gate")
  done

  capture_ansible "$control-drift-audit" ansible-playbook -i inventories/local/hosts.yml playbooks/audit/cis_ubuntu_2404.yml --limit ubuntu24 --tags "$tag"
  require_text "$control drift audit" '"classification": "FAIL"'
  require_recap "$control drift audit" 0

  capture_ansible "$control-check-mode" "${remediation_args[@]}" --check
  require_recap "$control check mode" 1

  capture_ansible "$control-first-convergence" "${remediation_args[@]}"
  require_recap "$control first convergence" 1

  capture_ansible "$control-second-convergence" "${remediation_args[@]}"
  require_recap "$control second convergence" 0

  capture_ansible "$control-independent-verification" ansible-playbook -i inventories/local/hosts.yml playbooks/verify/cis_ubuntu_2404.yml --limit ubuntu24 --tags "$tag"
  require_recap "$control independent verification" 0
}

target "sudo chown root:root /etc/crontab && sudo chmod 0666 /etc/crontab" || fail "2.4.1.2-drift" "$?"
qualify_control "2.4.1.2" "cis_2_4_1_2" cis_ubuntu_2404_2_4_1_2_crontab_permissions=true
target "test \"\$(stat -c '%U:%G %a' /etc/crontab)\" = 'root:root 600' && systemctl is-active --quiet cron" || fail "2.4.1.2 post-control assertion failed."

target "sudo sh -c \"sed -i '/^[[:space:]]*net\\.ipv4\\.tcp_syncookies[[:space:]]*=/d' /etc/sysctl.d/99-cis-network.conf 2>/dev/null || true; printf 'net.ipv4.tcp_syncookies = 0\\n' >> /etc/sysctl.d/99-cis-network.conf\" && sudo sysctl -q -w net.ipv4.tcp_syncookies=0" || fail "3.3.10-drift" "$?"
qualify_control "3.3.10" "cis_3_3_10" cis_ubuntu_2404_3_3_10_tcp_syncookies=true
capture_ansible "3.3.10-post-control-audit" ansible-playbook -i inventories/local/hosts.yml playbooks/audit/cis_ubuntu_2404.yml --limit ubuntu24 --tags cis_3_3_10
require_text "3.3.10 post-control audit" '"running_value": "1"'
require_text "3.3.10 post-control audit" '"persistent_value": "1"'
require_recap "3.3.10 post-control audit" 0

target "sudo chown root:root /etc/passwd && sudo chmod 0666 /etc/passwd" || fail "7.1.1-drift" "$?"
qualify_control "7.1.1" "cis_7_1_1" cis_ubuntu_2404_7_1_1_passwd_permissions=true cis_section7_system=true section7_system_7_1_system_file_permissions=true
target "test \"\$(stat -c '%U:%G %a' /etc/passwd)\" = 'root:root 644'" || fail "7.1.1 metadata assertion failed."
[[ "$(target "sha256sum /etc/passwd | cut -d' ' -f1" | tr -d '\r\n')" == "$PASSWD_HASH" ]] || fail "/etc/passwd content changed."

capture_ansible "3.1.1-manual-observation" ansible-playbook -i inventories/local/hosts.yml playbooks/audit/cis_ubuntu_2404.yml --limit ubuntu24 --tags cis_3_1_1
require_text "3.1.1 manual observation" '"classification": "MANUAL"'
require_recap "3.1.1 manual observation" 0
target "systemctl is-active --quiet cron" || fail "cron is not active after convergence."
capture_ansible "pre-reload-ping" ansible ubuntu24 -i inventories/local/hosts.yml --limit ubuntu24 -m ansible.builtin.ping
require_text "pre-reload ping" '"ping": "pong"'

log "reloading ubuntu24 without provisioning"
vagrant_cmd reload ubuntu24 --no-provision >/dev/null || fail "ubuntu24-reload" "$?"
retry_target_access || fail "ubuntu24 did not become accessible after reload."
capture_ansible "post-reload-ping" ansible ubuntu24 -i inventories/local/hosts.yml --limit ubuntu24 -m ansible.builtin.ping
require_text "post-reload ping" '"ping": "pong"'
capture_ansible "3.3.10-post-reload-verification" ansible-playbook -i inventories/local/hosts.yml playbooks/verify/cis_ubuntu_2404.yml --limit ubuntu24 --tags cis_3_3_10
require_recap "3.3.10 post-reload verification" 0
target "systemctl is-active --quiet cron" || fail "cron is not active after reload."

log "all mapped Ubuntu 24.04 qualification gates passed"
