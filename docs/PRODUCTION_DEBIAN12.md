# Controlled Debian 12 canary operation

Debian 12 x86_64 remains **canary-only**. This guide covers controlled use of
the selected controls already implemented by the project; it does not promote
Debian to released, claim benchmark-wide coverage, or provide automatic
rollback. [SUPPORT.md](SUPPORT.md) remains the authority for support status and
evidence boundaries.

## Required gates

Use the public entry point `ansible/playbooks/cis_debian_12_hardening.yml` and a
single reviewed Debian 12 x86_64 lab canary. Before remediation:

1. Copy `inventories/production/group_vars/debian_12.yml.example` to the real,
   reviewed inventory and replace its fail-closed values.
2. Set `cis_execution_environment` to `lab`, `staging`, or `production`.
3. For production, also set `cis_production_mode: true`, provide a non-empty
   change ID, confirm a tested backup and out-of-band access, retain sufficient
   root filesystem space, and use a non-root remote automation identity.
4. Set both `cis_debian_12_remediation_enabled: true` and
   `cis_debian_12_canary_confirmed: true` only for the approved run.
5. Always provide an explicit `--limit` and one explicit control tag. A run with
   remediation enabled and no explicit `--tags` is rejected.

The adapter accepts only Debian 12 on x86_64. The preflight admits Debian's
`canary` state for this Debian-specific path; it does not change that state.

## Discover and preview

Run from the `ansible/` directory. Discover the available project labels before
selecting a control; do not treat those labels as current external benchmark
metadata.

```bash
ansible-playbook -i inventories/production/hosts.yml \
  playbooks/cis_debian_12_hardening.yml --limit debian-canary --list-hosts
ansible-playbook -i inventories/production/hosts.yml \
  playbooks/cis_debian_12_hardening.yml --limit debian-canary --list-tags
ansible-playbook -i inventories/production/hosts.yml \
  playbooks/cis_debian_12_hardening.yml --limit debian-canary \
  --tags cis_3_3_10 --check --diff \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true
```

Check mode is only a simulation. Modules may report incomplete predictions,
registered results may differ from a real run, and diff output may expose
sensitive data. A successful preview is not convergence evidence.

## Controlled lab validation

For one selected tag at a time:

1. Capture the initial owner, group, mode, content, sysctl value, connectivity,
   and affected service state.
2. Run the bounded check-mode preview and review every predicted change.
3. Apply to one disposable or recoverable lab canary during an approved window.
4. Verify the selected file or sysctl, SSH/sudo access, and affected services.
5. Apply the same bounded command again; investigate anything other than
   `changed=0`.
6. Run audit or verification for the same selected scope and retain the output.

Do not use a broad Debian role tag for remediation. Select a control tag shown
by `--list-tags`/`--list-tasks`, and keep all control-specific gates cumulative.
Banner remediation additionally requires approved non-empty local text and both
banner approval gates.

## Recovery boundaries

There is no general rollback. Prepare and test recovery per selected change:

| Change boundary | Recovery preparation |
|---|---|
| `/etc/issue` banner | Retain the backup created by the task and restore the approved prior file. |
| `/etc/crontab`, `/etc/passwd`, `/etc/passwd-`, `/etc/group`, `/etc/shadow` ownership or mode | Record the exact prior owner, group, and mode; restore only that metadata from console if validation fails. |
| `net.ipv4.tcp_syncookies` | Record the prior runtime value and the prior content of `/etc/sysctl.d/99-cis-network.conf`; restore both deliberately. |

Disabling a selector prevents another task run; it does not undo an applied
change. If recovery cannot restore a known-safe state, restore the tested
snapshot or backup and stop the canary.

## Remaining production boundary

Production use still requires organization-specific inventory, host keys,
change approval, backup restoration evidence, out-of-band recovery, workload
tests, controlled real convergence, second-run idempotency, and retained
scope-specific results. Debian remains canary until the separate admission work
listed in [SUPPORT.md](SUPPORT.md) is completed.
