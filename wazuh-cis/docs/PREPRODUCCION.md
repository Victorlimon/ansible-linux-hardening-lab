# PRE-PRODUCTION (LAB) RUNBOOK — wazuh-cis delta

Applies the Wazuh SCA (CIS v1.0.0) delta on the lab nodes, then measures.
The lab is the only place where the exceptions listed below are allowed.

## Prerequisites
- Vagrant lab up: `ansible-control` (192.168.56.10), `debian12` (.11), `ubuntu24` (.12).
- Ansible-core 2.21.2 venv on ansible-control: `/home/vagrant/.venvs/ansible-cis`.
- `ansible/` CIS v1.1.0 hardening already applied (this delta is additive).
- Wazuh manager (Docker, host `wazuh`) with SCA policies `cis_debian12` and
  `cis_ubuntu24-04` deployed; agents: 005=debian12, 004=ubuntu24.
- Repo synced to `ansible-control:/home/vagrant/ansible/` (this directory:
  `/home/vagrant/ansible/wazuh-cis`).

## Apply (from ansible-control)
```bash
cd /home/vagrant/ansible/wazuh-cis
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml \
    playbooks/wazuh_delta.yml                 # serial: 1 node at a time
# idempotency proof: run it again — expect changed=0 failed=0
# force fresh SCA scans:
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml \
    playbooks/wazuh_rescan.yml
```

## Measure (Windows host)
```powershell
wazuh-cis/scripts/sca_report.ps1              # scores per agent
wazuh-cis/scripts/sca_report.ps1 -Detail      # + failed check ids/titles
```
Wait ~60–90 s after the rescan; verify `end_scan` moved forward.

Reference results (2026-11-05 lab run): debian12 71→75, ubuntu24 64→70.
Per-check dispositions: see `MAPPING.md`.

## LAB-ONLY exceptions (NEVER copy to production)
1. **Host key checking disabled** (`StrictHostKeyChecking=no`,
   `/dev/null` known_hosts) — ephemeral recreated VMs. Production uses
   known_hosts pinning.
2. **Root password hash committed in `inventory/lab/hosts.yml`** — crypt `$6$`
   of the throwaway lab password `LAB-ONLY-wazuh-sulogin-2026` (console
   authentication for single-user mode, Wazuh 33032). Production supplies the
   hash from ansible-vault; the role asserts a non-empty value and has no
   baked default.
3. **Lab agent enrollment / manager addressing** (192.168.56.1) — production
   uses the real manager VIP and full enrollment.
4. **AppArmor stub limitation accepted** (`busybox`, `nautilus` kernel
   transition stubs — §5.3 of MAPPING.md).
5. **squashfs/fat/fuse built-in modules accepted** (§5.2). snapd is present on
   ubuntu24 with no snaps configured; if snaps are installed later, revisit
   the squashfs posture before enforcing the file blacklist in production.
6. `create 0640` logrotate line is applied on debian (Wazuh 33128); Ubuntu's
   policy has no such check and it is skipped there by design.

## Apply order (matters)
`ansible/` hardening (v1.1.0) FIRST, then `wazuh-cis` delta, then rescan.
On ubuntu24 the delta must always be re-run after the repo role because the
repo rewrites modprobe install targets to `/bin/true` while the Wazuh Ubuntu
policy demands `/bin/false` (MAPPING.md §1, §8).

## Rollback (lab)
- Remove `/etc/ssh/sshd_config.d/99-wazuh-cis-delta.conf` and re-apply the repo
  sshd baseline; delete `/etc/modprobe.d/<mod>.conf` files the delta owns
  (they are exact-content checksums — diff before deleting); `apt remove
  rsyslog` on debian to return to journald-only; `chage --maxdays 99999 root`
  + relock root (`passwd -l root`) to undo the single-user change.
- Re-run the repo role to restore v1.1.0 file content, then rescan.

## Validation gates built into the role
Every area ends with a live-state assertion (`modprobe -n -v`, `sshd -T`,
`systemctl is-enabled rsyslog`, journald key grep, `logrotate` grep,
`aa-status --json`). A green `changed=0` rerun is the convergence proof.
