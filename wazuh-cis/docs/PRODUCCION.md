# PRODUCTION RUNBOOK — wazuh-cis delta

The delta raised the lab SCA scores by closing the CIS v1.0.0 gaps that the
v1.1.0 stack cannot close. Production applies the **same role** with **zero
lab exceptions**. Anything marked LAB-ONLY in `docs/PREPRODUCCION.md` must not
appear in production inventories.

## Hard requirements before a production run
1. **Inventory is production's own**: production hosts, `ansible_user`,
   key-based SSH with **known_hosts pinning** (no `StrictHostKeyChecking=no`),
   become via sudo policy, and `wazuh_delta_platform` set per host
   (`debian_12` / `ubuntu_2404`). No copy of `inventory/lab/`.
2. **Secrets**: `wazuh_delta_root_password_hash` comes from **ansible-vault**
   (or the site secret store) and is a real, rotated crypt(6)/yescrypt hash —
   the committed lab hash is a lab credential and is invalid in production.
   The role fails closed if the gate is enabled with an empty/invalid hash.
3. **Change window**: the play restarts `ssh`, `rsyslog` and
   `systemd-journald` (never `wazuh-agent` outside the rescan play).
   `sshd -t` validation runs before any restart (handler order); existing
   sessions survive restarts. Confirm console/IPMI access to root with the
   new sulogin password before enabling `wazuh_delta_single_user_auth_enabled`.
4. **Order**: production hardening from `ansible/` (CIS v1.1.0) first, then
   this delta, then agent rescan. On Ubuntu 24.04 the delta MUST re-run after
   every repo re-application (install-target conflict `/bin/true` vs
   `/bin/false`, MAPPING.md §1/§8) — or adopt MAPPING §1 as the single source
   and change the repo target centrally instead (decision owner: security
   engineering, not this delta).
5. **AppArmor**: verify production workloads against enforcing every
   file-backed profile (containers, custom services). The delta refuses
   (fails) rather than silently leaving file-backed profiles complain/kill.
   Kernel transition stubs (`busybox`, `nautilus` on Ubuntu 24.04 GA kernel)
   stay in Wazuh 35538/35539 as documented mismatches — score expectation, not
   a security gap (they confine nothing; see MAPPING.md §5.3).
6. **Built-in modules**: squashfs/fat/fuse are CONFIG=y on the Ubuntu 24.04 GA
   kernel; 35506/35509 cannot pass without a custom kernel — accepted
   documented mismatch (MAPPING.md §5.2). Do not "fix" it by disabling
   `lsmod`-visible loads a policy regex cannot see.
7. **Firewall posture stays production's chosen engine.** Wazuh CIS v1.0.0
   policies enable UFW/nftables/iptables subprofiles simultaneously; they are
   mutually exclusive. The delta does not switch firewalls. Expect the
   firewall-family checks (5 on debian, 13 on ubuntu) to stay failed and
   treat them as documented mismatches (MAPPING.md §5.4).
8. **Snapd/squashfs interaction (Ubuntu)**: if production installs snaps,
   squashfs becomes required at runtime; the blacklists stay harmless
   (module is built-in) but the functional review must be recorded.

## Apply
```bash
ansible-playbook -i inventory/production/hosts.yml playbooks/wazuh_delta.yml
# rerun for idempotency: changed=0
ansible-playbook -i inventory/production/hosts.yml playbooks/wazuh_rescan.yml
```
(Production inventories live in the production deployment of this repo; the
lab files under `inventory/lab/` are never referenced.)

## Acceptance
- Per-host: role's built-in assertions green; `sshd -T`, `aa-status`,
  `systemctl is-enabled rsyslog`, journald keys, logrotate line as in the lab.
- Per-manager: `scripts/sca_report.ps1` — score movement matching MAPPING.md §6
  directionally; documented mismatches are the ONLY delta-scope checks still
  failing; no delta check regresses a previously passing non-delta check
  (the 33164 guard in `single_user_auth.yml` exists because of exactly such a
  regression; treat any new one the same way).
- Report residual gaps honestly: the delta closes v1.0.0-specific findings; it
  does not reach 100% because partitions, auditd rule families, time sync,
  password aging and the documented mismatches remain (MAPPING.md §7).

## Rollback
Same procedure as the lab runbook minus the lab-credential steps; production
root password rotation is handled by the secret store, not by re-locking.
