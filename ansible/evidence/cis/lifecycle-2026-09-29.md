# CIS Runtime Lifecycle Receipts — 2026-09-29

Evidence from the full lifecycle run against a freshly provisioned lab
(`ansible-control` Ubuntu 24.04, ansible-core 2.21.2; targets `debian12`
192.168.56.11 and `ubuntu24` 192.168.56.12).

## Commands exercised

| Phase | Command (run on ansible-control, `cd /home/vagrant/ansible/ansible`) |
|---|---|
| Audit (observe) | `ansible-playbook -i inventories/local/hosts.yml playbooks/audit/cis_{debian_12,ubuntu_2404}.yml` |
| Hardening (remediate, sysctl subset) | `ansible-playbook ... playbooks/hardening/cis_<p>.yml -e cis_<p>_remediation_enabled=true [-e cis_debian_12_canary_confirmed=true] --tags sysctl` |
| Verify (observe) | `ansible-playbook ... playbooks/verify/cis_{debian_12,ubuntu_2404}.yml` |

## Audit — clean

| Platform | Recap |
|---|---|
| Debian 12 | `ok=1083 changed=0 failed=0 skipped=1642` |
| Ubuntu 24.04 | `ok=1143 changed=0 failed=0 skipped=1585` |

Both audits complete with **zero failures** (no fatal tasks, no undefined
variables) after the four lifecycle defects below were fixed.

## Hardening — convergence + idempotency (sysctl subset)

| Platform | 1st run | 2nd run (idempotency) |
|---|---|---|
| Debian 12 | `changed=21 failed=0` | `changed=0 failed=0` |
| Ubuntu 24.04 | `changed=19 failed=0` | `changed=0 failed=0` |

The sysctl remediation applies the CIS kernel parameters on the first run and
is a no-op on the second run — proving convergence and idempotency. The full
section coverage (SSH/PAM 5.x, firewall 4.x, services 2.x, file permissions
7.x) is the production rollout and remains a gated, site-specific operation.

## Verify — correctly detects non-compliance

- Before hardening: `failed=1` (sysctl persistent value unset).
- After sysctl hardening: sysctl passes; `failed=1` shifts to the not-yet-applied
  `fixed_file_permissions` (7.x) contract. This confirms verification is a real
  gate, not a vacuous pass.

## Defects surfaced and fixed by the lifecycle proof

1. **config_line audit/verification missing `regexp`** — 35 controls delegated to
   the mechanism without the required var; runtime failed with
   `cis_linux_common_config_line_regexp is undefined`. Fix: propagate remediation
   config into audit/verification (commit `a84f69e`).
2. **ufw_rule / ufw_policy `search` on undefined stdout** — crashed when ufw is
   absent. Fix: `| default('')` guard (commit `40087f7`).
3. **sysctl 3.3.7 incomplete contract** — omitted `runtime_path` and `file`.
   Fix: rewrite as a loop over ipv4 all+default with the full contract
   (commit `40087f7`).
4. **ufw_rule_match non-string pattern** — `cis_ufw_ssh_port` (int 22) reached
   `re.compile`, rejected. Fix: `| string` (commit `471ab48`).

## Remaining (non-blocking, production rollout)

Full convergence/idempotency/rollback receipts for the destructive families
(SSH/PAM, firewall, services, file permissions) require hardening those gated
sections on the target environment. The mechanism-level convergence and
idempotency are proven here on the sysctl family.
