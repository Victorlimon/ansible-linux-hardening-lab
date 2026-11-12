# Apply selected Wazuh CIS hardening in one run

Use `playbooks/wazuh_hardening.yml` for remediation and
`playbooks/wazuh_hardening_verify.yml` for independent read-only checks.
The role supports Debian 12 and Ubuntu 24.04 from gathered facts. Every
functional group defaults to **false**; the separate lab group policy enables
only this bounded batch. No old delta, priority initializer or lab service
remover is imported. Existing kernel, legacy-client, logging, audit and AIDE
configuration is preserved rather than reapplied through those broader sources.

## Quick path

Run from `/home/vagrant/ansible/wazuh-cis` on the authorized controller:

```console
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_hardening.yml
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_hardening_verify.yml
```

Repeat the apply command once to prove idempotence. Core **2.21.2** is required.
Use `--tags hardening_pam` (or another category below) with either entry point
to select one enabled category. Tags never override disabled gates. `always`
preflight checks still run; the verifier also proves a fresh SSH session and sudo.

Preproduction requires a **different inventory**, containing the
`wazuh_delta_targets` group, its own connection settings and explicitly
authorized administrator users. Do not copy lab connection exceptions,
password variables, usernames or network assumptions. This batch implements a
username allowlist, not network-based SSH restrictions; network authorization
and routing dependencies require separate site review.

## Policy inputs and control coverage

All switches below use the `wazuh_hardening_` prefix. Detailed inputs are in
`roles/wazuh_cis_hardening/defaults/main.yml`; lab overrides are only in
`inventory/lab/group_vars/wazuh_delta_targets.yml`.

| Switch / tag | Implemented behavior | Policy check references, not a score claim |
|---|---|---|
| `pam_enabled` / `hardening_pam` | Installed PAM providers; quality length 14, difok 2, four classes, repeat/sequence 3, dictionary/enforcement; root quality; history 24 with root enforcement and token reuse; remove only Unix `nullok` | Debian 33160, history intent of 33162; Ubuntu 35679–35690; preserve 35692–35693 |
| `ssh_enabled` / `hardening_ssh` | Nonempty explicit `admin_users`, connection user included; global AllowUsers before includes; complete config validation, reload and fresh SSH+sudo | Debian 33154; Ubuntu 35643 |
| `account_defaults_enabled` / `hardening_accounts` | Future maximum 365, minimum 1, warning 7 and inactive 30; report selected existing ages with `chage --list` | Defaults portion only of Debian 33164–33167 and Ubuntu 35694–35696, 35698 |
| `environment_enabled` / `hardening_environment` | Mask 0027 in login.defs, system login/interactive Bash and existing root startup files; interactive exported readonly TMOUT 900 | Ubuntu 35705–35706; root mask intent of 35703, detector also expects `.bash_profile` |
| `core_enabled` / `hardening_core` | Existing sysctl source reused for suid_dumpable=0; user/root hard core=0; installed systemd collector restrictions; installed Apport disabled/stopped/masked | Ubuntu 35543, 35545 intent; detector unit names/state may disagree |
| `shm_enabled` / `hardening_shm` | Explicit `shm_compatible` approval; retain unrelated live tmpfs options; persistent and live noexec,nodev,nosuid; no unmount or migration | Debian 33020–33022; Ubuntu 35515–35517 |
| `priority_enabled` / `hardening_priority` | Preserve established main sudoers logging, validate complete sudo policy; existing GRUB config root:root 0400 | Debian 33027, 33030; Ubuntu 35664, 35541 |

The lab administrator list is `ansible`, `vagrant`, supplied only by inventory.
The reusable role contains no lab hostnames, addresses or Vagrant dependencies.
Unknown/conditional SSH access policy is refused rather than silently broadened.
The PAM profile priority is deliberately **1000**, below pwquality's **1024**
and above Unix's **256**: quality must obtain a token before history consumes it.
For distro-managed stacks, `pam-auth-update --package --enable` activates only
required profiles, with no `--force`. The lab's first apply demonstrated that
the tool declines its locally modified stack; verification correctly failed.
The bounded correction explicitly sets `pam_preserve_local_stack: true` in
lab inventory. This mode follows the policy's custom-file remediation: retain
all existing controls, ordering and options, insert only history immediately
before Unix and remove only Unix `nullok` tokens. It does not regenerate the
stack or change numeric jumps. A preproduction site must explicitly review
that choice rather than inherit it. Preflight now compares the **entire active
common-password flow** before any role writes. The only supported flow is
pwquality `requisite retry=3`, optional managed history `requisite`, Unix
`[success=1 default=ignore] obscure use_authtok try_first_pass yescrypt`,
deny `requisite`, then permit `required`. The verifier requires history present.
The Unix success jump skips exactly the following deny entry and reaches
permit; no numeric jump precedes the history insertion. Only blank lines,
full-line comments and horizontal whitespace are ignored. Includes, substacks,
extra/duplicate modules, changed options/controls/order and other numeric jumps
are refused, not repaired. This narrowly models the observed lab flow, not
arbitrary distro or custom PAM stacks. Declarative fixtures exercise accepted
before/after flows and rejected extra modules, earlier/altered jumps,
include/substack directives, fallback control changes and missing history.
No passwords are changed to test
history: verification proves configuration/order and fresh key-based SSH+sudo,
not a complete password-change transaction.

### Interactive timeout semantics

The approved `tmout` is a ceiling (1–900 seconds), not a mandate to weaken a
smaller existing positive limit. Interactive Bash retains a canonical positive
integer at or below that ceiling and always makes it **readonly and exported**,
including values inherited from the environment. Missing, zero, malformed,
leading-zero or weaker writable values become the approved ceiling. A compliant
already-readonly value is never assigned again, so repeated startup is safe.
An invalid or weaker already-readonly value cannot be repaired safely: startup
prints an explicit policy error and exits1 without a conflicting assignment.
Review an earlier site startup setting to resolve that refusal; do not clear
the environment globally. Noninteractive shells do not set or freeze TMOUT.

Native verifier cases cover root and connection-user interactive startup with
clean, inherited900, weak1800, zero, malformed and stricter300 environments,
plus compliant readonly/repeated startup and expected weak-readonly refusal.
Clean/inherited noninteractive `bash -c` and `bash -lc` cases check preservation.
The initial writer's three earlier apply failures retain **unknown numeric
process exits**; this corrective attempt records its own process exits explicitly.

## Explicitly unresolved or excluded

- **Existing account aging remains unchanged.** Old lab credentials may already
  exceed 365 days. The apply reports dates but never changes last-change dates,
  maximum age, inactivity, passwords, locks or account expiry in `/etc/shadow`.
  Default compliance is not a claim of complete account-aging SCA compliance.
- **Debian 33163 expects literal sha512.** Existing yescrypt is retained; no
  detector-driven downgrade. Debian 33162 uses a negative test of `required`
  history; this role uses the stronger ordered `requisite` history and does not
  treat that detector alone as proof.
- **Network gate remains false and rejects enablement:** reverse-path-filter
  and IPv6 RA require current route/dependency confirmation and site policy.
  No IPv6 disable, DHCP change or firewall change is implemented.
- **No blanket kernel/AppArmor enforcement or audit reload.** Existing audit
  detector issues (33111, 33119, unresolved b32 applicability) are unchanged.
  No audit flush, `augenrules`, immutable mode or full-disk halt is invoked.
- No `/tmp` changes, partition migration, GUI installation, GRUB password,
  root password change, account unlock, production or manager change.
- Masked Apport is deliberately stronger than merely disabled. Ubuntu 35545
  literally requires `disabled`; 35543 queries `coredump.service`, not the
  usual systemd collector. No fake unit or package is added for either check.
- Root uses its existing `.profile` and `.bashrc`; no new `.bash_profile` is
  created merely to satisfy 35703 because that would shadow `.profile`.

## Integrity warning and rollback

The established `/var/lib/wazuh-priority-aide/aide.db` and
`/etc/aide/wazuh-priority.conf` are never initialized, refreshed, updated,
excluded or deleted by this entry point. The prior AIDE **rc=6** remains an
unresolved integrity warning (Debian 32 removed/10 changed; Ubuntu 23 removed/7
changed). New PAM/profile/SSH/login/limits/fstab/sudo configuration changes and
private backups create additional expected monitored deltas. Do not report
overall integrity as passed, and do not rebaseline to hide this warning.

First-run PAM files, SSH configuration and fstab copies are preserved under
`/var/backups/wazuh-cis-hardening/` with `.original` suffixes and mode 0600.
Other line/block edits and replacements use Ansible timestamped adjacent
backups. Inspect these root-only files locally before restoration; never print
credential stores. Roll back a group from console/authorized existing access:

- PAM: restore the five `common-*` files and original Unix/pwquality profiles
  together; remove only the new `wazuh-cis-pwhistory` profile if reverting this
  group. Review distro profile selection/cache before a later regeneration.
- SSH: restore `sshd_config.original`, run `sshd -t`, then reload `ssh` and prove
  a fresh login+sudo. Keep the working session open until proof completes.
- Mount: restore `fstab.original`, reload systemd and remount `/dev/shm` using
  the reviewed original options. Never unmount active shared memory.
- Defaults/environment/core: restore the relevant timestamped backups; remove
  only this role's new limits fragment. Restore optional collector service
  state according to the approved previous site policy, not a blanket unmask.
- Sudo/GRUB: restore the reviewed previous metadata or sudoers backup and run
  `visudo -c`. Never roll back the unrelated AIDE baseline.

Disabling a gate stops management; it does **not** undo prior hardening.
The priority group expects GRUB already installed; it never installs a
bootloader or creates a missing boot configuration on another site.

## Measured lab results — 2026-11-09 UTC

After the final correction, both agents were restarted through the existing
rescan playbook. The Wazuh API returned these newly completed scans:

| Client | Previous score | New score | Passed / failed / invalid | Scan completed (UTC) |
|---|---|---|---|---|
| Debian 12, agent 006 | 80% | 82% | 143 / 31 / 6 | 02:05:14 |
| Ubuntu 24.04, agent 007 | 69% | 73% | 199 / 71 / 9 | 02:05:48 |

This is three additional passed checks on Debian and thirteen on Ubuntu.
The API confirms SSH access restrictions, password-quality settings and
`/dev/shm` restrictions as passed. Ubuntu also passes the history length/root
enforcement, Unix `nullok` removal, shell timeout and default umask checks.
Debian's literal SHA-512 and existing-account aging checks remain failed.
Ubuntu's PAM profile-detection, lockout, history-token detection, existing-account
expiration and crash-collector detection checks are not declared closed.

The exact second apply reported `changed=0 failed=0` on both clients.
After a bounded correction, an independent read-only verifier reported
`ok=68 changed=0 failed=0` on Debian and `ok=72 changed=0 failed=0` on Ubuntu,
including fresh SSH and sudo access, inherited-timeout cases and eleven PAM
contract fixtures. Real password-change transactions and reboot persistence
were not exercised. Existing AIDE differences remain open; a higher SCA score
is not a clean integrity verdict or formal native review closure.
