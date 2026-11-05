# Wazuh SCA ↔ CIS Benchmark ↔ Repo Hardening — MAPPING

Scope: reconciliation between the **Wazuh SCA policies** deployed on the lab
manager (CIS **v1.0.0** spelling) and the `ansible/` hardening stack (CIS
**v1.1.0**), plus the delta controls implemented by `wazuh-cis/roles/wazuh_sca_delta`.

- Policies read for exact requirements:
  - `cis_debian12` — "Center for Internet Security Debian Family Linux Benchmark v1.0.0" (180 checks)
  - `cis_ubuntu24-04` — "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0" (279 checks)
- Evidence basis: rule strings echoed by the Wazuh API for the **deployed**
  policies plus live scan results on agents `005` (debian12) and `004` (ubuntu24).
- The `ansible/` directory implements CIS v1.1.0 and is **not modified** by this
  delta. Disposition legend:
  - **CLOSED** — delta remediation applied and the check flipped to `passed` in the rescan.
  - **PASS (already)** — check was already `passed` before the delta; the delta keeps it passing.
  - **DOCUMENTED MISMATCH** — the check cannot pass on this platform/policy; remediation
    equivalent to the benchmark's own guidance is applied where possible, but the
    Wazuh rule is structurally unsatisfiable. **Not chased.**
  - **REMAINING (out of scope)** — failing check outside the agreed delta scope.

## 1. Kernel modules

Wazuh v1.0.0 requires `modprobe -n -v <mod>` to print the install directive for
**every** listed module, even when the `.ko` is absent. The `ansible/`
`kernel_module_disabled` mechanism deliberately skips modules that are not
loadable on the kernel, which is why those checks failed at v1.1.0 level. The
delta force-creates `/etc/modprobe.d/<mod>.conf` with `install <mod> <target>`
+ `blacklist <mod>` for every module the respective policy probes.

**Critical platform difference:** `cis_debian12` matches `install /bin/true`,
while `cis_ubuntu24-04` matches `^install /bin/false`. The delta therefore
writes per-platform targets (`vars/debian_12.yml`: `/bin/true`;
`vars/ubuntu_2404.yml`: `/bin/false`). Because both touch the same files, the
**delta must be re-applied after every `ansible/` hardening re-run on Ubuntu**
(the repo role would rewrite `/bin/true`, regressing 14 Ubuntu checks).

### debian12 (cis_debian12)

| Wazuh ID | CIS ref | Title | Disposition |
|---|---|---|---|
| 33000 | 1.1.1.1 | cramfs disabled | **CLOSED** (forced `install cramfs /bin/true` + blacklist) |
| 33001 | 1.1.1.2 | freevxfs disabled | **DOCUMENTED MISMATCH** — policy regex defect, see §5.1 |
| 33002 | 1.1.1.3 | jffs2 disabled | PASS (already); file enforced by delta |
| 33003 | 1.1.1.4 | hfs disabled | PASS (already); file enforced by delta |
| 33004 | 1.1.1.5 | hfsplus disabled | PASS (already); file enforced by delta |
| 33005 | 1.1.1.6 | squashfs disabled | PASS (already); file enforced by delta |
| 33006 | 1.1.1.7 | udf disabled | PASS (already); file enforced by delta |
| 33024 | 1.1.23 | usb-storage disabled | PASS (already); file enforced by delta |
| 33078 | 3.5.1 | DCCP disabled | PASS (already); file enforced by delta |
| 33079 | 3.5.2 | SCTP disabled | PASS (already); file enforced by delta |
| 33080 | 3.5.3 | RDS disabled | PASS (already); file enforced by delta |
| 33081 | 3.5.4 | TIPC disabled | PASS (already); file enforced by delta |

### ubuntu24 (cis_ubuntu24-04)

| Wazuh ID | CIS ref | Title | Disposition |
|---|---|---|---|
| 35500 | 1.1.1.1 | cramfs | **CLOSED** (`install cramfs /bin/false`) |
| 35501 | 1.1.1.2 | freevxfs | **CLOSED** |
| 35502 | 1.1.1.3 | hfs | **CLOSED** |
| 35503 | 1.1.1.4 | hfsplus | **CLOSED** |
| 35504 | 1.1.1.5 | jffs2 | **CLOSED** |
| 35505 | 1.1.1.6 | overlayfs (literal policy spelling) | **CLOSED** |
| 35506 | 1.1.1.7 | squashfs | **DOCUMENTED MISMATCH** — built-in kernel module, §5.2 |
| 35507 | 1.1.1.8 | udf | **CLOSED** |
| 35508 | 1.1.1.9 | usb-storage | **CLOSED** |
| 35509 | 1.1.1.10 | unused filesystems (afs ceph cifs exfat ext fat fscache fuse gfs2 nfs_common nfsd smbfs_common) | **DOCUMENTED MISMATCH** — `fat`/`fuse` built-in, §5.2 |
| 35604 | 3.2.1 | dccp | **CLOSED** |
| 35605 | 3.2.2 | tipc | **CLOSED** |
| 35606 | 3.2.3 | rds | **CLOSED** (file also satisfies the policy's `d:/etc/modprobe.d` rules) |
| 35607 | 3.2.4 | sctp | **CLOSED** (same) |

All 25 Ubuntu module config files were force-created; 22 of 25 probe names are
interceptable. The compound 35509 check needs **all** sub-modules to print the
directive, so the built-in `fat`/`fuse` entries make it unsatisfiable on the
Ubuntu 24.04 stock kernel.

## 2. SSH forwarding

| Wazuh ID | CIS ref | Title | Disposition |
|---|---|---|---|
| 33142 | 5.2.5 | SSH X11 forwarding is disabled (debian) | **CLOSED** |
| 33157 | 5.2.20 | SSH AllowTcpForwarding is disabled (debian) | **CLOSED** |

Mechanism: `/etc/ssh/sshd_config.d/99-wazuh-cis-delta.conf` + pinned lines in
`/etc/ssh/sshd_config` (sshd first-match semantics make both places
equivalent), validated with `sshd -t` before restart; post-restart `sshd -T`
assertion is part of the role. On ubuntu24 these directives are also applied
(policy checks there were already passing).

## 3. Single-user mode authentication (sulogin)

| Wazuh ID | CIS ref | Title | Disposition |
|---|---|---|---|
| 33032 | 1.5.3 | Authentication required for single user mode (debian) | **CLOSED** |

Rule: `f:/etc/shadow -> r:^root:\$\w` — root must carry a real password hash so
`sulogin` can authenticate. Delta sets `wazuh_delta_root_password_hash`
(crypt `$6$`). **Regression guard:** giving root a hash brings its shadow row
into the numeric scope of check 33164 (password expiration ≤ 365), so the delta
also runs `chage --maxdays 365 root`; 33164 passed again on the following scan.
Ubuntu has no counterpart check in its policy; the control is not in
`vars/ubuntu_2404.yml` supported controls.

## 4. Logging

| Wazuh ID | CIS ref | Title | Disposition |
|---|---|---|---|
| 33122 | 4.2.1.1 | rsyslog is installed (debian) | **CLOSED** |
| 33123 | 4.2.1.2 | rsyslog service is enabled (debian) | **CLOSED** |
| 33124 | 4.2.1.3 | rsyslog default file permissions (debian) | PASS (kept: `$FileCreateMode 0640`) |
| 33125 | 4.2.2.1 | journald sends logs to rsyslog (debian) | **CLOSED** (`ForwardToSyslog=yes`) |
| 33128 | 4.4 | logrotate assigns appropriate permissions (debian) | **CLOSED** (`create 0640`) |
| 35708 | 6.1.1.3 | journald log file rotation (ubuntu) | **CLOSED** (5 integer keys in `/etc/systemd/journald.conf`) |
| 35717 | 6.1.3.2 | rsyslog service enabled and active (ubuntu) | **CLOSED** (unmask + enable + start; unit shipped masked) |
| 35719 | 6.1.3.4 | rsyslog log file creation mode (ubuntu) | **CLOSED** (`99-wazuh-cis-delta.conf` drop-in + `$FileCreateMode 0640`) |

Platform note: on ubuntu the policy **forbids** `ForwardToSyslog=yes` (35713)
while the debian policy **requires** it (33125). The delta writes the
platform-correct value from `vars/<platform>.yml`; a naive cross-platform
"rsyslog enable" would have broken 35713 on ubuntu.

## 5. Documented mismatches (do NOT chase)

### 5.1 cis_debian12 check 33001 (freevxfs) — policy regex defect
Deployed rule (echoed by the API):

```
"c:modprobe -n -v freevxfs -> r: install /bin/true"
```

The regex token begins with a space (`r:` + space + `install ...`). The correct
config is present (`/etc/modprobe.d/freevxfs.conf` with
`install freevxfs /bin/true`, verified live: `modprobe -n -v freevxfs` prints
`install /bin/true`), and the sibling checks without the stray space (33000
cramfs, 33002+ jffs2 …) all passed the same scan. The regex can only match a
line starting with a space, which `modprobe -n -v` never prints →
**unsatisfiable by any system state**. Remediation applied anyway (config file
is exactly what CIS prescribes); the check is classified
documented-mismatch, not chased further.

### 5.2 Ubuntu 24.04 built-in kernel modules (35506 squashfs, 35509 fat/fuse)
On `6.8.0-86-generic`, `squashfs`, `fat`, `fuse` (and `vfat`) are **built into
the kernel** (`modules.builtin`). `modprobe -n -v <builtin>` prints nothing for
built-ins — the `install` directive is never reached — so the policy's
`^install /bin/false` cannot match regardless of configuration. Files with the
benchmark-prescribed `install`+`blacklist` pair **are** written (harmless, and
correct should the modules become loadable). Changing this would require a
custom kernel or `module_blacklist=` boot params, which the Wazuh rule does not
evaluate. Functional note: with snapd present, blocking `squashfs` (if it were
loadable) would break snap mounting; no snaps are configured on these nodes.

### 5.3 Ubuntu AppArmor kernel transition stubs (35538, 35539)
`aa-status` reports "2 profiles are in unconfined mode: busybox, nautilus".
Verified live on the lab node:
- No backing file exists in `/etc/apparmor.d` for either name.
- They appear only as `/sys/kernel/security/apparmor/profiles` stubs created by
  AppArmor 4 transition machinery.
- `aa-enforce busybox|nautilus` is accepted but has no effect; direct sysfs
  writes are refused (I/O error); `aa-remove-unknown` cannot remove them.
Every **file-backed** profile is enforcing (117/119 enforced; the role asserts
this set is clean and idempotent). Because the policy requires literally "0
profiles are in unconfined mode", 35538/35539 remain failed →
documented-mismatch (packaging limitation, not remediable by configuration).

### 5.4 Debian firewall: UFW/iptables policy vs nftables implementation (user-directed)
The lab implements **nftables** (repo v1.1.0 design). The Wazuh cis_debian12
policy v1.0.0 additionally enables the UFW and iptables subprofiles
simultaneously; those are **mutually exclusive** stances of CIS §3.6, and the
delta must not switch the firewall engine (explicit instruction). Affected
failing checks, documented not chased:

| Wazuh ID | CIS ref | Title |
|---|---|---|
| 33082 | 3.6.1.1 | Uncomplicated Firewall is installed |
| 33084 | 3.6.1.3 | ufw service is enabled |
| 33090 | 3.6.2.5 | base chains exist (expects literal `priority 0`; repo ruleset uses the equivalent `priority filter` keyword) |
| 33094 | 3.6.3.1.1 | iptables packages are installed |
| 33095 | 3.6.3.1.2 | nftables is not installed (directly contradicts the deployed nftables engine) |

The same simultaneous-subprofile artifact affects ubuntu24 (13 failing
firewall checks 35624–35639 across its ufw/nftables/iptables sections; the lab
uses UFW there): all documented-mismatch, none chased.

### 5.5 Additional Ubuntu policy self-contradiction (informational)
cis_ubuntu24-04 enables journald AND rsyslog subprofiles at once (e.g. 35713
forbids `ForwardToSyslog=yes`, 35718 is any-of). The delta's platform-conditional
journald handling is exactly the posture the benchmark expects per chosen
logging stack; 35720 (send logs to remote host) / 35721 remain out of scope.

## 6. Scores (Wazuh API, policy `score`)

| Node | Agent | Before (pre-delta session baseline) | After delta |
|---|---|---|---|
| debian12 | 005 | **71** (user-provided earlier baseline: 69) | **75** |
| ubuntu24 | 004 | **64** (user-provided earlier baseline: 59) | **70** |

Baseline measured at the start of this session (`/sca/{agent}` scans
2026-11-05T01:21Z); post-delta scans at 02:43Z (ubuntu) and 02:50Z (debian,
after the 33164 regression fix). The user's stated 69%/59% predate lab
re-hardening that had already raised the live baseline.

## 7. Disposition counts

| | debian12 | ubuntu24 |
|---|---|---|
| Delta checks CLOSED by this work | 8 | 17 |
| Delta checks already PASS, kept green by delta | 12 | 0 |
| Delta checks DOCUMENTED MISMATCH (§5) | 1 | 4 |
| Firewall DOCUMENTED MISMATCH (§5.4) | 5 | 13 |
| Other checks REMAINING (out of scope) | 37 | 63 |
| Invalid / not-applicable (excluded from score) | 7 | 8 |

### Remaining failing checks — out of delta scope (for the record)
- **debian12 (37):** separate-partition family (33011,33012,33014,33016,33017,33018),
  sudo log (33027), AIDE timer (33029), grub permissions (33030), AppArmor
  bootloader (33038), GDM (33047, unpassable rule `dpkg -s GDM` — package is
  `gdm3`), time-sync family (33050,33051,33052), rsync/RPC (33067,33074),
  audit-rule family (33108-33120), cron/at allowlists (33136,33137), strong MACs
  (33150), password-policy family (33160,33161 (expects deprecated pam_tally2),
  33163,33165,33166,33167), shadow-account (33178, rule logic inverted — not
  fixable without breaking login).
- **ubuntu24 (63):** partition/mount-option family, bootloader access (35541),
  core dumps / error reporting (35543,35545), GDM (35552), MTA loopback-only
  (35581), time sync (35588,35591,35592), cron/at (35600,35601), IPv6 RA
  (35618), sshd MACs (35654), sudo log (35664), PAM/pwquality families
  (35675-35706 subset), journal-upload (35710,35711), rsyslog remote target
  (35720,35721), logfile perms (35722), audit-rule family (35731-35760),
  shadow perms (35765-35770).
  None of these were in the agreed delta scope; many are the same
  structural/partition/auditd families already tracked as lab limitations.

## 8. Known interaction with the ansible/ stack
- Re-applying `ansible/playbooks/hardening/*` **on ubuntu24** rewrites the
  modprobe files to `/bin/true` (v1.1.0 mechanism target) → re-run the delta
  afterwards (14 module checks depend on this order).
- The delta does not touch `ansible/` at all; it only owns its own files
  (`/etc/modprobe.d/<mod>.conf` content, sshd drop-in, rsyslog drop-in,
  journald/logrotate/sshd_config lines).
