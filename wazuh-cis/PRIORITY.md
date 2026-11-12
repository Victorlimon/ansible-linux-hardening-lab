# Isolated lab priority hardening

Run only `playbooks/wazuh_priority.yml`, then `playbooks/wazuh_priority_verify.yml`
from this directory with `-i inventory/lab/hosts.yml`. Neither imports the full
delta or the baseline roles. Supported targets are Debian 12 and Ubuntu 24.04.

## Behavior and policy mapping

| Area | Change | Check IDs |
|---|---|---|
| Sudo logging | Add the existing `/var/log/sudo.log` destination to main sudoers, with `visudo` validation; leave access drop-ins unchanged | 33027 / 35664 |
| AIDE installation | Install `aide` and `aide-common`, without recommended packages or package removals | 33028 / 35758 |
| Integrity schedule | Use the vendor `dailyaidecheck.timer`; a service drop-in runs scoped read-only checks and reports to the journal | 35759; Debian 33029 remains a policy mismatch |
| GRUB file | Change only existing regular `/boot/grub/grub.cfg` to root:root `0400`; no boot content or password changes | 33030 / 35541 |

The sudo drop-in already contained a valid directive without a final newline.
The Debian directory rule uses an unusual filename expression. A main-file
directive avoids relying on directory detection; the exact detection cause was
not isolated. No policy files were modified.

## Observed lab results — 2026-11-08

After applying this unit and restarting agents with the existing rescan playbook:

| Node | Previous score | New score | Passed / failed / invalid | Scan completed (UTC) |
|---|---|---|---|---|
| Debian 12, agent 006 | 78% | 80% | 140 / 34 / 6 | 22:57:43 |
| Ubuntu 24.04, agent 007 | 67% | 68% | 185 / 84 / 10 | 22:58:29 |

The API reports Debian checks 33027, 33028 and 33030 as passed, and Ubuntu checks
35541, 35664, 35758 and 35759 as passed. Debian 33029 remains failed. An invalid
result is not automatically a security failure or an accepted exception.
The second application reported `changed=0` on both hosts. An independent
foreground verification also returned `ok=14 changed=0 failed=0` on each host.
The first scheduled timer execution and a post-reboot check remain unobserved;
these results are not whole-host compliance certification or native review closure.

## Trust and monitoring boundary

AIDE covers `/etc`, `/usr`, and `/boot` recursively, with metadata and SHA-256.
It deliberately does not traverse runtime filesystems, `/home` (including the
VirtualBox shared folder), `/var`, `/tmp`, or `/opt`. This is a bounded initial OS
scope, not whole-host coverage or proof the current lab is uncompromised.
The database is private at `/var/lib/wazuh-priority-aide/aide.db`; vendor databases
and vendor AIDE configuration are preserved. A successful foreground initialization
has a 600-second limit and is promoted only if no baseline exists. A leftover
candidate stops the run. Scope changes under an existing database require review;
there is no automatic baseline update. Scheduled differences fail the service
and remain visible in `journalctl -u dailyaidecheck.service`; alert forwarding is
not configured. Verification performs an actual bounded comparison.

Debian 33029 requires a different unit name and a timer in `active (running)`
rather than the normal waiting state. Do not start a second scanner to satisfy it.
Ubuntu 35755 rejects normal audit-tool modes, 35765-68 combine alternative groups
with `all`, and 35770 combines mode `0600` with a `0644` permission string. These
permission findings are deferred rather than weakening permissions or editing policy.

## Rollback boundary

Remove only the added main-file logging line using `visudo` validation; the
pre-existing logging drop-in and NOPASSWD grants remain. Restore the recorded
GRUB mode (`0600` on both lab hosts) without regenerating GRUB. Stop/disable the
daily timer before removing this unit's service drop-in, scoped configuration,
and isolated database directory; then reload systemd. AIDE packages were absent
before this unit, but package removal is a separate reviewed operation. Keep
the trusted database if future integrity evidence is needed. No rollback is run.
