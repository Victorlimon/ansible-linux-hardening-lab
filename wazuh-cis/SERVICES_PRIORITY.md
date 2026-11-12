# Unused rsync removed from the disposable lab

Only rsync was removed on Debian12 and Ubuntu24. Configuration contents and all
other package states/versions were retained. Verification and the single exact
repeat passed. Fresh Wazuh measurements are recorded below; formal review remains
open. AIDE reports differences: do not refresh its database or call the earlier
baseline clean.

## Scope and safety decision

| Client | Original installed version | Native dependency/removal evidence |
|---|---|---|
| debian12 / 192.168.56.11 | `3.2.7-1+deb12u2` | No installed reverse dependencies; simulation removed only rsync |
| ubuntu24 / 192.168.56.12 | `3.2.7-1ubuntu1.2` | No installed reverse dependencies; simulation removed only rsync |

`apt-cache rdepends --installed rsync` returned only `rsync` and `Reverse Depends:`.
`apt-get --simulate --no-auto-remove remove rsync` reported zero upgrades, zero
installs, one removal. Before/after dpkg snapshots matched exactly excluding rsync.
No rsync process, configured daemon, alternate inetd/anacron configuration, or
references in system cron, local executable directories, administrator systemd
units, or cron spools were found. Vendor unit search found only rsync.service.
Both services were disabled/inactive; neither socket existed. Vagrant config
disables target synced folders. Private user files were not searched.

The isolated apply playbook is an explicit **disposable-lab unused confirmation**:
`services_priority_site_confirms_unused` defaults false; its separately documented
`services_priority_lab_confirms_unused: true` is selected by invoking this lab-only
entry point. Set the latter false to refuse removal unless site confirmation is
supplied. Exact inventory, both host aliases/addresses, Ansible user and platform
mapping are mandatory. This is not a general-purpose production remover.

Prechecks refuse discovered jobs, customized daemon conffiles, active processes,
or a simulation containing any other package action. Apt uses `purge: false`,
`autoremove: false`, no cache update and no automatic module-dependency installs.
Run without concurrent package administration: simulation and apt are separate
transactions, not an atomic package-manager lock. Postchecks detect other package
state/version changes; they do not automatically roll back an external race.

## Exact commands and observed results

From host `lab/vagrant`, use `vagrant ssh ansible-control`; then manually run:

```console
cd /home/vagrant/ansible/wazuh-cis
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook --version
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_services_priority.yml --syntax-check
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_services_priority_verify.yml --syntax-check
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_services_priority.yml
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_services_priority.yml
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook -i inventory/lab/hosts.yml playbooks/wazuh_services_priority_verify.yml
```

Observed 2026-11-08: Core 2.21.2; version and both syntax checks exit 0. First apply
exit 0, each host ok=33/changed=1/failed=0/unreachable=0. Exact repeat exit 0, each host
ok=33/changed=0/failed=0/unreachable=0. Standalone verify exit 0, each host
ok=11/changed=0/failed=0/unreachable=0.
Fresh SSH plus become returned uid0; Wazuh service and agentd/logcollector/syscheckd
were healthy. Binary and vendor unit paths are absent; no rsync processes remain.
Conffile MD5 contents remained unchanged. The package's removal changed the retained
init script mode from 0755 to 0644 on both clients; this was not a separate chmod task.

## Policy result and fresh rescan

Read-only shipped Wazuh policy references: Debian `cis_debian12.yml:1328-1344`
(33067) requires `dpkg -s rsync` to print `package 'rsync' is not installed`.
Actual output remains `Status: deinstall ok config-files`, rc=0: **that literal
predicate is not satisfied**, despite executable/package removal. No purge workaround.
Ubuntu `cis_ubuntu24-04.yml:1783-1805` (35573) accepts package message OR absence of
loaded/active service. Actual `systemctl show rsync.service` gives
`LoadState=not-found`, `ActiveState=inactive`, rc=0: its service alternative is
structurally satisfied. The existing rescan playbook restarted both agents with
`failed=0`; subsequent API results confirmed the following:

| Client | Previous score | New score | Passed / failed / invalid | Scan completed (UTC) |
|---|---|---|---|---|
| Debian, agent 006 | 80% | 80% | 140 / 34 / 6 | 2026-11-08 23:56:13 |
| Ubuntu, agent 007 | 68% | 69% | 186 / 83 / 10 | 2026-11-08 23:56:59 |

Ubuntu check 35573 is now `passed`. Debian 33067, 33111 and 33119 remain `failed`;
the audit findings and remaining b32 uncertainty are detailed in `AUDIT_PRIORITY.md`.
An independent read-only verification returned `ok=11 changed=0 failed=0` on both
clients and reproduced native AIDE `rc=6`. This is a partial overall result, not
whole-host compliance or clean integrity verification. The first API query still
showed Ubuntu's older scan; only the later completed scan supports the score gain.

## AIDE delta and rollback boundary

Native foreground command on each client, before and after removal:
`/usr/bin/timeout --kill-after=10s 600s /usr/bin/aide --config=/etc/aide/wazuh-priority.conf --workers=1 --check`.
Before: rc=0 both, no differences (36975 Debian / 48175 Ubuntu entries). After:
rc=6 both (outer ad-hoc Ansible/Vagrant exit 2): Debian removed=32/changed=10/added=0;
Ubuntu removed=23/changed=7/added=0. Removed entries are rsync binaries, unit, manuals,
scripts and documentation; changed entries include parent directory metadata and
retained init-script permissions. Debian additionally reports `/etc/resolv.conf`
mtime/ctime and `/etc` metadata at 23:40:35, before removal at 23:42:15: **unattributed,
not claimed as a package effect**. No AIDE configuration/database was changed.
Operator review of these deltas is required; the daily check will remain nonclean.

Rollback removes only this new playbook pair and document from source. Restoring
runtime rsync requires a separate authorized operator action to reinstall the
exact version above, subject to repository availability; no automatic reinstall,
purge, autoremove, data deletion or AIDE rebaseline was performed. Audit evidence
in `AUDIT_PRIORITY.md`, previous priority work, and all sensitive controls remain
untouched. Native no-match probes (grep/pgrep rc=1, ad-hoc exit 2) were expected;
initial ansible-doc opened a pager and timed out, then succeeded with PAGER=cat.

Host checks: `git diff --check -- wazuh-cis/` exit 0 and
`git diff --exit-code -- ansible/` exit 0. Only the two new playbooks and this
document belong to this unit (under 400 authored lines); no staging or commit occurred.
