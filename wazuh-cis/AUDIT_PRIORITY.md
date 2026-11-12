# Audit priority: evidence-only partial result

No client configuration was changed. Debian checks **33111 and 33119 remain
open in Wazuh**: existing coverage and shipped detector discrepancies do not
justify duplicate rules. Debian b32 execution coverage remains unresolved.
No empty apply/verify playbooks were created. This is not a formal review PASS.

## Observed coverage

Read-only collection on 2026-11-08 used the authorized Vagrant-managed
`ansible-control` session and `inventory/lab/hosts.yml` only.

| Area | Persistent source on clients | Effective `auditctl -l` evidence |
|---|---|---|
| Both clients: AppArmor | `cis_6_2_3_14.rules:1` watches `/etc/apparmor`; `50-cis-wazuh.rules` watches `/etc/apparmor.d` (Debian line 12, Ubuntu line 34) | Both paths have `-p wa -k MAC-policy` |
| Debian: b64 elevated executions | `50-cis-wazuh.rules:21` | `-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=actions` |
| Debian: b64 user emulation | `cis_6_2_3_2.rules:1` | `-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation` |
| Ubuntu: b64/b32 user emulation | `cis_6_2_3_2.rules:1` (b64), `50-cis-wazuh.rules:2` (b32) | Both architectures have `execve`, `uid!=euid`, `auid!=-1`, `key=user_emulation` |

The corresponding entries also appear in each client's `/etc/audit/audit.rules`.
The full effective listings showed no `never` or `exclude` rules. Collection
did not modify watched files or generate synthetic security events.

## Exact shipped policy discrepancies

Policy files were read only at the host's Wazuh Docker `single-node/config/sca/`
directory; neither policies nor manager files were modified.

- **Debian 33111**, `cis_debian12.yml:2228-2231`: persistent predicates accept
  `/etc/apparmor\s+` and `/etc/apparmor.d\s+`. Runtime predicates instead contain
  `/etc/apparmor\\s+` and `/etc/apparmor.d\\s+` (two literal backslashes in the
  single-quoted YAML), or require trailing slashes. The effective rules print
  slashless paths followed by spaces. Both requested watches already exist;
  adding slash variants would not supply missing event coverage.
- **Debian 33119**, lines 2395-2396: the persistent predicate accepts
  `-k actions|key=actions`; the runtime predicate requires the contiguous string
  `-k actions key=actions` without an alternation. The effective b64 rule instead
  prints `-F key=actions`. Its `euid=0` and `uid!=euid` filters cover the requested
  elevated b64 executions without the remediation's additional auid restriction.
  No additional b64 rule is justified merely to satisfy this predicate.
- **Ubuntu 35732**, `cis_ubuntu24-04.yml:5540-5543`, accepts either uid comparison
  ordering and either `-k user_emulation` or `-F key=user_emulation`, separately
  for b64 and b32. Both have persistent and effective coverage already.
- **Ubuntu 35743**, lines 5874-5877, accepts slashless AppArmor watch paths;
  persistent and effective coverage already exists. No Ubuntu changes are justified
  by these observations. No fresh SCA/API result was collected here.

**Boundary:** no Debian b32 `execve` rule appeared in the full effective listing
or the persistent rule search. Compatibility-ABI applicability was not established.
Do not describe all of 33119 as a proven false negative or closed control; assess
that coverage separately before designing a minimal additive activation unit.

## Reproduce the read-only evidence

From the host process directory `lab/vagrant`, enter the authorized controller
with `vagrant ssh ansible-control`. Then run these native commands manually:

```console
cd /home/vagrant/ansible/wazuh-cis
/home/vagrant/.venvs/ansible-cis/bin/ansible-playbook --version
/home/vagrant/.venvs/ansible-cis/bin/ansible -i inventory/lab/hosts.yml all -m ansible.builtin.command -a 'auditctl -s'
/home/vagrant/.venvs/ansible-cis/bin/ansible -i inventory/lab/hosts.yml all -m ansible.builtin.command -a 'auditctl -l'
/home/vagrant/.venvs/ansible-cis/bin/ansible -i inventory/lab/hosts.yml all -m ansible.builtin.command -a 'grep -rHnE --include=*.rules -- ^(-[De]|.*(apparmor|execve|never|exclude)) /etc/audit/rules.d'
/home/vagrant/.venvs/ansible-cis/bin/ansible -i inventory/lab/hosts.yml all -m ansible.builtin.command -a 'auditctl -s'
```

Core **2.21.2** was observed. Successful native evidence commands returned rc=0
on both clients. Before/after: enabled=1, lost=0, backlog=0, backlog_limit=8192;
auditd PIDs remained Debian 42910 and Ubuntu 60607. Ad-hoc command-module output
says CHANGED even for these read-only commands; that is not a configuration delta.

One earlier persistent search failed with native rc=2 because it passed the
rules directory to nonrecursive grep. The recursive command above corrected it
and returned native rc=0 on both hosts, with outer Vagrant exit=0.

Requested syntax/apply/repeat/verify commands are **N/A**: the named playbook pair
was deliberately not created. No apply or idempotence claim is made. An initial
local content-search tool also failed to load its PowerShell archive module;
policy evidence was obtained using direct read-only file reads instead.

## Safety, rollback, and next step

Only this document was added; rollback removes this document only. Existing dirty
and untracked audit delta/priority files were preserved. Runtime rollback is N/A.
Existing `/etc/audit/rules.d/audit.rules:2` contains `-D` on both clients: do not
run a broad augenrules reload for this work. No audit restart, flush, immutable
flag change, package removal, baseline run, or Wazuh policy workaround occurred.

Next: establish Debian compatibility-ABI applicability and review missing b32
execution coverage independently. Rsync dependency assessment/remediation was not
attempted. All prohibited sensitive controls remain deferred. Parent owns API
rescan, score measurement, and native review; no updated scores are claimed.
