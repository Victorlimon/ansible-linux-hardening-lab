# CIS Benchmark 6.2: System Auditing (auditd)

> **Ubuntu 24.04 LTS** | **Idempotent & Modular Ansible Implementation**

## 📋 Overview

This role implements **Section 6.2** of the CIS Benchmark for Ubuntu 24.04 LTS, focusing on configuring the Linux Audit System (`auditd`) for comprehensive system activity logging and forensic investigation capabilities.

### 🔗 Reference
- **CIS Benchmark**: Ubuntu 24.04 LTS v1.0.0
- **Section**: 6.2 System Auditing
- **Total Controls**: ~40 (Automated + Manual)

---

## 📁 File Structure

```
roles/cis_benchmark/tasks/section6_logging/6.2-system_auditing/
├── main.yml                                          # Entry point with pre-flight checks
├── 6.2.1-configure_auditd_service.yml               # Controls 6.2.1.1 - 6.2.1.4
├── 6.2.2-configure_data_retention.yml               # Controls 6.2.2.1 - 6.2.2.4
├── 6.2.3-configure_auditd_rules.yml                 # Controls 6.2.3.1 - 6.2.3.21 (~21 rules)
├── 6.2.4-configure_audit_file_access.yml            # Controls 6.2.4.1 - 6.2.4.10
├── CIS_Benchmark_V1_Seccion_6.2.md                  # Official CIS guide (reference)
└── README.md                                        # This file

roles/cis_benchmark/handlers/
└── handlers_auditd.yml                              # Resilient handlers with extended timeouts

roles/cis_benchmark/defaults/
└── main_section6_2.yml                              # Configurable variables
```

---

## 🎯 Controls Summary

### 6.2.1 Configure auditd Service (4 controls)

| Control | Description | Tag | Status |
|---------|-------------|-----|--------|
| 6.2.1.1 | Ensure auditd packages are installed | `cis_6_2_1_1` | ✅ Automated |
| 6.2.1.2 | Ensure auditd service is enabled and active | `cis_6_2_1_2` | ✅ Automated |
| 6.2.1.3 | Ensure auditing for processes that start prior to auditd is enabled | `cis_6_2_1_3` | ✅ Automated |
| 6.2.1.4 | Ensure audit_backlog_limit is sufficient | `cis_6_2_1_4` | ✅ Automated |

### 6.2.2 Configure Data Retention (4 controls)

| Control | Description | Tag | Status |
|---------|-------------|-----|--------|
| 6.2.2.1 | Ensure audit log storage size is configured | `cis_6_2_2_1` | ✅ Automated |
| 6.2.2.2 | Ensure audit logs are not automatically deleted | `cis_6_2_2_2` | ✅ Automated |
| 6.2.2.3 | Ensure system is disabled when audit logs are full | `cis_6_2_2_3` | ✅ Automated ⚠️ LAB-safe |
| 6.2.2.4 | Ensure system warns when audit logs are low on space | `cis_6_2_2_4` | ✅ Automated |

### 6.2.3 Configure auditd Rules (~21 controls)

| Control | Description | Tag | Status |
|---------|-------------|-----|--------|
| 6.2.3.1 | Changes to system administration scope (sudoers) | `cis_6_2_3_1` | ✅ Automated |
| 6.2.3.2 | Actions as another user are always logged | `cis_6_2_3_2` | ✅ Automated |
| 6.2.3.3 | Events that modify the sudo log file | `cis_6_2_3_3` | ✅ Automated |
| 6.2.3.4 | Events that modify date and time information | `cis_6_2_3_4` | ✅ Automated |
| 6.2.3.5 | Events that modify network environment | `cis_6_2_3_5` | ✅ Automated |
| 6.2.3.6 | Use of privileged commands | `cis_6_2_3_6` | ⚠️ Disabled by default (performance) |
| 6.2.3.7 | Unsuccessful file access attempts | `cis_6_2_3_7` | ✅ Automated |
| 6.2.3.8 | Events that modify user/group information | `cis_6_2_3_8` | ✅ Automated |
| 6.2.3.9 | Discretionary access control permission modifications | `cis_6_2_3_9` | ✅ Automated |
| 6.2.3.10 | Successful file system mounts | `cis_6_2_3_10` | ✅ Automated |
| 6.2.3.11 | Session initiation information | `cis_6_2_3_11` | ✅ Automated |
| 6.2.3.12 | Login and logout events | `cis_6_2_3_12` | ✅ Automated |
| 6.2.3.13 | File deletion events by users | `cis_6_2_3_13` | ✅ Automated |
| 6.2.3.14 | Events that modify Mandatory Access Controls | `cis_6_2_3_14` | ✅ Automated |
| 6.2.3.15 | Successful/unsuccessful use of `chcon` | `cis_6_2_3_15` | ✅ Automated |
| 6.2.3.16 | Successful/unsuccessful use of `setfacl` | `cis_6_2_3_16` | ✅ Automated |
| 6.2.3.17 | Successful/unsuccessful use of `chacl` | `cis_6_2_3_17` | ✅ Automated |
| 6.2.3.18 | Successful/unsuccessful use of `usermod` | `cis_6_2_3_18` | ✅ Automated |
| 6.2.3.19 | Kernel module loading/unloading/modification | `cis_6_2_3_19` | ✅ Automated |
| 6.2.3.20 | Audit configuration is immutable | `cis_6_2_3_20` | ⚠️ Disabled by default (reboot required) |
| 6.2.3.21 | Running and on-disk configuration match | `cis_6_2_3_21` | ✅ Automated |

### 6.2.4 Configure auditd File Access (10 controls)

| Control | Description | Tag | Status |
|---------|-------------|-----|--------|
| 6.2.4.1 | Audit log files mode (0640) | `cis_6_2_4_1` | ✅ Automated |
| 6.2.4.2 | Audit log files owner (root) | `cis_6_2_4_2` | ✅ Automated |
| 6.2.4.3 | Audit log files group owner (adm/root) | `cis_6_2_4_3` | ✅ Automated |
| 6.2.4.4 | Audit log directory mode (0750) | `cis_6_2_4_4` | ✅ Automated |
| 6.2.4.5 | Audit config files mode (0640) | `cis_6_2_4_5` | ✅ Automated |
| 6.2.4.6 | Audit config files owner (root) | `cis_6_2_4_6` | ✅ Automated |
| 6.2.4.7 | Audit config files group owner (root) | `cis_6_2_4_7` | ✅ Automated |
| 6.2.4.8 | Audit tools mode (0755) | `cis_6_2_4_8` | ✅ Automated |
| 6.2.4.9 | Audit tools owner (root) | `cis_6_2_4_9` | ✅ Automated |
| 6.2.4.10 | Audit tools group owner (root) | `cis_6_2_4_10` | ✅ Automated |

---

## 🚀 Usage

### Execute All Section 6.2 Controls
```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit "ubuntu-server" \
  --tags "cis_6_2" \
  -vvv
```

### Execute Specific Subsection
```bash
# Only auditd service configuration (6.2.1)
ansible-playbook playbooks/cis_hardening.yml \
  --limit "ubuntu-server" \
  --tags "cis_6_2_1" \
  -vvv

# Only audit rules (6.2.3)
ansible-playbook playbooks/cis_hardening.yml \
  --limit "ubuntu-server" \
  --tags "cis_6_2_3" \
  -vvv
```

### Execute Single Control
```bash
# Only control 6.2.1.1 (install packages)
ansible-playbook playbooks/cis_hardening.yml \
  --limit "ubuntu-server" \
  --tags "cis_6_2_1_1" \
  -vvv
```

### Check Mode (Dry-Run - No Changes Applied)
```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit "ubuntu-server" \
  --tags "cis_6_2" \
  --check \
  --diff \
  -vvv
```

### Validate Idempotency
```bash
# First run - should show changes
ansible-playbook playbooks/cis_hardening.yml --tags "cis_6_2" -vvv | grep "changed="

# Second run - should show changed=0 (idempotent)
ansible-playbook playbooks/cis_hardening.yml --tags "cis_6_2" -vvv | grep "changed="
```

---

## ⚙️ Configuration Variables

All settings are configurable via `group_vars/all.yml` or `host_vars/<hostname>.yml`:

```yaml
section6_logging:
  # 6.2.1.4 - Audit backlog limit
  '6_2_1_4_audit_backlog_limit':
    enabled: true
    value: "8192"  # Increase for high-activity systems
  
  # 6.2.2.1 - Max log file size (MB)
  '6_2_2_1_max_log_file':
    enabled: true
    value: "100"  # Adjust based on available disk space
  
  # 6.2.2.3 - Disk full actions (LAB vs PROD)
  '6_2_2_3_disk_actions':
    enabled: true
    disk_full_action: "syslog"      # LAB: syslog | PROD: halt
    disk_error_action: "syslog"
  
  # 6.2.3.6 - Privileged commands (performance warning)
  '6_2_3_6_privileged_cmds':
    enabled: false  # Enable only after capacity planning
  
  # 6.2.3.20 - Immutable configuration (reboot required)
  '6_2_3_20_immutable':
    enabled: false  # Enable when ready to lock audit config
```

---

## ⚠️ Important Notes

### 🔐 LAB-Safe Defaults
Several controls use conservative defaults for lab/testing environments:

| Control | LAB Default | PROD Recommendation |
|---------|------------|-------------------|
| 6.2.2.3 `disk_full_action` | `syslog` | `halt` or `single` |
| 6.2.3.6 Privileged commands | `disabled` | `enabled` (after testing) |
| 6.2.3.20 Immutable config | `disabled` | `enabled` (requires reboot) |

### 🔄 Reboot Requirements
The following controls require a system reboot to take full effect:

| Control | Reason |
|---------|--------|
| 6.2.1.3 `audit=1` GRUB parameter | Kernel boot parameter |
| 6.2.1.4 `audit_backlog_limit` | Kernel boot parameter |
| 6.2.3.20 Immutable mode (`-e 2`) | Audit subsystem lock |

### 📊 Performance Considerations
- **6.2.3.6 (Privileged commands)**: Can generate significant audit volume. Test with `enabled: false` first, then enable after capacity planning.
- **Disk I/O**: Ensure adequate I/O capacity for audit log writes.
- **CPU overhead**: System call rules may impact performance on high-load systems.

### 🗂️ Rule File Organization
Audit rules are stored in `/etc/audit/rules.d/` with numbered prefixes for deterministic loading order:
- `50-*.rules` - CIS Benchmark rules (center-weighted)
- `99-finalize.rules` - Immutable flag (loaded last)

Rules are merged into `/etc/audit/audit.rules` via `augenrules --load`.

---

## 🔍 Verification Commands

### Check auditd Service Status
```bash
systemctl status auditd.service
auditctl -s  # Show audit system status
```

### Verify Audit Rules
```bash
# List loaded rules
auditctl -l

# Check on-disk rules
grep -r "^-a\|^ -w" /etc/audit/rules.d/

# Verify rules are synced
augenrules --check
```

### Check Audit Log Configuration
```bash
# View auditd.conf settings
grep -E "^(max_log_file|disk_full_action|log_group)" /etc/audit/auditd.conf

# Check log directory permissions
ls -la /var/log/audit/
stat -c "%a %U:%G %n" /var/log/audit/*.log
```

### Test Idempotency
```bash
# Run playbook twice and compare output
ansible-playbook cis_hardening.yml --tags cis_6_2 -v | tee run1.log
ansible-playbook cis_hardening.yml --tags cis_6_2 -v | tee run2.log

# Second run should show: changed=0
grep "changed=" run2.log
```

---

## 🛠️ Troubleshooting

### auditd Service Won't Start
```bash
# Check for configuration errors
auditd -t  # Test configuration syntax

# View service logs
journalctl -u auditd.service -n 50

# Check disk space
df -h /var/log/audit
```

### Rules Not Loading
```bash
# Force reload rules
augenrules --load

# Check for syntax errors in rules files
for f in /etc/audit/rules.d/*.rules; do
  echo "Checking $f:"
  augenrules --check "$f" 2>&1
done
```

### Immutable Mode Issues
```bash
# Check if audit is locked
auditctl -s | grep enabled

# If enabled=2, reboot required for changes
# To unlock (not recommended in production):
# Edit /etc/audit/rules.d/99-finalize.rules and remove "-e 2"
# Then reboot
```

### Performance Issues
```bash
# Monitor audit event rate
ausearch -m all -ts recent | wc -l

# Check disk I/O
iostat -x 1 5

# Temporarily reduce rules for testing
# Edit section6_logging variables to disable high-volume controls
```

---

## 📚 References

1. [CIS Ubuntu 24.04 LTS Benchmark v1.0.0](https://www.cisecurity.org/benchmark/ubuntu_linux)
2. [auditd.conf(5) Man Page](https://man7.org/linux/man-pages/man5/auditd.conf.5.html)
3. [audit.rules(7) Man Page](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
4. [Linux Audit Framework Documentation](https://github.com/linux-audit/audit-documentation)

---

## 🔄 Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-05-08 | Initial implementation of CIS 6.2 with idempotency patterns |

---

> 💡 **Pro Tip**: Always test in a staging environment before applying to production. Audit rules can generate significant log volume and impact system performance if not properly sized.
