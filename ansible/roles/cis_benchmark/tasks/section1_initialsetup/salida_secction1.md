vagrant@ansible-control:~/ansible$ ansible-playbook playbooks/cis_hardening.yml --tags cis_1

PLAY [Aplicar hardening CIS] ***************************************************************************************************************************

TASK [Gathering Facts] *********************************************************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Gather package facts for Section 2] **********************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Gather service facts for Section 2] **********************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Gather filesystem module paths] ******************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Disable unused filesystem kernel modules] **************************************************************
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.1-configure_filesystem/_disable_module.yml for ubuntu-server => (item=cramfs)
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.1-configure_filesystem/_disable_module.yml for ubuntu-server => (item=freevxfs)
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.1-configure_filesystem/_disable_module.yml for ubuntu-server => (item=hfs)
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.1-configure_filesystem/_disable_module.yml for ubuntu-server => (item=hfsplus)
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.1-configure_filesystem/_disable_module.yml for ubuntu-server => (item=jffs2)
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.1-configure_filesystem/_disable_module.yml for ubuntu-server => (item=usb-storage)

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Check if cramfs module exists on system] *********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Configure modprobe.d for cramfs] ***********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Unload cramfs from running kernel] *********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Check if freevxfs module exists on system] *******************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Configure modprobe.d for freevxfs] *********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Unload freevxfs from running kernel] *******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Check if hfs module exists on system] ************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Configure modprobe.d for hfs] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Unload hfs from running kernel] ************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Check if hfsplus module exists on system] ********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Configure modprobe.d for hfsplus] **********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Unload hfsplus from running kernel] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Check if jffs2 module exists on system] **********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Configure modprobe.d for jffs2] ************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Unload jffs2 from running kernel] **********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | AUDIT | Check if usb-storage module exists on system] ****************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Configure modprobe.d for usb-storage] ******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1 | Remediation | Unload usb-storage from running kernel] ****************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1.10 | AUDIT | List all available filesystem modules] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.1.10 | REPORT | Display modules for manual review] ***********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.1 | AUDIT | Check if /tmp is a separate partition] *******************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.2 | AUDIT | Re-read /tmp mount options] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.2 | Remediation | Apply nodev to /tmp] *******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.3 | AUDIT | Re-read /tmp mount options] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.3 | Remediation | Apply nosuid to /tmp] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.4 | AUDIT | Re-read /tmp mount options] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.1.4 | Remediation | Apply noexec to /tmp] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.1 | AUDIT | Check if /dev/shm is a separate partition] ***************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.2 | AUDIT | Re-read /dev/shm mount options] **************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.2 | Remediation | Apply nodev to /dev/shm] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.3 | AUDIT | Re-read /dev/shm mount options] **************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.3 | Remediation | Apply nosuid to /dev/shm] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.4 | AUDIT | Re-read /dev/shm mount options] **************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.2.4 | Remediation | Apply noexec to /dev/shm] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.3.1 | AUDIT | Check if /home is a separate partition] ******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.3.2 | AUDIT | Re-read /home mount options] *****************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.3.2 | Remediation | Apply nodev to /home] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.3.3 | AUDIT | Re-read /home mount options] *****************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.3.3 | Remediation | Apply nosuid to /home] *****************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.4.1 | AUDIT | Check if /var is a separate partition] *******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.4.2 | AUDIT | Re-read /var mount options] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.4.2 | Remediation | Apply nodev to /var] *******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.4.3 | AUDIT | Re-read /var mount options] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.4.3 | Remediation | Apply nosuid to /var] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.1 | AUDIT | Check if /var/tmp is a separate partition] ***************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.2 | AUDIT | Re-read /var/tmp mount options] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.2 | Remediation | Apply nodev to /var/tmp] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.3 | AUDIT | Re-read /var/tmp mount options] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.3 | Remediation | Apply nosuid to /var/tmp] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.4 | AUDIT | Re-read /var/tmp mount options] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.5.4 | Remediation | Apply noexec to /var/tmp] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.1 | AUDIT | Check if /var/log is a separate partition] ***************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.2 | AUDIT | Re-read /var/log mount options] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.2 | Remediation | Apply nodev to /var/log] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.3 | AUDIT | Re-read /var/log mount options] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.3 | Remediation | Apply nosuid to /var/log] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.4 | AUDIT | Re-read /var/log mount options] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.6.4 | Remediation | Apply noexec to /var/log] **************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.1 | AUDIT | Check if /var/log/audit is a separate partition] *********************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.2 | AUDIT | Re-read /var/log/audit mount options] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.2 | Remediation | Apply nodev to /var/log/audit] *********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.3 | AUDIT | Re-read /var/log/audit mount options] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.3 | Remediation | Apply nosuid to /var/log/audit] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.4 | AUDIT | Re-read /var/log/audit mount options] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.1.2.7.4 | Remediation | Apply noexec to /var/log/audit] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.1 | Update apt cache] ****************************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.1 | Ensure main Ubuntu repositories are enabled] *************************************************************************
[WARNING]: Deprecation warnings can be disabled by setting `deprecation_warnings=False` in ansible.cfg.
[DEPRECATION WARNING]: INJECT_FACTS_AS_VARS default to `True` is deprecated, top-level facts will not be auto injected after the change. This feature will be removed from ansible-core version 2.24.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.2-configure_package_management/1.2.1-configure_repositories.yml:21:11   

19         update_cache: no
20       loop:
21         - "deb http://archive.ubuntu.com/ubuntu {{ ansible_distribution_release }} main restricted universe multiv...
             ^ column 11

Use `ansible_facts["fact_name"]` (no `ansible_` prefix) instead.

[DEPRECATION WARNING]: INJECT_FACTS_AS_VARS default to `True` is deprecated, top-level facts will not be auto injected after the change. This feature will be removed from ansible-core version 2.24.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.2-configure_package_management/1.2.1-configure_repositories.yml:25:13

23         - "deb http://archive.ubuntu.com/ubuntu {{ ansible_distribution_release }}-security main restricted univer...
24         - "deb http://archive.ubuntu.com/ubuntu {{ ansible_distribution_release }}-backports main restricted unive...
25       when: ansible_distribution == "Ubuntu"
               ^ column 13

Use `ansible_facts["fact_name"]` (no `ansible_` prefix) instead.

ok: [ubuntu-server] => (item=deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse)
ok: [ubuntu-server] => (item=deb http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse)
ok: [ubuntu-server] => (item=deb http://archive.ubuntu.com/ubuntu noble-security main restricted universe multiverse)
ok: [ubuntu-server] => (item=deb http://archive.ubuntu.com/ubuntu noble-backports main restricted universe multiverse)

TASK [cis_benchmark : CIS 1.2.1 | Ensure no unsigned repositories are configured] **********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.1 | Report if insecure repositories found] *******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Ensure apt-transport-https is installed] *****************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Ensure Ubuntu archive keyring is installed] **************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Verify GPG keys for configured repositories] *************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Report if no Ubuntu GPG keys found] **********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Ensure AllowUnauthenticated is not set in apt config] ****************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Install unattended-upgrades package] *********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Configure unattended-upgrades] ***************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.2.2 | Enable unattended-upgrades service] **********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.3.1.1 | Remediation | Ensure AppArmor is installed] ************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.3.1.2 | AUDIT | Read current GRUB config] **********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.3.1.2 | Remediation | Ensure apparmor=1 security=apparmor in GRUB] *********************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.3.1.3 | Remediation | Ensure all AppArmor Profiles are in enforce or complain mode] ****************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.3.1.4 | Remediation | Ensure all AppArmor Profiles are enforcing (Level 2)] ************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.4.1 | Ensure /etc/grub.d/40_custom exists] *********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.4.1 | Configure GRUB password in /etc/grub.d/40_custom] ********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.4.1 | Ensure GRUB password block has correct permissions] ******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.4.2 | Remediation | Ensure permissions on bootloader config are configured] ************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.1 | Remediation | Ensure address space layout randomization is enabled] **************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.2 | Remediation | Ensure ptrace_scope is restricted] *********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.3 | Set hard limit for core dumps in limits.conf] ************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.3 | Set fs.suid_dumpable kernel parameter] *******************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.3 | Ensure systemd-coredump.conf has Storage=none] ***********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.3 | Ensure systemd-coredump.conf has ProcessSizeMax=0] *******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.4 | Remediation | Ensure prelink is not installed] ***********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.5 | Disable apport in /etc/default/apport] *******************************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.5 | Stop and mask apport service] ****************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.5.5 | Optionally remove apport package] ************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6.1 | Remediation | Ensure message of the day is configured properly] ******************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6.2 | Remediation | Ensure local login warning banner is configured properly] **********************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6.3 | Remediation | Ensure remote login warning banner is configured properly] *********************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6.4 | Remediation | Ensure access to /etc/motd is configured] **************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6.5 | Remediation | Ensure access to /etc/issue is configured] *************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6.6 | Remediation | Ensure access to /etc/issue.net is configured] *********************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6 | Remove OS info from /etc/motd] *****************************************************************************************
[DEPRECATION WARNING]: INJECT_FACTS_AS_VARS default to `True` is deprecated, top-level facts will not be auto injected after the change. This feature will be removed from ansible-core version 2.24.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.6-configure_login_banners.yml:88:17

86       ansible.builtin.replace:
87         path: /etc/motd
88         regexp: '(\\v|\\r|\\m|\\s|{{ ansible_distribution }}|{{ ansible_distribution_version }})'
                   ^ column 17

Use `ansible_facts["fact_name"]` (no `ansible_` prefix) instead.

ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6 | Remove OS info from /etc/issue] ****************************************************************************************
[DEPRECATION WARNING]: INJECT_FACTS_AS_VARS default to `True` is deprecated, top-level facts will not be auto injected after the change. This feature will be removed from ansible-core version 2.24.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.6-configure_login_banners.yml:95:17

93       ansible.builtin.replace:
94         path: /etc/issue
95         regexp: '(\\v|\\r|\\m|\\s|{{ ansible_distribution }}|{{ ansible_distribution_version }})'
                   ^ column 17

Use `ansible_facts["fact_name"]` (no `ansible_` prefix) instead.

ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.6 | Remove OS info from /etc/issue.net] ************************************************************************************
[DEPRECATION WARNING]: INJECT_FACTS_AS_VARS default to `True` is deprecated, top-level facts will not be auto injected after the change. This feature will be removed from ansible-core version 2.24.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section1_initialsetup/1.6-configure_login_banners.yml:102:17

100       ansible.builtin.replace:
101         path: /etc/issue.net
102         regexp: '(\\v|\\r|\\m|\\s|{{ ansible_distribution }}|{{ ansible_distribution_version }})'
                    ^ column 17

Use `ansible_facts["fact_name"]` (no `ansible_` prefix) instead.

ok: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.1 | Remediation | Ensure GDM is removed] *********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.2 | Check if GDM user profile exists] ************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.2 | Create GDM profile if not exists] ************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.2 | Configure GDM banner message via dconf] ******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.3 | Configure GDM disable-user-list via dconf] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.4 | Configure GDM screen lock via dconf] *********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.5 | Lock screen lock settings via dconf locks] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.6 | Disable automount via dconf] *****************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.7 | Lock automount settings via dconf locks] *****************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.8 | Disable autorun via dconf] *******************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.9 | Lock autorun settings via dconf locks] *******************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.10 | Find GDM config files with XDMCP section] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 1.7.10 | Disable XDMCP in GDM config files] **********************************************************************************
skipping: [ubuntu-server]

PLAY RECAP *********************************************************************************************************************************************
ubuntu-server              : ok=47   changed=2    unreachable=0    failed=0    skipped=81   rescued=0    ignored=0