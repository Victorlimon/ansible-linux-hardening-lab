vagrant@ansible-control:~/ansible$ ansible-playbook playbooks/cis_hardening.yml --tags cis_3

PLAY [Aplicar hardening CIS] ***************************************************************************************************************************

TASK [Gathering Facts] *********************************************************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.1 | AUDIT | Check IPv6 kernel parameter] *************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.1 | AUDIT | Read IPv6 disable value] *****************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.1 | AUDIT | Check sysctl IPv6 all] *******************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.1 | AUDIT | Check sysctl IPv6 default] ***************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.1 | REPORT | IPv6 status summary] ********************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.1.1 — IPv6 Status ===\nIPv6 enabled: YES\nKernel parameter: 0\nsysctl all: 0\nsysctl default: 0\n\n  Para deshabilitar IPv6, configure:\nsection3_network.3_1_network_devices.ipv6_enabled: false\n\n  ADVERTENCIA: Deshabilitar IPv6 puede romper SSH en Vagrant/Cloud!\n"
}

TASK [cis_benchmark : 3.1.2 | AUDIT | Find wireless interfaces] ****************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.2 | AUDIT | Gather wireless module names] ************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 3.1.2 | REPORT | Wireless interfaces detected] ***********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 3.1.2 | Remediation | Disable wireless modules] **********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 3.1.3 | AUDIT | Check bluez package] *********************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.3 | AUDIT | Check bluetooth.service status] **********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.1.3 | REPORT | Bluetooth status] ***********************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.1.3 — Bluetooth Status ===\nPackage bluez: NOT INSTALLED\nService enabled: N/A\nService active: inactive\n\n  Para deshabilitar Bluetooth, configure:\nsection3_network.3_1_network_devices.bluetooth_disabled: true\n"
}

TASK [cis_benchmark : 3.1.3 | Remediation | Stop and mask bluetooth.service] ***************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 3.1.3 | Remediation | Remove bluez package (if not dependency)] ******************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 3.2.1 | AUDIT | Check if dccp module exists] *************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.1 | AUDIT | Check if dccp is loaded] *****************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.1 | AUDIT | Check modprobe config for dccp] **********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.1 | REPORT | DCCP module status] *********************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.2.1 — DCCP Module Status ===\nModule file exists: YES\nModule loaded: NO\nModprobe config: not_configured\n\n⚠️ Para deshabilitar  dccp, configure:\nsection3_network['3_2_network_modules'].disable_dccp: true\n"
}

TASK [cis_benchmark : 3.2.1 | Create modprobe config for dccp] *****************************************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : 3.2.1 | Unload dccp if loaded] ***************************************************************************************************
[ERROR]: Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:64:15'. Conditionals must have a boolean result.

Task failed.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:61:11

59           when: _dccp_module_path.stdout | length > 0
60
61         - name: "3.2.1 | Unload dccp if loaded"
             ^ column 11

<<< caused by >>>

Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:64:15'. Conditionals must have a boolean result.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:64:15

62           ansible.builtin.command: modprobe -r dccp
63           when:
64             - _dccp_module_path.stdout
                 ^ column 15

Broken conditionals can be temporarily allowed with the `ALLOW_BROKEN_CONDITIONALS` configuration option.

fatal: [ubuntu-server]: FAILED! => {"changed": false, "msg": "Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:64:15'. Conditionals must have a boolean result."}      
...ignoring

TASK [cis_benchmark : 3.2.2 | AUDIT | Check if tipc module exists] *************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.2 | AUDIT | Check if tipc is loaded] *****************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.2 | AUDIT | Check modprobe config for tipc] **********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.2 | REPORT | TIPC module status] *********************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.2.2 — TIPC Module Status ===\nModule file exists: YES\nModule loaded: NO\nModprobe config: not_configured\n\n⚠️ Para deshabilitar  tipc, configure:\nsection3_network['3_2_network_modules'].disable_tipc: true\n"
}

TASK [cis_benchmark : 3.2.2 | Create modprobe config for tipc] *****************************************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : 3.2.2 | Unload tipc if loaded] ***************************************************************************************************
[ERROR]: Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:143:15'. Conditionals must have a boolean result.

Task failed.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:140:11

138           when: _tipc_module_path.stdout | length > 0
139
140         - name: "3.2.2 | Unload tipc if loaded"
              ^ column 11

<<< caused by >>>

Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:143:15'. Conditionals must have a boolean result.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:143:15

141           ansible.builtin.command: modprobe -r tipc
142           when:
143             - _tipc_module_path.stdout
                  ^ column 15

Broken conditionals can be temporarily allowed with the `ALLOW_BROKEN_CONDITIONALS` configuration option.

fatal: [ubuntu-server]: FAILED! => {"changed": false, "msg": "Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:143:15'. Conditionals must have a boolean result."}     
...ignoring

TASK [cis_benchmark : 3.2.3 | AUDIT | Check if rds module exists] **************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.3 | AUDIT | Check if rds is loaded] ******************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.3 | AUDIT | Check modprobe config for rds] ***********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.3 | REPORT | RDS module status] **********************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.2.3 — RDS Module Status ===\nModule file exists: YES\nModule loaded: NO\nModprobe config: not_configured\n\n⚠️ Para deshabilitar rrds, configure:\nsection3_network['3_2_network_modules'].disable_rds: true\n"
}

TASK [cis_benchmark : 3.2.3 | Create modprobe config for rds] ******************************************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : 3.2.3 | Unload rds if loaded] ****************************************************************************************************
[ERROR]: Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:222:15'. Conditionals must have a boolean result.

Task failed.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:219:11

217           when: _rds_module_path.stdout | length > 0
218
219         - name: "3.2.3 | Unload rds if loaded"
              ^ column 11

<<< caused by >>>

Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:222:15'. Conditionals must have a boolean result.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:222:15

220           ansible.builtin.command: modprobe -r rds
221           when:
222             - _rds_module_path.stdout
                  ^ column 15

Broken conditionals can be temporarily allowed with the `ALLOW_BROKEN_CONDITIONALS` configuration option.

fatal: [ubuntu-server]: FAILED! => {"changed": false, "msg": "Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:222:15'. Conditionals must have a boolean result."}     
...ignoring

TASK [cis_benchmark : 3.2.4 | AUDIT | Check if sctp module exists] *************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.4 | AUDIT | Check if sctp is loaded] *****************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.4 | AUDIT | Check modprobe config for sctp] **********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.2.4 | REPORT | SCTP module status] *********************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.2.4 — SCTP Module Status ===\nModule file exists: YES\nModule loaded: NO\nModprobe config: not_configured\n\n⚠️ Para deshabilitar  sctp, configure:\nsection3_network['3_2_network_modules'].disable_sctp: true\n"
}

TASK [cis_benchmark : 3.2.4 | Create modprobe config for sctp] *****************************************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : 3.2.4 | Unload sctp if loaded] ***************************************************************************************************
[ERROR]: Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:301:15'. Conditionals must have a boolean result.

Task failed.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:298:11

296           when: _sctp_module_path.stdout | length > 0
297
298         - name: "3.2.4 | Unload sctp if loaded"
              ^ column 11

<<< caused by >>>

Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:301:15'. Conditionals must have a boolean result.
Origin: /home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:301:15

299           ansible.builtin.command: modprobe -r sctp
300           when:
301             - _sctp_module_path.stdout
                  ^ column 15

Broken conditionals can be temporarily allowed with the `ALLOW_BROKEN_CONDITIONALS` configuration option.

fatal: [ubuntu-server]: FAILED! => {"changed": false, "msg": "Task failed: Conditional result (True) was derived from value of type 'str' at '/home/vagrant/ansible/roles/cis_benchmark/tasks/section3_network/3.2-configure_network_kernel_modules.yml:301:15'. Conditionals must have a boolean result."}     
...ignoring

TASK [cis_benchmark : 3.3.1 | AUDIT | Check IPv4 forwarding] *******************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.3.1 | AUDIT | Check IPv6 forwarding] *******************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : 3.3.1 | REPORT | IP forwarding status] *******************************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 3.3.1 — IP Forwarding Status ===\nIPv4 forwarding: 0\nIPv6 forwarding: 0\n\n⚠️ Para deshabilitar forwarding, configure:\nsection3_neetwork['3_3_network_kernel_parameters'].ip_forward_disabled: true\n\n⚠️ ADVERTENCIA: Esto puede romper routing en sistemas multi-interfaz!\n"
}

TASK [cis_benchmark : 3.3.1 | Remediation | Disable IPv4 forwarding] ***********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 3.3.1 | Remediation | Disable IPv6 forwarding] ***********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.1 | AUDIT | Check IP forwarding status] **********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.1 | AUDIT | Check IPv6 forwarding status] ********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.1 | Remediation | Configure net.ipv4.ip_forward = 0] *********************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.1 | Remediation | Configure net.ipv6.conf.all.forwarding = 0] ************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.2 | AUDIT | Check send_redirects status (all)] ***************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.2 | AUDIT | Check send_redirects status (default)] ***********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.2 | Remediation | Configure net.ipv4.conf.all.send_redirects = 0] ********************************************************
[WARNING]: Deprecation warnings can be disabled by setting `deprecation_warnings=False` in ansible.cfg.
[DEPRECATION WARNING]: Importing 'to_native' from 'ansible.module_utils._text' is deprecated. This feature will be removed from ansible-core version 2.24. Use ansible.module_utils.common.text.converters instead.
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.2 | Remediation | Configure net.ipv4.conf.default.send_redirects = 0] ****************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.3 | AUDIT | Check icmp_ignore_bogus_error_responses status] **************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.3 | Remediation | Configure net.ipv4.icmp_ignore_bogus_error_responses = 1] **********************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.4 | AUDIT | Check icmp_echo_ignore_broadcasts status] ********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.4 | Remediation | Configure net.ipv4.icmp_echo_ignore_broadcasts = 1] ****************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.5 | AUDIT | Check accept_redirects status (IPv4 all)] ********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.5 | AUDIT | Check accept_redirects status (IPv4 default)] ****************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.5 | Remediation | Configure net.ipv4.conf.all.accept_redirects = 0] ******************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.5 | Remediation | Configure net.ipv4.conf.default.accept_redirects = 0] **************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.6 | AUDIT | Check secure_redirects status (all)] *************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.6 | AUDIT | Check secure_redirects status (default)] *********************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.6 | Remediation | Configure net.ipv4.conf.all.secure_redirects = 0] ******************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.6 | Remediation | Configure net.ipv4.conf.default.secure_redirects = 0] **************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.7 | AUDIT | Check rp_filter status (all)] ********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.7 | AUDIT | Check rp_filter status (default)] ****************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.7 | Remediation | Configure net.ipv4.conf.all.rp_filter = 1] *************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.7 | Remediation | Configure net.ipv4.conf.default.rp_filter = 1] *********************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.8 | AUDIT | Check accept_source_route status (IPv4 all)] *****************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.8 | AUDIT | Check accept_source_route status (IPv4 default)] *************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.8 | Remediation | Configure net.ipv4.conf.all.accept_source_route = 0] ***************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.8 | Remediation | Configure net.ipv4.conf.default.accept_source_route = 0] ***********************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.9 | AUDIT | Check log_martians status (all)] *****************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.9 | AUDIT | Check log_martians status (default)] *************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.9 | Remediation | Configure net.ipv4.conf.all.log_martians = 1] **********************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.9 | Remediation | Configure net.ipv4.conf.default.log_martians = 1] ******************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.10 | AUDIT | Check tcp_syncookies status] ********************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : CIS 3.3.10 | Remediation | Configure net.ipv4.tcp_syncookies = 1] ****************************************************************
skipping: [ubuntu-server]

PLAY RECAP *********************************************************************************************************************************************
ubuntu-server              : ok=65   changed=15   unreachable=0    failed=0    skipped=13   rescued=0    ignored=4   
