vagrant@ansible-control:~/ansible$ ansible-playbook playbooks/cis_hardening.yml --tags cis_6_3

PLAY [Aplicar hardening CIS] ***************************************************************************************************************************

TASK [Gathering Facts] *********************************************************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Include section 6 logging and auditing] ******************************************************************************************
included: /home/vagrant/ansible/roles/cis_benchmark/tasks/section6_logging/main.yml for ubuntu-server

TASK [cis_benchmark : AUDIT | Check if AIDE packages are installed] ************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : REMEDIATE | Install AIDE packages if not present] ********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : Check if AIDE database exists] ***************************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Initialize AIDE database (first run only)] ***************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : Move new AIDE database to production location] ***********************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : Ensure daily AIDE check timer is unmasked] ***************************************************************************************
ok: [ubuntu-server] => (item=dailyaidecheck.timer)
ok: [ubuntu-server] => (item=dailyaidecheck.service)

TASK [cis_benchmark : Ensure daily AIDE check timer is enabled and active] *****************************************************************************ok: [ubuntu-server]

TASK [cis_benchmark : Verify AIDE timer is active] *****************************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Configure AIDE wrapper script usage (Ubuntu recommendation)] *********************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : Ensure /etc/aide directory has correct permissions] ******************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Ensure aide.conf has correct permissions] ****************************************************************************************
changed: [ubuntu-server]

TASK [cis_benchmark : Add audit tools integrity rules to aide.conf] ************************************************************************************
changed: [ubuntu-server] => (item=auditctl)
changed: [ubuntu-server] => (item=auditd)
changed: [ubuntu-server] => (item=ausearch)
changed: [ubuntu-server] => (item=aureport)
changed: [ubuntu-server] => (item=autrace)
changed: [ubuntu-server] => (item=augenrules)

TASK [cis_benchmark : Validate AIDE configuration syntax] **********************************************************************************************
ok: [ubuntu-server]

TASK [cis_benchmark : Report AIDE configuration validation result] *************************************************************************************
skipping: [ubuntu-server]

TASK [cis_benchmark : 6.3 | REPORT | Generate AIDE compliance summary] *********************************************************************************
ok: [ubuntu-server] => {
    "msg": "=== CIS 6.3 AIDE Compliance Summary ===\nHost: ubuntu-server\nAIDE Installed: True\nDatabase Exists: False\nTimer Active: active\nConfig Valid: False\nLevel: Level 2\n"
}

RUNNING HANDLER [cis_benchmark : Update AIDE database] *************************************************************************************************
changed: [ubuntu-server]

PLAY RECAP *********************************************************************************************************************************************
ubuntu-server              : ok=14   changed=4    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0