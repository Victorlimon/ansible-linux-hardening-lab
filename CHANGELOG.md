# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Documentación completa del proyecto (README.md, CONTRIBUTING.md, LICENSE, .gitignore)
- Soporte multi-distro: Ubuntu 24.04 (ufw) y Debian 12 (nftables) en Sección 4
- Variables dinámicas para auto-selección de motor de firewall por distribución
- Tags granulares para ejecución selectiva de controles CIS
- Handlers con validación para configs críticas (sshd, sudoers, grub)

### Changed
- Renombrado de archivos de Sección 1 para consistencia con otras secciones
- Normalización de variables: eliminado sufijo `_bol` inconsistente
- Mejora de idempotencia: uso de `changed_when`, `failed_when`, condicionales basados en facts
- Corrección de nombre de paquete PAM: `pam-runtime` → `libpam-runtime`
- Templates de repositorios apt: eliminada dependencia de archivos `.j2` inexistentes

### Fixed
- Error en `1.2.1-configure_repositories.yml`: template no encontrado
- Error en `1.6-configure_login_banners.yml`: variables `cis_issue_text` no definidas
- Error en `5.3.1-configure_pam_software_packages.yml`: nombre de paquete incorrecto
- Warning de deprecations: uso de `ansible_facts.*` en lugar de `ansible_*`
- Tasks de particiones: optimización de lecturas de `findmnt` para evitar redundancia

### Security
- Agregado `backup: yes` en tasks que modifican configs críticas
- Validación de sintaxis con `validate` en sshd_config, sudoers, grub
- Variables sensibles documentadas para uso con `ansible-vault`

---

## [1.0.0] - 2026-05-17

### Initial Release - CIS Benchmark v1.0.0 Complete

#### Sección 1: Initial Setup ✅
- 1.1 Filesystem Configuration
  - 1.1.1 Kernel modules hardening (9 módulos + auditoría)
  - 1.1.2 Partitions mount options (/tmp, /dev/shm, /home, /var, /var/tmp, /var/log, /var/log/audit)
- 1.2 Package Management
  - 1.2.1 Repositories configuration
  - 1.2.2 GPG keys and package verification
- 1.3 Mandatory Access Control (AppArmor)
- 1.4 Bootloader Configuration (GRUB)
- 1.5 Process Hardening (ASLR, core dumps, prelink, apport)
- 1.6 Login Banners (/etc/motd, /etc/issue, /etc/issue.net)
- 1.7 GDM Configuration (Workstation only)

#### Sección 2: Services ✅
- 2.1 Server Services (autofs, avahi, dhcp, dns, ftp, ldap, nfs, nis, cups, rpcbind, rsync, samba, snmp, tftp, proxy, webserver, xinetd, xwindow, MTA)
- 2.2 Client Services (nis, rsh, talk, telnet, ldap-utils, ftp clients)
- 2.3 Time Synchronization (chrony / systemd-timesyncd)
- 2.4 Job Schedulers (cron, at permissions)

#### Sección 3: Network ✅
- 3.1 Disable Unused Network Protocols (IPv6, SCTP, DCCP, RDS, TIPC)
- 3.2 Network Parameters - Host Only (send_redirects, ip_forwarding, icmp_redirects, tcp_syncookies)
- 3.3 Network Parameters - Host and Router (reverse_path_filtering, log_martians)

#### Sección 4: Firewall ✅
- 4.1 Single Firewall Utility enforcement
- 4.2 UFW Configuration (Ubuntu default)
  - Installation, legacy removal, service enablement
  - Loopback, outbound, open ports rules, default deny policy
- 4.3 nftables Configuration (Debian default)
  - Installation, ufw conflict resolution, iptables flush
  - Table/chains creation, loopback, outbound, default deny, persistence
- 4.4 iptables Configuration (Legacy/Override)
  - IPv4 and IPv6 policies, loopback, outbound, open ports

#### Sección 5: Access Control ✅
- 5.1 SSH Server Hardening (22 controles)
  - Protocol, ciphers, MACs, KexAlgorithms, authentication, access control, banners, timeouts
- 5.2 Privilege Escalation (sudo/su)
  - Installation, PTY usage, logging, authentication, timestamp timeout, su restrictions
- 5.3 PAM Configuration
  - Software packages, auth-update profiles, arguments (faillock, pwquality, pwhistory, unix)
- 5.4 User Accounts and Environment
  - Shadow password suite parameters, root/system accounts, default environment (TMOUT, umask)

#### Sección 6: Logging and Auditing ✅
- 6.1 System Logging
  - systemd-journald service, journald configuration, rsyslog, logfiles permissions
- 6.2 System Auditing (auditd)
  - Service configuration, data retention, audit rules, file access monitoring
- 6.3 Integrity Checking (AIDE)
  - Installation, database initialization, cron timer, configuration

#### Sección 7: System Maintenance ✅
- 7.1 System File Permissions
  - File/directory permissions, SUID/SGID audit, orphan files, dotfiles
- 7.2 Local User and Group Settings
  - Password aging, empty passwords, root UID uniqueness, legacy entries removal

---

## Arquitectura y Diseño

### Estructura de Roles
```
roles/cis_benchmark/
├── defaults/main.yml          # Variables granulares por control CIS
├── tasks/
│   ├── main.yml               # Entry point con imports por sección
│   ├── section1_initialsetup/ # 1.1-1.7
│   ├── section2_services/     # 2.1-2.4
│   ├── section3_network/      # 3.1-3.3
│   ├── section4_firewall/     # 4.1-4.4
│   ├── section5_access/       # 5.1-5.4
│   ├── section6_logging/      # 6.1-6.3
│   └── section7_system/       # 7.1-7.2
├── handlers/main.yml          # Handlers con validación
├── templates/                 # Jinja2 templates
└── vars/main.yml              # Variables internas
```

### Naming Convention
- Archivos: `{numero}-{accion}-{objeto}.yml` (ej: `1.1.1-configure_kernel_modules.yml`)
- Variables: `cis_<seccion>_<subseccion>_<control>` en `snake_case`
- Tags: `cis_secX`, `cis_X.Y.Z`, `NIST800-53R5_*`, `level1/level2`

### Multi-Distro Support
```yaml
# Auto-detect firewall engine by distribution
cis_firewall_engine: "{{ 'ufw' if ansible_facts.distribution == 'Ubuntu' else 'nftables' }}"
cis_nftables_family: "{{ 'inet' if ansible_facts.distribution == 'Debian' else 'ip' }}"
```

---

## Known Issues

| Issue | Workaround | Status |
|-------|-----------|--------|
| Particiones no separadas (1.1.2) | Tasks se saltan automáticamente si la partición no existe | ✅ Diseñado |
| OverlayFS/SquashFS en contenedores | Usar `cis_1_1_1_disable_overlayfs: false` en group_vars | ✅ Documentado |
| GRUB password requiere generación manual | Usar `ansible-vault encrypt_string` para cifrar hash | ✅ Documentado |
| SSH remoto puede perderse al aplicar hardening | Ejecutar con `--check` primero, permitir SSH antes de policies deny | ✅ Documentado |

---

## Upgrade Guide

### De versión anterior a 1.0.0

1. **Backup de variables personalizadas**:
   ```bash
   cp group_vars/local.yml group_vars/local.yml.backup
   ```

2. **Actualizar estructura de variables**:
   - Variables con sufijo `_bol` fueron normalizadas a `snake_case`
   - Ejemplo: `cis_ssh_config.LoginGraceTime_bol` → `cis_ssh_config.login_grace_time`

3. **Revisar tags de ejecución**:
   - Tags ahora siguen formato `cis_secX`, `cis_X.Y.Z`
   - Actualizar scripts de CI/CD si usan tags antiguos

4. **Validar idempotencia**:
   ```bash
   ansible-playbook playbooks/cis_hardening.yml --check --diff
   # Ejecutar dos veces para confirmar changed=0 en segunda ejecución
   ```

---

## Roadmap

### Próximamente (v1.1.0)
- [ ] Rol de auditoría (`audit/`) con reportes JSON `PASS/FAIL` por control
- [ ] Integración con AWX/Tower para ejecución programada
- [ ] Molecule tests para validación de roles
- [ ] Soporte para RHEL/CentOS 9

### Futuro (v2.0.0)
- [ ] Migración a Ansible Collections para distribución
- [ ] Dashboard web para visualización de compliance
- [ ] Integración con SIEM para alertas de desviación CIS
- [ ] Soporte para CIS Benchmark v2.0.0

---

## Contributors

- **Victor** - Arquitectura inicial, desarrollo de secciones 1-7, documentación
- [Tu Nombre](https://github.com/tu-usuario) - Mantenedor actual

---

> **Nota**: Este changelog refleja cambios significativos. Para detalles de cada commit, revisar el [historial de Git](https://github.com/tu-usuario/ansible-cis-benchmark/commits/main).
