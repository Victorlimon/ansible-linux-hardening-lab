# CIS Benchmark Section 6.1 - System Logging - Implementation Summary

## 📋 Overview
Este documento resume la implementación completa de la **Sección 6.1: System Logging** del CIS Benchmark para Ubuntu 24.04 LTS, automatizada con Ansible.

## 🗂️ Estructura de Archivos

```
roles/cis_benchmark/tasks/section6_logging/6.1-system_logging/
├── main.yml                                    # Entry point para 6.1
├── 6.1.1-configure_systemd_journald_service.yml  # 6.1.1.x - journald service
├── 6.1.2-configure_journald.yml                  # 6.1.2.x - journald config
├── 6.1.3-configure_rsyslog.yml                   # 6.1.3.x - rsyslog config
└── 6.1.4-configure_logfiles.yml                  # 6.1.4.1 - logfile permissions
```

## ✅ Controles Implementados

### 6.1.1 | Configure systemd-journald service

| Control | Descripción | Tipo | Tags |
|---------|-------------|------|------|
| **6.1.1.1** | Ensure journald service is enabled and active | Automated | `cis_6_1_1_1` |
| **6.1.1.2** | Ensure journald log file access is configured | Manual | `cis_6_1_1_2` |
| **6.1.1.3** | Ensure journald log file rotation is configured | Manual | `cis_6_1_1_3` |
| **6.1.1.4** | Ensure only one logging system is in use | Automated | `cis_6_1_1_4` |

### 6.1.2 | Configure journald

| Control | Descripción | Tipo | Tags |
|---------|-------------|------|------|
| **6.1.2.1.1** | Ensure systemd-journal-remote is installed | Automated | `cis_6_1_2_1_1` |
| **6.1.2.1.2** | Ensure systemd-journal-upload authentication is configured | Manual | `cis_6_1_2_1_2` |
| **6.1.2.1.3** | Ensure systemd-journal-upload is enabled and active | Automated | `cis_6_1_2_1_3` |
| **6.1.2.1.4** | Ensure systemd-journal-remote service is not in use | Automated | `cis_6_1_2_1_4` |
| **6.1.2.2** | Ensure journald ForwardToSyslog is disabled | Automated | `cis_6_1_2_2` |
| **6.1.2.3** | Ensure journald Compress is configured | Automated | `cis_6_1_2_3` |
| **6.1.2.4** | Ensure journald Storage is configured | Automated | `cis_6_1_2_4` |

### 6.1.3 | Configure rsyslog

| Control | Descripción | Tipo | Tags |
|---------|-------------|------|------|
| **6.1.3.1** | Ensure rsyslog is installed | Automated | `cis_6_1_3_1` |
| **6.1.3.2** | Ensure rsyslog service is enabled and active | Automated | `cis_6_1_3_2` |
| **6.1.3.3** | Ensure journald is configured to send logs to rsyslog | Automated | `cis_6_1_3_3` |
| **6.1.3.4** | Ensure rsyslog log file creation mode is configured | Automated | `cis_6_1_3_4` |
| **6.1.3.5** | Ensure rsyslog logging is configured | Manual | `cis_6_1_3_5` |
| **6.1.3.6** | Ensure rsyslog is configured to send logs to a remote log host | Manual | `cis_6_1_3_6` |
| **6.1.3.7** | Ensure rsyslog is not configured to receive logs from a remote client | Automated | `cis_6_1_3_7` |
| **6.1.3.8** | Ensure logrotate is configured | Manual | `cis_6_1_3_8` |

### 6.1.4 | Configure Logfiles

| Control | Descripción | Tipo | Tags |
|---------|-------------|------|------|
| **6.1.4.1** | Ensure access to all logfiles has been configured | Automated | `cis_6_1_4_1` |

## 🔧 Variables de Configuración

Todas las variables están definidas en `defaults/main.yml` bajo `section6_logging`:

### Ejemplo de configuración personalizada:

```yaml
# inventories/local/group_vars/all.yml
section6_logging:
  # Preferir rsyslog sobre journald
  '6_1_1_4_single_logging_system':
    preferred_system: 'rsyslog'
  
  # Configuración de rotación de logs para producción
  '6_1_1_3_journald_rotation':
    SystemMaxUse: '2G'
    SystemKeepFree: '1G'
    RuntimeMaxUse: '500M'
    RuntimeKeepFree: '100M'
    MaxFileSec: '3month'
  
  # Configuración de logging remoto
  '6_1_3_6_rsyslog_remote_logging':
    enabled: true
    remote_host: 'logs.example.com'
    port: 6514
    protocol: 'tcp'
    resumeRetryCount: 100
    queueSize: 5000
  
  # Permisos específicos para logs sensibles
  '6_1_4_1_logfile_permissions':
    file_overrides:
      - { path: '/var/log/secure', mode: '0600', owner: 'root', group: 'root' }
      - { path: '/var/log/auth.log', mode: '0600', owner: 'root', group: 'root' }
```

## 🚀 Ejecución del Playbook

### Modo Auditoría (Check Mode - Sin cambios):
```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit "production" \
  --tags "cis_6_1" \
  --check \
  -vvv
```

### Modo Remediación (Aplicar cambios):
```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit "production" \
  --tags "cis_6_1" \
  -vvv
```

### Ejecutar controles específicos:
```bash
# Solo journald service
ansible-playbook playbooks/cis_hardening.yml --tags "cis_6_1_1"

# Solo rsyslog configuration
ansible-playbook playbooks/cis_hardening.yml --tags "cis_6_1_3"

# Solo permisos de logfiles
ansible-playbook playbooks/cis_hardening.yml --tags "cis_6_1_4_1"
```

## 🔄 Handlers Disponibles

Los handlers están definidos en `roles/cis_benchmark/handlers/main.yml`:

| Handler | Descripción | Disparado por |
|---------|-------------|---------------|
| `Reload systemd daemon` | Recarga configuración systemd | Cambios en unit files |
| `Restart journald` | Reinicia systemd-journald | Cambios en journald.conf |
| `Restart journal-upload` | Reinicia journal-upload | Cambios en upload config |
| `Restart rsyslog` | Reinicia rsyslog | Cambios en rsyslog.conf |
| `Reload systemd-tmpfiles` | Aplica configuración tmpfiles | Cambios en tmpfiles.d |

## 🛡️ Características de Implementación

### ✅ Idempotencia Garantizada
- Todas las tareas usan `changed_when` apropiado
- Verificación previa con `check_mode` en auditoría
- Uso de `backup: true` en modificaciones de archivos de configuración

### ✅ Modularidad
- Cada control CIS tiene su propia sección identificable
- Tags específicos para ejecución selectiva
- Variables configurables por entorno

### ✅ Auditoría y Reporting
- Cada tarea incluye fase AUDIT → REMEDIATE → REPORT
- Mensajes de debug informativos cuando `not ansible_check_mode`
- Registro de estado en `register` para trazabilidad

### ✅ Seguridad por Defecto
- Permisos restrictivos en archivos de configuración (`0644`)
- Propietario `root:root` en todos los archivos generados
- Validación de sintaxis con `validate` en archivos de configuración

## ⚠️ Consideraciones Importantes

### 🔄 Reinicios Requeridos
- Algunos cambios en journald/rsyslog requieren reinicio del servicio
- Cambios en configuración de auditoría pueden requerir reboot del sistema

### 📊 Planificación de Capacidad
- Configurar `SystemMaxUse` y `RuntimeMaxUse` según espacio disponible
- Considerar rotación de logs para evitar llenado de disco

### 🔐 Entornos LAB vs PROD
```yaml
# LAB: disk_full_action en 'syslog' para evitar shutdowns
'6_2_2_3_disk_actions':
  disk_full_action: 'syslog'

# PROD: disk_full_action en 'halt' para máxima seguridad
'6_2_2_3_disk_actions':
  disk_full_action: 'halt'
```

### 🌐 Logging Remoto
- Configurar TLS/SSL para transporte seguro de logs
- Verificar conectividad de red antes de habilitar forwarding remoto
- Considerar buffer de cola para tolerancia a fallos de red

## 🔍 Verificación Post-Implementación

### Verificar estado de servicios:
```bash
# journald
systemctl status systemd-journald.service

# rsyslog
systemctl status rsyslog.service

# Configuración efectiva
systemd-analyze cat-config systemd/journald.conf
rsyslogd -N1  # Validar configuración rsyslog
```

### Verificar permisos de logs:
```bash
# Listar permisos de archivos de log
ls -la /var/log/*.log

# Verificar configuración tmpfiles
systemd-tmpfiles --cat-config | grep journal
```

### Verificar rotación de logs:
```bash
# Ver configuración logrotate
cat /etc/logrotate.d/rsyslog

# Simular rotación (dry-run)
logrotate -d /etc/logrotate.conf
```

## 📚 Referencias

- [CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [systemd-journald Documentation](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)
- [rsyslog Documentation](https://www.rsyslog.com/doc/)
- [auditd Documentation](https://man7.org/linux/man-pages/man8/auditd.8.html)

---
*Documento generado automáticamente - Última actualización: $(date)*
