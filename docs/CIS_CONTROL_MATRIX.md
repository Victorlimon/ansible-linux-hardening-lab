# Matriz de controles CIS 1-7

Esta matriz resume el comportamiento actual del rol, no una certificación de
cumplimiento. Estados usados:

- **Automated**: existen tareas de remediación o configuración activas por
  defecto para parte de la sección.
- **Manual**: el rol observa/informa o la operación requiere decisión externa;
  no hay remediación integral.
- **Opt-in**: la sección o controles disruptivos están desactivados por defecto.

Una sección puede tener los tres estados. "Automated" no equivale a cobertura
completa ni a resultado `PASS`.

El entry point canónico Ubuntu antepone
`cis_ubuntu_2404_remediation_enabled: false` a todos los defaults de la tabla y
rechaza habilitarlo sin `--tags` explícitos. Los valores de entrada siguientes
solo se evalúan después de ese master gate.

| Sección | Default de entrada | Estado real | Opt-in/manual relevante | Riesgos y límites |
|---|---|---|---|---|
| 1. Initial Setup | `cis_section1_initial_setup: true` | **Automated + Manual + Opt-in**. Módulos de filesystem seleccionados, repositorios/updates, AppArmor básico, permisos GRUB, hardening de proceso y banners tienen tareas activas. | OverlayFS, squashfs, UDF y USB storage; módulos no usados; retirada de repositorios; auto-updates; enforcing global de AppArmor; password GRUB; retirada de paquetes y GDM son opt-in. Las particiones ausentes solo se reportan. | Deshabilitar módulos puede romper contenedores/medios. Opciones `noexec` pueden romper aplicaciones. GRUB y AppArmor pueden impedir arranque o servicios. No crea/migra particiones. |
| 2. Services | `cis_section2_services: true` | **Automated + Manual + Opt-in**. Endurece el daemon horario seleccionado y permisos de cron; inventaría listeners. | Todas las retiradas de servicios servidor/cliente están desactivadas. Selección de daemon único y archivos `cron.allow`/`at.allow` son opt-in. La revisión de listeners es manual. | Retirar/maskar servicios rompe roles de aplicación. Cambiar NTP afecta tiempo y autenticación. Allow files vacíos pueden denegar trabajos. |
| 3. Network | `cis_section3_network: true` y `section3_network.enabled: true` | **Automated + Opt-in**. Aplica la mayor parte de sysctl de red segura para servidor. | Wi-Fi/Bluetooth, DCCP/TIPC/RDS/SCTP y `rp_filter` estricto están desactivados. | Cambios de forwarding, redirects y source route afectan routers, VPN, hosts multihomed y redes asimétricas. Descargar módulos puede cortar servicios. |
| 4. Firewall | `cis_section4_firewall: false` | **Opt-in + Automated + Manual**. La ruta UFW reconstruye una política autoritativa cuando cambia su huella o detecta deriva en los archivos de reglas, crea allowlists explícitas, aplica deny y habilita el servicio; lista sockets para revisión. | Toda la sección requiere opt-in. Deben declararse fuentes SSH y reglas inbound/outbound. El reset elimina reglas no declaradas y exige `cis_ufw_authoritative_reset_confirmed: true` en la ejecución real. Comparar listeners es manual. nftables/iptables no están implementados de forma segura y fallan deliberadamente. | Alto riesgo de perder SSH, DNS, NTP, repositorios, monitorización o tráfico de aplicación. Una interrupción durante el reset puede dejar UFW desactivado. El deny de salida exige inventario completo. Solo UFW es la ruta operativa para Ubuntu 24.04. |
| 5. Access Control | `cis_section5_access_control: true` | **Automated + Manual + Opt-in**. SSH, sudo y parte de cuentas/entorno están activos. | Allowlist SSH, sudo sin password, restricción `su`, PAM completo, cambios a usuarios existentes, shells y bloqueos disruptivos son opt-in. Varias comprobaciones de cuentas son manuales. | Riesgo crítico de bloqueo SSH/PAM/sudo. Algoritmos SSH pueden excluir clientes. Políticas de contraseña/cuenta pueden romper servicios y automatización. |
| 6. Logging and Auditing | `cis_section6_logging_audit: false` | **Opt-in + Automated + Manual**. Al habilitarla, configura journald/rsyslog, auditd, retención y muchas reglas. | `journal-upload` admite material TLS; el forwarding rsyslog implementado es TCP (`@@`), no TLS. Acciones disruptivas de disco, regla de comandos privilegiados e immutable son opt-in. Instalación e inicialización AIDE están desactivadas separadamente. | Puede consumir disco, CPU e I/O. Auditd está limitado a `x86_64`; parámetros de arranque requieren reboot. Immutable dificulta correcciones. AIDE inicial recorre todo el filesystem. No genera informe JSON ni existe playbook de auditoría separado. |
| 7. System Maintenance | `cis_section7_system: false`; subsecciones 7.1 y 7.2 `false` | **Opt-in + Manual**, con remediaciones puntuales condicionadas. Ejecuta búsquedas de permisos, propietarios y cuentas cuando se habilita. | Quitar bits world-writable, reasignar huérfanos, convertir/bloquear cuentas, cambiar grupos y eliminar dotfiles requieren flags/mapas explícitos. | Escaneos completos son costosos. Cambios masivos de propiedad/permisos o cuentas pueden inutilizar datos, homes, servicios y acceso. Requiere revisión humana de hallazgos. |

## Tags de sección

| Sección | Tag recomendado |
|---|---|
| 1 | `cis_sec1` |
| 2 | `cis_sec2` |
| 3 | `cis_sec3` |
| 4 | `cis_sec4` |
| 5 | `cis_sec5` |
| 6 | `cis_sec6` |
| 7 | `cis_sec7` |

Los tags de control mezclan formatos, por ejemplo `cis_5.1.4`, `cis_4_2_6` y
`cis_6_2_3_1`. Liste las tareas antes de ejecutar:

```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec6 --list-tasks
```

## Criterio de aprobación

Para declarar un control operativo en un entorno concreto se necesita, como
mínimo: aplicabilidad documentada, variables aprobadas, `--check --diff`, una
aplicación canaria, segunda aplicación idempotente, validación técnica externa
al rol y procedimiento de recuperación probado. La presencia de una task o un
tag no satisface por sí sola esos criterios.

El modo de ejecución debe declararse en inventario mediante
`cis_execution_environment`. Para `production`, el rol exige además
`cis_production_mode: true` y los gates operativos documentados.

## Bloqueos conocidos para declarar cumplimiento CIS

El rol todavía no constituye un perfil CIS Level 1 completo. Antes de esa
declaración se requiere una matriz por control y evidencia independiente. Entre
los gaps principales están: controles Level 1 desactivados sin mecanismo formal
de excepción, PAM y allowlists de acceso, retirada aprobada de servicios,
validación de todas las cuentas y logfiles existentes, precedencia persistente
de sysctl, estado post-reboot de GRUB/audit, secciones 4/6/7 opt-in y ausencia de
un verificador PASS/FAIL por control. Los valores conservadores de retención
auditd priorizan disponibilidad y no satisfacen las acciones disruptivas CIS sin
aprobación explícita.
