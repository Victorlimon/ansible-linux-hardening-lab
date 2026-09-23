# Plan de implementación CIS Debian 12

Referencia: CIS Debian Linux 12 Benchmark v1.1.0, probado por CIS sobre Debian
12.7 x86_64. Este documento registra trabajo del proyecto; no certifica
cumplimiento ni sustituye la evaluación CIS independiente.

## Estado por sección

| Sección | Reutilización esperada | Estado inicial | Riesgo principal |
|---|---|---|---|
| 1 Initial Setup | Mixta | Pendiente | mounts, GRUB, repositorios |
| 2 Services | Parametrizable | Pendiente | retirar servicios requeridos |
| 3 Network | Alta | Pendiente | routers, VPN, red asimétrica |
| 4 Firewall | Política compartible | Pendiente | pérdida de administración |
| 5 Access Control | Alta con validación | Pendiente | bloqueo SSH/PAM/sudo |
| 6 Logging/Auditing | Alta con datos Debian | Pendiente | disco, I/O, reboot |
| 7 Maintenance | Alta | Pendiente | cambios masivos y scans costosos |

## Estados permitidos por control

- `NOT_REVIEWED`
- `SHARED_IDENTICAL`
- `SHARED_PARAMETERIZED`
- `DEBIAN_SPECIFIC`
- `MANUAL`
- `NOT_APPLICABLE`
- `IMPLEMENTED_UNTESTED`
- `TESTED_CHECK`
- `TESTED_CONVERGED`
- `TESTED_POST_REBOOT`
- `EXCEPTION`

## Definition of Done

Un control Debian no se marca liberado hasta registrar:

1. ID, perfil L1/L2 y Server/Workstation.
2. Automated/Manual y aplicabilidad local.
3. comparación con Ubuntu 24.04;
4. implementación común o Debian específica;
5. impacto y gate disruptivo;
6. `--syntax-check` y `--check --diff`;
7. primera y segunda aplicación real;
8. salud SSH/sudo/red/aplicación según el dominio;
9. prueba post-reboot si afecta boot, sysctl, firewall o audit;
10. resultado del verificador independiente y evidencia versionada.

## Hitos

### D0 — Gobierno y baseline

- Revisar licencia antes de distribuir copias completas del benchmark.
- Estabilizar y versionar el baseline Ubuntu actual.
- Fijar toolchain y dependencias de CI.

### D1 — Plataforma

- [x] Grupos `ubuntu_2404`, `debian_12` y `cis_targets`.
- [x] Preflight Debian sin remediación.
- [x] Matriz de facts y arquitectura.

### D2 — Bajo riesgo

- [x] Matriz inicial por control y auditoría IPv6 3.1.1 de solo lectura.
- [x] Canarios 7.1.1, 7.1.2, 7.1.3 y 7.1.5 de permisos fijos con gates por control.
- [x] Cron con gates por control y regresión común en ambas plataformas.
- [x] Auditoría de banners con remediación bloqueada hasta aprobación legal.
- [ ] Permisos fijos restantes con gates por control.
- Regresión Ubuntu en cada extracción común.

### D3 — Plataforma Debian

- Repositorios/keyring, paquetes, servicios, NTP y AppArmor/GRUB.

### D4 — Acceso y red crítica

- UFW, SSH, sudo y PAM con consola y rollback probado.

### D5 — Evidencia y auditoría

- Logging TLS, auditd, AIDE, sección 7 y reporte PASS/FAIL por control.

### D6 — DevSecOps

- Lint, secret scanning, integración en VMs, idempotencia, reboot,
  evaluación externa y promoción canario-producción.
