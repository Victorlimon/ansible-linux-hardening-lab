# Matriz incremental CIS Debian 12

Referencia: CIS Debian Linux 12 Benchmark v1.1.0. Esta matriz registra el estado
del proyecto; no representa una certificación de cumplimiento.

| Control | Perfil | Tipo | Estado | Implementación y riesgo |
|---|---|---|---|---|
| 3.1.1 Identificar estado IPv6 | L1 Server/Workstation | Manual | `P4_COMMON_READ_ONLY` | Mecanismo común de audit y verification para Ubuntu 24.04 y Debian 12. Observa parámetro del módulo y sysctl global/default, clasifica `MANUAL` y compara con política local sin modificar red. Ambas VMs observaron IPv6 habilitado con `changed=0`; check mode de hardening tampoco predijo cambios y los pings pasaron. |
| 3.3.10 Habilitar TCP SYN cookies | L1 Server/Workstation | Automated | `P4_COMMON_TESTED_REBOOT` | Mecanismo sysctl común con audit, remediation y verification. Comprueba runtime, precedencia persistente de `systemd-sysctl` y el archivo seleccionado por UFW. En ambas plataformas audit detectó runtime `1` sin persistencia, check mode predijo el alta, la primera convergencia creó `99-cis-network.conf`, la segunda terminó con `changed=0` y verification pasó. Tras un ciclo completo `make stop`/`make start`, runtime y persistencia conservaron `1`, verification terminó con `changed=0` y los pings pasaron. |
| 1.6.2 Banner local | L1 Server/Workstation | Automated | `AUDIT_IMPLEMENTED_BLOCKED` | Auditoría sanitizada detecta metadata y exposición del SO con `changed=0`. Verification y remediation rechazan operar sin texto no vacío y aprobación legal explícita. Falta demostrar equivalencia contra el benchmark Ubuntu exacto antes de extraer un mecanismo común. |
| 7.1.1 Permisos `/etc/passwd` | L1 Server/Workstation | Automated | `P4_COMMON_TESTED` | Mecanismo común probado en Debian 12 y Ubuntu 24.04 con evidencia separada. La auditoría detectó deriva con `changed=0`; check mode predijo el cambio, la primera convergencia corrigió solo el modo, la segunda terminó con `changed=0` y la verificación posterior pasó. |
| 7.1.2 Permisos `/etc/passwd-` | L1 Server/Workstation | Automated | `DEBIAN_SPECIFIC_TESTED` | El adaptador Debian reutiliza el mecanismo técnico de permisos fijos sin declarar equivalencia de benchmark con Ubuntu. Audit y verification exigen archivo regular `root:root`, modo `0644` o más restrictivo sin ejecución. La ausencia es `FAIL`; remediation no crea el backup. Se probaron deriva `0666`, check mode, dos convergencias, gates canary, verification y ping. |
| 7.1.3 Permisos `/etc/group` | L1 Server/Workstation | Automated | `DEBIAN_SPECIFIC_TESTED` | Única ruta canónica por modo, sin wrapper adicional. Exige archivo regular `root:root`, modo `0644` o más restrictivo sin ejecución. Se probaron baseline, deriva `0666`, check mode, dos convergencias, ausencia, gates canary, verification y ping. No se declara equivalencia Ubuntu sin evidencia exacta. |
| 7.1.5 Permisos `/etc/shadow` | L1 Server/Workstation | Automated | `INDEPENDENT_INTERFACES_TESTED` | Audit y verification independientes usan solo metadatos sanitizados, sin checksum ni contenido. Debian permite grupo `root` o `shadow`; remediation selecciona `shadow` y conserva gates canary. Check mode, dos convergencias reales, segunda con `changed=0`, verification y ping pasaron. |
| 2.4.1.2 Permisos `/etc/crontab` | L1 Server/Workstation | Automated | `P4_COMMON_TESTED` | Mecanismo común condicionado por la presencia del paquete `cron`; no instala el paquete ni crea el archivo cuando no aplica. En ambas plataformas audit detectó `0644` con `changed=0`, check mode predijo solo `0600`, la primera convergencia cambió solo el modo, la segunda terminó con `changed=0` y verification pasó. |
| 3.2.1 Deshabilitar DCCP | L2 Server/Workstation | Automated | `NOT_REVIEWED` | Opt-in; requiere confirmar que el protocolo no se usa y revisar todos los kernels instalados. |

## Primer lote

Los entry points canónicos Debian son:

- `playbooks/audit/cis_debian_12.yml`;
- `playbooks/hardening/cis_debian_12.yml`;
- `playbooks/verify/cis_debian_12.yml`.

Los playbooks raíz conservan compatibilidad. Los controles 7.1.1, 7.1.2, 7.1.3
y 7.1.5 no cambian el objetivo salvo que se confirmen explícitamente los gates
`cis_debian_12_remediation_enabled` y `cis_debian_12_canary_confirmed`.

Tags canónicos: `cis_debian_12`, `cis_debian_12_audit`,
`cis_debian_12_remediation`, `cis_debian_12_verification`, `cis_3_1_1`,
`cis_3_3_10`, `cis_7_1_1`, `cis_7_1_2`, `cis_7_1_3`, `cis_7_1_5`,
`ipv6_audit`, `sysctl` y `fixed_file_permissions`.

## Ejecución canaria en laboratorio

La activación requiere ambos gates y debe comenzar en check mode:

```bash
ansible-playbook -i inventories/local/hosts.yml \
  playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags fixed_file_permissions --check --diff \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true
```

La ejecución sin esos gates no modifica archivos. No se debe trasladar esta
orden a producción sin completar sus gates operativos y valores aprobados.

El gate read-only del piloto se ejecuta desde `ansible-control`:

```bash
ansible-playbook -i inventories/local/hosts.yml playbooks/audit/cis_debian_12.yml \
  --limit debian12 --tags cis_7_1_1
```
