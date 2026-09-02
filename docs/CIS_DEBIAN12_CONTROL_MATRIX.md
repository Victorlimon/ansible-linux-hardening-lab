# Matriz incremental CIS Debian 12

Referencia: CIS Debian Linux 12 Benchmark v1.1.0. Esta matriz registra el estado
del proyecto; no representa una certificación de cumplimiento.

| Control | Perfil | Tipo | Estado | Implementación y riesgo |
|---|---|---|---|---|
| 3.1.1 Identificar estado IPv6 | L1 Server/Workstation | Manual | `TESTED_CONVERGED` | Auditoría de solo lectura de parámetro del módulo y sysctl global/default. Debian del laboratorio observó IPv6 habilitado y dos ejecuciones con `changed=0`. No cambia conectividad. |
| 1.6.2 Banner local | L1 Server/Workstation | Automated | `NOT_REVIEWED` | Requiere texto y aprobación legal antes de reemplazar `/etc/issue`. |
| 7.1.1 Permisos `/etc/passwd` | L1 Server/Workstation | Automated | `P3_PILOT_TESTED` | Auditoría, remediación y verificación independientes. La auditoría detectó deriva con `changed=0`; check mode predijo el cambio, la primera convergencia corrigió solo el modo, la segunda terminó con `changed=0` y la verificación posterior pasó. |
| 7.1.5 Permisos `/etc/shadow` | L1 Server/Workstation | Automated | `TESTED_CONVERGED` | Canario opt-in; Debian permite grupo `root` o `shadow`; se usa `shadow`. Dos ejecuciones reales y verificación posterior finalizaron con `changed=0`. |
| 2.4.1.2 Permisos `/etc/crontab` | L1 Server/Workstation | Automated | `NOT_REVIEWED` | Aplicar solo cuando cron y el archivo ya existan; no instalar ni crear implícitamente. |
| 3.2.1 Deshabilitar DCCP | L2 Server/Workstation | Automated | `NOT_REVIEWED` | Opt-in; requiere confirmar que el protocolo no se usa y revisar todos los kernels instalados. |

## Primer lote

Los entry points canónicos Debian son:

- `playbooks/audit/cis_debian_12.yml`;
- `playbooks/hardening/cis_debian_12.yml`;
- `playbooks/verify/cis_debian_12.yml`.

Los playbooks raíz conservan compatibilidad. Los controles 7.1.1 y 7.1.5 no
cambian el objetivo salvo que se confirmen explícitamente los gates
`cis_debian_12_remediation_enabled` y `cis_debian_12_canary_confirmed`.

Tags canónicos: `cis_debian_12`, `cis_debian_12_audit`,
`cis_debian_12_remediation`, `cis_debian_12_verification`, `cis_3_1_1`,
`cis_7_1_1`, `cis_7_1_5`, `ipv6_audit` y `fixed_file_permissions`.

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
bash scripts/test_p3_pilot.sh
```
