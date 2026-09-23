# Índice de documentación

La documentación mantenida del proyecto es:

| Archivo | Contenido |
|---|---|
| [`docs/SUPPORT.md`](SUPPORT.md) | Sole normative authority for support, evidence, lifecycle, and claim boundaries |
| [`README.md`](../README.md) | Alcance, requisitos y primera ejecución segura |
| [`docs/README.md`](README.md) | Arquitectura real, inventario, usuarios, tags y pruebas |
| [`docs/PRODUCTION_UBUNTU24.md`](PRODUCTION_UBUNTU24.md) | Preparación, ejecución y recuperación para Ubuntu 24.04 Server |
| [`docs/PRODUCTION_DEBIAN12.md`](PRODUCTION_DEBIAN12.md) | Controlled canary operation and recovery boundaries for Debian 12 |
| [`docs/CIS_CONTROL_MATRIX.md`](CIS_CONTROL_MATRIX.md) | Estado automatizado, manual u opt-in y riesgos por secciones 1-7 |
| [`docs/ARCHITECTURE_CIS_MULTI_PLATFORM.md`](ARCHITECTURE_CIS_MULTI_PLATFORM.md) | Arquitectura incremental para Ubuntu 24.04 y Debian 12 |
| [`docs/CIS_DEBIAN12_IMPLEMENTATION_PLAN.md`](CIS_DEBIAN12_IMPLEMENTATION_PLAN.md) | Hitos y Definition of Done para Debian 12 |
| [`docs/CIS_DEBIAN12_CONTROL_MATRIX.md`](CIS_DEBIAN12_CONTROL_MATRIX.md) | Estado y riesgos por control del adaptador Debian 12 |
| [`docs/SCALABILITY.md`](SCALABILITY.md) | Capas, contratos y migración incremental Ubuntu/Debian |
| [`docs/PRODUCTION_MIGRATION_MASTER_PLAN.md`](PRODUCTION_MIGRATION_MASTER_PLAN.md) | Plan integral de arquitectura, migración, producción, SIEM, drift, compatibilidad y contenedores |
| [`docs/MIGRATION_EXECUTION_LOG.md`](MIGRATION_EXECUTION_LOG.md) | Evidencia cronológica de fases y validaciones realmente ejecutadas |
| [`SECURITY.md`](../SECURITY.md) | Reporte de vulnerabilidades y respuesta ante secretos |
| [`docs/adr/README.md`](adr/README.md) | Decisiones de arquitectura versionadas |

## Documentation lifecycle

- **Current:** `SUPPORT.md`, operator guidance, and security reporting policy.
- **Reference:** architecture and control matrices; these do not establish
  support.
- **Historical:** changelog, execution log, and architecture session record;
  these are non-normative.
- **Future:** migration plans; these are non-normative.

For any support question, use [SUPPORT.md](SUPPORT.md), not a status statement
in another page.

## Fuente de verdad de implementación

Para validar que la documentación sigue correspondiendo al código, revise:

- `ansible/playbooks/cis_ubuntu_2404_hardening.yml` y los entry points Debian
  para los patrones de hosts; `cis_hardening.yml` es compatibilidad Ubuntu.
- `ansible/roles/cis_ubuntu_2404/tasks/main.yml` para la orquestación canónica
  Ubuntu y `ansible/roles/cis_benchmark/tasks/_section_*.yml` para las entradas
  internas de compatibilidad.
- `ansible/roles/cis_benchmark/defaults/main/*.yml` para defaults efectivos.
- `ansible/inventories/local/hosts.yml` y `group_vars/ubuntu_2404.yml` para el
  laboratorio.
- `ansible/playbooks/{audit,hardening,verify}/cis_debian_12.yml` y
  `roles/cis_debian_12/` para las interfaces canónicas y canarios Debian 12;
  los playbooks Debian de la raíz son wrappers compatibles.
- `ansible/requirements.yml` para colecciones.
- `Makefile`, `lab/vagrant/Vagrantfile` y scripts de provisión para usuarios y
  flujo del laboratorio.

Los inventarios `staging` y `production` están vacíos. No constituyen evidencia
de soporte multiambiente. La referencia vendorizada en
`docs/ansible-documentation/` es documentación oficial local de consulta y no
forma parte de la documentación editable del proyecto.
