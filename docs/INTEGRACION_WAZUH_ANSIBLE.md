# Evidencia de la integración Wazuh–Ansible en el laboratorio

**Resultado comprobado:** Wazuh **4.12.0** envió órdenes manuales al agente de `ansible-control` (ID `001`), y este ejecutó los playbooks existentes con Ansible Core **2.21.2** sobre Debian 12 y Ubuntu 24.04 **por separado**. Los dos `FULL APPLY` terminaron sin tareas fallidas. Esta evidencia corresponde al código y a la release usados el **21 de octubre de 2026**; no valida automáticamente los cambios posteriores de selección por sección.

## Aplicación FULL observada

Se ejecutó `FULL CHECK`, se crearon snapshots de los nodos y se emitió una aprobación de un solo uso por host antes de cada `FULL APPLY`.

| Destino | `request_id` CHECK/APPLY | Recap APPLY | Comprobaciones posteriores |
| --- | --- | --- | --- |
| `debian12` | `dd001dbd-3746-4a00-9cb8-a6f290f05caa` | `ok=418 changed=43 unreachable=0 failed=0` | Ansible `ping=pong`, sudo y `sshd -t` correctos; agente Wazuh activo. |
| `ubuntu24` | `a0a4448b-3d24-4e63-9089-90dbdcfc8fdd` | `ok=405 changed=44 unreachable=0 failed=0` | Ansible `ping=pong`, sudo y `sshd -t` correctos; agente Wazuh activo. |

Los eventos JSONL registraron `accepted`, `started`, `progress`, `recap` y `completed`; el terminal confirmó salida cero. El manager Wazuh registró **seis alertas correlacionadas por cada APPLY**, incluidas aceptación, recapitulación, verificación pendiente y finalización. Una comprobación independiente posterior confirmó conectividad Ansible a ambos nodos y tres agentes Wazuh activos.

`FULL` selecciona el rol completo de cada plataforma y recorre sus siete secciones, **pero los gates por control pueden omitir remediaciones**. `failed=0` prueba ejecución satisfactoria de lo seleccionado, no cumplimiento íntegro del perfil CIS, segunda corrida idempotente ni estabilidad de aplicaciones de negocio. La política de afirmaciones está en [SUPPORT.md](SUPPORT.md).

## Comprobación de migración anterior

El **20 de octubre de 2026**, antes de los APPLY anteriores, dos órdenes `FULL CHECK` recorrieron Wazuh API → Active Response en `ansible-control` → Ansible → nodo → JSONL → alertas Wazuh:

| Destino | `request_id` | Recap `--check --diff` |
| --- | --- | --- |
| `debian12` | `bede8b23-8c02-46c7-91c4-39c0141eaa87` | `ok=443 changed=29 unreachable=0 failed=0` |
| `ubuntu24` | `7a359c5b-5f84-482c-ac0f-1c33bcd4c877` | `ok=433 changed=28 unreachable=0 failed=0` |

Aquí `changed` representa **cambios previstos**, no aplicados. Cada solicitud tuvo evento terminal y cinco alertas correlacionadas. Ambos nodos conservaron conectividad Ansible.

## Qué permanece sin probar

- La nueva selección `sections` (1–7 o subgrupo `5.1`) y los tags CIS individuales **no** se han instalado como una nueva release ni ejecutado de extremo a extremo en los nodos. Cuentan con pruebas locales de contrato, no con evidencia `CHECK → APPLY` real.
- Falta auditoría/verificación posterior de cada alcance, segunda aplicación para medir idempotencia y pruebas con servicios y puertos de preproducción configurados por el administrador.
- Los inventarios `staging` y `production` del repositorio están vacíos. El despliegue, RBAC, secretos, almacenamiento y recuperación del Wazuh institucional siguen pendientes de adaptación y prueba.
- El indicador `verification=pending` del gateway no significa verificación aprobada; se requiere evidencia separada de los playbooks de auditoría/verificación y del estado de los servicios.

La [guía de preproducción](PREPRODUCCION_WAZUH.md) define la matriz pendiente. El registro histórico extenso de laboratorios anteriores (4.14.8 y releases `lab_v8`–`lab_v20`) se conservó fuera de la documentación operativa en `backups-limpia/docs/`; esa carpeta es local y **no forma parte del repositorio entregable**.