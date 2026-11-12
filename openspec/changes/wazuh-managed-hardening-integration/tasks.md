# Tareas: órdenes Wazuh para CIS existente

## Review Workload Forecast

Decision needed before apply: No
Chained PRs recommended: Yes
Delivery strategy: exception-ok
Chain strategy: size-exception
400-line budget risk: High

El mantenedor ya autorizó un único PR con `size:exception`; agrupar commits por comportamiento, con pruebas y documentación. No crear playbooks ni modificar controles CIS para resolver el puente.

| Unidad | Test focalizado | Runtime | Reversión |
|---|---|---|---|
| U1 protocolo | `python3 -m unittest discover -s tests -p 'test_managed_job.py'` | N/A: parser puro | `managed_job.py` y test |
| U2 ejecución | `python3 -m unittest discover -s tests -p 'test_managed_supervisor*.py'` | Vagrant: check/apply controlado | gateway, runner y estado Wazuh |
| U3 observabilidad/E2E | `python3 -m unittest discover -s tests -p 'test_wazuh_managed_hardening_e2e.py'` | Docker 4.14.8→agente→Vagrant | config/rules/logs Wazuh |

## 1 RED y baseline

- [x] 1.1 Crear `integration/wazuh/tests/test_managed_profiles.py`: validación basal de puertos/CIDR y perfil; completado para alcance anterior, no prueba selección full.
- [ ] 1.2 Ampliar `integration/wazuh/tests/test_managed_job.py`: RED managed-v2 JSON acotado, legado check-only, full/tags/roles, campos hostiles y duplicados.
- [ ] 1.3 Ampliar `integration/wazuh/tests/test_managed_supervisor_systemd.py`: RED replay, caída, reserva/descendiente y terminal; sólo si la unidad sigue en ruta real.
- [ ] 1.4 Ampliar `integration/wazuh/tests/test_managed_supervisor.py`: RED inventario ajeno, tag inerte, var/gate desconocido, UFW inválido, SSH /0, aprobación por host y digest distinto.
- [x] 1.5 Baseline `integration/wazuh/`: suite 146 (11 omitidas) y Gitleaks aprobados; no equivale a E2E apply.

## 2 Orden y runner

- [x] 2.1 `integration/wazuh/managed_profiles.py` y `integration/wazuh/config/profiles.lab.json.example`: base de perfiles sellados; cron anterior no cubre full.
- [ ] 2.2 Extender `integration/wazuh/managed_profiles.py`: catálogo de playbooks existentes, inventario/grupos, tags/roles reales y esquema tipado de overrides; verificar tareas efectivas.
- [ ] 2.3a Extender `integration/wazuh/managed_job.py`: parsear/normalizar managed-v2, mantener cuatro argumentos check-only y despachar por host sin paths/argv libres.
- [ ] 2.3b Integrar `integration/wazuh/local_executor.py`: argv fijo full/parcial, `--limit` por host, `--check --diff` opcional y vars JSON privadas.
- [ ] 2.3c Integrar `integration/wazuh/launch_claim.py` y `integration/wazuh/execution_state.py`: reserva, consumo único y recibo por host; ambigüedad bloquea.
- [ ] 2.3d Integrar `integration/wazuh/managed_supervisor.py` y `integration/wazuh/config/ansible-wazuh@.service`: usar supervisión existente sólo si aplica; no crear framework nuevo.

## 3 Aprobación y ejecución completa

- [ ] 3.1 Extender `integration/wazuh/tests/test_managed_job.py`: RED check→aprobación separada→apply Ubuntu/Debian completo y lote atómico sin aprobación.
- [ ] 3.2 Extender `integration/wazuh/managed_job.py`: evidencia inmutable y aprobación por host/alcance/vars; ejecutar playbooks existentes sin `--check`.

## 4 Salida Wazuh

- [ ] 4.1 Extender `integration/wazuh/tests/test_managed_job.py`: RED enviado≠terminal, progreso/recap/fallo JSONL y secretos excluidos.
- [ ] 4.2 Extender `integration/wazuh/managed_job.py` y `integration/wazuh/config/`: eventos acotados, `localfile log_format=json` y reglas; raw root-only.

## 5 Laboratorio

- [ ] 5.1 Crear `integration/wazuh/tests/test_wazuh_managed_hardening_e2e.py`: E2E 4.14.8 full Ubuntu/Debian, tags, grupo/hosts, variables UFW y rechazos; registrar API→alerta→terminal.
- [ ] 5.2 Registrar en `integration/wazuh/evidence/`: prueba aislada 4.12.0 o estado explícito no validado; nunca extrapolar 4.14.8.

## 6 Entrega

- [ ] 6.1 Actualizar `docs/INTEGRACION_WAZUH_ANSIBLE.md`: petición de ejemplo, aprobaciones por host, filtros de logs, límites y rollback.
- [ ] 6.2 Validar pruebas, Gitleaks y `git diff --check`; preparar un PR con `size:exception` sólo si E2E y review pasan.
