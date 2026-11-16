# Puente Wazuh → ansible-control

**Responsabilidad:** Wazuh envía una orden manual de Active Response al agente instalado en `ansible-control`; el gateway de ese servidor valida la orden y ejecuta los playbooks Ansible existentes. Wazuh **no** accede por SSH a los nodos ni ejecuta hardening. La evidencia `FULL` con Wazuh 4.12.0 está en [la guía del laboratorio](../../docs/INTEGRACION_WAZUH_ANSIBLE.md). El selector nuevo de secciones todavía requiere despliegue y pruebas reales.

## Contrato operativo

La API Console del dashboard envía `PUT /active-response` al **agente de control** con `command: "!ansible-job"` y `arguments: ["managed-v2", "<orden JSON canónica>"]`. La orden admite:

| Campo | Alcance |
| --- | --- |
| `playbook_id` | Trabajo autorizado para Debian o Ubuntu: preflight donde aplica, auditoría, hardening o verificación. |
| `inventory_profile_id`, `targets` | Perfil sellado y alias/grupo aprobado; no rutas ni `all` libre. |
| `selection` | `full`, `sections` (1–7, subgrupo como `5.1`), `tags` (controles CIS validados) o el rol de plataforma. |
| `extra_vars` | Solo las variables UFW/SSH de Ubuntu expresamente permitidas; las demás se revisan en inventario/release. |
| `mode` | `check` o `apply`; cada APPLY requiere aprobación de un solo uso por host. |

La expansión de secciones se calcula contra los controles de la **release sellada** en `ansible-control`, no contra una lista enviada por el usuario. Los gates Ansible por plataforma y control siguen vigentes. `full` recorre el rol entero; no certifica conformidad CIS. El ejemplo de orden, las restricciones y la matriz de validación están en [PREPRODUCCION_WAZUH.md](../../docs/PREPRODUCCION_WAZUH.md).

Un aprobador separado registra el respaldo y la recuperación fuera de banda y emite la aprobación en el backoffice de `ansible-control`; **la API Console de Wazuh no emite esa aprobación**. El operador sí puede solicitar y observar `CHECK`/`APPLY` desde Wazuh. No se debe retirar esta separación para simular una interfaz inexistente.

## Componentes que se entregan

- `managed_job.py`: valida órdenes, alcance, release, aprobaciones y ejecución.
- `prepare_isolated_runtime.py`: prepara el runtime Ansible aislado de la release.
- `managed_profiles.py`, `managed_supervisor.py` y módulos auxiliares: perfiles y seguimiento del trabajo; no son scripts sobrantes.
- `build_release.py` (estación de administración), `install_controller.py`, `prepare_safety.py` (controlador), `install_manager.py` (manager), `wazuh_order.py` (operador) y `site.example/`: instalación reproducible y flujo operativo; ver la [guía de preproducción](../../docs/PREPRODUCCION_WAZUH.md). `config/rbac_ansible_operator.md` define el usuario de API de mínimo privilegio.
- `config/`: ejemplos de política y fragmentos de Active Response, recolección y reglas. **Son plantillas**, no configuración institucional instalada.
- `tests/`: pruebas de contrato y seguridad. Los ejemplos de laboratorio no son inventario de producción.

## Verificación antes de desplegar

En Linux, con la versión fijada de Ansible Core **2.21.2**, validar la release, los inventarios, `--syntax-check` y la matriz de selección de la [guía de preproducción](../../docs/PREPRODUCCION_WAZUH.md). Como prueba local del código Python:

```bash
python3 -B -m unittest discover -s integration/wazuh/tests -p 'test_*.py'
```

La suite completa usa mecanismos POSIX; ejecutarla en Windows no sustituye la prueba en Linux. La respuesta HTTP de Wazuh solo confirma recepción. Para acreditar ejecución, correlacionar `request_id`, evento terminal, recap y alertas, y comprobar después la salud de SSH, sudo, agente Wazuh y servicios de negocio. No se ha probado todavía la selección `sections` en nodos reales.
