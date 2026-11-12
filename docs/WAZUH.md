# Wazuh ordena; ansible-control ejecuta

**Estado:** el laboratorio con Wazuh **4.12.0** probó órdenes manuales `FULL CHECK` y `FULL APPLY` para Debian 12 y Ubuntu 24.04. El selector nuevo de secciones y controles está en el código fuente, pero **aún no se instaló ni ejecutó en los nodos**. Consultá la [evidencia](INTEGRACION_WAZUH_ANSIBLE.md) y el [procedimiento de preproducción](PREPRODUCCION_WAZUH.md).

## Flujo operativo

```text
Operador → API Console de Wazuh → Active Response del agente ansible-control
         → gateway local → Ansible Core 2.21.2 → nodos autorizados
         → eventos del gateway → agente → alertas en Wazuh
```

Wazuh **no** ejecuta los playbooks ni necesita acceso SSH a los nodos. El agente de `ansible-control` recibe la orden; el gateway valida la release, el perfil de inventario, los hosts, el selector y las aprobaciones. Solo `ansible-control` ejecuta Ansible con el acceso existente. La orden se dirige al agente de control, no al agente del servidor que se endurecerá.

| Responsabilidad | Ubicación |
| --- | --- |
| Solicitar `CHECK` o `APPLY` y consultar alertas | API Console y dashboard de Wazuh |
| Inventario, variables aprobadas, release y ejecución | `ansible-control` |
| Aprobación independiente por host y alcance | Backoffice de `ansible-control`; **no** está disponible en la API Console actual |
| Auditoría posterior de los controles | Playbooks `audit/` y `verify/`, más SCA cuando corresponda |

El operador puede elegir `full`, una o varias secciones (1–7), el subgrupo `5.1`, o tags CIS de controles existentes. No puede enviar rutas de playbook, inventarios libres, comandos de shell ni variables arbitrarias. La selección de secciones se expande según la release sellada; no se necesitan siete playbooks nuevos. El contrato y un ejemplo de solicitud están en [PREPRODUCCION_WAZUH.md](PREPRODUCCION_WAZUH.md).

## Evidencia y logs

El gateway escribe eventos de aceptación, inicio, progreso, recapitulación y resultado terminal en `ansible-control`. El agente los remite a Wazuh para generar alertas correlacionadas por `request_id`. En el manager, `alerts/alerts.json` contiene los eventos que dispararon reglas; el dashboard consulta los documentos indexados. Un HTTP `200` indica que la API recibió la solicitud: **no demuestra** que Ansible terminó ni que el host cumple CIS. Verificá el evento terminal, el recap, la conectividad y la auditoría posterior.

El log local y los diffs de Ansible pueden contener información sensible. Aplicá permisos y retención institucionales; no publiques salidas completas en las alertas. La política de soporte y de afirmaciones está en [SUPPORT.md](SUPPORT.md): ejecutar una sección o `FULL` no equivale a conformidad de todos los controles.

## Límite para producción

El entorno institucional necesita su propio inventario y variables revisados por host, permisos restringidos de Active Response sobre el agente de control, secretos rotados, respaldo, recuperación fuera de banda y pruebas con servicios reales. La instalación de laboratorio no acredita esos requisitos. Seguí la [guía de preproducción](PREPRODUCCION_WAZUH.md) antes de autorizar una remediación institucional.
