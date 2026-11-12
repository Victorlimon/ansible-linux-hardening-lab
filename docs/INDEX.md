# Índice de documentación

La documentación mantenida del proyecto es:

| Documento | Contenido |
|---|---|
| [README.md](../README.md) | Alcance, requisitos y primera ejecución segura |
| [USAGE.md](USAGE.md) | Manual de uso: modos, tags reales, gates y variables |
| [ROLLOUT.md](ROLLOUT.md) | Procedimiento de hardening por secciones gated |
| [LAB.md](LAB.md) | Cómo se trabaja en el laboratorio Vagrant |
| [WAZUH.md](WAZUH.md) | Integración con Wazuh y almacenamiento de logs |
| [PREPRODUCCION_WAZUH.md](PREPRODUCCION_WAZUH.md) | Orden desde Wazuh, selección y criterios de entrada a preproducción |
| [INTEGRACION_WAZUH_ANSIBLE.md](INTEGRACION_WAZUH_ANSIBLE.md) | Evidencia FULL del laboratorio Wazuh 4.12.0 y sus límites |
| [IMPROVING.md](IMPROVING.md) | Cómo mejorar: calificación, mecanismos, nuevos controles |
| [SUPPORT.md](SUPPORT.md) | Autoridad normativa de soporte, evidencia y límites de afirmación |
| [SECURITY.md](../SECURITY.md) | Reporte de vulnerabilidades y respuesta ante secretos |

## Fuente de verdad de implementación

La documentación describe el código; el código manda. Para validar que un dato
sigue vigente, revisá:

- `ansible/playbooks/{audit,hardening,verify}/cis_{ubuntu_2404,debian_12}.yml`
  para los entry points y el grupo de hosts de cada modo.
- `ansible/roles/cis_{ubuntu_2404,debian_12}/tasks/main.yml` para los tags
  reales y los gates (master gate y canario).
- `ansible/roles/cis_{ubuntu_2404,debian_12}/defaults/main.yml` para los
  selectores por control y las variables clave (`cis_firewall`,
  `cis_ufw_ssh_port`, gates de remediación).
- `ansible/roles/cis_platform_preflight/` para el catálogo de plataformas y el
  gate de preflight.
- `ansible/roles/cis_linux_common/tasks/mechanisms/` para la biblioteca de
  mecanismos compartidos.
- `ansible/inventories/local/` para el laboratorio.
- `ansible/scripts/` y `ansible/cis/` para el pipeline de calificación y
  metadatos.

## Notas de ciclo de vida

- **Normativo:** `SUPPORT.md` y la política de seguridad.
- **Operativo:** `USAGE.md`, `ROLLOUT.md`, `LAB.md`, `WAZUH.md`.
- **Referencia:** `IMPROVING.md` y la evidencia de integración.

La referencia `ansible-documentation/` es documentación oficial local de consulta
(Ansible) y no forma parte de la documentación editable del proyecto. Los
inventarios `staging` y `production` están vacíos y son plantillas, no entornos
listos para ejecutar.
