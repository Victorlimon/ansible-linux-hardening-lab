# Entrega a la DTIC: hardening CIS con Ansible integrado a Wazuh

Documento de traspaso para iniciar la **preproducción** en la infraestructura de la DTIC. Resume qué se entrega, qué debe proveer la DTIC, en qué orden se instala y cómo se acepta. El detalle operativo está en [PREPRODUCCION_WAZUH.md](PREPRODUCCION_WAZUH.md).

## 1. Qué se entrega

| Componente | Ubicación en el repositorio | Para qué sirve |
| --- | --- | --- |
| Playbooks y roles CIS (Ubuntu 24.04, Debian 12) | `ansible/` | Auditoría, hardening y verificación de las 7 secciones del CIS Benchmark |
| Gateway Wazuh → Ansible | `integration/wazuh/managed_job.py` y módulos asociados | Recibe órdenes de Wazuh, las valida y ejecuta Ansible con aprobación |
| Constructor de releases | `integration/wazuh/build_release.py` | Empaqueta código + configuración del sitio en un bundle sellado |
| Instalador del controlador | `integration/wazuh/install_controller.py` | `bootstrap` (preparación) y `release` (instalar y activar un bundle) |
| Instalador del manager | `integration/wazuh/install_manager.py` | Reglas 100120–100130 y comando `ansible-job` en el manager |
| Cliente del operador | `integration/wazuh/wazuh_order.py` | Envía `CHECK` y `APPLY` por la API de Wazuh |
| Preparación de seguridad | `integration/wazuh/prepare_safety.py` | Registra respaldo y acceso fuera de banda antes de un `APPLY` |
| Plantilla del sitio | `integration/wazuh/site.example/` | Base del repositorio privado de configuración de la DTIC |
| Usuario API de mínimo privilegio | `integration/wazuh/config/rbac_ansible_operator.md` | Política, rol y usuario `ansible_operator` |
| Runbook | `docs/PREPRODUCCION_WAZUH.md` | Instalación, operación, rollback, problemas frecuentes, aceptación |
| Requisitos del servidor | `docs/REQUISITOS_SERVIDOR_ANSIBLE_CONTROL_DTIC.md` | Recursos del `ansible-control` |

## 2. Qué debe proveer la DTIC

| # | Recurso | Detalle |
| --- | --- | --- |
| 1 | Servidor `ansible-control` | Ubuntu Server 24.04 LTS, 4 vCPU, 8 GB RAM, 100 GB, sin servicios de negocio |
| 2 | Agente Wazuh 4.12.0 en el controlador | Enrolado en el manager institucional |
| 3 | Acceso administrativo al manager Wazuh 4.12.0 | Para instalar reglas y comando y crear el usuario `ansible_operator` |
| 4 | Servidores de preproducción | Ubuntu 24.04 y/o Debian 12, representativos de producción, con snapshot o respaldo |
| 5 | Cuenta de automatización en cada servidor | Usuario `ansible` con sudo; se le autoriza la clave pública del controlador |
| 6 | Conectividad | Controlador → servidores por SSH (22/TCP); agente → manager (1514/1515 TCP) |
| 7 | Repositorio Git privado para la configuración del sitio | Inventario y variables por servidor (copiar `site.example/`) |
| 8 | Acceso fuera de banda (consola) y ventana de cambio | Obligatorios antes de cualquier `APPLY` |
| 9 | Roles de personas | Operador (envía órdenes) y aprobador (emite la aprobación) **distintos** |

## 3. Orden de instalación en preproducción

1. Crear el repositorio del sitio a partir de `site.example/` con los servidores reales y revisar `cis_*_sshd_allow_users` (debe incluir `ansible` y los administradores).
2. Manager: `install_manager.py --dry-run`, luego sin `--dry-run`.
3. Manager: crear el usuario `ansible_operator` según `rbac_ansible_operator.md` y validar las respuestas 403.
4. Controlador: `install_controller.py bootstrap --dry-run`, luego real; autorizar la clave pública impresa en cada servidor y registrar `known_hosts`.
5. Controlador: retirar los scripts de Active Response innecesarios del agente (procedimiento en `rbac_ansible_operator.md`).
6. Estación de administración: `build_release.py` con un `release_id` nuevo; anotar el sha256.
7. Controlador: `install_controller.py release --expect-sha256 <hash> --expect-release-id <id>`.
8. Operador: `CHECK` por servidor y sección; revisar el diff con el responsable del servidor.
9. Aprobador: snapshot/respaldo → `prepare_safety.py` → `ansible-job --managed-v2-approve`.
10. Operador: `APPLY`; comprobar SSH, sudo, agente Wazuh y servicios de negocio; ejecutar `verify`.

## 4. Criterio de aceptación

La lista completa está en la sección 9 de [PREPRODUCCION_WAZUH.md](PREPRODUCCION_WAZUH.md). Como mínimo:

- [ ] Instalación con `bootstrap` y `release` sin pasos manuales, con `--dry-run` previo archivado.
- [ ] `ansible_operator` solo puede enviar órdenes al agente del controlador.
- [ ] `CHECK` y `APPLY` correctos en cada sistema operativo y segunda ejecución con `changed=0`.
- [ ] `APPLY` sin aprobación, con aprobación vencida o con otro alcance es rechazado.
- [ ] Servicios de negocio operativos después de cada `APPLY`; rollback por snapshot ensayado.
- [ ] Alertas localizadas en Wazuh por `request_id`.

## 5. Estado al momento de la entrega

Validado en el laboratorio (VirtualBox, Wazuh 4.12.0, Ansible Core 2.21.2): instalación reproducible, `CHECK`/`APPLY` por Wazuh en ambos sistemas operativos, rechazo de órdenes inválidas, usuario RBAC de mínimo privilegio y revisión de seguridad independiente con hallazgos corregidos. El detalle de cada prueba está en la tabla de evidencia de [PREPRODUCCION_WAZUH.md](PREPRODUCCION_WAZUH.md).

**Pendiente de la DTIC:** los recursos de la sección 2. **Fuera de alcance:** cumplimiento CIS de servidores con servicios de negocio sin un estudio previo por servidor; los controles condicionados por riesgo se habilitan uno a uno en el repositorio del sitio.
