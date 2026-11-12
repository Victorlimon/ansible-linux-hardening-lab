# Plan de endurecimiento local de ansible-control

El controlador dedicado con Ubuntu 24.04 ejecuta **su propio** perfil, manualmente y en el mismo equipo. No se aplica el rol CIS de nodos ni se habilita este playbook en la lista permitida del gateway de Wazuh. El objetivo es reducir riesgo y conservar el plano de gestión; no existe una garantía de invulnerabilidad ni una declaración de conformidad CIS completa.

## Ruta de ejecución

| Etapa | Acción | Condición para avanzar |
| --- | --- | --- |
| 1. Preparación | Aprobar acceso de recuperación, respaldo, redes, cuentas y retención de registros. | Administrador puede recuperar el equipo fuera de banda. |
| 2. Arranque | Instalar Ubuntu 24.04 y Ansible Core 2.21.2 en un entorno virtual institucional confiable; instalar agente Wazuh y gateway por su procedimiento independiente. | Comprobar versión, propietario del entorno virtual y conectividad actual antes de endurecer. |
| 3. Base | Ejecutar el lanzador sin argumentos. | Verificar sesión administrativa nueva, agente/gateway Wazuh y salida a nodos. |
| 4. Permisos críticos | Aprobar un archivo de política privado y ejecutar `--critical`. | Verificar de nuevo acceso, lectura del repositorio por procesos autorizados y auditoría de credenciales. |
| 5. Producción | Configurar recolección saneada hacia Wazuh, respaldos, mantenimiento y controles de red/autenticación en cambios separados. | Evidencia externa de continuidad y plan de reversión probado. |

### Prerrequisitos institucionales

Antes de la primera ejecución, registrar: identidad y responsables de cuentas administrativas, ruta y propietario del repositorio de Ansible, archivos de credenciales y lectores autorizados, redes y puertos de gestión, destinos SSH de nodos, endpoint del manager Wazuh, origen de paquetes, política de retención y método de recuperación fuera de banda. El perfil **no inventa** usuarios, CIDR, puertos ni rutas sensibles.

El entorno virtual de Ansible y este repositorio deben proceder de una fuente aprobada y ser confiables antes de ejecutar su código con `sudo`. El administrador debe poder introducir su contraseña de `sudo`; no se asume `NOPASSWD` del laboratorio. Confirmar `hostname -s` igual a `ansible-control`, sistema Ubuntu 24.04 y respaldo recuperable. No invocar desde Wazuh ni mediante un equipo remoto.

### Aplicación base

Desde `ansible/` en el propio controlador, sustituir la ruta por el ejecutable absoluto y aprobado de Ansible Core 2.21.2. Antes de aplicar, comprobar su versión y la sintaxis con **ese mismo ejecutable**:

```sh
ANSIBLE_PLAYBOOK_BIN=/ruta/venv-institucional/bin/ansible-playbook
sudo "$ANSIBLE_PLAYBOOK_BIN" --version
sudo "$ANSIBLE_PLAYBOOK_BIN" --syntax-check \
  -i inventories/ansible_control/hosts.yml \
  playbooks/hardening/ansible_control_ubuntu_2404.yml
```

Luego ejecutar la etapa base:

```sh
ANSIBLE_PLAYBOOK_BIN=/ruta/venv-institucional/bin/ansible-playbook \
  bash ./scripts/run_ansible_control_hardening.sh
```

El lanzador verifica **ese mismo binario bajo `sudo`**, exige que `/var/log` sea confiable y que los objetos de log preexistentes sean reales y tengan `root:root 0700` (directorio) y `root:root 0600` (archivo). Rechaza enlaces simbólicos, archivos especiales y permisos inesperados **sin corregirlos a ciegas**; solo crea los objetos cuando no existen. Activa `ANSIBLE_LOG_PATH` y usa el inventario exclusivo de `localhost`. El rol vuelve a comprobar el log antes de modificar la configuración. El playbook comprueba identidad local, conexión y sistema operativo antes del rol. Son protecciones operativas, no una frontera frente a quien pueda modificar el repositorio o la política.

### Aplicación crítica de permisos

Copiar `inventories/ansible_control/policy.example.yml` **fuera del repositorio**, completarlo con valores aprobados y protegerlo como `root:root 0600` (también se acepta `0400`). `controller_policy_approved: true` documenta la aprobación, pero no reemplaza una revisión humana. La ruta del repositorio debe ser **exactamente el checkout actual de Ansible** derivado de la ubicación del rol, en forma canónica y bajo `/home`, `/opt` o `/srv`; `/`, `/./`, `//`, rutas del sistema y rutas con enlaces simbólicos se rechazan. Si el checkout institucional está en otra ubicación, hay que revisar el diseño antes de usar `--critical`, no ampliar el destino por conveniencia. Cada credencial declarada debe existir como archivo regular sin enlace simbólico. El rol valida **todas** las entradas antes de cambiar la configuración del host; el lanzador sí prepara su archivo de registro antes de esa validación.

```sh
ANSIBLE_PLAYBOOK_BIN=/ruta/venv-institucional/bin/ansible-playbook \
  bash ./scripts/run_ansible_control_hardening.sh --critical /ruta/privada/policy.yml
```

| Variable del archivo privado | Decisión necesaria |
| --- | --- |
| `controller_repository_path`, `controller_repository_owner`, `controller_repository_group`, `controller_repository_mode` | Ruta canónica del checkout actual y acceso aprobado. Modo `0700` o `0750`; comprobar si el gateway de Wazuh necesita atravesar el directorio. El rol verifica propietario/grupo actual y **solo cambia el modo de ese directorio, sin recursión**. |
| `controller_private_paths` | Lista no vacía de archivos existentes con `path`, `owner`, `group`, `mode` (`0600` o `0640`). **Solo auditoría:** el rol verifica tipo, propietario, grupo y modo; **no cambia credenciales ni otros archivos**. Si no cumplen, un administrador debe remediarlos por un procedimiento separado y volver a comprobar. |

La etapa crítica vuelve a ejecutar los controles base, diseñados para ser idempotentes. Si falta una decisión, falla cerrada antes de las tareas del rol, aunque el lanzador puede haber creado o ajustado `ansible.log`. No colocar secretos ni valores institucionales reales en el archivo de ejemplo ni en Git.

## Controles aplicados y límites CIS

| Familia de control | Aplicado por este perfil | Pendiente / no afirmado |
| --- | --- | --- |
| Actualizaciones | Instala `unattended-upgrades`, habilita comprobación/instalación periódica con orígenes configurados por Ubuntu. | Validar orígenes, ventanas, reinicios y resultados institucionalmente; no se impone una política de parches completa. |
| Registro y auditoría | Journal persistente con máximo de 1 GiB; `auditd` activo; registro Ansible restringido y rotado semanalmente (12 copias). | No añade reglas de auditoría específicas ni configura el envío Wazuh. El límite de tamaño y la rotación requieren aprobación de retención. |
| Acceso y archivos | `umask 027` en nuevos shells interactivos que carguen `/etc/profile.d/`; etapa crítica para el modo del directorio del checkout actual y auditoría de archivos privados declarados. | No afecta sesiones previas ni necesariamente shells interactivos sin inicio de sesión; no recorre el checkout ni modifica credenciales. |
| SSH, PAM, sudo, firewall | **Sin cambios**. | No se atribuye cumplimiento CIS de estas familias. Requieren política, pruebas de conectividad y reversión independientes. |

La tabla describe **cobertura funcional**, no un mapeo certificado a identificadores o nivel de un benchmark CIS. El rol CIS de Ubuntu para nodos no es seguro por defecto para el controlador. El Ansible del sistema puede diferir de Core 2.21.2; usar siempre el ejecutable seleccionado y verificado.

### Puertas para futuros controles de acceso y red

- **SSH:** confirmar usuarios, llaves, puerto, origen administrativo y método de rescate; mantener una sesión abierta y probar otra antes de cambiar autenticación o recargar `sshd`.
- **Firewall:** documentar CIDR/puertos de entrada administrativa y tráfico saliente a nodos, Wazuh, DNS, repositorios y tiempo; preparar reversión automática o fuera de banda antes de activar reglas.
- **PAM y sudo:** identificar cuentas de servicio, método de recuperación, políticas MFA/contraseña y comandos autorizados; validar `sudo -v` y una cuenta de respaldo antes de cualquier cambio.

Ninguno de esos controles se activa con `--critical`: faltan los datos institucionales y sería peligroso asumirlos. Implementarlos, si se aprueban, como unidades separadas con validación y plan de reversión propios.

## Verificación de continuidad y registros

Después de cada etapa, comprobar **desde fuera del controlador**: una nueva sesión administrativa, elevación con contraseña, conexión SSH a un nodo autorizado, comunicación del agente con el manager Wazuh y funcionamiento del gateway sin haber añadido este playbook a su allowlist. Confirmar también `auditd`, journal persistente, permisos de `ansible.log` y ausencia de secretos en eventos remitidos a Wazuh. El archivo completo de Ansible puede contener datos sensibles; usar `no_log` en tareas con secretos y enviar a Wazuh únicamente eventos saneados, con retención aprobada. Esta integración de recolección es externa al perfil.

Para mantenimiento, revisar periódicamente actualizaciones fallidas, capacidad/retención de journal y logs, estado de `auditd`, caducidad de credenciales y continuidad de acceso. Repetir la ejecución manual tras cambios aprobados y comparar resultados; la idempotencia debe confirmarse en un controlador de prueba antes de producción. `--check` es una simulación incompleta y no sustituye pruebas de acceso y telemetría.

## Reversión y criterio de aceptación

**Código:** retirar únicamente el inventario, playbook, rol, lanzador, pruebas y esta guía no revierte el estado del equipo. **Estado del controlador:** revisar la retirada de archivos gestionados en `/etc/apt/apt.conf.d/90ansible-control-auto-upgrades`, `/etc/systemd/journald.conf.d/90-ansible-control.conf`, `/etc/logrotate.d/ansible-control` y `/etc/profile.d/90-ansible-control-umask.sh`; evaluar por separado paquetes, `auditd` habilitado, modo previo del directorio del checkout y configuración previa de journald. Las credenciales auditadas no fueron modificadas por este perfil. Preservar registros conforme a retención legal; no borrar auditoría automáticamente. Mantener respaldo y acceso de recuperación hasta demostrar continuidad tras la reversión.

Aceptar la fase solo con: versión Core 2.21.2 comprobada, ejecución local correcta, segunda ejecución sin cambios inesperados, acceso administrativo nuevo y de rescate, tráfico a nodos y Wazuh intacto, permisos y registros verificados, y evidencia registrada por el responsable. **Este repositorio aún no tiene ejecución ni syntax-check de Ansible en el controlador real**; las pruebas locales son estructurales.

Referencia local para conexión local y límites del modo de comprobación: `docs/ansible-documentation/docs/docsite/rst/inventory_guide/implicit_localhost.rst` y `docs/ansible-documentation/docs/docsite/rst/playbook_guide/playbooks_checkmode.rst`.
