# Preproducción y producción: Wazuh → ansible-control

Wazuh **envía la orden** al agente de `ansible-control`; solo ese servidor ejecuta los playbooks Ansible existentes sobre Debian 12 y Ubuntu 24.04. No se necesitan playbooks nuevos: el mismo playbook acepta un selector de alcance. Esta guía describe cómo instalar la integración de forma **reproducible** sin cambiar su modelo de seguridad. Los comandos de instalación se ejecutaron de extremo a extremo en el laboratorio (releases `lab_v2` a `lab_v4`, ver la evidencia al final); **aún no en un controlador de preproducción institucional**: la primera instalación real debe hacerse con `--dry-run` y registrarse.

## 1. Arquitectura y roles

| Pieza | Función | Quién la controla |
| --- | --- | --- |
| Repositorio del proyecto (Git) | Playbooks, roles y código del gateway. | Equipo del proyecto. |
| Repositorio **site** (Git privado de la institución) | Inventario, `group_vars`/`host_vars` y política (`policy/jobs.json`, `policy/profiles.json`). Plantilla: `integration/wazuh/site.example/`. | Institución; revisión como código. |
| Estación de administración | Construye el bundle (`build_release.py`). Tiene Git; **no** guarda secretos en el bundle. | Administrador de release. |
| `ansible-control` (sin Git) | Verifica, instala, sella y activa el bundle; ejecuta Ansible con el runtime aislado. Guarda la clave SSH privada. | Root del controlador. |
| Manager Wazuh | Reglas y comando; API para el operador. | Administrador de Wazuh. |
| Operador Wazuh | Pide `CHECK`/`APPLY` con `wazuh_order.py` o la API Console. Solo envía identificadores. | Operador (RBAC mínimo, sección 7). |
| Aprobador | Registra respaldo y acceso fuera de banda y emite la aprobación de un solo uso en el controlador. **Persona distinta del operador.** | Responsable del cambio. |

Wazuh nunca envía inventario, hosts, IP ni variables libres: solo `inventory_profile_id`, `playbook_id`, `targets`, `selection`, `change_id`, `request_id`, `release_id`, `mode`, `approvals` y las tres variables UFW que el gateway ya valida.

## 2. Variables sin Git en producción

El controlador de producción no tiene Git. La fuente de verdad sigue siendo Git, pero en la estación de administración:

```text
repo site (Git privado) ─┐
                         ├─> build_release.py ─> <ID>.tar.gz + .sha256 ─> scp ─> install_controller.py release ─> release sellada y activa
repo proyecto (Git)  ────┘
```

- Cada cambio de variables o del código es una **release nueva** con un `release_id` nuevo. Un identificador **nunca** se reutiliza ni se reactiva (el gateway lo impide), de modo que una aprobación antigua no puede volver a ser válida.
- El bundle contiene playbooks, roles, inventario, variables, política y colecciones. **No** contiene claves SSH privadas ni contraseñas de la API de Wazuh; `build_release.py` rechaza claves privadas, `ansible_password`/`ansible_become_password`, contenido cifrado con vault (el gateway no tiene contraseña de vault), enlaces simbólicos y valores literales de claves tipo `*password*`/`*token*`.
- La clave SSH vive solo en el controlador (`/var/lib/ansible-wazuh/ssh/id_rsa`, usuario `ansible-wazuh`, modo 0600). El inventario debe apuntar a esa ruta exacta.

## 3. Primera instalación

**Estación de administración**

```bash
# Colecciones fijadas (ansible/requirements.yml), sin tests ni docs en el bundle
ansible-galaxy collection install -r ansible/requirements.yml -p ./collections
python integration/wazuh/build_release.py --repo-root . --site ../site-institucion \
    --release-id prep_2026_11_a --out ./dist --collections ./collections
sha256sum -c dist/prep_2026_11_a.tar.gz.sha256
# Anotar el sha256 que imprime build_release.py (o el de la solicitud de cambio): se teclea en el controlador
# Copiar al controlador: el código del gateway y el bundle
scp -r integration/wazuh admin@ansible-control:wazuh-src
scp dist/prep_2026_11_a.tar.gz* admin@ansible-control:
```

Para el runtime aislado se necesita Ansible Core **2.21.2** como ruedas (wheelhouse) preparadas en una máquina con Python 3.12 y la misma arquitectura: `pip download --only-binary=:all: --python-version 3.12 --platform manylinux2014_x86_64 -d wheelhouse ansible-core==2.21.2` (verificar las etiquetas de plataforma admitidas por `cryptography`).

**Controlador** (Ubuntu 24.04, agente Wazuh 4.12 instalado y enrolado; ejecutar como root)

```bash
cd ~/wazuh-src
python3 -I install_controller.py bootstrap --dry-run --generate-ssh-key --wheelhouse /root/wheelhouse
python3 -I install_controller.py bootstrap           --generate-ssh-key --wheelhouse /root/wheelhouse
# o instalar una clave existente: --ssh-key /ruta/clave   (nunca se imprime la clave privada)
# opcional: --known-hosts known_hosts_publicos
```

`bootstrap` crea el usuario `ansible-wazuh`, los directorios y el `deployment.lock`, copia el gateway a `/opt/ansible-hardening/src/integration/wazuh`, instala `ansible-job` (root:wazuh 0750), añade el `localfile` a `ossec.conf` (idempotente, con copia `.bak-ansible-job`) y reinicia el agente. **Imprime la clave pública**: autorizarla para la cuenta de automatización en cada nodo gestionado y registrar sus claves de host en `/var/lib/ansible-wazuh/ssh/known_hosts` (por ejemplo `ssh-keyscan -t ed25519 host >> known_hosts_publicos` verificando la huella por un canal independiente). Es idempotente; si el `ansible-job` instalado es distinto, exige `--force-update-gateway`.

```bash
python3 -I /opt/ansible-hardening/src/integration/wazuh/install_controller.py release \
    --bundle ~/prep_2026_11_a.tar.gz --expect-sha256 <SHA256_DEL_BUILD> \
    --expect-release-id prep_2026_11_a --dry-run
python3 -I /opt/ansible-hardening/src/integration/wazuh/install_controller.py release \
    --bundle ~/prep_2026_11_a.tar.gz --expect-sha256 <SHA256_DEL_BUILD> \
    --expect-release-id prep_2026_11_a
```

`--expect-sha256` y `--expect-release-id` son obligatorios. El hash debe obtenerse **por un canal independiente de la copia del bundle** (salida del build en la estación de administración o solicitud de cambio): el archivo `.sha256` que viaja junto al bundle solo prueba integridad en tránsito, no autenticidad, por lo que `--sha256 <archivo>` es opcional y solo sirve de comprobación cruzada.

`release` verifica el SHA-256 esperado, valida cada entrada del bundle (rechaza rutas absolutas, `..`, enlaces y dispositivos), comprueba que el gateway instalado coincide con el del bundle, extrae el payload, genera `policy.json` (0600), prepara el runtime con `prepare_isolated_runtime.py` (ejecuta `--syntax-check` de todos los trabajos; puede tardar varios minutos), sella `release.json` y activa. Si falla antes de activar, elimina el directorio incompleto. Con `--no-activate` se detiene tras sellar.

**Manager Wazuh** (paquete o Docker)

```bash
python3 install_manager.py --dry-run
python3 install_manager.py                       # o: --docker-container wazuh.manager
```

Copia las reglas 100120–100130, añade el `<command>` a `ossec.conf`, prueba con `wazuh-analysisd -t` (revierte si falla) y reinicia el manager.

## 4. Agregar o cambiar un servidor

1. En el repo **site**: añadir el host a `inventory/hosts.yml` (grupos `ubuntu_2404` o `debian_12`, con `ansible_host` único), sus variables (`cis_*_sshd_allow_users` debe incluir la cuenta de Ansible), `policy/jobs.json` (`targets`) y `policy/profiles.json` (alias en el `inventory_profile`).
2. Autorizar la clave pública del controlador en el nodo y registrar su clave de host en `known_hosts`.
3. Construir un bundle con **`release_id` nuevo**, instalarlo y activarlo (sección 3). La release anterior queda inactiva; no se edita.
4. Ejecutar `CHECK` sobre el nuevo host antes de cualquier `APPLY`.

## 5. Flujo operativo: CHECK → revisión → respaldo → safety → aprobación → APPLY → verificación

La expansión de secciones se calcula contra la **release sellada**, nunca contra datos enviados por el operador.

| `selection` | Resultado |
| --- | --- |
| `{"kind":"full","names":[]}` | Todas las secciones 1–7 del rol de la plataforma. |
| `{"kind":"sections","names":["4"]}` | Controles remediables de la sección 4 (firewall). |
| `{"kind":"sections","names":["5.1"]}` | Subgrupo SSH 5.1 (22 controles); no toda la sección 5. |
| `{"kind":"tags","names":["cis_5_1_2"]}` | Un control CIS con tarea válida en la release instalada. |
| `{"kind":"roles","names":["cis_ubuntu_2404"]}` | Rol completo de la plataforma del playbook. |

1. **CHECK** (operador). Opciones globales antes del subcomando; la contraseña va en `WAZUH_API_PASSWORD` o se pide por teclado, nunca por argumento. Se imprime el `request_id`; guardarlo.

   ```bash
   export WAZUH_API_URL=https://manager.example.org:55000 WAZUH_API_USER=ansible_operator
   python integration/wazuh/wazuh_order.py --ca-file ca.pem check --agent-id 001 \
       --playbook ubuntu_hardening --release-id prep_2026_11_a --change-id CHG_001 \
       --inventory-profile ubuntu_staging --target ubuntu-app01 --selection sections --name 4
   ```

   `--print-only` muestra el cuerpo JSON para pegarlo en la API Console (`PUT /active-response?agents_list=001`). `--insecure` solo para laboratorio. Un HTTP 200 solo acusa recibo.
2. **Revisión** (root en el controlador): evento `completed` en `/var/log/ansible-wazuh-jobs.jsonl` y diff en `/var/lib/ansible-wazuh/state/<request_id>.<host>.v2.check.log`. Revisar selección efectiva y cambios.
3. **Respaldo/snapshot** por host y verificación del acceso fuera de banda (consola). Anotar identificadores (`SNAP_...`, `CONSOLA_...`).
4. **Safety** (root):

   ```bash
   python3 -I /opt/ansible-hardening/src/integration/wazuh/prepare_safety.py \
       --request-id <request_id> --host ubuntu-app01 --backup-ref SNAP_2026_11_15 --oob-ref CONSOLA_OK
   ```

   Escribe `<request_id>.<host>.v2.safety.json` (0600, solo creación exclusiva) con el `scope_digest` del CHECK. Caduca (`--ttl`, 2 h por defecto).
5. **Aprobación** (aprobador, root; un solo uso, 900 s por defecto):

   ```bash
   /var/ossec/active-response/bin/ansible-job --managed-v2-approve <request_id> --target ubuntu-app01 \
       --issuer aprobador_01 --reason "Cambio CHG_001 revisado" \
       --backup-ref SNAP_2026_11_15 --oob-ref CONSOLA_OK --change-ref CHG_001
   ```

   Imprime el UUID de aprobación del host. La API Console de Wazuh **no** puede emitirla.
6. **APPLY** (operador): mismo alcance exacto que el CHECK y el mismo `request_id`:

   ```bash
   python integration/wazuh/wazuh_order.py --ca-file ca.pem apply --agent-id 001 --request-id <request_id> \
       --playbook ubuntu_hardening --release-id prep_2026_11_a --change-id CHG_001 \
       --inventory-profile ubuntu_staging --target ubuntu-app01 --selection sections --name 4 \
       --approval ubuntu-app01=<uuid>
   ```

7. **Verificación**: eventos `accepted` → `completed`/`failed`, `recap` y `verification` por `request_id`; después una orden de solo lectura (`ubuntu_verify`/`debian_verify`) y comprobación manual de SSH, sudo, agente Wazuh y servicios de negocio. `completed` no acredita conformidad CIS. No repetir a ciegas si faltan eventos: un evento `ambiguous` exige reconciliación manual.

## 6. Rollback

- **Configuración/código de la release**: no se reactiva una release anterior. Reconstruir el bundle desde el commit anterior del repo **site** con un **`release_id` nuevo** e instalarlo (sección 3).
- **Cambios en los nodos**: el gateway no deshace cambios. Restaurar el respaldo/snapshot registrado en la safety o usar el acceso fuera de banda, y ejecutar `CHECK` de nuevo para confirmar el estado.

## 7. RBAC mínimo en Wazuh

El operador usa un usuario de API que solo puede ejecutar `active-response:command` sobre el agente de `ansible-control` y no tiene acciones `security:*`. Ese permiso **no** se limita a `ansible-job`: permite ejecutar cualquier script de active response presente en `active-response/bin` de ese agente, por lo que hay que eliminar o deshabilitar en el controlador los scripts y entradas `<command>` de active response que no sean necesarios (dejar solo `ansible-job`, `restart.sh` y `restart-wazuh`; procedimiento en el documento de RBAC) y repetirlo tras cada actualización del agente. Definición, comandos de creación y pruebas de validación: `integration/wazuh/config/rbac_ansible_operator.md`, ya confirmados en el laboratorio con Wazuh 4.12.0. En una consulta de listado sin permiso, Wazuh devuelve 200 con 0 resultados en lugar de 403; no expone datos. Un usuario por persona; no usar `wazuh`/`wazuh-wui`.

## 8. Resolución de problemas

| Síntoma | Qué revisar |
| --- | --- |
| HTTP 200 pero ningún evento | Agente conectado; `ansible-job` instalado con permisos `root:wazuh 0750`; `/var/ossec/logs/active-responses.log` y `ossec.log` del agente; active response no deshabilitado en el agente (verificar). |
| Evento `rejected` | El gateway no envía el motivo a Wazuh (por diseño). Ver el JSONL en el controlador y repetir la orden con `--print-only` para comprobar forma, `release_id` activo, perfil, alias y selección. |
| Eventos en el controlador pero sin alertas | `localfile` presente en `ossec.conf` del agente, reglas 100120–100130 cargadas en el manager (`wazuh-analysisd -t`). **Las alertas rotan a diario**: `alerts.json` solo contiene el día actual; buscar días anteriores en `/var/ossec/logs/alerts/AAAA/Mes/ossec-alerts-DD.json[.gz]` (por ejemplo `zgrep <request_id> /var/ossec/logs/alerts/2026/Nov/*`). |
| `release` rechaza el bundle | `sha256 mismatch` o `differs from --expect-sha256` (copia dañada o bundle distinto del construido), `release id differs` (`--expect-release-id` incorrecto), «release ... already exists/activated before» (usar un id nuevo), gateway distinto (ejecutar `bootstrap` con el mismo código), site-packages sin poblar (`--wheelhouse`). |
| `runtime staging rejected (phase: ...)` | La fase indica qué falló: `inventory_graph` (inventario con avisos, alias duplicado o fuera de grupo), `syntax_*` (colecciones ausentes en el bundle). Ver sección 3. |
| `deployment busy` / `target busy` | Otra orden o activación en curso; esperar. |
| `manual approval scope or lifetime mismatch` | Safety o aprobación caducada, o el alcance/`change_id` del APPLY difiere del CHECK. Repetir safety y aprobación. |
| Fallo SSH `Host key verification failed` | Añadir la clave de host a `/var/lib/ansible-wazuh/ssh/known_hosts`. |
| CIS 5.1.4 se niega a ejecutar | `cis_*_sshd_allow_users` vacío o sin la cuenta de Ansible en el repo **site**; requiere release nueva. |

## 9. Criterio de aceptación de preproducción

- [ ] Instalación reproducida con `bootstrap` y `release` en un controlador limpio; `--dry-run` previo archivado; Ansible Core **2.21.2** y conectividad comprobados sin modificar Vagrant.
- [ ] Repo **site** revisado: hosts, servicios y puertos **reales**; sin secretos (el build lo verifica); `known_hosts` con huellas verificadas.
- [ ] RBAC: el usuario del operador solo envía órdenes al agente de `ansible-control` (pruebas 403 de `rbac_ansible_operator.md`).
- [ ] `CHECK → safety → aprobación → APPLY → verificación` para secciones **1–7**, por separado, en **Debian 12 y Ubuntu 24.04**; también `full`, un control de firewall y uno de SSH.
- [ ] Tareas efectivamente ejecutadas confirmadas (no solo `--list-tasks`); SSH, sudo, agentes Wazuh y servicios de negocio comprobados tras cada aplicación.
- [ ] Idempotencia medida en una segunda ejecución; rollback por snapshot y por release nueva ensayados antes de autorizar producción.
- [ ] Un `APPLY` sin aprobación, con aprobación caducada y con alcance distinto es rechazado.
- [ ] Alertas localizadas por `request_id`, incluyendo búsqueda en alertas rotadas.

**Evidencia de laboratorio (Wazuh 4.12.0, Ansible Core 2.21.2, VirtualBox):**

| Prueba | Resultado |
| --- | --- |
| `bootstrap` + `release` (`lab_v2`, sitio `site.lab`) con el instalador | Release sellada y activa sin pasos manuales |
| CHECK sección 5.1 vía API en ubuntu24 / debian12 | `failed=0` (38 cambios previstos en cada nodo) |
| APPLY 5.1 con snapshot, safety y aprobación de un solo uso | `changed=20 failed=0` + verificación en ambos nodos; SSH, sudo y agente operativos; aprobación consumida |
| CHECK posterior en ubuntu24 (`lab_v2`, `wazuh_order.py`) | `changed=0` (idempotente) |
| APPLY con aprobación nunca emitida | `rejected` |
| Orden con release inactiva (`lab_v1`) | `rejected` |
| Destino fuera del perfil de inventario | `rejected` |
| `extra_vars` no autorizadas o campo `inventory` inyectado | `rejected` (forma inválida, sin identidad de la orden) |
| Reenvío de un APPLY con aprobación consumida | Sin nueva ejecución ni cambios |
| Usuario API `ansible_operator` (RBAC, `rbac_mode: white`) | Solo `active-response:command` sobre `agent:id:001`: orden al controlador aceptada; a otro agente → 403; `agents/restart`, configuración y alta de usuarios → 403; listados de usuarios y agentes vacíos |
| Scripts de Active Response no necesarios retirados del agente del controlador | `!firewall-drop` enviado por el operador sin efecto |
| `release` con `--expect-sha256` incorrecto | Rechazado antes de extraer |
| CHECK `full` vía Wazuh como `ansible_operator`, ubuntu24 (`lab_v7`) | `ok=2009 changed=137 failed=0` (≈38 min con 1 vCPU) |
| CHECK `full` vía Wazuh como `ansible_operator`, debian12 (`lab_v7`) | `ok=1845 changed=114 failed=0` (≈28 min con 1 vCPU) |

Correcciones derivadas de las pruebas `full`: el gateway limitaba el listado de tareas a 120 s y la salida a 1 MiB (ahora 600 s y 8 MiB; ejecución máxima 60 min), y nueve verificaciones posteriores a la remediación fallaban en modo `--check` (ahora se omiten solo en simulación; las ejecuciones reales y `verify/` las siguen comprobando). Con 1 vCPU cada orden `full` tarda 30–40 min; planificar las ventanas de cambio en consecuencia.

Las secciones 1–4 y 6–7 vía Wazuh, la selección `full`, el RBAC en el manager institucional y la ejecución en nodos de preproducción siguen pendientes de la matriz anterior. No se afirma cumplimiento CIS completo ni compatibilidad institucional hasta completarla.
