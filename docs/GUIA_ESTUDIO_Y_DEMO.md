# Guía de estudio y demostración en vivo

Hardening automatizado de servidores Linux con CIS Benchmark, Ansible y Wazuh 4.12 — DTIC USFX.

Este documento sirve para tres cosas: **entender el proyecto a fondo**, **ejecutar la demo en vivo paso a paso** y **preparar las respuestas** a las preguntas probables. Todo lo que aparece como resultado fue medido en el laboratorio; lo que no se probó está marcado como pendiente.

---

## Parte 1. El proyecto en un minuto

> En la DTIC el aseguramiento (hardening) de los servidores Linux se hacía a mano, sin proceso, sin repositorio y sin evidencia. El proyecto convierte el estándar internacional **CIS Benchmark** (311 controles en Ubuntu 24.04 y 310 en Debian 12) en código **Ansible** que revisa, corrige y verifica los servidores siempre igual. La ejecución se solicita y supervisa desde **Wazuh**, el SIEM que la DTIC ya usa, pero **ningún cambio se aplica sin una aprobación humana de un solo uso** emitida en el servidor de control. Todo queda registrado como alertas en Wazuh.

Tres ideas para repetir en cualquier respuesta:

1. **Wazuh pide, una persona aprueba, Ansible ejecuta.**
2. **Primero se revisa (CHECK), después se aplica (APPLY).** La revisión no cambia nada.
3. **Si algo no es seguro de cambiar, la herramienta se detiene** y deja la decisión a una persona.

---

## Parte 2. Conceptos que debés dominar

| Concepto | Qué es | Cómo se usa en el proyecto |
| --- | --- | --- |
| **Hardening** | Reducir la superficie de ataque de un sistema: quitar servicios innecesarios, endurecer accesos, activar auditoría. | Es el objetivo del proyecto, solo a nivel de sistema operativo. |
| **CIS Benchmark** | Guía del Center for Internet Security con controles concretos y verificables por sistema operativo. | Fuente de la línea base: Ubuntu 24.04 v1.0.0 y Debian 12 v1.1.0. |
| **Nivel 1 / Nivel 2** | L1: controles básicos de bajo impacto. L2: más estrictos, para entornos de mayor riesgo. | Ubuntu: 250 L1 + 61 L2. Debian: 248 L1 + 62 L2. |
| **Ansible** | Herramienta de automatización sin agente: se conecta por SSH y aplica configuraciones descritas en YAML. | Ejecuta auditoría, hardening y verificación. Versión fijada: **Ansible Core 2.21.2**. |
| **Playbook / rol / tarea** | Playbook: qué hacer y dónde. Rol: conjunto reutilizable de tareas. Tarea: una acción. | 3 playbooks por sistema (`audit`, `hardening`, `verify`) y 4 roles. |
| **Idempotencia** | Ejecutar dos veces da el mismo resultado: la segunda vez no cambia nada. | Se mide con la segunda ejecución: `changed=0`. |
| **Modo check (`--check --diff`)** | Simulación: Ansible muestra qué cambiaría sin cambiarlo. | Es el **CHECK** de Wazuh. Su resultado es lo que se aprueba. |
| **Wazuh** | SIEM/XDR de código abierto: **manager** (analiza), **indexer** (guarda), **dashboard** (muestra) y **agentes** (en cada servidor). | Versión 4.12.0, igual a la institucional. En el laboratorio corre en Docker. |
| **Active Response** | Mecanismo de Wazuh para ejecutar un script en un agente. | Lleva la orden al agente de `ansible-control`; el script es el gateway `ansible-job`. |
| **Gateway** | Programa Python propio (`managed_job.py`) instalado como `ansible-job`. | Valida la orden, exige la aprobación, ejecuta Ansible y escribe los eventos. |
| **Release sellada** | Paquete con playbooks, roles, inventario y variables, con un resumen criptográfico (hash). | Si alguien modifica un archivo, el gateway lo rechaza. Cada release se activa una sola vez. |
| **RBAC** | Control de acceso por roles en la API de Wazuh. | El usuario `ansible_operator` solo puede enviar Active Response al agente 001. |

### Cómo se clasificó cada control (línea base)

| Tratamiento | Ubuntu | Debian | Significado |
| --- | ---: | ---: | --- |
| Automatizado | 164 | 167 | Se aplica sin decisión adicional. |
| Condicionado por riesgo | 99 | 96 | Puede afectar acceso o servicio: se habilita uno por uno por servidor (`cis_<plataforma>_<id>_remediate: true`). |
| Manual | 32 | 33 | Requiere decisión humana o política institucional. |
| No aplicable | 16 | 14 | No corresponde (por ejemplo, el motor de firewall que no se usa). |
| **Total** | **311** | **310** | |

**263 rutas de remediación por plataforma** = automatizados + condicionados. Son rutas disponibles, no cambios que se aplican a ciegas.

---

## Parte 3. Arquitectura

### Laboratorio (DEV/TEST)

```text
 Laptop (Windows) ─ VirtualBox + Vagrant + Docker
 ├─ Docker: Wazuh 4.12.0 (manager, indexer, dashboard)   https://localhost  ·  API :55000
 └─ Red host-only 192.168.56.0/24 (solo laboratorio)
     ├─ ansible-control  192.168.56.10  Ubuntu 24.04 · agente Wazuh 001 · gateway · Ansible 2.21.2
     ├─ debian12         192.168.56.11  agente Wazuh 002
     └─ ubuntu24         192.168.56.12  agente Wazuh 003
```

Cada VM tiene 1 vCPU y 1 GB de RAM.

### Producción (lo que se entrega a la DTIC)

- **`ansible-control` dedicado**: Ubuntu Server 24.04 LTS, 4 vCPU, 8 GB, 100 GB, sin servicios de negocio, separado del Wazuh institucional.
- **Sin Git en producción.** Las variables viven en un repositorio privado de la DTIC (copia de `integration/wazuh/site.example/`). En la estación del administrador se arma el paquete y se copia al servidor:

```text
repo site (DTIC) + repo proyecto ──> build_release.py ──> paquete .tar.gz + sha256
        ──> copia al servidor ──> install_controller.py release --expect-sha256 <hash> ──> release activa
```

- Cambiar una variable (por ejemplo `AllowUsers`) = editar el repo site → release nueva con `release_id` nuevo → instalar. Nunca se edita el servidor a mano.

### Flujo completo de una orden

```text
1. Operador ── PUT /active-response ──> API Wazuh (manager)
2. Manager ── Active Response ──> agente 001 (ansible-control)
3. Agente ──> /var/ossec/active-response/bin/ansible-job (gateway, root)
4. Gateway valida: formato canónico, release activa, perfil de inventario, destino, selección
   - CHECK: ejecuta ansible-playbook --check --diff y guarda la evidencia
   - APPLY: exige check previo idéntico + safety file + aprobación de un solo uso
5. Ansible (usuario sin privilegios ansible-wazuh) ── SSH ──> servidor destino
6. Gateway escribe eventos en /var/log/ansible-wazuh-jobs.jsonl
7. Agente envía el log al manager ── reglas 100120–100130 ──> alertas ──> indexer ──> Discover
```

### Reglas de Wazuh y su significado

| Regla | Nivel | Evento (`data.status`) | Qué significa |
| --- | ---: | --- | --- |
| 100122 | 5 | `accepted` | El gateway aceptó la orden. |
| 100126 | 5 | `started` | Ansible empezó a ejecutar. |
| 100129 | 3 | `progress` | Resumen de tareas ejecutadas. |
| 100127 | 5 | `recap` | Resultado de Ansible: `ok / changed / unreachable / failed`. |
| 100130 | 5 | `verification` | Estado de verificación tras un APPLY (pendiente no equivale a conformidad). |
| 100123 | 7 | `completed` | Terminó bien. **No acredita por sí solo cumplimiento CIS.** |
| 100124 | 10 | `failed` | Ansible terminó con error. |
| 100125 | 8 | `rejected` | El gateway rechazó la orden (no se ejecutó nada). |
| 100128 | 10 | ambiguo | Estado incierto; requiere reconciliación manual. |

---

## Parte 4. Modelo de seguridad

| Amenaza | Qué la frena |
| --- | --- |
| Alguien roba la cuenta de la API de Wazuh | Solo puede enviar identificadores; un APPLY necesita una aprobación emitida **como root dentro del controlador**. |
| Wazuh envía un inventario o variables maliciosas | El gateway solo acepta identificadores y 3 variables UFW validadas; inventario o variables libres → `rejected` (probado). |
| Reutilizar una aprobación antigua | La aprobación es de un solo uso: al usarse pasa a `.consumed` y vence sola (TTL). |
| Aplicar algo distinto a lo revisado | La aprobación está atada al `scope_digest` y al `task_digest` del CHECK; si cambian, se rechaza. |
| Alterar el código en el servidor | Release sellada con hash; release ya usada no se puede reactivar. |
| Paquete reemplazado en tránsito | `install_controller.py` exige el sha256 escrito por el operador (`--expect-sha256`), obtenido por otro canal. |
| Dejar un servidor sin acceso | `AllowUsers` falla cerrado si no incluye al usuario de Ansible; `sshd -t` valida antes de recargar; PAM se detiene ante modificaciones locales. |
| Abuso de permisos en Wazuh | Usuario `ansible_operator`: solo `active-response:command` sobre `agent:id:001`; lo demás, 403 o listas vacías. |
| Otros scripts de Active Response | Se retiraron del agente del controlador; solo quedan `ansible-job`, `restart.sh` y `restart-wazuh`. |
| Una sola persona hace todo | Operador (envía) y aprobador (aprueba) deben ser personas distintas. |

Además: una **revisión de seguridad independiente** encontró 2 escaladas locales (alta y media) y 5 hallazgos menores en el instalador. Todos se corrigieron y probaron.

---

## Parte 5. Cómo está construido el código

| Pieza | Ubicación | Función |
| --- | --- | --- |
| `cis_platform_preflight` | `ansible/roles/` | Valida SO, versión y arquitectura; en producción exige `change_id`, respaldo y OOB. |
| `cis_linux_common` | `ansible/roles/` | Biblioteca de mecanismos reutilizables (el **cómo**). |
| `cis_ubuntu_2404`, `cis_debian_12` | `ansible/roles/` | Adaptadores (el **qué**): variables, selectores y rutas por control. |
| Playbooks | `ansible/playbooks/{audit,hardening,verify}` | Auditoría sin cambios, aplicación con gates, verificación independiente. |
| Catálogo CIS | `ansible/cis/catalog/` | Matriz de disposición y registro de trazabilidad (sin copiar el texto licenciado). |
| Gateway | `integration/wazuh/managed_job.py` | Valida órdenes, aprobaciones y ejecuta Ansible. |
| Herramientas | `integration/wazuh/*.py` | `build_release`, `install_controller`, `install_manager`, `wazuh_order`, `prepare_safety`. |
| Pruebas | `ansible/tests`, `integration/wazuh/tests` | Unas 700 pruebas automáticas (`unittest`). |

Cada control tiene tres rutas: **auditoría** (`audit.yml`), **remediación** (`remediation.yml`) y **verificación** (`verification.yml`). Los gates evitan aplicaciones accidentales: la remediación está apagada por defecto y la habilita el gateway solo para órdenes aprobadas.

---

## Parte 6. Resultados medidos

| Prueba (vía Wazuh salvo indicación) | request_id | Resultado |
| --- | --- | --- |
| CHECK `full` ubuntu24 (`lab_v7`) | `1ac8b206-d2a6-4deb-9545-6964c09d3edc` | `ok=2009 changed=137 failed=0` (≈38 min) |
| CHECK `full` debian12 (`lab_v7`) | `7fc71f55-776b-4e1d-abe2-c9b2d5e36165` | `ok=1845 changed=114 failed=0` (≈28 min) |
| APPLY sección 5.1 ubuntu24 | `b8988c6a-baa0-4707-b568-930f6b2a2ae1` | `changed=20 failed=0`; acceso intacto |
| APPLY sección 5.1 debian12 | `8babeb8e-cd2c-45ab-98d7-25481ea695b4` | `changed=20 failed=0`; acceso intacto |
| CHECK posterior 5.1 (idempotencia) | `05fd07d3-…`, `03d0cbda-…` | `changed=0` en ambos |
| APPLY `full` ubuntu24 | `1ac8b206-…` | `ok=1347 changed=132 failed=1`: se detuvo a propósito en PAM (5.3.2.2) |
| Órdenes inválidas (sin aprobación, release inactiva, destino ajeno, variables/inventario inyectados) | `11111111-…` a `66666666-…` | Todas `rejected` |
| Usuario RBAC `ansible_operator` | — | Solo ordena al agente 001; resto 403 o vacío |
| Pruebas automáticas (Linux) | — | 299 de integración + unas 400 de Ansible, todas OK |

### Problemas reales encontrados y su solución (para contar como aprendizaje)

| Problema | Causa | Solución |
| --- | --- | --- |
| La orden `full` era rechazada sin motivo visible | El gateway daba 120 s para listar tareas; con 1 vCPU tarda 75–100 s por llamada | Límite a 600 s, salida a 8 MiB, ejecución a 60 min, con pruebas de regresión |
| La simulación `full` fallaba en `cron.allow` | En `--check` el archivo no se crea, y la tarea siguiente fijaba permisos a un archivo inexistente | Omitir solo en simulación cuando el archivo aún no existía |
| La simulación fallaba en PAM y AIDE | Verificaciones del estado *posterior* corrían en simulación, donde el cambio no ocurre | `when: not ansible_check_mode` en 9 verificaciones + prueba que lo exige |
| APPLY `full` detenido en PAM | `pam-auth-update` no sobrescribe archivos con modificaciones locales | Comportamiento correcto: decisión por servidor con `*_pam_auth_update_force` |
| La plantilla del sitio tenía variables que nadie usaba | Se copiaron variables heredadas | Plantilla reescrita solo con variables reales |

**Lección central:** el análisis estático no alcanza; los errores reales aparecieron al ejecutar `full` sobre sistemas reales. Por eso existe la preproducción.

### Pendiente (decirlo con honestidad)

- Ronda de PAM con `force` en Ubuntu y APPLY `full` en Debian vía Wazuh.
- Selecciones `tags` y `roles` vía Wazuh.
- Preproducción y producción en infraestructura de la DTIC (depende de que asignen el servidor).
- Mediciones antes/después con el módulo SCA de Wazuh.

---

## Parte 7. Demo en vivo (guion)

**Duración:** unos 20 minutos de demo con esperas. Se usa la sección **5.1 (SSH)** en `ubuntu24` porque tarda unos 4 minutos; una orden `full` tarda 30–40 minutos y no conviene en vivo.

### 7.0 Preparación (30 minutos antes)

1. Abrir **Docker Desktop** y esperar a que diga *Engine running*.
2. Encender Wazuh (PowerShell):

   ```powershell
   cd C:\Users\Victor\Desktop\wazuh\wazuh-docker\single-node
   docker compose up -d
   docker ps --format "table {{.Names}}\t{{.Status}}"
   ```

   Esperar unos 2–3 minutos hasta que los tres contenedores estén `Up`.
3. Encender el laboratorio sin reprovisionar:

   ```powershell
   cd C:\Users\Victor\Desktop\ansible_prod\lab\vagrant
   vagrant up --no-provision
   vagrant status
   ```

   Deben aparecer `ansible-control`, `debian12` y `ubuntu24` en `running`.
4. Abrir `https://localhost` (aceptar el certificado de laboratorio) e ingresar con `admin` / `SecretPassword` (credenciales por defecto del laboratorio Docker).
5. Comprobar en **Agents** (menú ☰ → Agents management → Summary) que los agentes 001, 002 y 003 estén **Active**.
6. Comprobar la release activa:

   ```powershell
   vagrant ssh ansible-control -c "sudo ls /var/lib/ansible-wazuh/activated-releases/"
   ```

   Usar la última (hoy `lab_v7`) en las órdenes.
7. **Plan B:** tener abiertas en otra pestaña de Discover las alertas de los request_id de la Parte 6, por si algo falla en vivo.

### 7.1 Generar la orden (cuerpo para Dev Tools)

La orden es un JSON canónico (claves ordenadas, sin espacios) dentro de un string, y es fácil equivocarse a mano. Lo genera el cliente del proyecto **sin enviarlo** (`--print-only`):

```powershell
cd C:\Users\Victor\Desktop\ansible_prod
python -I integration\wazuh\wazuh_order.py --print-only check --agent-id 001 `
  --playbook ubuntu_hardening --release-id lab_v7 --change-id CHG_DEMO_001 `
  --inventory-profile ubuntu_lab --target ubuntu24 --selection sections --name 5.1
```

Salida: una línea `request_id: <UUID>` y el cuerpo JSON. **Anotar el request_id**: se usa en todo lo que sigue.

### 7.2 Enviar el CHECK desde Wazuh (Dev Tools)

1. En el dashboard: menú ☰ → **Server management** → **Dev Tools** (la consola de la API de Wazuh). Si el menú tiene otro nombre, escribir «Dev Tools» en el buscador del menú y elegir la de **Server management**: la de *Indexer management* habla con OpenSearch, no con la API de Wazuh. Ensayarlo antes de la reunión.
2. Escribir y ejecutar (▶):

   ```text
   PUT /active-response?agents_list=001
   { pegar aquí el cuerpo JSON de 7.1 }
   ```

3. Respuesta esperada: `"message": "AR command was sent to all agents"` con `total_affected_items: 1`.
4. Explicar: **un 200 solo confirma la entrega, no la ejecución.** La evidencia está en las alertas.

> **Si te preguntan con qué cuenta se envió:** en este laboratorio el dashboard tiene `run_as: false`, así que Dev Tools usa el usuario de API del dashboard (`wazuh-wui`), no la cuenta personal. En producción el operador usa su usuario personal con el rol `ansible_operator` mediante `wazuh_order.py` (o se habilita `run_as` con el mapeo de roles, a verificar con la DTIC).

**Alternativa sin Dev Tools**, con el usuario de mínimo privilegio:

```powershell
$env:WAZUH_API_URL = "https://localhost:55000"
$env:WAZUH_API_USER = "ansible_operator"
python -I integration\wazuh\wazuh_order.py --insecure check --agent-id 001 `
  --playbook ubuntu_hardening --release-id lab_v7 --change-id CHG_DEMO_001 `
  --inventory-profile ubuntu_lab --target ubuntu24 --selection sections --name 5.1
```

Pide la contraseña sin mostrarla. `--insecure` solo porque el certificado del laboratorio es autofirmado.

### 7.3 Seguir el proceso en Discover con el request_id

1. Menú ☰ → **Explore** → **Discover**.
2. Index pattern: **`wazuh-alerts-*`**. Rango de tiempo: **Last 1 hour**.
3. Consulta (DQL):

   ```text
   data.request_id:"<request_id>"
   ```

4. Agregar columnas: `rule.id`, `rule.description`, `data.status`, `data.mode`, `data.recap`, `data.target_id`, `data.change_id`.
5. Ordenar por `timestamp`. Durante unos 4 minutos aparecen, en orden:
   `accepted` (100122) → `started` (100126) → `progress` (100129) → `recap` (100127) → `completed` (100123).
6. Mostrar `data.recap` del evento `recap`: por ejemplo `ok=130 changed=0 unreachable=0 failed=0`. **`changed=0` significa que el servidor ya cumple esos controles** (se aplicaron antes): es la prueba de idempotencia.

Consultas útiles:

```text
rule.id >= 100120 and rule.id <= 100130          (todos los trabajos)
data.status:"rejected"                           (órdenes rechazadas)
data.mode:"apply" and data.status:"completed"    (aplicaciones terminadas)
```

### 7.4 Mostrar la evidencia dentro del servidor de control (SSH)

```powershell
cd C:\Users\Victor\Desktop\ansible_prod\lab\vagrant
vagrant ssh ansible-control
```

Dentro de `ansible-control` (reemplazar `<RID>`):

```bash
RID=<request_id>

# 1. Los eventos que el gateway escribió (lo que Wazuh recogió)
sudo grep "$RID" /var/log/ansible-wazuh-jobs.jsonl | python3 -m json.tool --json-lines

# 2. La evidencia del CHECK: plan, alcance y hash de lo que se revisó
sudo ls -l /var/lib/ansible-wazuh/state/ | grep "$RID"
sudo python3 -m json.tool /var/lib/ansible-wazuh/state/$RID.ubuntu24.v2.check.json

# 3. El diff de Ansible (qué cambiaría)
sudo tail -n 40 /var/lib/ansible-wazuh/state/$RID.ubuntu24.v2.check.log

# 4. Permisos estrictos: todo es de root y privado
sudo ls -ld /etc/ansible-wazuh /var/lib/ansible-wazuh/{state,approvals} /var/ossec/active-response/bin/ansible-job

# 5. Release activa y sellada
sudo ls /opt/ansible-hardening/releases/
sudo ls /var/lib/ansible-wazuh/activated-releases/
```

Puntos para decir: el gateway corre como root, pero **Ansible corre como `ansible-wazuh`**, un usuario sin privilegios con su propia llave SSH; y nada de esto es modificable desde Wazuh.

### 7.5 Aprobación y APPLY (la parte clave)

**Paso A — respaldo** (en otra terminal PowerShell del anfitrión):

```powershell
cd C:\Users\Victor\Desktop\ansible_prod\lab\vagrant
vagrant snapshot save ubuntu24 demo-CHG_DEMO_001
```

**Paso B — archivo de seguridad y aprobación** (en `ansible-control`, como root):

```bash
sudo python3 -I /opt/ansible-hardening/src/integration/wazuh/prepare_safety.py \
  --request-id "$RID" --host ubuntu24 \
  --backup-ref vbox-snap-demo-CHG_DEMO_001 --oob-ref virtualbox-console-ubuntu24

sudo /var/ossec/active-response/bin/ansible-job --managed-v2-approve "$RID" \
  --target ubuntu24 --issuer victor --reason "Demo APPLY CIS 5.1 tras revisar el CHECK" \
  --backup-ref vbox-snap-demo-CHG_DEMO_001 --oob-ref virtualbox-console-ubuntu24 \
  --change-ref CHG_DEMO_001 --ttl 1800
```

La última línea imprime el **approval_id** (UUID). Anotarlo.

**Paso C — generar el cuerpo del APPLY** (anfitrión, mismo request_id):

```powershell
python -I integration\wazuh\wazuh_order.py --print-only apply --agent-id 001 `
  --playbook ubuntu_hardening --release-id lab_v7 --change-id CHG_DEMO_001 `
  --inventory-profile ubuntu_lab --target ubuntu24 --selection sections --name 5.1 `
  --request-id <RID> --approval ubuntu24=<approval_id>
```

**Paso D — enviarlo en Dev Tools** igual que en 7.2 y seguirlo en Discover con el mismo `data.request_id`. Ahora aparece también `verification` (100130) y `data.mode: apply`.

**Paso E — mostrar que la aprobación se consumió:**

```bash
sudo ls /var/lib/ansible-wazuh/approvals/ | grep <approval_id>     # termina en .consumed
```

### 7.6 Verificar el servidor destino en vivo

Desde `ansible-control`, con la misma identidad que usa Ansible:

```bash
sudo -u ansible-wazuh ssh -i /var/lib/ansible-wazuh/ssh/id_rsa \
  -o UserKnownHostsFile=/var/lib/ansible-wazuh/ssh/known_hosts ansible@192.168.56.12 \
  'hostname; sudo -n true && echo SUDO_OK; \
   sudo sshd -T | grep -E "^(allowusers|permitrootlogin|maxauthtries|disableforwarding|banner) "; \
   systemctl is-active ssh wazuh-agent'
```

Esperado: banner legal, `SUDO_OK`, `permitrootlogin no`, `maxauthtries 4`, `allowusers vagrant` y `allowusers ansible`, y servicios `active`.

### 7.7 Prueba negativa (muy convincente)

Reenviar **el mismo cuerpo del APPLY** en Dev Tools. La aprobación ya se consumió: **no hay una nueva ejecución ni cambios**. Mostrar en el servidor que no se creó un `apply.log` nuevo.

Otra prueba rápida: generar un APPLY con un `request_id` nuevo y una aprobación inventada (`--approval ubuntu24=22222222-2222-4222-8222-222222222222`). En Discover aparece `data.status: rejected` (regla 100125).

### 7.8 Si algo falla durante la demo

| Síntoma | Qué hacer |
| --- | --- |
| Dev Tools responde 200 pero no aparecen alertas | Esperar 1 minuto (las alertas se indexan con retardo); revisar `sudo tail /var/log/ansible-wazuh-jobs.jsonl` en el controlador. |
| Aparece `rejected` | El gateway no dice el motivo a Wazuh, por diseño. Revisar `release_id` activo, `request_id` nuevo y el destino. |
| No encuentra alertas de ayer | Las alertas rotan a diario: ampliar el rango de tiempo en Discover. |
| Agentes desconectados | `vagrant status`; si una VM está apagada: `vagrant up <nombre> --no-provision`. |
| El dashboard no carga | `docker ps`; esperar a que el indexer termine de iniciar (2–3 minutos). |
| Sin tiempo | Mostrar las alertas guardadas de la Parte 6 (Plan B). |

### 7.9 Al terminar

```powershell
vagrant snapshot restore ubuntu24 demo-CHG_DEMO_001   # opcional: volver al estado previo
vagrant halt
cd C:\Users\Victor\Desktop\wazuh\wazuh-docker\single-node; docker compose stop
```

---

## Parte 8. Preguntas probables y respuestas

### Sobre el problema y el alcance

**¿Por qué CIS y no otro estándar?**
Porque es el estándar de configuración segura más usado para sistemas operativos, tiene controles concretos y verificables por versión, y está alineado con marcos como ISO 27001 y NIST. Además, Wazuh trae evaluación de configuración (SCA) basada en CIS, lo que permite medir con la misma referencia.

**¿Se aplican los 311 controles?**
No a ciegas. 164 automatizados se aplican directamente; 99 condicionados por riesgo se habilitan uno por uno según la función del servidor; 32 son manuales y 16 no aplican. Un servidor web y uno de base de datos no se endurecen igual.

**¿Qué pasa con la red, los firewalls perimetrales o los switches?**
Están fuera del alcance: el proyecto endurece el sistema operativo de los servidores Linux. El firewall local del servidor (UFW o nftables) sí está incluido (sección 4 de CIS).

**¿Por qué solo Ubuntu 24.04 y Debian 12?**
Son los sistemas usados en la DTIC. La arquitectura separa el "qué" (adaptador por sistema) del "cómo" (mecanismos comunes), así que agregar otra versión es crear otro adaptador.

### Sobre la seguridad de la propia herramienta

**Si alguien hackea Wazuh, ¿puede tomar control de todos los servidores?**
No. Desde Wazuh solo se envían identificadores. Para aplicar cambios hace falta una aprobación de un solo uso emitida como root dentro del servidor de control, ligada exactamente a lo que se revisó. Lo probamos: órdenes sin aprobación, con variables o inventario inyectados, con otra versión o a otro servidor fueron rechazadas.

**¿Por qué no ejecutar Ansible directamente desde el servidor Wazuh?**
Porque el SIEM es el sistema más expuesto: recibe datos de toda la red. Si además tuviera las llaves SSH de todos los servidores, comprometerlo sería comprometer todo. Por eso Wazuh solo pide y supervisa.

**¿Dónde está la llave SSH y quién la ve?**
Solo en el servidor de control, en `/var/lib/ansible-wazuh/ssh/id_rsa`, con permisos 600 para el usuario de servicio. Nunca viaja en el paquete; el constructor rechaza cualquier llave privada o contraseña.

**¿Qué impide que el operador se apruebe a sí mismo?**
El procedimiento separa los roles: el operador tiene acceso a la API de Wazuh y el aprobador tiene root en el controlador. Son credenciales distintas, y el runbook exige personas distintas.

**¿Se auditó el código?**
Sí. Hubo una revisión de seguridad independiente del instalador y las herramientas: encontró 2 escaladas locales y 5 puntos menores, y todos se corrigieron con pruebas. Además hay unas 700 pruebas automáticas.

### Sobre el riesgo operativo

**¿Y si el hardening deja un servidor sin acceso?**
Hay varias barreras. El CHECK muestra antes qué cambiará. `AllowUsers` falla cerrado si no incluye al usuario de Ansible. Los cambios de SSH se validan con `sshd -t` antes de recargar. Antes de aplicar se exige respaldo o snapshot y acceso de emergencia por consola.

**¿Qué pasó en la prueba completa de Ubuntu que falló?**
No falló el servidor: la herramienta se detuvo a propósito. `pam-auth-update` detectó configuraciones de PAM modificadas a mano y no las sobrescribió. Aplicó 1347 tareas y el servidor quedó con acceso, sudo, monitoreo y firewall funcionando. Continuar requiere que el responsable autorice regenerar PAM para ese servidor.

**¿Se puede deshacer un cambio?**
El gateway no "deshace" automáticamente, porque deshacer seguridad también es riesgoso. El rollback es por el respaldo o snapshot registrado en la aprobación, o por una release nueva con la configuración anterior. El runbook tiene la sección de rollback.

**¿Cuánto tarda?**
En el laboratorio (1 vCPU por VM) una revisión completa tarda 30–40 minutos por servidor y una sección, unos 4 minutos. En el servidor de producción (4 vCPU) debería bajar, aunque parte del proceso usa un solo núcleo. Por eso las ventanas de cambio se planifican.

**¿Cuántos servidores puede manejar?**
Fue diseñado para hasta 8 servidores clientes por controlador. La concurrencia real se valida en preproducción: no se probó con 8 servidores todavía.

### Sobre la operación diaria

**¿Cómo se agrega un servidor nuevo?**
Se agrega al inventario del repositorio del sitio, se autoriza la llave pública del controlador en ese servidor, se arma una release nueva y se instala. Luego se hace un CHECK antes de cualquier APPLY.

**¿Necesitan saber Ansible los operadores?**
No para operar: envían una orden y aprueban. Sí para mantener el código. Para eso están el runbook, la guía de uso, las pruebas y la documentación en el repositorio.

**¿Qué pasa cuando sale una nueva versión de CIS o de Wazuh?**
CIS: se actualiza la matriz y los adaptadores, se prueba en laboratorio y se publica como release nueva. Wazuh: se revisa que el agente del controlador siga sin los scripts de Active Response retirados (la actualización los restaura) y que el usuario RBAC conserve solo su política.

**¿Cómo se demuestra cumplimiento en una auditoría?**
Con tres evidencias: las alertas en Wazuh por `request_id` (quién pidió, qué se aplicó, resultado), el playbook `verify` que comprueba cada control de forma independiente y el módulo SCA de Wazuh, que mide el puntaje antes y después. La medición con SCA está pendiente para producción.

**¿Por qué `completed` no significa "cumple CIS"?**
Porque indica que Ansible terminó sin errores en lo que se seleccionó, no que todos los controles del estándar estén cumplidos. El cumplimiento lo muestran `verify` y SCA. La regla 100123 lo dice en su descripción.

### Sobre el trabajo realizado

**¿Qué fue lo más difícil?**
No fueron los controles individuales, sino que cientos de rutas compartan una base idempotente y segura. Varios errores solo aparecieron ejecutando sobre sistemas reales: límites de tiempo del gateway, verificaciones que fallaban en simulación, PAM con cambios locales. Por eso la preproducción es indispensable.

**¿Qué se aprendió?**
Diseño idempotente en Ansible, pruebas de contrato, integración de un SIEM con automatización mediante Active Response, despliegues sellados y verificables, y modelado de amenazas de la propia herramienta.

**¿Qué falta para producción?**
El servidor de control asignado por la DTIC, servidores de prueba representativos, la instalación con el runbook, la matriz de aceptación (CHECK y APPLY por sección en ambos sistemas, rollback ensayado, servicios de negocio verificados) y las mediciones con SCA.

---

## Parte 9. Glosario rápido

- **APPLY**: aplicación real de los cambios; requiere CHECK previo idéntico y aprobación.
- **CHECK**: simulación (`--check --diff`); no cambia nada y genera la evidencia que se aprueba.
- **change_id**: identificador del cambio institucional (ticket); viaja en la orden y en la aprobación.
- **request_id**: UUID de la orden; correlaciona CHECK, APPLY, eventos y alertas.
- **release_id**: nombre de la versión sellada activa (por ejemplo `lab_v7`); se usa una sola vez.
- **safety file**: archivo root-local con referencia al respaldo y al acceso de emergencia; obligatorio para aprobar.
- **scope_digest / task_digest**: hashes del alcance y de las tareas revisadas; la aprobación queda atada a ellos.
- **OOB (out-of-band)**: acceso de emergencia por consola, independiente de SSH.
- **SCA**: Security Configuration Assessment de Wazuh; mide el cumplimiento con políticas CIS.

Documentos relacionados: `docs/ENTREGA_DTIC.md` (traspaso), `docs/PREPRODUCCION_WAZUH.md` (runbook) e `integration/wazuh/config/rbac_ansible_operator.md` (usuario de mínimo privilegio).
