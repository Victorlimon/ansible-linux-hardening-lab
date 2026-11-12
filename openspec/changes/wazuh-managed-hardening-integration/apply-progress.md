# Progreso de aplicación: integración administrada de hardening Wazuh → Ansible

## Estado

`in_progress`: U1 terminó y validó las tareas 1.1 y 2.1; el baseline 1.5 también quedó validado. Las demás 16 tareas permanecen pendientes.

## Unidad U1

- [x] 1.1 Crear `integration/wazuh/tests/test_managed_profiles.py`.
- [x] 2.1 Implementar `integration/wazuh/managed_profiles.py` y `integration/wazuh/config/profiles.lab.json.example`.

### Cambios implementados y validados

- El resolvedor acepta únicamente IDs existentes de release, inventario, host y sección, los vincula al alias solicitado y calcula un SHA-256 sobre el perfil resuelto.
- El resolvedor rechaza puertos fuera de 1–65535, protocolos fuera de `tcp`/`udp`, CIDR no canónicos, SSH desde `/0`, sustitución de destino y disposiciones `manual`/`na`.
- Las pruebas cubren el perfil Ubuntu válido, límites de red, sustitución, IDs desconocidos, disposiciones no aplicables y cambios que deben alterar el digest.

## Work Unit Evidence

| Evidencia | Resultado |
|---|---|
| Comando enfocado requerido | Desde `lab/vagrant`: `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible/integration/wazuh && python3 -m unittest discover -s tests -p test_managed_profiles.py -v'` → salida 0; 10 pruebas nombradas `ok`, 0,094 s, `OK`. |
| Diagnóstico de comandos previo | El alias Windows `python3` falló antes de iniciar el intérprete; un intento previo con comillas dobles en Vagrant salió 1 sin salida. Un `vagrant ssh ... 'echo U1_READY'` salió 0 y la forma con comillas simples ejecutó la prueba correctamente. |
| Harness de runtime | N/A: U1 valida estructuras Python en memoria y un ejemplo JSON local. La VM sólo ejecutó la suite unitaria; no se iniciaron Ansible, systemd, Wazuh, Docker, Vagrant adicional ni nodos objetivo. |
| Límite de rollback | Revertir únicamente `integration/wazuh/managed_profiles.py`, `integration/wazuh/config/profiles.lab.json.example` e `integration/wazuh/tests/test_managed_profiles.py`; `lab_v9` permanece sin cambios. |

## Resolución de evidencia

La evidencia Linux requerida pasó en `ansible-control`. El fallo del alias Windows y el diagnóstico de quoting quedan registrados como contexto de la recuperación; no invalidan el resultado Linux aprobado.

## Baseline 1.5

- [x] 1.5 Validar el baseline completo de `integration/wazuh/` en Linux y escanear secretos con Gitleaks.

### Correcciones test-only

- `test_managed_profiles.py` carga `managed_profiles.py` por ruta explícita y registra el módulo antes de ejecutarlo, por lo que la suite no depende del directorio actual y `dataclass` puede resolver su módulo.
- `test_runtime_bootstrap.py` simula propiedad UID 0 únicamente dentro del fixture de umask 077, conservando modos, tipos y enlaces reales. La exigencia productiva de propiedad root en `prepare_isolated_runtime.py` permanece intacta.
- `SECURITY.md` se leyó sin modificaciones. No se ejecutó Ansible, hardening ni acceso institucional.

### Work Unit Evidence — baseline 1.5

| Evidencia | Resultado |
|---|---|
| Comando enfocado y suite Linux | Desde `lab/vagrant`: `vagrant ssh ansible-control -c "cd /home/vagrant/ansible && python3 -B -m unittest discover -s integration/wazuh/tests -p 'test_*.py'"` → salida 0; 146 pruebas, 11 omitidas, `OK`, 3,441 s. |
| Escaneo de secretos | Desde la raíz: `docker run --rm --network none -v "${PWD}:/repo:ro" ghcr.io/gitleaks/gitleaks:v8.30.1 dir /repo/integration/wazuh --config /repo/.gitleaks.toml --redact --no-banner` con salida suprimida → salida 0. El montaje fue de solo lectura, incluyó archivos no rastreados y el contenedor no tuvo red. |
| Harness de runtime | VM local `ansible-control` para la suite Linux y Docker local sólo para el escaneo. No se inició Ansible, systemd, Wazuh ni ningún nodo objetivo. |
| Límite de rollback | Revertir únicamente `integration/wazuh/tests/test_managed_profiles.py` e `integration/wazuh/tests/test_runtime_bootstrap.py`, y volver a abrir el checkbox 1.5; no revertir los archivos de U1 ni modificar `prepare_isolated_runtime.py`. |

## Resolución del baseline

Los dos errores iniciales eran defectos de portabilidad de los tests: una importación dependiente del directorio actual y un fixture no root para una función que exige correctamente propiedad root. Las correcciones quedaron limitadas a tests y la suite completa más Gitleaks pasaron sin exponer hallazgos ni secretos.

## Unidad U2 (provisional; no validada)

- [ ] 1.2, 1.3, 1.4, 2.2 y 2.3a–d: implementación provisional retirada de la contabilidad hasta validar ruta real de aprobación, entrypoints y evidencia terminal.

### Hallazgos del auditor independiente

- Las pruebas anteriores no demostraron la ruta real: `managed_job.py` seguía con emisión deshabilitada y apply rechazado; la unidad referenciaba entrypoints inexistentes; no había evidencia terminal inmutable ni pruebas sustantivas de las caídas requeridas.

### Evidencia anterior invalidada — U2

| Evidencia | Resultado |
|---|---|
| Estado | La suite de 10 pruebas pasó, pero no cubrió la ruta de autorización/worker ni su evidencia terminal. No es prueba de U2. |

## Próximo paso

Continuar con U2 antes de U3. `lab_v9` permanece sólo en `check/diff`; no se realizó E2E ni remediación y producción institucional sigue fuera de alcance.

## Subunidad U2: parseo y dispatch tipados (2026-10-14)

Estado: subunidad implementada y prueba enfocada aprobada; U2 continúa provisional y no validada. No se cierran 1.2 ni 2.3a, ni las demás tareas de U2. La estrategia sigue siendo `exception-ok`, con `size:exception` autorizado para una sola PR; no se creó commit ni PR.

- `managed_job.py` incorpora `RequestKind` y las variantes inmutables `LegacyCheckRequest`, `ManagedCheckRequest` y `ManagedApplyRequest`.
- Los contratos administrados aceptan exactamente ocho/nueve strings con UUID no nulos y canónicos e identificadores limitados; rechazan rutas, flags, variables, entorno, digests y metacaracteres antes del dispatch.
- El cuarto slot legado nunca concede autoridad: `dispatch_request` pasa siempre `none` al runner check-only, incluso cuando el slot contiene un UUID.
- Ambas variantes administradas permanecen deshabilitadas antes de política, reserva, consumo o proceso; falta implementar el productor de evidencia y el coordinador recuperable. Esta subunidad no demuestra apply ni el ciclo U2 completo.

### Work Unit Evidence — parseo y dispatch

| Evidencia | Resultado |
|---|---|
| Comando enfocado | Desde `lab/vagrant`: `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible/integration/wazuh && python3 -B -m unittest discover -s tests -p test_managed_job.py -v'`. |
| RED previo al código | Salida 1; 25 pruebas; 1 fallo y 6 errores; 2,888 s. Faltaban las variantes tipadas y los contratos administrados, y el dispatch legado propagaba el UUID. Las pruebas hostiles existentes y nuevas ya rechazaban entradas. |
| GREEN tras implementación | Mismo comando, una ejecución; salida 0; 25 pruebas; 0,857 s; `OK`. Incluye ocho pruebas nuevas de contratos, inmutabilidad, argumentos hostiles, canonicalidad y dispatch fail-closed. |
| Harness de runtime | VM local para la suite y subproceso Python sintético del entrypoint; fronteras de instalación y lanzamiento sustituidas. No se ejecutó Ansible, systemd, Wazuh ni acceso a nodos. El E2E de productor/coordinador continúa pendiente. |
| Límite de rollback | Retirar únicamente los tipos, validadores y dispatch añadidos en `integration/wazuh/managed_job.py` y el helper `managed_args` con sus ocho pruebas en `integration/wazuh/tests/test_managed_job.py`; conservar las pruebas preexistentes, U1 y el baseline. |

El intento nativo permanece bajo autoridad del orquestador; este ejecutor no adquirió ni liquidó tokens.

## Subunidad U2: puente directo `managed-v2` (2026-10-14)

Estado: implementación fuente parcial; ninguna tarea adicional se marca terminada. La release instalada en `ansible-control` sigue siendo `lab_v9` y **no** contiene este puente. No se ejecutó hardening real.

- `managed_job.py` admite una orden JSON canónica y acotada: playbook existente, inventario sellado, host/grupo autorizado, selección completa/rol/tag existente y variables UFW tipadas. Los contratos `managed-apply-v1` y legado permanecen sin elevación.
- El flujo nuevo genera check/diff y registro por host; la CLI root-local emite una aprobación independiente por host y digest de alcance; apply requiere todas las aprobaciones de un lote antes de iniciar, consume cada una una sola vez y usa `ansible-playbook` con argv fijo y `--limit` exacto. Reserva exclusiva, bloqueo de host compartido con el gateway legado y recibo terminal impiden relanzamiento tras caída o replay.
- JSONL publica aceptación, inicio, recapitulación numérica y terminal sin salida Ansible privada. Las reglas Wazuh incorporan inicio, recap y ambigüedad. Una fuente pública `any` para UFW se rechaza porque la política actual no ofrece una autorización explícita para ella.

### Work Unit Evidence — puente directo parcial

| Evidencia | Resultado |
|---|---|
| Prueba focal | `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible/integration/wazuh && python3 -B -m unittest discover -s tests -p test_managed_job.py -q'` → salida 0, 35 pruebas, `OK`. |
| Suite completa | `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible && python3 -B -m unittest discover -s integration/wazuh/tests -p "test_*.py" -q'` → salida 0, 177 pruebas, 12 omitidas, `OK`. |
| XML y herramienta | Parse XML de `ansible_job_rules.xml` en VM: salida 0. `ansible --version`: Core 2.16.3 del sistema; la release sellada existente usa Core 2.21.2. |
| Harness de runtime | La VM ejecutó tests con mocks del runner y un ciclo simulado check→aprobación→apply→recibo. No se instaló nueva release ni se envió una orden Wazuh real; por tanto la ruta API→agente→Ansible→nodo y la resistencia a caídas **siguen sin probarse**. |
| Límite de rollback | Retirar exclusivamente el contrato y flujo `managed-v2` de `integration/wazuh/managed_job.py`, las pruebas nuevas de `integration/wazuh/tests/test_managed_job.py` y las reglas 100126–100128/regex ampliada de `integration/wazuh/config/ansible_job_rules.xml`; conservar el legado check-only y U1. |

Pendientes para cerrar U2–U6: pruebas de rechazo/caída/concurrencia más profundas, empaquetar una release nueva e instalar el gateway sin modificar `lab_v9`, E2E Wazuh 4.14.8 con check y apply controlado por host, eventos/alertas verificadas, documentación operativa y validación independiente. Wazuh 4.12.0 institucional sigue no validado.

## Corrección acotada U2: hallazgos del verificador independiente (2026-10-14)

Estado: corrección fuente parcial; 3/19 tareas completas sin nuevos cierres. No se instaló release ni se ejecutó hardening.

- La aprobación exige referencias explícitas de respaldo, acceso fuera de banda y cambio; además comprueba un `*.v2.safety.json` root-owned, vigente, ligado a request/host/digest y revisado de nuevo antes de apply. Falta documentar el procedimiento humano de creación de esta evidencia.
- El selector requiere una enumeración `--list-tasks` del Ansible sellado para el host/tag exacto; una lista vacía, sólo preflight o cambio del digest de tareas desde check bloquea apply. Esto NO demuestra por sí solo las siete secciones ni conformidad.
- El recibo terminal incluye `approval_id` y se publica en JSONL antes de liberar el bloqueo. Un marcador durable permite recuperar el evento terminal si la escritura a Wazuh falla; replay con otra aprobación se rechaza.
- Se eliminó la unidad `ansible-wazuh@.service` no desplegada que invocaba flags inexistentes. El flujo v2 usa el gateway sin esa unidad; el bloqueo persistente deja un estado ambiguo ante caída antes del terminal. JSONL agrega conteo resumido de tareas y estado de verificación explícitamente pendiente/aprobado/fallido.

### Work Unit Evidence — corrección U2

| Evidencia | Resultado |
|---|---|
| RED | Focal VM antes del arreglo: 36 pruebas, salida 1, un fallo y un error (aprobación sin safety y función de selección efectiva ausente). Prueba de unidad obsoleta: salida 1, un fallo. Un RED adicional para safety root-local: 37 pruebas, salida 1, un fallo. |
| GREEN focal | `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible/integration/wazuh && python3 -B -m unittest discover -s tests -p test_managed_job.py -q'` → salida 0, 38 pruebas, `OK`. |
| Suite completa y XML | `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible && python3 -B -m unittest discover -s integration/wazuh/tests -p "test_*.py" -q'` → salida 0, 180 pruebas, 12 omitidas, `OK`. Parse XML de `ansible_job_rules.xml` → salida 0. |
| Harness de runtime | VM Linux ejecutó mocks del flujo; `--list-tasks` del Ansible del sistema 2.16.3 falló por un archivo `tasks/audit.yml` faltante y el binario sellado sin entorno fijo falló al crear `/nonexistent/.ansible/tmp`. Ninguno prueba el listado sellado real; E2E sigue pendiente. |
| Límite de rollback | Revertir sólo la corrección en `managed_job.py`, tests añadidos en `test_managed_job.py` y `test_managed_supervisor_systemd.py`, reglas 100129–100130 y retirar/restaurar el artefacto de unidad no desplegada; preservar el puente v2 previo y las tareas 1.1/1.5/2.1. |

El token nativo de esta corrección es administrado por el orquestador; este ejecutor no lo adquirió ni liquidó.

## Corrección acotada U2: limpieza del listado temporal de tareas (2026-10-14)

Estado: corrección fuente validada en la VM; siguen completas únicamente 3/19 tareas. No se desplegó el puente ni se ejecutó hardening.

- `_v2_selected_tasks` eliminaba el archivo temporal de variables, pero conservaba indefinidamente la salida privada de `--list-tasks` por host y solicitud. Ahora retira esa salida en un bloque `finally`, tanto después de obtener el digest como ante rechazo o fallo.
- El verificador independiente confirmó posteriormente que el `--list-tasks` sellado real finaliza con salida 0 para Ubuntu y Debian. Esa comprobación no equivale a E2E del gateway ni prueba las siete secciones.

| Evidencia | Resultado |
|---|---|
| RED | Suite focal en `ansible-control`: salida 1, 39 pruebas, dos fallos por archivos `*.selected-tasks.log` remanentes en éxito y rechazo. |
| GREEN focal | `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible/integration/wazuh && python3 -B -m unittest discover -s tests -p test_managed_job.py -q'` → salida 0, 39 pruebas, `OK`. |
| Suite completa | `vagrant ssh ansible-control -c 'cd /home/vagrant/ansible && python3 -B -m unittest discover -s integration/wazuh/tests -p "test_*.py" -q'` → salida 0, 181 pruebas, 12 omitidas, `OK`. |
| Límite de rollback | Revertir sólo el `finally` de `_v2_selected_tasks` en `managed_job.py` y las dos aserciones/prueba de limpieza en `test_managed_job.py`; conservar los controles de aprobación y el resto del puente v2. |

El token nativo sigue bajo autoridad del orquestador; este ejecutor no lo adquirió ni liquidó.

## Subunidad U2/U3: despliegue y recorrido real de comprobación (2026-10-15)

Estado: el gateway `managed-v2` está desplegado en `ansible-control` con la
release sellada `lab_v11`; una orden Wazuh real de **check** llegó hasta
Ansible y el nodo `ubuntu24`, y sus alertas aparecieron en el manager. Se
mantienen **3/19 tareas cerradas**: este recorrido parcial no acredita apply,
los dos playbooks completos, lote, variables ni compatibilidad 4.12.0. La
entrega sigue bajo `exception-ok` con `size:exception` autorizado, sin PR.

- El primer envío HTTP 200 con request ID
  `269841a9-d8b6-4a44-b984-4a17d1abaca0` produjo `rejected`: la
  candidata `lab_v10` no concedía recorrido al usuario `ansible-wazuh`.
- Después de corregir ese permiso, un import dinámico escribió
  `__pycache__/managed_profiles.cpython-312.pyc` dentro del payload sellado.
  El segundo envío (`9fe6c44f-663f-47fe-a6dd-61c05ff7f304`) fue
  `rejected` y generó alerta 100125. Ambos rechazos son **fallos**, no E2E.
- `managed_job.py` ahora desactiva la escritura de bytecode antes de cargar
  helpers sellados. `lab_v11` se preparó desde fuente limpia y no se editó
  `lab_v10` activa en sitio. Durante la recuperación se detuvo el agente, se
  respaldó la política dañada, se seleccionó transitoriamente la política
  válida de `lab_v9` y se activó `lab_v11`; luego se reinició el agente.
- El agente reconectó al manager por `192.168.56.1` (red host-only), tras
  cambiar la dirección LAN inaccesible; se actualizaron y validaron las
  reglas 100126–100130 en el manager Docker local.

### Work Unit Evidence — despliegue y E2E check

| Evidencia | Resultado |
|---|---|
| Prueba focal | En `ansible-control`, `python3 -B -m unittest discover -s tests -p test_managed_job.py -q` desde `integration/wazuh`: salida 0, 40 pruebas, `OK`. |
| Integridad sellada | `policy_and_hash(lab_v11)` válido; preflight real `--list-tasks` del tag `cis_2_4_1_3` sobre `ubuntu24` completó; SHA-256 de payload antes/después `8e7d11b897927d557eb6ce8126adfd0520ab4e9387730220bbc0b769340e9374`; cero `.pyc`. Tras el E2E, digest aún coincide con `release.json`. |
| Harness real | API Wazuh 4.14.8 `PUT /active-response` → HTTP 200, agente `001` afectado, request ID `17d213c4-e91e-4664-a3f5-709b1a5b98a7`; JSONL `accepted` → `started` → `progress` (28 tareas) → `recap` → `completed`; Ansible en `ubuntu24`: `ok=12 changed=1 unreachable=0 failed=0 skipped=16`; comprobación `--check --diff`, sin mutación. Registro check por host existente. Alertas manager correlacionadas 100126, 100129, 100127 y 100123. |
| Límite de rollback | Revocar nuevas órdenes `managed-v2` y conservar recibos; para volver al payload anterior preparar una **nueva** release sellada a partir de `lab_v9`, no reactivar ni editar IDs antiguos. El gateway anterior y `ossec.conf` tienen respaldos root-only en `/etc/ansible-wazuh/gateway-backups/`; reglas previas en `/var/ossec/etc/rules/ansible_job_rules.xml.before-lab-v10` del contenedor. Revertir sólo el cambio de bytecode en `managed_job.py` y su test si se retira esta unidad de código. |

No se ejecutó apply: no existe evidencia root-local auténtica de respaldo,
acceso fuera de banda y cambio para el host y alcance exactos. El siguiente
paso debe probar el rechazo seguro y después un ciclo aprobado sobre un
objetivo desechable con dichas precondiciones verificadas; no fabricar
referencias para hacer pasar una prueba.

## Subunidad U2/U3: preparación segura de Debian y comprobación Wazuh (2026-10-15)

Estado: **parcial**, sin aprobación ni aplicación. Permanecen **3/19 tareas
cerradas**. El alcance autorizado fue únicamente la VM desechable `debian12`;
`ubuntu24` continuó en `livesnapshotting` y no se tocó. Estrategia de entrega:
`exception-ok`, con `size:exception` previamente autorizado.

- `vagrant halt debian12` terminó correctamente y VirtualBox informó
  `VMState=poweroff`. Se creó la instantánea **offline**
  `wazuh-debian12-preapply-20261015`, UUID
  `0a787e37-b3bd-4590-b7ae-acaea838e27c`. Se ejecutó y completó una
  restauración real con `VBoxManage snapshot ... restore <UUID>`, independiente
  de SSH; después `vagrant up debian12` y la comprobación de salud devolvieron
  `Linux`, `debian12` y UID 1000. La instantánea continúa registrada con ese
  UUID y la VM volvió a `running`.
- Para disponer de un cambio observable, sólo en Debian se pasó
  `/etc/cron.hourly` de `root:root 0755` a `root:root 0775`. La comprobación
  predijo `0775 → 0700`; después del check el nodo seguía en `0775`.
- Orden real `PUT /active-response?agents_list=001` al manager Docker
  Wazuh 4.14.8: `managed-v2`, `mode=check`, solicitud
  `2b5c1214-62bc-4fa2-95e7-7a839dd60141`, cambio
  `lab_debian_cron_20261015`, `debian_hardening`, perfil `debian_lab`, host
  `debian12`, selección `tags=[cis_2_4_1_3]`, `extra_vars={}`. La API devolvió
  HTTP 200 y agente `001` afectado. JSONL registró
  `accepted → started → progress(29) → recap → completed`; recapitulación
  `ok=13 changed=1 unreachable=0 failed=0`. Se observaron alertas de la
  integración 100122/100123/100126/100127/100129.
- El check root-local `*.v2.check.json` es `root:wazuh 0600`, con digest de
  alcance `a5978007e8fed7dc4466641b81fb6d6176a57a5fa1b4ec15f6ec56d2ca3971a7`
  y digest de diff
  `7dd937bf6b3b6a8384a3d10c521ddb95ee7c2e2ac684b69dffe8fbab2a0b65b5`.
  Se creó `*.v2.safety.json` `root:root 0600`, ligado al mismo host,
  solicitud, cambio y alcance, con referencias auténticas
  `vbox_snapshot_0a787e37_b3bd_4590_b7ae_acaea838e27c` y
  `vbox_restore_0a787e37_b3bd_4590_b7ae_acaea838e27c`;
  vence el 2026-10-15 a las 23:07:13 UTC.

### Work Unit Evidence — preparación Debian

| Evidencia | Resultado |
|---|---|
| Comprobación enfocada | Wazuh API → agente 001 → gateway → Ansible → Debian → JSONL/alertas, solicitud anterior: terminal `completed`, recap `ok=13 changed=1 unreachable=0 failed=0`; en el nodo permaneció modo `0775`, por tratarse de `--check --diff`. |
| Harness de runtime | Restauración **real** de snapshot offline por VirtualBox, arranque y ping Ansible; `VBoxManage snapshot ... list` conservó UUID. No se utilizó SSH como sustituto del mecanismo de recuperación del hipervisor. |
| Límite de rollback | Antes de apply, retirar únicamente `*.v2.safety.json` y devolver `/etc/cron.hourly` a `0755`, o detener Debian, restaurar la instantánea citada y reiniciar. Conservar check, JSONL y alertas como evidencia. Ubuntu y producción quedan fuera. |

La especificación exige una aprobación humana separada para host y alcance
exactos. La autorización general de continuar el laboratorio no se atribuyó
falsamente a un aprobador de esta solicitud. **No se emitió `approval_id`, no
se envió `mode=apply` y no se ejecutó remediación real.** El siguiente paso
depende de esa aprobación específica mientras la evidencia de seguridad siga
vigente; si vence, renovar el preflight antes de aprobar.

## Subunidad U2/U3: playbook Debian completo desde Wazuh, sólo check (2026-10-15)

Estado: **parcial/fallido**, sin aplicación. Permanecen **3/19 tareas cerradas**.
Esta prueba responde a la prioridad de recorrer primero el playbook completo,
pero **no** demuestra que todos los controles se ejecutaron. Entrega:
`exception-ok`, con `size:exception` ya autorizado; sin commit ni PR.

- Orden real Wazuh 4.14.8 `PUT /active-response?agents_list=001`, agente
  afectado `001`, solicitud `170427de-87ad-4f50-9d9a-268147ad4106`,
  cambio `lab_debian_full_check_20261015`, `debian_hardening`, perfil
  `debian_lab`, destino `debian12`, selección `full` con `names=[]` y
  `extra_vars={}`. La release activa era `lab_v11`.
- El gateway resolvió el playbook existente
  `cis_debian_12.yml` con el tag de **rol completo**
  `cis_debian_12_remediation` y las variables técnicas de remediación/canary;
  ejecutó `--check --diff`. JSONL emitió
  `accepted → started → progress(1173) → recap → failed` con
  `ok=290 changed=83 unreachable=0 failed=1`. No hubo `mode=apply`,
  aprobación nueva ni mutación de hardening.
- El primer fallo fue `cis_linux_common : Common fixed file permissions |
  Apply declared metadata`: `/var/log/audit/audit.log` está ausente.
  En un nodo recién creado el check no materializa los archivos que pasos
  anteriores crearían en apply, por lo que una tarea posterior de permisos
  no puede continuar. Este es un bloqueo de compatibilidad con check-mode
  en el rol existente, no una falla de transporte Wazuh→Ansible.
- Alertas correlacionadas del manager: `100122 accepted`, `100126 started`,
  `100129 progress`, `100127 recap` y `100124 failed`, todas con el mismo
  `request_id`, host y cambio. HTTP 200 significó envío, no éxito.

### Work Unit Evidence — check completo Debian

| Evidencia | Resultado |
|---|---|
| Prueba focal y resultado exacto | API Wazuh→agente 001→gateway→Ansible→`debian12`: solicitud `170427de-87ad-4f50-9d9a-268147ad4106`; JSONL terminal `failed`, recap `ok=290 changed=83 unreachable=0 failed=1`; log privado `/var/lib/ansible-wazuh/state/170427de-87ad-4f50-9d9a-268147ad4106.debian12.v2.check.log`. |
| Harness de runtime | `debian12` respondió al ping Ansible antes de la orden; proceso sellado de `lab_v11` ejecutó `cis_debian_12.yml --limit debian12 --tags cis_debian_12_remediation --check --diff`; cinco alertas correlacionadas aparecen en el manager Docker. |
| Límite de rollback | No hubo mutación del nodo: ningún cambio de hardening que revertir. Conservar el log privado, JSONL y alertas; no reintentar el mismo `request_id`. La corrección de check-mode es una unidad posterior y acotada del rol, fuera de este work unit. |

Siguiente paso: corregir únicamente la incompatibilidad de check-mode del
rol existente sin debilitar su comportamiento apply ni idempotencia; repetir
una sola comprobación `full` con una solicitud nueva y volver a evaluar el
primer fallo real. Ubuntu y producción no se tocaron en esta subunidad.

