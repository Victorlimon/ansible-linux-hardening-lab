# Guía de evidencias de la Fase 3: línea base CIS

Esta guía permite organizar las capturas existentes, completar las fichas de la Tabla 4.17 y preparar la revisión de la Tabla 4.25. Su alcance es la línea base de `ansible/` para Debian 12 y Ubuntu 24.04, no la edición posterior de endurecimiento de `wazuh-cis/` ni sus resultados.

**Primero se recupera la evidencia histórica; después se decide si hace falta una ejecución nueva.** El responsable confirmó que conserva capturas, pero sus imágenes no se inspeccionaron para redactar esta guía. Los espacios vacíos son datos pendientes, no ceros ni pruebas fallidas.

## 1. Ruta de trabajo

1. Reunir las capturas y salidas originales de las siete secciones, las pruebas unitarias y la prueba conjunta. Conservar sus nombres y fechas; trabajar con copias para la presentación.
2. Abrir una ficha por sección, plataforma y ejecución. Separar auditoría, aplicación, repetición y verificación; no combinar sus números.
3. Transcribir el resumen completo y los casos unitarios desde cada archivo. Si un campo no aparece, dejarlo vacío y anotar «no visible en la evidencia».
4. Vincular cada ficha con la tabla y figura correspondientes. Revisar la propuesta de figuras contra el índice real antes de incorporarla a la memoria.
5. Contrastar los cinco problemas de la Tabla 4.25 con el catálogo de esta guía. No elegir cinco por semejanza del nombre.

### Documentos que faltan

No se localizaron el documento de tesis, las páginas de las Tablas 4.17 y 4.25, el índice de las Figuras 4.13–4.23 ni el apartado académico 3.1.2 en los textos consultados. Se revisaron los nombres de archivos de la raíz y `docs/`, los textos versionados pertinentes y los textos de `docs/` incluidos los no versionados, excluyendo la referencia vendorizada, respaldos y benchmarks licenciados. Las coincidencias de `3.1.2` en el documento de preguntas y respuestas son identificadores CIS, no el apartado del capítulo 3. El archivo Word de requisitos del controlador no se convirtió ni se trató como tesis.

Por tanto, la numeración recibida se conserva como referencia del solicitante. **El plan de figuras es una asignación provisional; el catálogo de problemas no es la transcripción de las cinco filas originales.** No se modifica la tesis ni el documento de preguntas y respuestas.

## 2. Qué debe mostrar cada captura

### Lista de comprobación al seleccionar o tomar una imagen

- [ ] Comando completo y directorio de trabajo; si no caben junto al resultado, conservar un panel de contexto y otro de salida vinculados a la misma ejecución.
- [ ] Fecha y zona horaria, revisión del repositorio y estado de cambios locales de la fuente utilizada. Un commit por sí solo no identifica contenido modificado sin confirmar.
- [ ] Versión del Python y del runtime Ansible utilizado. El proyecto exige **Ansible Core 2.21.2**; no sustituirlo por el Ansible del sistema sin identificar la diferencia.
- [ ] Controlador identificado y destino con alias de host, distribución y versión. La prueba unitaria se ejecuta en el controlador: no atribuirla a un cliente solo porque evalúe su adaptador.
- [ ] Sección, familia de pruebas o selección exacta de controles, modo, inventario, etiquetas y variables no secretas.
- [ ] En Ansible: encabezado `PLAY RECAP`, línea completa del host y errores anteriores relevantes; conservar también el código de salida si fue registrado.
- [ ] En `unittest`: nombres de casos con `-v`, línea `Ran N tests`, resultado final y detalles de fallos, errores u omisiones.
- [ ] Texto legible al tamaño final de la memoria. Recortar el escritorio ajeno a la prueba, no errores, omisiones ni partes del resumen.
- [ ] Ausencia de contraseñas, tokens, claves privadas, contenido de shadow o información privada de la red institucional. Usar alias coherentes y, si es indispensable ocultar un dato, marcar la ocultación en una copia y conservar el original de forma restringida.

No editar cifras ni recrear terminales para aparentar una ejecución histórica. Mantener el archivo original y su salida completa, cuando exista. Una captura de una ejecución actual debe llevar **su fecha y versión actuales**, aunque reproduzca el mismo caso. Si solo falta contexto de una imagen antigua, un registro nuevo no demuestra retrospectivamente cuál era su entorno.

Nombre sugerido para una copia de presentación: `fase3_s01_debian12_verify_FECHA_REV.png`. No cambiar el nombre del original sin conservar la correspondencia en la ficha. Un hash es opcional; no reemplaza el contexto ni acredita por sí mismo la fecha de ejecución.

### Contexto para una eventual captura nueva

Los siguientes comandos son **instrucciones manuales para el responsable**, no operaciones realizadas durante esta tarea. No requieren reinstalar, limpiar ni cambiar de revisión el repositorio. Antes de utilizarlos, comprobar que se está en el controlador y entorno adecuados, no en un cliente alterado por otra edición del proyecto.

```bash
cd /home/vagrant/ansible
pwd
date -Is
git rev-parse HEAD
git status --short
export PATH="/home/vagrant/.venvs/ansible-cis/bin:$PATH"
/home/vagrant/.venvs/ansible-cis/bin/python --version
ansible-playbook --version
```

Esta es la ruta canónica del laboratorio de desarrollo, no una ruta prevista para Fase 4. Registrar por separado la identificación de los destinos que figure en los registros de la prueba. No volcar inventarios o variables con secretos para obtener una captura.

**No ejecutar una aplicación de hardening solo para completar una figura.** Puede modificar acceso, autenticación, firewall o montajes y, sobre clientes intervenidos por una capa posterior, producir evidencia que ya no representa la línea base original. Tampoco se promete que una verificación actual termine satisfactoriamente. Para las salidas históricas, transcribir el comando realmente usado.

Rutas confirmadas para reconocer los registros, desde la raíz del repositorio:

| Elemento | Ruta de la línea base |
| --- | --- |
| Inventario local | `ansible/inventories/local/hosts.yml` |
| Aplicación Debian | `ansible/playbooks/hardening/cis_debian_12.yml` |
| Aplicación Ubuntu | `ansible/playbooks/hardening/cis_ubuntu_2404.yml` |
| Verificación Debian | `ansible/playbooks/verify/cis_debian_12.yml` |
| Verificación Ubuntu | `ansible/playbooks/verify/cis_ubuntu_2404.yml` |

No existen etiquetas generales `cis_sec1` a `cis_sec7` en esta línea base. Deben conservarse las etiquetas reales de mecanismo o control que aparecen en cada ejecución. La remediación tiene un selector general desactivado por defecto; Debian exige además confirmación canaria y selección explícita de etiquetas. Una ficha no debe suplir esas condiciones con un comando inventado.

## 3. Pruebas unitarias: comandos y alcance para la captura

La suite está en `ansible/tests/` y utiliza Python `unittest`, PyYAML y Jinja2. Desde `/home/vagrant/ansible`, después de preparar `PATH` como arriba, el comando completo documentado es:

```bash
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_*.py' -v
echo "exit_code=$?"
```

La segunda línea debe ejecutarse inmediatamente después de la prueba, sin intercalar otro comando. Si el directorio de trabajo es `/home/vagrant/ansible/ansible`, se usa `-s tests`, no `-s ansible/tests`. No ejecutar estos comandos para esta revisión documental: quedan disponibles para una nueva toma manual, claramente fechada.

### Familias que conviene buscar en las salidas históricas

Todas las rutas de la columna central son relativas a `ansible/tests/`. Son ejemplos verificados de cobertura, **no siete suites exhaustivas ni archivos exclusivos de cada sección**.

| Sección | Archivos existentes | Alcance que puede describirse |
| --- | --- | --- |
| 1. Configuración inicial | `test_mount_options_controls.py`; `test_kernel_module_disabled.py`; `test_cis_section17_gdm.py` | Montajes, opciones, módulos y contratos GDM. La familia de módulos también incluye controles de la sección 3. |
| 2. Servicios | `test_section2_lab_gates.py`; `test_time_sync_selection.py`; `test_service_enabled_oneshot.py` | Habilitaciones del laboratorio, selección horaria y estados de servicios de ejecución puntual. |
| 3. Configuración de red | `test_logging_sysctl_consistency.py`; casos pertinentes de `test_remediation_gates.py` | Precedencia sysctl/UFW y condiciones de selección. El primer archivo también contiene casos de registro; ninguno demuestra por sí solo toda la sección 3. |
| 4. Firewall | `test_firewall_allowlist.py`; `test_ufw_loopback_control.py`; `test_nftables_pattern_matching.py`; `test_single_firewall_utility.py` | Orígenes permitidos, loopback, patrones y selección de herramienta. |
| 5. Acceso y autenticación | `test_sudoers_config_line.py`; `test_config_line_effective_command.py`; `test_cis_pam_faillock_family.py`; `test_cis_pam_pwhistory_family.py`; `test_cis_pwquality_family.py` | Sudoers, configuración efectiva SSH y contratos PAM. El archivo de configuración efectiva contiene también casos de banners de sección 1. |
| 6. Auditoría y registro | `test_audit_log_group_policy.py`; `test_journal_upload_destination.py`; `test_privileged_commands_audit.py`; casos pertinentes de `test_fixed_file_set_mechanism.py` | Grupos de registros, destino remoto, reglas y conjuntos de archivos de auditoría. |
| 7. Mantenimiento del sistema | Casos pertinentes de `test_fixed_file_set_mechanism.py`, `test_fixed_file_check_mode.py` y `test_remediation_gates.py` | Permisos, comparación de modos y habilitaciones compartidas. No constituye una inspección real de todas las cuentas del cliente. |

Para una captura nueva delimitada, estos son ejemplos de comandos completos desde la raíz; ejecutar únicamente la familia que se quiera documentar:

```bash
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_mount_options_controls.py' -v
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_time_sync_selection.py' -v
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_logging_sysctl_consistency.py' -v
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_firewall_allowlist.py' -v
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_cis_pam_faillock_family.py' -v
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_journal_upload_destination.py' -v
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_fixed_file_set_mechanism.py' -v
```

Cada línea es una ejecución independiente; registrar su salida antes de pasar a otra. No sumar ejecuciones solapadas como casos únicos. En archivos compartidos, copiar los nombres completos de los casos que sustentan la sección, por ejemplo `test_ufw_override_is_inspected_and_corrected_after_sysctl` para la relación sysctl/UFW, `test_audit_config_controls_cover_conf_and_rules_sets` para auditoría o `test_ubuntu_7_1_3_targets_group_not_group_backup` para mantenimiento.

`test_ssh_tag_routing.py` requiere `ansible-playbook` en `PATH`; de lo contrario omite sus casos. Emplea tareas sustitutas locales para comprobar el enrutamiento: no ejecuta el endurecimiento remoto original. Registrar `SKIP` y su motivo, aunque la suite termine con `OK`. Una prueba unitaria con datos simulados no acredita continuidad de servicios, reinicio o acceso SSH posterior a cambios reales.

## 4. Tabla 4.17: ficha y siete grupos de evidencia

### Ficha reutilizable por sección, plataforma y ejecución

Duplicar esta ficha para cada fila del índice siguiente y para cada modo disponible. Para repetición, enlazar la primera aplicación comparable. Si no existe evidencia para un modo, no crear resultados para él.

| Campo | Dato que se debe transcribir |
| --- | --- |
| ID de ficha / sección / nombre | ____________ |
| Plataforma y versión / alias del destino | ____________ |
| Controlador / fecha, hora y zona de la ejecución | ____________ |
| Procedencia: histórica o nueva / fecha de transcripción | ____________ |
| Commit y cambios locales de la fuente / versión del runtime | ____________ |
| Directorio de trabajo / comando literal completo | ____________ |
| Inventario / límite de hosts / controles seleccionados | ____________ |
| Modo: audit, apply, repeat o verify / uso de check mode | ____________ |
| Etiquetas exactas / variables efectivas no secretas y referencias a sus archivos | ____________ |
| Excepciones y controles omitidos o no aplicables / motivo | ____________ |
| `ok` | ____________ |
| `changed` | ____________ |
| `failed` | ____________ |
| `unreachable` | ____________ |
| `skipped` | ____________ |
| `rescued` | ____________ |
| `ignored` | ____________ |
| Código de salida del proceso Ansible | ____________ |
| Familia(s) unitaria(s), comando y versión / fecha de esa prueba | ____________ |
| Casos ejecutados (`Ran N tests`) | ____________ |
| Fallos unitarios / errores / omisiones y motivos | ____________ |
| Resultado literal unitario / código de salida | ____________ |
| Archivo original de captura / log / panel o líneas relevantes | ____________ |
| Figura y fila de tabla vinculadas | ____________ |
| Primera aplicación vinculada, si es repetición | ____________ |
| Conclusión limitada a esta selección / campos no visibles | ____________ |

Para «casos de las pruebas unitarias», adjuntar este desglose a la ficha; no basta con indicar un total:

| Archivo y clase.método tal como aparecen en `-v` | Caso o condición comprobada | Estado literal: ok / FAIL / ERROR / skipped | Evidencia y motivo de incidencia |
| --- | --- | --- | --- |
| ____________ | ____________ | ____________ | ____________ |

### Índice de las siete fichas de sección

Cada grupo mantiene dos entradas de plataforma. Los resultados unitarios comunes pueden referenciar una misma salida del controlador, sin duplicar su recuento como si fueran dos ejecuciones distintas.

| Grupo | Sección | Plataforma | ID(s) de ficha por modo | Captura / log original |
| --- | --- | --- | --- | --- |
| F3-S01 | 1. Configuración inicial | Debian 12 | ____________ | ____________ |
| F3-S01 | 1. Configuración inicial | Ubuntu 24.04 | ____________ | ____________ |
| F3-S02 | 2. Servicios | Debian 12 | ____________ | ____________ |
| F3-S02 | 2. Servicios | Ubuntu 24.04 | ____________ | ____________ |
| F3-S03 | 3. Configuración de red | Debian 12 | ____________ | ____________ |
| F3-S03 | 3. Configuración de red | Ubuntu 24.04 | ____________ | ____________ |
| F3-S04 | 4. Firewall | Debian 12 | ____________ | ____________ |
| F3-S04 | 4. Firewall | Ubuntu 24.04 | ____________ | ____________ |
| F3-S05 | 5. Acceso y autenticación | Debian 12 | ____________ | ____________ |
| F3-S05 | 5. Acceso y autenticación | Ubuntu 24.04 | ____________ | ____________ |
| F3-S06 | 6. Auditoría y registro | Debian 12 | ____________ | ____________ |
| F3-S06 | 6. Auditoría y registro | Ubuntu 24.04 | ____________ | ____________ |
| F3-S07 | 7. Mantenimiento del sistema | Debian 12 | ____________ | ____________ |
| F3-S07 | 7. Mantenimiento del sistema | Ubuntu 24.04 | ____________ | ____________ |

### Cómo interpretar la transcripción

- El recap cuenta tareas por host, no controles CIS únicos. No sumar `ok` y `changed` como categorías independientes ni convertirlos en controles aprobados.
- Una auditoría puede registrar una clasificación `FAIL` sin que el proceso termine con `failed` distinto de cero. Conservar la clasificación, no solo el recap.
- `changed=0` en una repetición comparable de aplicación puede sustentar idempotencia de esa selección. En auditoría, check mode o una selección vacía no demuestra lo mismo.
- Examinar `rescued`, `ignored`, `unreachable` y omisiones. Un cero aislado no demuestra que se probó una sección completa.
- No sustituir recuentos unitarios desconocidos por 395 en cada sección. Ese total histórico es de otra ejecución, no siete resultados independientes. Los 311 ID del catálogo tampoco son una lista de aplicaciones reales ni un recuento SCA.

**Antecedentes separados, no valores para rellenar estas fichas:** `ansible/evidence/cis/lifecycle-2026-09-29.md` conserva auditorías con `ok=1083` en Debian y `ok=1143` en Ubuntu, ambas con `failed=0`; las repeticiones sysctl pasaron de `changed=21` a `0` y de `19` a `0`, respectivamente. Esto último corresponde solo al subconjunto sysctl. El registro histórico del 28-10-2026, reproducido en la pregunta 17 de `PREGUNTAS_RESPUESTAS_PROYECTO.md`, informa verificaciones con `ok=1879` y `ok=1983`, ambas con `failed=0`, y 395 pruebas unitarias. No aporta aquí todos los campos ni el desglose de siete secciones; no se presenta como transcripción de imágenes inspeccionadas.

## 5. Figuras 4.13–4.23: plan de once espacios

**ASIGNACIÓN PROVISIONAL.** Los siguientes contenidos son una propuesta de organización, no los títulos recuperados de la tesis. Antes de usarlos, comparar con el índice real; no renumerar ni reemplazar figuras existentes sin esa conciliación.

| Espacio | Contenido propuesto | Qué debe quedar visible | Ficha y archivo por vincular |
| --- | --- | --- | --- |
| Fig. 4.13 | Contexto de la línea base | Directorio, revisión y cambios locales, versiones, controlador y referencia al inventario sin secretos. | ____________ |
| Fig. 4.14 | Sección 1 | Panel unitario de montajes/módulos/GDM según evidencia disponible; paneles de recap Debian y Ubuntu con modo y selección. | F3-S01 / ____________ |
| Fig. 4.15 | Sección 2 | Panel unitario de servicios/tiempo y recaps de ambas plataformas. | F3-S02 / ____________ |
| Fig. 4.16 | Sección 3 | Casos sysctl pertinentes, sin atribuir todo el archivo a red; recaps de ambas plataformas. | F3-S03 / ____________ |
| Fig. 4.17 | Sección 4 | Familia de firewall utilizada y recaps de ambas plataformas, con herramienta y selección. | F3-S04 / ____________ |
| Fig. 4.18 | Sección 5 | Familia concreta SSH/sudo/PAM y recaps de ambas plataformas. | F3-S05 / ____________ |
| Fig. 4.19 | Sección 6 | Familia de auditoría/registro y recaps de ambas plataformas. | F3-S06 / ____________ |
| Fig. 4.20 | Sección 7 | Casos pertinentes de mantenimiento/permisos y recaps de ambas plataformas. | F3-S07 / ____________ |
| Fig. 4.21 | Suite unitaria completa | Comando, `Ran N tests`, resultado, fallos, errores, omisiones y referencia al listado completo. | ____________ |
| Fig. 4.22 | Verificación integrada Debian | Playbook baseline, contexto y selección completos, recap del host y código de salida disponible. | ____________ |
| Fig. 4.23 | Verificación integrada Ubuntu | Mismo criterio para Ubuntu, sin reutilizar el recap Debian. | ____________ |

Para mantener once figuras sin perder contexto, cada figura de sección puede componerse de paneles **(a) pruebas unitarias, (b) Debian y (c) Ubuntu**. Añadir paneles de aplicación/repetición solo si se sostiene una conclusión de cambios o idempotencia. Cada panel conserva su fecha y ficha: colocarlos juntos no los convierte en una sola ejecución. Si no se dispone de uno, indicar la ausencia; no duplicar una imagen de otro host.

La figura puede mostrar el resumen por legibilidad; el log y el desglose de casos quedan vinculados en la ficha. Un recorte que muestra únicamente `failed=0` u `OK` no acredita por sí solo el sprint completo. La Figura 4.17 propuesta y la Tabla 4.17 son objetos distintos.

## 6. Tabla 4.25: catálogo de problemas contrastados

**No se conocen los cinco enunciados originales ni sus secciones asignadas.** Este catálogo ofrece soluciones sustentadas en las fuentes locales para reconocer los casos, no cinco filas elegidas en nombre del autor. La sección indicada se basa en el control o destino afectado. Las comprobaciones descritas son criterios para vincular evidencia existente o planificar una validación posterior; no se ejecutaron al preparar esta guía.

En las referencias siguientes, `M/` significa `ansible/roles/cis_linux_common/tasks/mechanisms/`; `C/`, `ansible/roles/cis_linux_common/tasks/sections/`; y `T/`, `ansible/tests/`.

| Candidato / sección comprobada | Problema y causa | Solución que puede redactarse | Cómo verificar y fuente |
| --- | --- | --- | --- |
| P1. Contrato sysctl / **3: red**, control `3.3.7` | La delegación omitía `runtime_path` y `file`; el mecanismo no recibía su contrato completo. | Se completó la delegación mediante un bucle con los parámetros, rutas de ejecución y archivos persistentes correspondientes a IPv4 `all` y `default`. | Vincular el fallo original y la salida posterior; revisar los wrappers de `ansible/roles/cis_debian_12/tasks/sections/section_03_network/3_3_7_reverse_path_filtering/`. Incidente real del 29-09-2026, archivo de ciclo de vida, líneas 52–54; commit allí registrado: `40087f7`. No presentar la repetición sysctl como idempotencia de las siete secciones. |
| P2. Puerto UFW entero / **4: firewall**, control `4.2.6` | El puerto nativo `22` llegaba a `re.compile` como entero, aunque el patrón debía ser texto. | Se convirtió explícitamente `cis_ufw_ssh_port` a cadena con el filtro `string` antes de emplearlo como patrón. | Revisar `ansible/roles/cis_ubuntu_2404/tasks/sections/section_04_firewall/4_2_6_ufw_rules_for_open_ports/audit.yml` y `verification.yml`, y vincular el registro corregido. Incidente real del 29-09-2026, ciclo de vida, líneas 55–56; commit registrado: `471ab48`. |
| P3. Salida UFW indefinida / **4: firewall**, mecanismos `ufw_rule` y `ufw_policy` | Si UFW no estaba disponible, se intentaba buscar un patrón sobre `stdout` indefinido. | Se protegió la lectura con `default('')` antes de evaluar la expresión. Evita el error de variable; no convierte la ausencia del servicio en conformidad. | `M/ufw_rule/audit.yml`, `verification.yml` y equivalentes de `ufw_policy`; vincular el caso de ausencia y la clasificación. Incidente real del 29-09-2026, ciclo de vida, líneas 50–51; commit registrado: `40087f7`. Es distinto del problema de tipo del puerto. |
| P4. Permisos de `config_line` / **transversal: 5 y 6 documentadas** | Imponer `0644` a archivos ya existentes provocaba cambios transitorios en `sshd_config` y `auditd.conf`, y oscilación frente a controles de permisos. | Se añadió una consulta `stat`; para archivos existentes ajenos a sudoers se omite `mode` y se conserva el permiso. Para archivos nuevos se fija `0644`; sudoers conserva la excepción `0440` y la validación con `visudo`. | `M/config_line/remediation.yml`, líneas 6–24; `T/test_sudoers_config_line.py`, casos de conservación y creación. Fixture real con Core 2.21.2 del 21-10-2026, Engram n.º 1270: no fue una aplicación integral de producción. Los wrappers SSH y auditd confirman secciones 5 y 6; no asignar este mecanismo solo a sudo por el nombre del test ni añadir sección 1 sin demostrar el destino afectado. |
| P5. Montaje de `/tmp` / **1: configuración inicial, montajes** | Montar tmpfs sobre `/tmp` cubría el payload de AnsiballZ; la operación podía haberse realizado aunque la respuesta fallara con `No start of json char found`. | Se estableció `TMPDIR: /run` en las tareas de montaje y remontaje, fuera del árbol que se iba a cubrir. | `M/mount_options/remediation.yml`, líneas 78 y 89; `T/test_mount_options_controls.py`, caso `test_unmounted_fresh_target_mounts_after_fstab_and_reload`. Incidente de laboratorio del 30-10-2026, Engram n.º 1599. La aserción unitaria conserva la regresión, pero no sustituye una evidencia operacional de montaje. |
| P6. Estados systemd / **1: montajes**, no sección 2 por el nombre de la herramienta | systemd 252 y 255 comunicaban de forma distinta una unidad inexistente por stdout, stderr y código de retorno. | Se normalizaron estados conocidos por tokens y se mantuvo la exigencia de unidad según el contrato de cada control, sin usar un retorno no nulo como regla universal. | `M/mount_options/inspect.yml`; `T/test_mount_options_controls.py`, casos `test_unit_required_rejects_missing_unit_file`, `test_unit_required_accepts_generated` y `test_unit_not_required_keeps_benchmark_findmnt_scope`. Antecedente real del 30-10-2026, Engram n.º 1599. `/dev/shm` no exige una unidad independiente como `/tmp`; no generalizar el incidente a todos los servicios. |
| P7. Banner con información previa / **1: configuración inicial**, control `1.6.2` | Añadir la advertencia dejaba contenido anterior que revelaba información del sistema operativo. | Se sustituyó el contenido completo del banner local mediante `copy`, en lugar de añadir únicamente la línea deseada. | `C/section_01_initial_setup/1_6_2_issue_banner/remediation.yml`; casos `BannerContentControlsTest` de `T/test_config_line_effective_command.py`. Antecedente de ejecución del 28-10-2026, Engram n.º 1531. Para la memoria, mostrar la comprobación del contenido sin divulgar datos sensibles. |
| P8. Parámetro opcional de `account_integrity` / **mecanismo compartido por 5 y 7** | La comprobación `is defined` del parámetro opcional mediante `import_role` no resolvía correctamente su ausencia. | Se normalizó `cis_linux_common_account_status_regex` mediante `default('')` antes de clasificar: expresión no vacía para estado de contraseña y, en su ausencia, semántica de salida vacía. | `M/account_integrity/audit.yml`, líneas 21–26. La cadena de delegación actual se comprueba en `C/section_05_access_control/5_4_2_8_accounts_locked/audit.yml` y `C/section_07_maintenance/7_2_1_shadowed_passwords/audit.yml`, con sus wrappers Ubuntu. Estos omiten la variable opcional. Engram n.º 1531 documenta el fallo del 28-10-2026, pero no identifica el control exacto que lo disparó: no asignarlo históricamente a 5 o 7 sin el log. |

Las fechas y commits de P1–P3 proceden del archivo de ciclo de vida; las fechas de P4–P8 proceden de los registros históricos indicados y se recogen también en la pregunta 18 del documento de preguntas y respuestas. La lectura del código actual confirma la solución presente, no por sí sola la fecha ni la ejecución del incidente. Las pruebas de contrato acreditan el comportamiento esperado; solo su salida acredita que se ejecutaron en una versión concreta.

### Traslado a las cinco filas reales

Cuando se reciban las páginas, usar una fila de trabajo por cada problema original. No trasladar P1–P5 automáticamente ni forzar problemas transversales a una única sección.

| Fila original / enunciado literal | Candidato coincidente, si existe | Sección original → sección sustentada | Solución y evidencia para incorporar |
| --- | --- | --- | --- |
| ____________ | ____________ | ____________ | ____________ |

Si el enunciado no coincide con ningún candidato, conservarlo pendiente de investigación. No atribuir revisiones o aprobaciones al docente sin su confirmación documental.

## 7. Texto listo para incorporar a 3.1.2, Fase 4

**Propuesta para pegar tras revisar el apartado original; no incorporada a la tesis.** Mantiene la Fase 4 en futuro y no altera la planificación general:

> En la Fase 4 se validará la preproducción en un laboratorio limpio, preparado sin Vagrant y separado del entorno de desarrollo, bajo condiciones operacionales representativas del entorno institucional. Esto no implica excluir las máquinas virtuales ni exigir equipos físicos dedicados para cada cliente. Se utilizarán un inventario y credenciales propios de preproducción, con sistemas operativos y servicios representativos que se definirán cuando la DTIC proporcione la información correspondiente. Antes de intervenir se acordarán la conectividad y los accesos autorizados, los respaldos, el procedimiento de recuperación y los criterios de aceptación. La validación incluirá pruebas funcionales de los servicios, continuidad del acceso administrativo, reinicio, idempotencia e integración, con trazabilidad entre la versión evaluada, la selección de controles y sus evidencias. El objetivo de hasta ocho servidores concurrentes requerirá una prueba específica y no se considera demostrado. La Fase 3 comprende el desarrollo de las siete secciones, sus pruebas unitarias y la prueba conjunta del laboratorio de desarrollo; los ensayos históricos de integración del prototipo se conservarán como antecedentes, sin presentarlos como la conclusión formal de la Fase 4, que permanece pendiente de ejecución. Se mantiene la planificación general de 18 semanas y 360 horas.

Datos que seguirán pendientes, sin sustituirlos por supuestos:

| Dato institucional | Campo por completar |
| --- | --- |
| Hardware y plataforma del controlador y clientes | ____________ — pendiente de DTIC |
| Sistemas operativos y servicios representativos | ____________ — pendiente de DTIC |
| Red autorizada, accesos y responsables | ____________ — pendiente de autorización e información institucional |
| Respaldos, recuperación y aceptación | ____________ — pendiente de definición y aprobación |

## 8. Control documental y material para cerrar la transcripción

Fuentes principales: [preguntas 15–21](PREGUNTAS_RESPUESTAS_PROYECTO.md#fase-3-desarrollo-y-pruebas-de-los-playbooks), [registro del ciclo de vida](../ansible/evidence/cis/lifecycle-2026-09-29.md), [pruebas de la línea base](../ansible/tests/) y rutas específicas de la sección 6. No se reproduce texto licenciado de recomendaciones CIS.

- [ ] Cada resultado tiene host, fecha, versión, modo y evidencia; los datos no visibles permanecen vacíos.
- [ ] Las siete secciones están indexadas para ambas plataformas; las familias compartidas no se cuentan dos veces.
- [ ] Los once espacios de figuras se conciliaron con sus títulos originales antes de editar la memoria.
- [ ] Las cinco filas de problemas se identificaron por su enunciado y fuente, no por una inferencia del nombre.
- [ ] El texto de Fase 4 mantiene el futuro y no afirma validaciones o autorizaciones todavía inexistentes.

**Material necesario para transcribir exactamente:** capturas o logs de las siete secciones por host y de la prueba conjunta; salidas unitarias con casos y resumen; páginas de las cinco filas de la Tabla 4.25; títulos originales de las Figuras 4.13–4.23; y fragmento del apartado 3.1.2. Puede entregarse como un único conjunto de páginas de los capítulos correspondientes y sus archivos de evidencia. Hasta recibirlo, esta guía organiza la recopilación, pero no completa cifras ni títulos originales.
