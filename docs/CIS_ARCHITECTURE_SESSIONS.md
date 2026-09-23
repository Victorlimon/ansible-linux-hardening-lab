# Sesiones de arquitectura CIS

> **Historical and non-normative.** Session outcomes record what was observed at
> a point in time and do not establish current support or exact benchmark
> metadata. Use [SUPPORT.md](SUPPORT.md) for the current correction: Ubuntu
> 24.04 x86_64 is released for the qualified subset, Debian 12 x86_64 is
> canary-only, and Docker, Ubuntu 22.04, and Debian 11 are unsupported.

Este registro divide la reorganización en cambios pequeños y verificables. Una
sesión no habilita nuevos controles salvo que su alcance lo indique de forma
explícita.

## Reglas de sesión

- Un control o una preocupación arquitectónica por sesión.
- Sin migraciones masivas ni cambios cosméticos no relacionados.
- Imports estáticos y tags existentes preservados.
- Audit, remediation y verification permanecen separados.
- Los mecanismos comunes no deciden política de plataforma.
- Cada control tiene una única implementación canónica. No se crean wrappers de
  compatibilidad sin un consumidor existente y documentado.
- Cada sesión termina con validación, evidencia y un commit independiente.

## Plan incremental

| Sesión | Alcance | Riesgo | Estado |
|---|---|---|---|
| A1 | Definir arquitectura semántica y migrar CIS 3.1.1 a `sections/section_03_network` | Bajo; control read-only | `COMPLETED` |
| A2 | Migrar CIS 7.1.1 a `sections/section_07_maintenance` | Bajo; solo cambia la ruta de composición | `COMPLETED` |
| A3 | Migrar CIS 2.4.1.2 a `sections/section_02_services` | Bajo; conservar rama `NOT_APPLICABLE` | `COMPLETED` |
| A4 | Migrar CIS 3.3.10 a `sections/section_03_network` | Medio; preservar runtime, persistencia y gates | `COMPLETED` |
| A5 | Reubicar mecanismos bajo `tasks/mechanisms/` con wrappers compatibles | Medio; cambia rutas internas | `COMPLETED` |
| A6 | Dividir adaptador Ubuntu por secciones, sin alterar orden histórico | Medio | `COMPLETED` |
| A7 | Dividir adaptador Debian por secciones, sin alterar gates canary | Medio | `COMPLETED` |
| A8 | Completar interfaces independientes de Debian CIS 7.1.5 | Alto; cambio funcional | `COMPLETED` |
| A9 | Implementar Debian CIS 7.1.2 sin declarar equivalencia Ubuntu | Bajo; metadata de un backup requerido | `COMPLETED` |
| A10 | Transferir la orquestación Ubuntu completa al adaptador canónico | Medio; grafo de 647 tareas históricas | `COMPLETED` |
| A11 | Implementar Debian CIS 7.1.3 con una única entrada canónica por modo | Bajo; metadata de `/etc/group` | `COMPLETED` |

## Definition of Done por sesión

1. `git diff --check` limpio.
2. Syntax-check de entry points afectados.
3. Gate específico en Ubuntu 24.04 y Debian 12 cuando sea común.
4. Regresiones de contratos y baseline estático sin deuda nueva.
5. Documentación y mapa de archivos actualizados.
6. Árbol de trabajo revisado antes del commit.

## Evidencia A1

- Se añadió la API semántica de CIS 3.1.1 sin mover ni duplicar el mecanismo
  `ipv6_status`.
- Ubuntu 24.04 y Debian 12 consumen la nueva ruta mediante imports estáticos.
- Las rutas técnicas anteriores permanecen disponibles como compatibilidad.
- El gate CIS 3.1.1 conservó clasificación `MANUAL`, evidencia read-only,
  `changed=0` y conectividad en ambas plataformas.
- Contratos, syntax-check, ansible-lint y yamllint pasaron sin deuda nueva;
  ansible-lint mantuvo 0 fallos y 575 warnings históricos.

## Evidencia A2

- CIS 7.1.1 dispone de entradas semánticas separadas para audit, remediation y
  verification bajo `section_07_maintenance/7_1_1_passwd_permissions`.
- Los adaptadores Ubuntu 24.04 y Debian 12 consumen la nueva ruta sin cambiar
  contratos, gates, tags ni el mecanismo `fixed_file_permissions`.
- El baseline previo y el gate posterior clasificaron `PASS` con `/etc/passwd`
  en `root:root` y modo `0644`; audit y verification terminaron con
  `changed=0` y ping correcto en ambas plataformas.
- Los seis entry points afectados pasaron syntax-check. También pasaron
  contratos, inventario, ansible-lint y yamllint sin deuda nueva; ansible-lint
  mantuvo 0 fallos y 575 warnings históricos.

## Evidencia A3

- CIS 2.4.1.2 dispone de entradas semánticas separadas para audit, remediation
  y verification bajo `section_02_services/2_4_1_2_crontab_permissions`.
- Los adaptadores Ubuntu 24.04 y Debian 12 consumen la nueva ruta sin cambiar el
  contrato ni el mecanismo `installed_package_fixed_file`.
- El baseline previo y el gate posterior clasificaron `PASS` con
  `/etc/crontab` en `root:root` y modo `0600`, `changed=0` y ping correcto.
- La prueba con paquete deliberadamente ausente mantuvo `NOT_APPLICABLE` y
  `changed=0`; no instaló `cron` ni creó archivos.
- Los seis entry points pasaron syntax-check. También pasaron contratos,
  inventario, ansible-lint y yamllint; ansible-lint mantuvo 0 fallos y 575
  warnings históricos.

## Evidencia A4

- CIS 3.3.10 dispone de entradas semánticas separadas para audit, remediation
  y verification bajo `section_03_network/3_3_10_tcp_syncookies`.
- Los adaptadores Ubuntu 24.04 y Debian 12 consumen la nueva ruta sin cambiar el
  contrato ni el mecanismo `sysctl_parameter`.
- El baseline previo y el gate posterior observaron runtime y persistencia con
  valor `1`, clasificación `PASS`, `changed=0` y ping correcto en ambas VMs.
- Ubuntu continuó considerando `/etc/ufw/sysctl.conf`; Debian mantuvo UFW como
  no configurado. No se modificó `/etc/sysctl.d/99-cis-network.conf`.
- Un ciclo posterior completo `make stop`/`make start` confirmó runtime y
  persistencia `1`, verification `changed=0` y conectividad en ambas VMs.
- Los seis entry points pasaron syntax-check. También pasaron contratos,
  inventario, ansible-lint y yamllint; ansible-lint mantuvo 0 fallos y 575
  warnings históricos.

## Evidencia A5

- Los cuatro mecanismos comunes se reubicaron bajo `tasks/mechanisms/` sin
  cambiar tareas, contratos, variables, clasificaciones ni comportamiento.
- Las 17 rutas técnicas anteriores permanecen disponibles mediante wrappers
  estáticos; un fixture temporal confirmó que los cuatro `tasks_from` públicos
  anteriores siguen parseando y no quedó incluido en el árbol del proyecto.
- Las entradas semánticas y los imports internos apuntan directamente a las
  implementaciones canónicas, sin atravesar wrappers de compatibilidad.
- Las listas de tareas y tags de audit, hardening y verification fueron
  idénticas antes y después para Ubuntu 24.04 y Debian 12.
- Pasaron los gates de IPv6, sysctl, cron, permisos comunes y el piloto P3 en
  ambas VMs, además de contratos y baseline estático. Ansible-lint mantuvo
  0 fallos y 575 warnings históricos.

## Evidencia A6

- El adaptador Ubuntu distribuye sus once entradas comunes bajo
  `tasks/sections/`, por sección, control y modo; `tasks/main.yml` conserva la
  validación de plataforma y el rol histórico.
- Cada entrada mantiene localmente el contrato, los gates y los tags originales;
  no se trasladaron variables a defaults o vars ni se usaron aliases YAML entre
  documentos.
- El orden estático histórico se preservó, incluida la ubicación separada de las
  entradas de CIS 7.1.1 alrededor de CIS 2.4.1.2.
- Las listas de tareas y tags de audit, hardening y verification fueron
  idénticas al baseline previo.
- Pasaron los cuatro gates comunes, contratos, syntax-check, inventario,
  ansible-lint y yamllint. Ansible-lint mantuvo 0 fallos y 575 warnings
  históricos; el baseline estático no remedió targets.

## Evidencia A7

- Las quince hojas del adaptador Debian se reubicaron bajo `tasks/sections/`
  por sección, control y modo; `tasks/main.yml` conserva exactamente el orden,
  las condiciones, los selectores y los tags.
- Las quince rutas mode-first anteriores permanecen como wrappers estáticos y
  fueron parseadas mediante un fixture temporal retirado tras el syntax-check.
- Los gates globales `cis_debian_12_remediation_enabled` y
  `cis_debian_12_canary_confirmed`, además del gate legal de banners, no se
  relajaron. CIS 7.1.5 conserva en A7 su comportamiento previo para aislar A8.
- Las listas de tareas y tags de audit, hardening y verification fueron
  idénticas al baseline previo.
- Pasaron piloto P3, banners, los cuatro gates comunes, contratos, syntax-check,
  inventario, ansible-lint y yamllint. Ansible-lint mantuvo 0 fallos y 575
  warnings históricos; el baseline estático no remedió targets.

## Evidencia A8

- Debian CIS 7.1.5 dispone ahora de audit, remediation y verification
  independientes bajo su entrada de Sección 07, además de wrappers mode-first.
- Audit y verification comparten una inspección de metadatos que deshabilita
  checksum, MIME y atributos extendidos; la evidencia no lee ni expone contenido
  de `/etc/shadow` y acepta los grupos válidos `root` o `shadow`.
- Remediation conserva exclusivamente el estado histórico `root:shadow` y
  `u-x,g-wx,o-rwx`; sus gates canary no se relajaron.
- El gate nuevo comprobó audit `PASS` y `changed=0`, remediation deshabilitada,
  rechazo sin confirmación canary, check mode con ambos gates, dos convergencias
  reales con la segunda en `changed=0`, verification independiente y ping final.
- Pasaron además todos los gates P3/P4, contratos, syntax-check, inventario,
  ansible-lint y yamllint. Ansible-lint mantuvo 0 fallos y 575 warnings
  históricos.

## Evidencia A9

- Debian CIS 7.1.2 dispone de audit, remediation y verification independientes
  bajo `section_07_maintenance/7_1_2_passwd_backup_permissions/`, además de
  wrappers mode-first compatibles.
- El adaptador declara `/etc/passwd-` en `root:root` y modo `0644` o más
  restrictivo sin bits de ejecución. Reutiliza únicamente el mecanismo técnico
  de permisos fijos; no se añadió una entrada semántica común porque falta citar
  la fuente exacta del benchmark Ubuntu 24.04.
- La auditoría inicial observó `0644 root:root` y clasificó `PASS` con
  `changed=0`. Una deriva controlada a `0666` clasificó `FAIL` sin cambios;
  check mode predijo solo `0666 -> 0644`, la primera convergencia corrigió el
  modo y la segunda terminó con `changed=0`.
- Un path deliberadamente ausente clasificó `FAIL`; la remediación fue rechazada
  por `ansible.builtin.file` y no creó el archivo. Verification independiente y
  ping final pasaron sobre el path real.
- El gate confirmó que la remediación deshabilitada no cambia nada y que el
  master gate sin confirmación canary es rechazado. No se relajó ningún gate.
- Pasaron contratos, los syntax-check de todos los entry points, ansible-lint,
  yamllint y ShellCheck. Ansible-lint mantuvo 0 fallos y 575 warnings históricos.

## Evidencia A10

- `cis_ubuntu_2404/tasks/main.yml` dejó de importar el entry point principal de
  `cis_benchmark`. Ahora compone setup y las siete secciones mediante imports
  estáticos propios; cada hoja delega a un `tasks_from` histórico acotado.
- `cis_benchmark/tasks/main.yml` conserva compatibilidad y consume los mismos
  ocho entry points raíz. Las tareas internas, helpers dinámicos, handlers,
  defaults, condiciones, orden y tags no se reescribieron.
- El setup registra `handlers/main.yml` una sola vez. Las siete importaciones de
  sección usan `handlers_from: none.yml` para no duplicar handlers en el play.
- Antes y después del corte, el grafo Ubuntu produjo exactamente SHA-256
  `3ee9d36be76b0a8fba22eb53fcae10908be183ebb13858353ed68c3baa8a4ecd`
  para `--list-tasks` y
  `31a9b8a3c896b81ff5720271acf5b60e3a1bb076ef46314a6abe11c279ccd283`
  para `--list-tags`.
- Toda remediación canónica Ubuntu requiere ahora el master gate
  `cis_ubuntu_2404_remediation_enabled=true` y tags explícitos, además de todos
  los gates históricos. El default es `false`; no se modificó ningún gate
  crítico ni se interpretaron tags Level 1/2 como autorización suficiente.
- `test_ubuntu_adapter_graph.sh` valida permanentemente propiedad del grafo,
  paridad de tareas/tags, remediación deshabilitada, rechazo de ejecución global
  y check mode dirigido sobre CIS 3.3.10.
- Pasaron todos los syntax-check, contratos, gates P3/P4, el gate del grafo,
  ShellCheck, yamllint y ansible-lint. Este último mantuvo 0 fallos y 575
  warnings históricos; no se ejecutó hardening global real sobre Ubuntu.

## Evidencia A11

- Debian CIS 7.1.3 dispone de audit, remediation y verification bajo la única
  ruta canónica
  `section_07_maintenance/7_1_3_group_permissions/`; no se añadió un wrapper
  mode-first sin consumidores.
- El adaptador exige `/etc/group` regular, `root:root` y modo `0644` o más
  restrictivo sin ejecución. Reutiliza el mecanismo técnico común, pero no
  declara equivalencia de benchmark con Ubuntu 24.04.
- El gate común de permisos fijos sustituyó la prueba exclusiva de 7.1.2 para
  evitar scripts duplicados. Comprueba ambos controles de forma parametrizada.
- El baseline clasificó `PASS` con `changed=0`. La deriva controlada a `0666`
  clasificó `FAIL`; check mode predijo una corrección, la primera convergencia
  restauró `0644` y la segunda terminó con `changed=0`.
- La ausencia deliberada clasificó `FAIL`; la remediación fue rechazada y no
  creó el archivo. También pasaron los gates global y canary, verification
  independiente y el ping final.
- Pasaron contratos, el gate del grafo Ubuntu, todos los gates P3/P4,
  syntax-check, ShellCheck, yamllint y ansible-lint. Este último mantuvo
  0 fallos y 575 warnings históricos.
