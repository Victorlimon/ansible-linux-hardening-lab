# Registro de ejecución de la migración

Este documento registra acciones realmente ejecutadas. El plan y los estados
objetivo permanecen en `PRODUCTION_MIGRATION_MASTER_PLAN.md`.

## Convenciones

- `COMPLETED`: ejecutado y verificado.
- `PARTIAL`: ejecutado parcialmente o con una comprobación pendiente.
- `BLOCKED`: no puede continuar sin prerrequisito o aprobación.
- `PLANNED`: todavía no ejecutado.

## 2026-08-29 — Inicio de P0

### Clasificación del repositorio — COMPLETED

- Rama: `main`.
- Remoto: repositorio privado GitHub.
- Baseline previo: un único commit `c053301`.
- Estado inicial observado: 88 archivos rastreados modificados y múltiples
  archivos nuevos de arquitectura, Debian, documentación y DevSecOps.
- No había cambios en staging.
- La clave `lab/vagrant/ssh/id_rsa` y su pública permanecían rastreadas por el
  commit base aunque estaban eliminadas del working tree.

### Respaldo previo — COMPLETED

Se generó fuera del repositorio, bajo `/tmp/opencode/`:

- `ansible_prod_before_p0.bundle`: referencias Git;
- `ansible_prod_worktree.patch`: diff binario rastreado;
- `ansible_prod_index.patch`: diff de staging;
- `ansible_prod_untracked.tar.gz`: archivos nuevos no ignorados;
- `ansible_prod_before_p0.sha256`: checksums.

Los cuatro artefactos pasaron `sha256sum --check`. Este respaldo es local y
temporal; antes de operaciones irreversibles deberá copiarse a almacenamiento
privado persistente aprobado por el propietario.

### Herramientas de saneamiento en el host — BLOCKED

No estaban instalados:

- `git-filter-repo`;
- Gitleaks;
- pre-commit;
- ShellCheck.

No se instalarán en el host. La toolchain se preparará dentro de
`ansible-control`.

### Rotación de clave — PARTIAL

- Se generó localmente una clave efímera nueva e ignorada por Git.
- Todavía no fue desplegada en las VMs.
- La clave histórica debe considerarse autorizada hasta reemplazar
  `authorized_keys` o reconstruir las VMs.
- El script de provisión fue ajustado para transferir claves mediante
  `vagrant upload` en lugar de incluir material privado en argumentos remotos.

### Laboratorio — PARTIAL

- Las VMs se encontraron apagadas.
- `make start` inició parcialmente el laboratorio, con timeouts de boot
  conocidos durante el arranque secuencial.
- No se ejecutó `make destroy`.
- No se ejecutó provisión ni instalación de paquetes.

## Estado de fases

| Fase | Estado | Próximo gate |
|---|---|---|
| P0 Saneamiento | PARTIAL | Consolidar cambios, desplegar clave y limpiar historial |
| P1 Toolchain | PLANNED | Nodo de control accesible y lock resuelto |
| P2 Baseline | PLANNED | P1 completada |
| P3 Separación audit/remediation/verification | PLANNED | Baseline verde |
| P4 Verticales comunes | PLANNED | Vertical piloto validada |
| P5 Debian released | PLANNED | Matriz y secciones probadas |
| P6 Evidencia/SIEM | PLANNED | Schema aprobado |
| P7 Producción | PLANNED | Gates, staging y runbooks |
| P8 Compatibilidad anterior | PLANNED | Servidores principales released |
| P9 Docker | DEFERRED | Proyecto de servidores concluido |

## 2026-09-01 — Consolidación y preparación de P1

### Consolidación Git — COMPLETED

Se crearon cuatro commits locales y no se realizó push:

- arquitectura Ubuntu/Debian y baseline de hardening;
- seguridad del laboratorio y eliminación de claves rastreadas;
- baseline DevSecOps;
- documentación y plan maestro de producción.

Después de los commits, `git status --short` quedó vacío y
`git diff --check` no reportó errores.

### Diseño de toolchain — PARTIAL

- `ansible-core` se fijó en 2.21.2.
- La ubicación prevista es `/home/vagrant/.venvs/ansible-cis`.
- La primera provisión generará `requirements-dev.lock` con hashes dentro de
  `ansible-control`; después el lock será obligatorio y versionado.
- Se fijaron las versiones observadas de python3-venv, pip, ShellCheck,
  Gitleaks y git-filter-repo disponibles para Ubuntu 24.04 del nodo de control.
- Se eliminó el `apt upgrade` implícito del flujo de provisión.
- La instalación todavía no se ejecutó.

## 2026-09-01 — Ejecución de P1 y baseline parcial P2

### Rotación y provisión — PARTIAL

- Se corrigieron las rutas WSL usadas por `vagrant upload`.
- La clave efímera ED25519 quedó instalada para el usuario remoto `ansible` en
  Debian 12 y su par privado/público quedó disponible únicamente para
  `vagrant` en `ansible-control`.
- Debian 12 pasó `ansible.builtin.ping` y una recopilación de facts con
  `become`; se confirmó Debian 12.15.
- Ubuntu 24.04 dejó de aceptar conexiones Vagrant durante la reprovisión y no
  fue alcanzable desde `ansible-control` (`timeout`/`No route to host`). No se
  ejecutaron remediaciones nuevas sobre Ubuntu.
- `make provision-lab` permanece parcial hasta reconstruir o recuperar Ubuntu.

### Toolchain reproducible — COMPLETED

- Se instaló y verificó `ansible-core 2.21.2` exclusivamente dentro de
  `ansible-control` en `/home/vagrant/.venvs/ansible-cis`.
- Se instalaron las colecciones fijadas `ansible.posix 1.5.4` y
  `community.general 8.6.0`.
- Se generó `ansible/requirements-dev.lock` con hashes y `--allow-unsafe` para
  fijar también `pip` y `setuptools`.
- Una instalación posterior con `pip install --require-hashes` terminó
  correctamente.
- También quedaron disponibles ansible-lint 26.8.0, yamllint 1.38.0,
  ShellCheck 0.9.0, Gitleaks 8.16.0 y git-filter-repo 2.38.0.

### Baseline estático y contratos — PARTIAL

- `ansible --version` confirmó Core 2.21.2 y el `ansible.cfg` del proyecto.
- El inventario se interpretó correctamente.
- Los cinco entry points pasaron `--syntax-check`.
- Los contratos de aislamiento Ubuntu/Debian pasaron.
- `ansible-doc` resolvió los módulos `file`, `stat`, `assert`, `slurp`,
  `set_fact` y `debug` antes de las pruebas de los canarios Debian.
- ansible-lint procesó 138 archivos y reportó 518 infracciones preexistentes;
  el baseline todavía no está verde y no se ocultaron los resultados.
- La ejecución inicial de yamllint y Gitleaks no fue válida para el repositorio
  completo: Vagrant solo había montado `ansible/`, por lo que yamllint recorrió
  colecciones instaladas y Gitleaks no encontró `.git`.
- Se corrigió el `Vagrantfile` para montar el repositorio completo en
  `/home/vagrant/ansible`; la corrección requiere reconstrucción o recarga del
  nodo de control antes de repetir ambos checks.

### Canarios Debian 12 — COMPLETED

- Se ejecutó primero `--check --diff` limitado a `debian12` y a los tags
  `cis_7_1_1,cis_7_1_5` con los gates canario explícitos.
- El check, la primera ejecución real y la segunda ejecución real finalizaron
  con `changed=0`, `unreachable=0` y `failed=0`.
- Las verificaciones de propietario, grupo y permisos de `/etc/passwd` y
  `/etc/shadow` pasaron; el ping final también pasó.

## Estado de fases actualizado

| Fase | Estado | Próximo gate |
|---|---|---|
| P0 Saneamiento | PARTIAL | Secret scan Git válido y limpieza del historial |
| P1 Toolchain | COMPLETED | Verificarla tras reconstrucción limpia |
| P2 Baseline | PARTIAL | Recuperar Ubuntu, repetir lint/yamllint/Gitleaks |
| P3 Separación audit/remediation/verification | PLANNED | Baseline aceptado |
| P4 Verticales comunes | PLANNED | Vertical piloto validada |
| P5 Debian released | PLANNED | Matriz y secciones probadas |
| P6 Evidencia/SIEM | PLANNED | Schema aprobado |
| P7 Producción | PLANNED | Gates, staging y runbooks |
| P8 Compatibilidad anterior | PLANNED | Servidores principales released |
| P9 Docker | DEFERRED | Proyecto de servidores concluido |

## 2026-09-01 — Reconstrucción limpia y saneamiento local P0

### Reconstrucción del laboratorio — COMPLETED

- El propietario reconstruyó las tres VMs y `make status` confirmó
  `ansible-control`, `ubuntu24` y `debian12` en ejecución.
- `make provision-lab` completó la rotación de identidad, la instalación desde
  el lock con hashes y las colecciones fijadas.
- Ubuntu 24.04 y Debian 12 pasaron ping, facts con `become`, contratos de
  aislamiento y los cinco syntax checks.
- El preflight Ubuntu en `--check --diff` finalizó con `changed=0`.
- El gate negativo Debian falló de la forma esperada cuando faltó la
  confirmación canario.
- Los canarios Debian 7.1.1 y 7.1.5 pasaron `--check --diff`, dos ejecuciones
  reales con `changed=0` y ping final en ambos nodos.

### Calidad estática — PARTIAL

- yamllint ya usó la configuración real del repositorio. Se corrigieron sus
  errores bloqueantes y la comprobación termina correctamente; conserva
  warnings no bloqueantes de deuda histórica.
- ansible-lint confirmó que el perfil `min` pasa, pero el perfil `basic`
  requerido reportó 585 infracciones. La deuda no fue silenciada.

### Purga de la clave histórica — COMPLETED LOCAL / REMOTE PENDING

- Gitleaks confirmó un único hallazgo previo: la clave privada
  `lab/vagrant/ssh/id_rsa` en el antiguo commit `c053301`.
- Antes de reescribir se creó un respaldo nuevo en `/tmp/opencode` con bundle,
  patches de índice/working tree, archivos no rastreados y checksums válidos.
- `git-filter-repo` eliminó la clave privada y su pública de los seis commits
  locales; los hashes de toda la rama cambiaron.
- Se eliminaron refs temporales de stash/replace, se expiraron reflogs y se
  ejecutó `git gc --prune=now`; `git fsck --full` terminó sin errores.
- El objeto antiguo `c053301` ya no existe localmente, las claves efímeras no
  están rastreadas y permanecen cubiertas por `.gitignore`.
- Gitleaks volvió a escanear los seis commits y finalizó sin hallazgos.
- No se realizó push. `origin/main` todavía contiene la historia comprometida;
  su reemplazo requerirá coordinación y un push no fast-forward explícito.

## 2026-09-01 — Cierre local de P2

### Baseline auditable de ansible-lint — COMPLETED

- Se generó y revisó `.ansible-lint-ignore` con 96 parejas archivo/regla.
- Siete hallazgos de formato YAML se corrigieron antes del cierre; las 585
  infracciones iniciales quedaron en 578 warnings históricos explícitos.
- Con el perfil `basic`, ansible-lint procesó 138 archivos y terminó con cero
  fallos. La salida conserva los 578 warnings como evidencia visible.
- El baseline no se debe regenerar automáticamente. Su formato opera por
  archivo/regla, por lo que las revisiones deben impedir instancias nuevas de
  reglas ya exceptuadas en el mismo archivo y retirar entradas al sanear deuda.

### Gates finales desde ansible-control — COMPLETED

- Se confirmó `ansible-core 2.21.2` y la configuración versionada del proyecto.
- `ansible-doc` resolvió `ansible.builtin.import_tasks`.
- El inventario, los cinco syntax checks y los contratos de aislamiento
  Ubuntu/Debian pasaron.
- yamllint terminó correctamente con warnings históricos no bloqueantes.
- ShellCheck terminó sin hallazgos sobre los scripts versionados.
- Gitleaks escaneó los seis commits saneados y no encontró secretos.
- `ansible.builtin.ping`, con inventario local y límites separados, devolvió
  `pong` para `ubuntu24` y `debian12`.
- No se ejecutó ninguna remediación en este cierre.

## Estado de fases al cierre local

| Fase | Estado | Próximo gate |
|---|---|---|
| P0 Saneamiento | COMPLETED LOCAL / REMOTE PENDING | Push coordinado con lease |
| P1 Toolchain | COMPLETED | Mantener lock y hashes |
| P2 Baseline | COMPLETED | Evitar regresiones y reducir warnings |
| P3 Separación audit/remediation/verification | PLANNED | Vertical piloto |
| P4 Verticales comunes | PLANNED | Vertical piloto validada |
| P5 Debian released | PLANNED | Matriz y secciones probadas |
| P6 Evidencia/SIEM | PLANNED | Schema aprobado |
| P7 Producción | PLANNED | Gates, staging y runbooks |
| P8 Compatibilidad anterior | PLANNED | Servidores principales released |
| P9 Docker | DEFERRED | Proyecto de servidores concluido |

## 2026-09-01 — Cierre remoto de P0 y vertical piloto P3

### Historia remota saneada — COMPLETED

- Se obtuvo `origin/main` y se confirmó el tip comprometido exacto
  `c0533011289273f86d12b8fc2399ae55b5a7d9f0`.
- El reemplazo autorizado se realizó con un lease explícito; `origin/main`
  quedó en `1d06d54c955ad9f4f5fd07054fe76f2a4133eb2f`.
- Gitleaks volvió a escanear las nueve revisiones alcanzables y no encontró
  secretos. Los clones anteriores requieren reemplazo o reset coordinado.

### P3 — CIS Debian 12 7.1.1 — COMPLETED

- Se crearon entry points canónicos independientes en `playbooks/audit/`,
  `playbooks/hardening/` y `playbooks/verify/`; los entry points Debian de la
  raíz permanecen como wrappers compatibles.
- El control 7.1.1 separa físicamente `audit`, `remediation` y `verification`.
  Audit y verify no usan handlers, no cambian contenido y no requieren reboot.
- La auditoría inicial clasificó `/etc/passwd` conforme y terminó con
  `changed=0`.
- Se indujo una deriva controlada de modo `0644` a `0744`. La auditoría la
  clasificó `FAIL` con `changed=0` y la verificación independiente falló sin
  cambios.
- Sin gates, hardening terminó con `changed=0`. Con habilitación de remediación
  pero sin confirmación canario, el gate rechazó la ejecución y la deriva
  permaneció intacta.
- Con ambos gates, `--check --diff` predijo exactamente `0744 -> 0644` sin que
  la verificación mezclada produjera un falso fallo.
- La primera convergencia realizó un cambio; la verificación independiente pasó
  con `changed=0`; la segunda convergencia terminó con `changed=0`.
- La auditoría final clasificó `PASS` con modo `0644` y el ping final devolvió
  `pong`.
- `scripts/test_p3_pilot.sh` automatiza el gate read-only de auditoría,
  verificación y conectividad sin inducir deriva ni remediar.

## Estado de fases después del piloto P3

| Fase | Estado | Próximo gate |
|---|---|---|
| P0 Saneamiento | COMPLETED | Mantener secret scan y retirar clones antiguos |
| P1 Toolchain | COMPLETED | Mantener lock y hashes |
| P2 Baseline | COMPLETED | Evitar regresiones y reducir warnings |
| P3 Separación audit/remediation/verification | COMPLETED | Iniciar P4 |
| P4 Verticales comunes | PLANNED | Comparar 7.1.1 en Ubuntu y Debian |
| P5 Debian released | PLANNED | Matriz y secciones probadas |
| P6 Evidencia/SIEM | PLANNED | Schema aprobado |
| P7 Producción | PLANNED | Gates, staging y runbooks |
| P8 Compatibilidad anterior | PLANNED | Servidores principales released |
| P9 Docker | DEFERRED | Proyecto de servidores concluido |

## 2026-09-01 — P4 vertical común CIS 7.1.1

### Extracción a `cis_linux_common` — COMPLETED

- Se creó un mecanismo parametrizado de permisos de archivo fijo con caminos
  separados de audit, remediation y verification. El rol común no decide IDs,
  benchmarks, habilitación ni autorización de cambios.
- Debian 12 conserva sus gates canario. Ubuntu 24.04 conserva los gates
  históricos `cis_section7_system` y
  `section7_system_7_1_system_file_permissions` para remediación.
- La tarea histórica Ubuntu 7.1.1 fue retirada para evitar doble ejecución.
- Se añadieron interfaces canónicas Ubuntu audit/hardening/verify y el wrapper
  histórico de hardening conserva su ruta.

### Integración cruzada — COMPLETED

- En ambas VMs, audit inicial clasificó `PASS` con `changed=0` y verify pasó.
- Se indujo deriva controlada `0644 -> 0744` en ambos `/etc/passwd`.
- Ambos audits clasificaron `FAIL` con `changed=0`; ambos verify fallaron sin
  modificar los objetivos.
- Check mode predijo `0744 -> 0644` en ambas plataformas.
- La primera convergencia realizó un cambio por host, las verificaciones
  independientes pasaron y la segunda convergencia terminó con `changed=0`.
- El gate read-only `scripts/test_p4_common.sh` terminó correctamente y ambos
  pings finales devolvieron `pong`. Este control no requiere reboot.

### Estado P4

P4 queda `IN_PROGRESS`: el primer mecanismo común está probado. La siguiente
vertical del plan es banners; requiere definir y aprobar el texto antes de
permitir remediación.

## 2026-09-02 — P4 banners, avance seguro

- La referencia Debian 12 confirma que el contenido es específico del sitio y
  debe revisarlo asesoría legal antes de modificar sistemas.
- Se implementaron audit, remediation y verification separados para Debian
  CIS 1.6.2. Audit nunca publica el contenido: solo informa metadata,
  presencia de información prohibida y clasificación.
- El banner Debian observado contiene información del sistema operativo; audit
  lo clasificó `FAIL` con `changed=0` y metadata `0644 root:root` conforme.
- Verification rechazó declarar `PASS` porque no existe texto aprobado.
- Remediation sin su gate específico terminó con `changed=0`; al habilitar el
  gate sin texto aprobado, falló de forma explícita antes de cambiar el archivo.
- En Ubuntu, el contenido de ejemplo de `/etc/motd`, `/etc/issue`,
  `/etc/issue.net`, SSH y GDM quedó protegido por
  `cis_benchmark_banner_text_approved=false`. El check mode por tags confirmó
  `changed=0` y no sustituyó banners.
- No se extrajo esta vertical a `cis_linux_common`: falta la referencia exacta
  Ubuntu 24.04 y la política legal aprobada. El gate automatizado es
  `scripts/test_p4_banners.sh`.

## 2026-09-02 — P4 vertical común CIS 2.4.1.2

- Se compararon CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 y CIS Debian Linux
  12 Benchmark v1.1.0. Ambos requieren `/etc/crontab` propiedad de `root:root`,
  sin permisos para grupo u otros, y consideran la subsección no aplicable si
  `cron` no está instalado.
- `cis_linux_common` ahora compone package facts con el mecanismo existente de
  permisos fijos. No instala `cron`, no crea `/etc/crontab` cuando el paquete no
  existe y reporta `NOT_APPLICABLE` en ese caso.
- Se retiró la tarea Ubuntu duplicada de CIS 2.4.1.2 y ambos adaptadores exponen
  caminos separados de audit, remediation y verification.
- Estado inicial: `0644 root:root` en Ubuntu 24.04 y Debian 12. Las auditorías
  clasificaron `FAIL` con `changed=0`.
- `--check --diff` predijo exclusivamente `0644 -> 0600` en cada VM. La primera
  convergencia cambió solo el modo; la segunda terminó con `changed=0`.
- Verification independiente pasó en ambas plataformas y los pings finales
  devolvieron `pong`.
- La recuperación no requiere restaurar contenido: se registró el modo previo
  `0644`; si una aplicación demuestra incompatibilidad, el mismo mecanismo
  declarativo puede restaurar temporalmente esa metadata tras aprobar la
  excepción y deshabilitar el selector del control.
- La rama de paquete ausente se probó con un contrato deliberadamente no
  aplicable: audit y remediation en check mode reportaron `NOT_APPLICABLE` con
  `changed=0`, sin ejecutar el mecanismo de archivo.
- El gate read-only posterior a la convergencia es `scripts/test_p4_cron.sh`.

## 2026-09-02 — P4 vertical común read-only CIS 3.1.1

- Se compararon los controles CIS 3.1.1 de Ubuntu 24.04 v1.0.0 y Debian 12
  v1.1.0. Ambos usan la misma decisión: IPv6 está deshabilitado si el parámetro
  del módulo no es `0`, o si los sysctl global y default son ambos `1`.
- La auditoría Debian se extrajo a `cis_linux_common`; la observación histórica
  Ubuntu, que solo leía el parámetro del módulo, fue sustituida por el mecanismo
  completo común.
- Los adaptadores exponen audit y verification independientes. No existe camino
  de remediation para este control manual; habilitar o deshabilitar IPv6 exige
  una decisión de política y una vertical posterior específica.
- Ubuntu y Debian observaron módulo `0`, sysctl global `0` y sysctl default `0`:
  estado `enabled`. Audit clasificó `MANUAL` y terminó con `changed=0`.
- Verification identificó el mismo estado con `changed=0`. Los hardening entry
  points ejecutados con `--check --diff --tags cis_3_1_1` también terminaron con
  `changed=0`, y los pings posteriores devolvieron `pong`.
- El contrato rechazó una política IPv6 deliberadamente inválida antes de
  interpretar la evidencia.
- No se requiere rollback porque no se escribió configuración ni se alteró la
  conectividad. El gate automatizado es `scripts/test_p4_network.sh`.

## 2026-09-02 — P4 vertical común sysctl CIS 3.3.10

- Se eligió `net.ipv4.tcp_syncookies=1` como primer sysctl común por su
  equivalencia entre Ubuntu 24.04 v1.0.0 y Debian 12 v1.1.0 y su bajo impacto
  operativo. CIS 3.3.1 quedó diferido porque desactivar forwarding requiere
  confirmar que el host no actúa como router, NAT, proxy o nodo CSP.
- `cis_linux_common` expone caminos separados de audit, remediation y
  verification. La observación lee `/proc`, obtiene la precedencia persistente
  con `systemd-sysctl --cat-config` y considera el archivo sysctl seleccionado
  por UFW. El único `command` es read-only, declara `changed_when: false` y
  falla explícitamente si no puede leer la configuración efectiva.
- Se consultó `ansible-doc` para `ansible.posix.sysctl`, `command`, `slurp` y
  `stat` bajo Ansible Core 2.21.2. La tarea Ubuntu histórica duplicada se retiró
  y ambos adaptadores conservan sus gates de política.
- El estado inicial fue runtime `1` sin definición persistente en ambas VMs.
  Audit clasificó `FAIL` con `changed=0`; `--check --diff` predijo una única
  alta en `/etc/sysctl.d/99-cis-network.conf` por plataforma.
- Tras confirmar `make status`, conectividad y check mode, la primera
  convergencia terminó con `changed=1` en cada VM. Verification pasó y la
  segunda convergencia terminó con `changed=0` en ambas.
- El gate `scripts/test_p4_sysctl.sh` confirmó audit `PASS`, runtime y
  persistencia `1`, verification independiente, `changed=0` y ping posterior
  en Ubuntu 24.04 y Debian 12.
- El baseline estricto de control pasó inventario, syntax-check, ansible-lint y
  yamllint. Ansible-lint mantuvo 0 fallos y 575 warnings históricos. También
  pasaron contratos, el piloto P3 y todos los gates P4 existentes.
- `scripts/check_host.sh` no pudo completar Gitleaks porque usa el subcomando
  no disponible `gitleaks git` con la versión instalada 8.16.0. El escaneo
  equivalente `gitleaks detect` se ejecutó por separado y no encontró
  filtraciones; ShellCheck pasó para el gate sysctl nuevo.

## 2026-09-02 — Sesión de arquitectura A1

- Se formalizó el trabajo por sesiones en `CIS_ARCHITECTURE_SESSIONS.md`: cada
  sesión limita su alcance a un control o preocupación arquitectónica y exige
  validación y evidencia independientes.
- `cis_linux_common` ahora documenta dos capas: entradas semánticas bajo
  `tasks/sections/` y mecanismos técnicos reutilizables. La invocación directa
  del rol se rechaza para exigir un control y modo explícitos mediante
  `tasks_from`.
- Como piloto read-only, CIS 3.1.1 se expuso en
  `sections/section_03_network/3_1_1_ipv6_status/`. Los adaptadores Ubuntu y
  Debian consumen esa ruta sin cambiar contratos, condiciones ni tags. El
  mecanismo y sus rutas anteriores permanecen compatibles.
- Pasaron syntax-check de audit/verification para ambas plataformas,
  `test_contracts.sh`, `test_p4_network.sh`, inventario, ansible-lint y yamllint.
  El gate mantuvo `changed=0` y ping posterior; ansible-lint mantuvo 0 fallos y
  575 warnings históricos.

## 2026-09-02 — Sesión de arquitectura A2

- Se capturó primero el baseline de CIS 7.1.1 en ambas VMs: audit `PASS`,
  `/etc/passwd` en `root:root` con modo `0644`, verification independiente,
  `changed=0` y conectividad correcta.
- Se añadieron entradas audit, remediation y verification bajo
  `sections/section_07_maintenance/7_1_1_passwd_permissions/`. Estas entradas
  delegan mediante imports estáticos al mecanismo `fixed_file_permissions`.
- Los adaptadores Ubuntu y Debian usan ahora la ruta semántica. No cambiaron
  los contratos, valores, condiciones, gates, tags ni el orden de ejecución;
  las rutas técnicas previas permanecen compatibles.
- Pasaron syntax-check de los seis entry points de ambas plataformas,
  `test_p4_common.sh`, `test_contracts.sh`, inventario, ansible-lint y yamllint.
  El gate posterior mantuvo `PASS`, `changed=0` y ping; ansible-lint conservó
  0 fallos y 575 warnings históricos.

## 2026-09-02 — Sesión de arquitectura A3

- Se capturó el baseline de CIS 2.4.1.2 antes del cambio: `/etc/crontab` estaba
  en `root:root` con modo `0600`; audit y verification pasaron con `changed=0`
  y conectividad correcta en Ubuntu 24.04 y Debian 12.
- Se añadieron entradas audit, remediation y verification bajo
  `sections/section_02_services/2_4_1_2_crontab_permissions/`. Estas delegan
  mediante imports estáticos al mecanismo `installed_package_fixed_file`.
- Los adaptadores usan ahora la ruta semántica sin cambiar contratos, gates,
  tags, valores ni orden. Las rutas técnicas anteriores siguen compatibles.
- El gate posterior mantuvo `PASS` en ambas plataformas y `NOT_APPLICABLE` con
  `changed=0` para un paquete deliberadamente ausente; no instaló `cron` ni
  creó archivos.
- Pasaron syntax-check de los seis entry points, `test_p4_cron.sh`,
  `test_contracts.sh`, inventario, ansible-lint y yamllint. Ansible-lint
  conservó 0 fallos y 575 warnings históricos.
