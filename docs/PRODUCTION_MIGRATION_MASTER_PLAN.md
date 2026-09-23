# Plan maestro de migración y preparación para producción

> **Future and non-normative.** This plan describes proposed outcomes, not
> current behavior or support. Use [SUPPORT.md](SUPPORT.md) for the current
> authority. In particular, Docker, Ubuntu 22.04, and Debian 11 remain
> unsupported, and Debian 12 remains canary-only.

## 1. Propósito

Este documento define la evolución del proyecto de hardening GNU/Linux hacia
una plataforma profesional, modular, granular, idempotente, auditable y
preparada para producción. Es un plan de ejecución; no certifica cumplimiento
CIS ni declara soporte para plataformas que todavía no se han probado.

El alcance funcional prioritario es:

- Ubuntu Server 24.04 con su benchmark CIS correspondiente.
- Debian 12 con CIS Debian Linux 12 Benchmark v1.1.0.
- Ubuntu 22.04 y Debian 11 como compatibilidad técnica futura mientras no se
  disponga de sus benchmarks licenciados y versionados.
- Hardening posterior de imágenes de contenedor basadas en Ubuntu y Debian,
  limitado a controles aplicables dentro de una imagen.
- Integración desacoplada con SIEM, automatización CI/CD y procesos DevSecOps.

## 2. Restricciones y afirmaciones permitidas

1. Solo Ubuntu 24.04 y Debian 12 pueden evolucionar hacia estado CIS
   `released` con la documentación disponible.
2. Ubuntu 22.04 y Debian 11 se identificarán como `compatibility_only` hasta
   obtener y revisar sus benchmarks exactos.
3. Una tarea existente no equivale a un resultado `PASS`.
4. El proyecto automatiza hardening y verificación, pero no emite por sí mismo
   una certificación CIS.
5. Los textos completos de CIS requieren revisión de licencia antes de
   publicarse o redistribuirse.
6. El perfil inicial recomendado es Level 1 Server. Level 2 será opt-in por
   control; los controles Workstation estarán desactivados salvo aprobación.
7. Ansible se ejecutará únicamente desde un nodo de control autorizado. En el
   laboratorio actual ese nodo es `ansible-control`.

## 3. Principios arquitectónicos

### 3.1 Separar política y mecanismo

El adaptador de plataforma decide qué exige el benchmark. Un rol común ejecuta
únicamente mecanismos técnicos probados como equivalentes.

Ejemplo:

- política: Debian 12 permite grupo `root` o `shadow` para `/etc/shadow`;
- mecanismo: asegurar propietario, grupo permitido y modo máximo sin ampliar
  permisos existentes.

No se compartirán controles solo porque tengan títulos o números parecidos.

### 3.2 Liberación incremental

Estados de plataforma:

- `unsupported`: ejecución rechazada;
- `preflight_only`: facts y contrato sin cambios;
- `compatibility_only`: mecanismos portables sin afirmación CIS;
- `canary`: controles concretos con gates explícitos;
- `released`: conjunto documentado y probado para producción.

### 3.3 Seguridad por defecto

El estado esperado por CIS estará separado de la autorización de remediación.
El auditor podrá detectar un incumplimiento aunque el cambio automático esté
bloqueado.

Los controles críticos requerirán confirmaciones independientes para firewall,
SSH, sudo, PAM, bootloader, servicios, mounts, audit immutable y acciones que
puedan agotar disco.

### 3.4 No crear abstracciones vacías

Los roles comunes, verificadores y conectores se crearán al migrar el primer
caso real. No se añadirán plataformas ficticias ni roles sin pruebas.

## 4. Estructura objetivo

```text
ansible/
├── ansible.cfg
├── requirements.yml
├── requirements-dev.lock
├── inventories/
│   ├── local/
│   ├── staging/
│   └── production/
├── playbooks/
│   ├── audit/
│   │   ├── cis_ubuntu_2404.yml
│   │   └── cis_debian_12.yml
│   ├── hardening/
│   │   ├── cis_ubuntu_2404.yml
│   │   └── cis_debian_12.yml
│   ├── verify/
│   │   ├── cis_ubuntu_2404.yml
│   │   └── cis_debian_12.yml
│   ├── compatibility/
│   │   ├── ubuntu_2204.yml
│   │   └── debian_11.yml
│   └── operations/
│       ├── postflight.yml
│       └── collect_evidence.yml
├── profiles/
│   ├── level1_server/
│   ├── level2_server/
│   ├── ubuntu_2404/
│   ├── debian_12/
│   └── environments/
├── roles/
│   ├── cis_platform_preflight/
│   ├── cis_linux_common/
│   ├── cis_ubuntu_2404/
│   ├── cis_debian_12/
│   ├── compatibility_ubuntu_2204/
│   ├── compatibility_debian_11/
│   ├── cis_verify/
│   ├── cis_evidence/
│   ├── cis_postflight/
│   └── cis_siem_export/
├── plugins/
│   └── callback/
├── schemas/
│   ├── control.schema.json
│   └── evidence.schema.json
├── scripts/
│   ├── check_control.sh
│   ├── test_contracts.sh
│   └── test_integration.sh
└── tests/
    ├── contracts/
    ├── common/
    ├── ubuntu_2404/
    ├── debian_12/
    └── compatibility/
```

Esta es una estructura objetivo. Los movimientos se harán por fases y con
wrappers de compatibilidad para no romper comandos existentes.

## 5. Responsabilidad de los roles

### `cis_platform_preflight`

- detectar plataforma, versión y arquitectura;
- cargar catálogo interno;
- validar estado de liberación;
- validar entorno y gates;
- impedir que un adaptador se ejecute sobre otra plataforma.

No implementará controles CIS.

### `cis_linux_common`

Mecanismos compartidos y parametrizados que hayan demostrado equivalencia en
Ubuntu y Debian. No contendrá decisiones de benchmark ni una lista global de
controles habilitados.

### Adaptadores de plataforma

`cis_ubuntu_2404` y `cis_debian_12` serán responsables de:

- IDs y versión del benchmark;
- Level 1/Level 2 y Server/Workstation;
- Automated/Manual;
- aplicabilidad;
- rutas, paquetes, unidades y datos propios;
- selección de mecanismos comunes;
- excepciones y estado de liberación.

### `cis_verify`

Solo lectura. No instalará paquetes, no modificará archivos, no notificará
handlers, no reiniciará servicios y no cambiará cuentas o firewall.

### `cis_evidence`

Normalizará resultados, eliminará datos sensibles y generará evidencia por
host, control y ejecución.

### `cis_postflight`

Validará acceso y salud después de cambios: SSH, sudo, red, firewall, servicios,
espacio, reboot y conectividad Ansible.

### `cis_siem_export`

Transformará evidencia normalizada en formatos de transporte. No contendrá
credenciales ni lógica específica de un proveedor dentro de los controles.

## 6. Catálogo de controles

Cada control deberá disponer de metadata equivalente a:

```yaml
control_key: account_files_passwd_permissions
platform: debian_12
benchmark: CIS Debian Linux 12 Benchmark v1.1.0
benchmark_control: 7.1.1
profile: level1_server
classification: automated
applicable: true
risk: low
reboot_required: false
mechanism: fixed_file_permissions
audit_entry: audit/account_files.yml
remediation_entry: remediation/account_files.yml
verification_entry: verification/account_files.yml
rollback: not_required
release_status: tested_converged
```

El catálogo debe permitir comparar controles semánticamente, no solo por ID.

## 7. Estrategia de reutilización Ubuntu/Debian

Un control podrá migrar a `cis_linux_common` cuando cumpla todos estos puntos:

1. mismo estado final o diferencias expresables como datos;
2. mismas rutas, o paths parametrizados y validados;
3. paquetes y servicios explícitos por adaptador;
4. check mode correcto en ambas VMs;
5. primera convergencia correcta;
6. segunda convergencia con `changed=0`;
7. verificación independiente;
8. prueba post-reboot cuando corresponda;
9. evidencia separada por benchmark;
10. rollback o recuperación documentada.

Primeras verticales candidatas:

1. permisos de archivos de cuentas;
2. banners;
3. permisos de cron;
4. auditoría IPv6;
5. algunos sysctl;
6. módulos no utilizados;
7. sudo;
8. partes compatibles de SSH;
9. logging básico;
10. AIDE y auditd con datos de plataforma.

PAM, repositorios, GRUB y firewall conservarán adaptadores más específicos.

## 8. Auditoría, remediación y verificación

Cada vertical tendrá tres caminos separados:

```text
control/
├── audit.yml
├── remediation.yml
└── verification.yml
```

- `audit`: observa y clasifica;
- `remediation`: declara estado final y aplica solo con gates;
- `verification`: comprueba el resultado sin depender de que la remediación se
  haya ejecutado en la misma sesión.

Un playbook audit-only deberá poder probarse automáticamente para confirmar que
su recap siempre tiene `changed=0`.

## 9. Modelo de variables

### Defaults

- valores configurables;
- perfil recomendado;
- gates desactivados;
- comportamiento seguro documentado.

### Vars internas

- catálogo de plataforma;
- constantes de implementación;
- datos que el inventario no debe redefinir.

### Inventario

- `group_vars/all.yml`: política compartida del entorno;
- `group_vars/ubuntu_2404.yml`: política exacta Ubuntu;
- `group_vars/debian_12.yml`: política exacta Debian;
- `host_vars`: excepciones justificadas y revisadas.

Se evitarán diccionarios parciales que sustituyan accidentalmente políticas
completas. Se preferirán variables planas y namespaced para nuevas interfaces.

## 10. Inventarios y entornos

Local, staging y production tendrán la misma topología lógica:

```text
all
└── cis_targets
    ├── ubuntu_2404
    └── debian_12
```

Reglas de producción:

- host key checking obligatorio;
- credenciales mediante Vault o gestor externo;
- usuario de automatización no-root;
- `--limit` obligatorio;
- `serial` conservador;
- no copiar CIDR, NTP o allowlists del laboratorio;
- grupos funcionales separados de grupos de plataforma.

## 11. Toolchain reproducible

Versión de producción autorizada:

```text
ansible-core==2.21.2
```

Herramientas a instalar exclusivamente en `ansible-control`:

- ansible-core;
- ansible-lint;
- yamllint;
- pre-commit;
- ShellCheck;
- Gitleaks;
- herramienta de lock Python;
- colecciones fijadas.

Proceso requerido:

1. entorno virtual dedicado;
2. resolución de versiones compatibles;
3. lock versionado;
4. instalación limpia desde lock;
5. comprobación de versiones;
6. reconstrucción del nodo de control;
7. segunda instalación;
8. comparación de versiones y checks.

No se instalarán herramientas en el host de edición.

## 12. CI/CD y DevSecOps

### Pull request: checks estáticos

- whitespace y archivos finales;
- YAML;
- ansible-lint;
- ShellCheck;
- Gitleaks sobre cambios e historial;
- estructura del inventario;
- syntax check;
- lista de hosts/tags/tasks;
- contratos de aislamiento;
- dependencias y licencias;
- enlaces y documentación.

### Integración en laboratorio

Inicialmente manual y reproducible:

1. VMs limpias;
2. ping inicial;
3. audit-only;
4. `--check --diff` por control;
5. primera convergencia;
6. verificación funcional;
7. segunda convergencia;
8. exigir `changed=0`;
9. postflight;
10. reboot si aplica;
11. evidencia sanitizada.

### Integración futura

La convergencia CI necesitará un runner efímero compatible con Windows,
VirtualBox y Vagrant. Los runners hospedados solo ejecutarán análisis estático
mientras no exista ese entorno.

### Promoción

```text
audit → check → canary → verify → second convergence → observation → rollout
```

## 13. Evidencia y logging de automatización

Cada ejecución debe tener un `run_id` y registrar:

- timestamp UTC;
- commit y versión de colección;
- entorno;
- host lógico y plataforma;
- benchmark y control;
- tarea audit/remediation/verification;
- resultado;
- cambio realizado;
- handler ejecutado;
- reboot pendiente;
- excepción aprobada;
- identidad de automatización;
- change ticket en producción.

Formato normalizado propuesto:

```yaml
schema_version: 1
run_id: 2026-08-29T010000Z-change-1234
platform: debian_12
benchmark: CIS Debian Linux 12 Benchmark v1.1.0
control: 7.1.5
profile: level1_server
applicable: true
expected: compliant
observed: compliant
result: PASS
remediation_executed: false
changed: false
reboot_required: false
```

Resultados permitidos:

- `PASS`;
- `FAIL`;
- `MANUAL`;
- `NOT_APPLICABLE`;
- `ERROR`;
- `EXCEPTION`.

Los logs no deberán incluir passwords, claves privadas, tokens, Vault data,
contenido de shadow ni diffs sensibles. La salida `--diff` será un artefacto
restringido, no un log público de SIEM.

## 14. Integración neutral con SIEM

La arquitectura no dependerá de un fabricante. El pipeline interno generará un
evento canónico y los conectores podrán exportarlo mediante:

- JSON/JSON Lines;
- syslog con TLS;
- CEF cuando sea requerido;
- HTTP collector autenticado;
- archivo local recogido por un agente;
- cola o bus de eventos futuro.

Campos mínimos para correlación:

- `event.category=configuration`;
- `event.action=audit|remediate|verify|drift`;
- `event.outcome=success|failure|unknown`;
- host, plataforma, control, run ID y change ID;
- severidad;
- estado anterior y posterior sanitizados;
- justificación o excepción.

Los conectores SIEM se configurarán por entorno y sus secretos se mantendrán en
Vault o un gestor externo.

## 15. Detección de deriva, puertos y firewall

Ansible programado permite detectar deriva periódica, pero no sustituye IDS,
EDR, auditd o telemetría en tiempo real. Para detectar que un atacante abre un
puerto se necesitan dos capas.

### Capa casi en tiempo real

- auditd o tecnología equivalente observando configuraciones de firewall;
- logging de UFW y kernel;
- eventos de cambios de unidades y servicios;
- telemetría de sockets/procesos mediante agente de seguridad cuando exista;
- envío remoto al SIEM;
- alertas por cambios fuera de ventana y sin change ID.

### Capa periódica de reconciliación

Auditorías Ansible read-only:

- listeners TCP/UDP y proceso propietario;
- estado y reglas UFW;
- políticas default;
- allowlist aprobada;
- servicios habilitados;
- hashes de archivos gestionados;
- sysctl;
- módulos cargados;
- cambios en SSH, sudo, PAM, logging y auditd.

Frecuencia propuesta:

- cada 15 minutos: puertos, UFW y servicios críticos, si el impacto está medido;
- diaria: controles rápidos Level 1 y drift de configuración;
- semanal: auditoría completa no disruptiva;
- mensual: scans costosos y revisión de excepciones;
- después de cada cambio: verificación inmediata y postflight.

Una apertura de puerto no justificada generará al menos:

```text
severity: high
action: unauthorized_port_detected
listener: protocolo/dirección/puerto
process: nombre/pid cuando sea seguro
firewall_rule_present: true|false
change_id: missing
response: alert_only
```

La respuesta automática será `alert_only` por defecto. Cerrar automáticamente
un puerto puede causar una indisponibilidad y requerirá una política aprobada,
allowlist completa, consola de recuperación y gate específico.

## 16. Logging del sistema objetivo

La estrategia debe incluir:

- journald persistente y rotación;
- rsyslog cuando sea el backend elegido;
- forwarding remoto cifrado y autenticado;
- permisos de logs;
- retención dimensionada;
- auditd y reglas relevantes;
- sincronización horaria;
- protección ante disco lleno;
- separación entre logs operativos, seguridad y evidencia Ansible.

No se considerará lista para producción una integración remota sin TLS cuando
la red no sea confiable.

## 17. UFW para Ubuntu y Debian

UFW será el estándar inicial de ambas plataformas. La política común describirá
intención; la implementación validará paquetes, servicios y comportamiento por
distribución.

Requisitos:

- preservar SSH antes de default deny;
- fuentes de administración explícitas;
- política de salida declarada;
- IPv6 coherente entre kernel y UFW;
- inventario de listeners;
- detección de reglas no declaradas;
- huella de política;
- backup y consola;
- confirmación antes de reset autoritativo;
- log de cambios y drift;
- postflight de conectividad.

nftables e iptables no se presentarán como opciones seguras hasta tener
implementación y pruebas completas.

## 18. Compatibilidad Ubuntu 22.04 y Debian 11

Sin benchmark exacto, solo se reutilizarán mecanismos portables:

- permisos de archivos de cuentas;
- banners;
- permisos de cron;
- algunos sysctl;
- auditoría de módulos;
- umask;
- cuentas y shells;
- sudo compatible;
- partes de SSH verificadas contra la versión instalada;
- logging básico;
- AIDE/auditd con adaptación.

No se declararán CIS en esas versiones:

- repositorios;
- PAM completo;
- GRUB;
- firewall como cumplimiento CIS;
- algoritmos SSH;
- servicios por paquete;
- reglas audit específicas;
- retención.

Cada plataforma comenzará como `compatibility_only` y tendrá pruebas propias.

## 19. Imágenes de contenedor, fase posterior

El hardening de imágenes no heredará automáticamente el perfil de servidor. Se
creará una interfaz separada para imágenes Ubuntu y Debian.

Controles candidatos:

- usuario no-root;
- permisos de archivos;
- cuentas bloqueadas y shells no interactivos;
- ausencia de passwords vacíos;
- retirada de SSH y sudo no requeridos;
- eliminación de paquetes y herramientas de build;
- SUID/SGID no autorizados;
- repositorios y certificados;
- actualización durante build;
- limpieza de caches;
- SBOM;
- secret scanning;
- vulnerability scanning;
- metadata OCI;
- healthcheck cuando aplique;
- prueba funcional y firma.

No aplican dentro de una imagen:

- kernel y módulos;
- UFW;
- sysctl global;
- GRUB;
- auditd como daemon;
- mounts y particiones;
- NTP;
- systemd, salvo diseño especial;
- firewall del host.

Docker se abordará solo después de liberar el proyecto de servidores.

## 20. Recuperación y rollback

Cada dominio crítico tendrá runbook:

- SSH: consola, backup, `sshd -t`, restauración y conexión nueva;
- sudo: backup y `visudo -cf`;
- PAM: consola, perfiles anteriores y prueba de login;
- UFW: allowlist de administración, backup y reset controlado;
- GRUB: snapshot, consola y recuperación de boot;
- auditd: reglas previas y consideración de immutable;
- AIDE: base candidata y promoción separada;
- mounts: fstab validado y recuperación por consola;
- servicios: dependencia, orden de parada y restauración.

## 21. Plan de migración por fases

### P0 — Saneamiento

- clasificar cambios;
- respaldo Git;
- commits por dominio;
- rotar clave;
- reconstruir laboratorio;
- secret scan completo;
- limpiar y verificar historial;
- documentar eliminación de clones antiguos.

### P1 — Toolchain

- entorno virtual;
- Ansible 2.21.2;
- lint, pre-commit, ShellCheck y Gitleaks;
- lock;
- instalación reproducible;
- reconstrucción y comparación.

### P2 — Baseline ejecutable

- inventario;
- syntax;
- lint;
- contratos;
- gates negativos;
- check mode;
- convergencia;
- idempotencia;
- conectividad;
- reboot selectivo.

### P3 — Separar audit/remediation/verification

- crear interfaces reales;
- migrar una vertical piloto;
- probar audit con `changed=0`;
- conservar wrappers compatibles.

### P4 — Verticales comunes

1. archivos de cuentas;
2. banners;
3. cron;
4. red read-only;
5. sysctl;
6. módulos;
7. servicios/clientes;
8. tiempo;
9. SSH;
10. sudo;
11. UFW;
12. PAM;
13. logging;
14. auditd;
15. AIDE;
16. mantenimiento.

### P5 — Debian 12 released

- implementar por sección;
- mantener gates;
- evidencia por control;
- UFW como motor único inicial;
- completar Definition of Done.

### P6 — Evidencia y SIEM

- schema;
- callback/eventos;
- sanitización;
- almacenamiento;
- conector syslog TLS y JSON iniciales;
- pruebas de entrega y caída del colector.

### P7 — Producción

- inventarios seguros;
- Vault/secret manager;
- staging;
- canary;
- rollback;
- observabilidad;
- promoción gradual;
- runbooks.

### P8 — Compatibilidad anterior

- Ubuntu 22.04;
- Debian 11;
- mecanismos portables;
- etiqueta `NOT_CIS_VALIDATED`;
- benchmarks futuros cuando estén disponibles.

### P9 — Imágenes

- builder aislado;
- Docker fijado;
- perfiles de imagen;
- SBOM, secretos y vulnerabilidades;
- pruebas y firma.

## 22. Definition of Done por control

Un control está terminado cuando dispone de:

1. benchmark, ID, perfil y clasificación;
2. aplicabilidad y riesgo;
3. comparación Ubuntu/Debian;
4. política y variables documentadas;
5. audit separado;
6. remediación idempotente;
7. verificación independiente;
8. check mode;
9. dos convergencias reales;
10. postflight;
11. reboot si aplica;
12. rollback;
13. evidencia sanitizada;
14. tags canónicos;
15. matriz actualizada.

## 23. Definition of Done para servidores

- Ubuntu 24.04 `released`.
- Debian 12 `released`.
- matriz por control.
- Level 1 Server cubierto o con excepciones aprobadas.
- Level 2 opt-in.
- audit/remediation/verification separados.
- controles comunes probados en ambas VMs.
- gates y rollback para dominios críticos.
- toolchain fijada.
- lint y secret scan en verde.
- pruebas de convergencia e idempotencia.
- persistencia post-reboot.
- evidencia y exportación SIEM.
- inventarios production seguros.
- monitoreo de deriva.
- sin claves en Git.
- documentación sin afirmaciones de certificación no demostradas.

## 24. Riesgos y decisiones pendientes

- licencia y versiones exactas de benchmarks;
- capacidad de un runner futuro para VirtualBox;
- SIEM concreto y formato preferido;
- NTP, retención, logging TLS, repositorios y allowlists de producción;
- tratamiento de respuestas automáticas ante drift;
- ventana y frecuencia de auditorías costosas;
- política de excepciones y su caducidad.

Hasta resolver estos valores, el proyecto debe ofrecer interfaces y ejemplos,
pero no inventar configuración de producción.
