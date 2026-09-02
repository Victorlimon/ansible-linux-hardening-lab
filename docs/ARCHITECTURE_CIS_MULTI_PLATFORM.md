# Arquitectura CIS multiplataforma

## Alcance

El proyecto soporta hardening liberado para Ubuntu 24.04 x86_64. Debian 12
x86_64 dispone de controles canario explícitos contra CIS Debian Linux 12
Benchmark v1.1.0. Reconocer una plataforma no autoriza otras remediaciones.

## Principios

1. Separar política de benchmark, implementación Linux y datos de plataforma.
2. Reutilizar únicamente mecanismos demostrados equivalentes.
3. Conservar un mapeo y evidencia independientes por benchmark y versión.
4. Usar imports estáticos para secciones auditables y tags heredables.
5. Mantener inventarios separados por entorno y grupos por versión exacta.
6. Separar auditoría, remediación, evidencia y comprobaciones postflight.
7. Liberar Debian sección por sección sin relajar la protección Ubuntu actual.

## Estado objetivo incremental

```text
roles/
├── cis_platform_preflight/   # plataforma, arquitectura y gates
├── cis_ubuntu_2404/          # adaptador canónico Ubuntu
├── cis_debian_12/            # mapeo/política CIS Debian v1.1.0
├── cis_linux_common/          # controles equivalentes y mecanismos comunes
└── cis_benchmark/            # implementación Ubuntu histórica en migración
```

No se realizará una migración masiva. El rol `cis_benchmark` permanece como
implementación Ubuntu compatible mientras se extraen controles con pruebas.
Las capas comunes, evidencia y postflight se crearán únicamente cuando exista
un control real que las justifique; no se mantienen roles vacíos.

## Capas de un control común

`cis_linux_common` separa la navegación semántica de la reutilización técnica:

```text
adaptador de plataforma
  -> tasks/sections/section_<NN>_<dominio>/<control>/<modo>.yml
     -> mecanismo técnico (sysctl, permisos, observación, etc.)
        -> módulo Ansible con FQCN
```

- El adaptador define benchmark, variables, aplicabilidad, gates y tags.
- `sections/` permite localizar un control por su ID CIS y expone audit,
  remediation y verification como entradas separadas.
- El mecanismo técnico implementa una operación reutilizable sin decidir la
  política de una distribución.
- `tasks/main.yml` rechaza la invocación directa del rol común: siempre se debe
  seleccionar un control y un modo mediante `tasks_from`.

Las rutas se normalizan como
`section_<NN>_<dominio>/<ID_con_guiones_bajos>_<nombre>/<modo>.yml`. Durante la
migración, las rutas técnicas anteriores permanecen disponibles para mantener
compatibilidad. La referencia operativa del rol está en
`ansible/roles/cis_linux_common/README.md`.

## Trabajo por sesiones

Cada sesión modifica un solo control o una sola preocupación arquitectónica:

1. declarar alcance, riesgo y archivos permitidos;
2. capturar el comportamiento previo;
3. realizar el cambio estructural mínimo;
4. ejecutar syntax-check y el gate específico;
5. ejecutar regresiones compartidas;
6. registrar evidencia, riesgo pendiente y rollback;
7. cerrar con un commit enfocado, sin mezclar la sesión siguiente.

El estado y orden de las sesiones se registra en
`CIS_ARCHITECTURE_SESSIONS.md`.

## Contrato de plataforma

Cada plataforma declara distribución, release, arquitectura, benchmark,
adaptador y estado de liberación en el catálogo interno
`cis_platform_preflight/vars/main.yml`. Los estados previstos son:

- `released`: puede ejecutar el conjunto explícitamente validado.
- `canary`: solo permite entry points y controles canario con gates explícitos.
- `preflight_only`: solo facts y validaciones sin cambios.
- `unsupported`: aborta.

## Inventario

Los grupos funcionales (`web_servers`, `database_servers`) son ortogonales a los
grupos `ubuntu_2404` y `debian_12`. `cis_targets` agrupa plataformas, pero el
playbook Ubuntu conserva por ahora `hosts: ubuntu` para impedir una exposición
accidental de Debian.

La política de plataforma reside en `group_vars/ubuntu_2404.yml` o
`group_vars/debian_12.yml`; la política compartida del entorno reside en
`group_vars/all.yml`. El grupo `ubuntu` se conserva solo como alias compatible.

## Entry points

- `cis_ubuntu_2404_hardening.yml`: entry point canónico Ubuntu.
- `cis_hardening.yml`: shim compatible que importa el playbook canónico.
- `cis_debian_12_preflight.yml`: validación de plataforma Debian.
- `cis_debian_12_audit.yml`: controles Debian de solo lectura.
- `cis_debian_12_hardening.yml`: canarios Debian con gates explícitos.

## Criterio para compartir una implementación

Un control se mueve a `cis_linux_common` solo después de demostrar en ambas VMs:

1. mismo estado final;
2. mismos paquetes, rutas y semántica, o parámetros explícitos;
3. check mode válido;
4. primera aplicación correcta;
5. segunda aplicación con `changed=0`;
6. persistencia post-reboot cuando corresponda;
7. evidencia separada para cada ID CIS.

## Orden de liberación Debian

1. Preflight y facts.
2. Banners 1.6.
3. Permisos fijos de archivos 7.1.
4. Auditoría IPv6 3.1.1 y módulos de red 3.2.
5. Sysctl seleccionados y cron/at.
6. SSH y sudo, inicialmente audit-only.
7. Repositorios, servicios y sincronización horaria Debian.
8. UFW Debian, si es aprobado como estándar único.
9. PAM.
10. Logging remoto cifrado, auditd y AIDE.
11. Escaneos completos y remediaciones de sección 7.

## Gates por control

Cada control requiere aplicabilidad, impacto, variables aprobadas, prueba en
check mode, aplicación canaria, idempotencia, comprobación funcional, evidencia
y procedimiento de recuperación. Los controles manuales no se consideran PASS
por el solo hecho de que exista una tarea.

## Referencias Ansible locales

- `playbook_guide/playbooks_reuse_roles.rst`: estructura de roles y archivos por plataforma.
- `playbook_guide/playbooks_reuse.rst`: imports estáticos frente a includes dinámicos.
- `tips_tricks/sample_setup.rst`: separación de inventarios por entorno.
- `inventory_guide/intro_inventory.rst`: grupos, variables y orden de carga.
- `reference_appendices/test_strategies.rst`: check mode como detección de deriva.

Las rutas anteriores están bajo
`docs/ansible-documentation/docs/docsite/rst/` y son referencia de solo lectura.
