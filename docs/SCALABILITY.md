# Diseño escalable del proyecto CIS

## Alcance actual

Solo existen dos plataformas operativas:

- Ubuntu 24.04, estado `released`.
- Debian 12, estado `canary` y controles explícitos.

La escalabilidad es una propiedad del diseño; no implica declarar soporte para
distribuciones que no han sido implementadas y probadas.

## Capas

1. **Catálogo de plataforma**: identidad, arquitectura, benchmark, adaptador y
   estado de liberación en `cis_platform_preflight/vars/main.yml`.
2. **Entry point por plataforma**: selección de hosts, serialización y gates.
3. **Adaptador de benchmark**: `cis_ubuntu_2404` o `cis_debian_12` decide qué
   controles están liberados para ese benchmark.
4. **Implementación**: `cis_ubuntu_2404` orquesta setup y secciones; el rol
   histórico `cis_benchmark` queda como biblioteca interna acotada mientras sus
   controles se extraen de forma incremental.
5. **Mecanismos comunes**: solo se extraen después de demostrar equivalencia en
   ambas VMs. No se comparte código solo porque los títulos CIS coincidan.

## Regla para extraer código común

Un control puede pasar a una futura capa `cis_linux_common` cuando tenga el
mismo estado final, rutas y semántica, o diferencias expresadas como datos;
syntax check, check mode, dos convergencias reales, verificación funcional y
evidencia separada para Ubuntu y Debian.

## Convenciones nuevas

- Roles y variables: `cis_<distribucion>_<version>`.
- Archivos y tags de control: ID con guiones bajos, por ejemplo `cis_7_1_5`.
- `defaults/`: política configurable y gates seguros.
- `vars/`: catálogo interno no destinado a inventario.
- `import_tasks`: estructura estática por control o dominio.
- Auditoría y remediación permanecen separadas.

Los nombres y tags históricos de Ubuntu se conservan como compatibilidad hasta
que una migración tenga pruebas equivalentes.

## Incorporación futura de una plataforma

1. Añadir grupo de versión exacta al inventario.
2. Registrar metadata interna y comenzar en `preflight_only`.
3. Crear adaptador y entry points separados.
4. Implementar primero auditorías read-only.
5. Liberar canarios con gates por control.
6. Promover a `released` solo al completar pruebas y evidencia.

No se reutiliza el rol Ubuntu cambiando variables de distribución y nunca se
combinan plataformas en un mismo play de remediación.
