# ADR 0001: adaptadores por plataforma

- Estado: Accepted
- Fecha: 2026-08-29

## Contexto

Ubuntu 24.04 tiene una implementación amplia en el rol histórico
`cis_benchmark`. Debian 12 se libera control por control. Los benchmarks pueden
compartir mecanismos, pero no necesariamente IDs, aplicabilidad ni impacto.

## Decisión

Cada plataforma tiene un entry point y adaptador explícitos. Un catálogo interno
define identidad, benchmark, arquitectura y estado. Ubuntu conserva
`cis_benchmark` detrás de `cis_ubuntu_2404`; Debian usa `cis_debian_12`.

No se crearán implementaciones para plataformas no probadas. Un mecanismo pasa
a una capa común solo después de demostrar equivalencia e idempotencia en Ubuntu
y Debian. El playbook `cis_hardening.yml` permanece como compatibilidad Ubuntu.

## Consecuencias

- Se evita ejecutar lógica Ubuntu en Debian por sustitución de variables.
- La duplicación pequeña y temporal es aceptable durante un canario.
- La migración es más lenta, pero cada cambio es auditable y reversible.
- Una plataforma futura debe comenzar en preflight y no en remediación.
