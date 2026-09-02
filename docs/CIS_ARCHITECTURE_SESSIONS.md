# Sesiones de arquitectura CIS

Este registro divide la reorganización en cambios pequeños y verificables. Una
sesión no habilita nuevos controles salvo que su alcance lo indique de forma
explícita.

## Reglas de sesión

- Un control o una preocupación arquitectónica por sesión.
- Sin migraciones masivas ni cambios cosméticos no relacionados.
- Imports estáticos y tags existentes preservados.
- Audit, remediation y verification permanecen separados.
- Los mecanismos comunes no deciden política de plataforma.
- Cada sesión termina con validación, evidencia y un commit independiente.

## Plan incremental

| Sesión | Alcance | Riesgo | Estado |
|---|---|---|---|
| A1 | Definir arquitectura semántica y migrar CIS 3.1.1 a `sections/section_03_network` | Bajo; control read-only | `VALIDATED` |
| A2 | Migrar CIS 7.1.1 a `sections/section_07_maintenance` | Bajo; solo cambia la ruta de composición | `PLANNED` |
| A3 | Migrar CIS 2.4.1.2 a `sections/section_02_services` | Bajo; conservar rama `NOT_APPLICABLE` | `PLANNED` |
| A4 | Migrar CIS 3.3.10 a `sections/section_03_network` | Medio; preservar runtime, persistencia y gates | `PLANNED` |
| A5 | Reubicar mecanismos bajo `tasks/mechanisms/` con wrappers compatibles | Medio; cambia rutas internas | `PLANNED` |
| A6 | Dividir adaptador Ubuntu por secciones, sin alterar orden histórico | Medio | `PLANNED` |
| A7 | Dividir adaptador Debian por secciones, sin alterar gates canary | Medio | `PLANNED` |
| A8 | Completar interfaces independientes de Debian CIS 7.1.5 | Alto; cambio funcional | `PLANNED` |

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
