# Rol `cis_linux_common`

## Propósito

Este rol es la biblioteca de controles CIS cuya equivalencia ya fue demostrada
en Ubuntu 24.04 y Debian 12. Los adaptadores de plataforma conservan la política,
los selectores y los gates; `cis_linux_common` aporta la implementación técnica.

El rol no debe invocarse sin un `tasks_from` explícito. Su `tasks/main.yml`
rechaza esa llamada para evitar que una ejecución ambigua parezca aplicar
hardening completo.

## Organización

```text
tasks/
├── main.yml
├── sections/                         # API semántica por benchmark/control
│   ├── section_02_services/
│   │   └── 2_4_1_2_crontab_permissions/
│   │       ├── audit.yml
│   │       ├── remediation.yml
│   │       └── verification.yml
│   ├── section_03_network/
│   │   ├── 3_1_1_ipv6_status/
│   │   │   ├── audit.yml
│   │   │   └── verification.yml
│   │   └── 3_3_10_tcp_syncookies/
│   │       ├── audit.yml
│   │       ├── remediation.yml
│   │       └── verification.yml
│   └── section_07_maintenance/
│       └── 7_1_1_passwd_permissions/
│           ├── audit.yml
│           ├── remediation.yml
│           └── verification.yml
├── ipv6_status/                      # mecanismo técnico existente
├── sysctl_parameter/
├── fixed_file_permissions/
└── installed_package_fixed_file/
```

- `sections/` responde a “qué control CIS se ejecuta”.
- Los directorios de mecanismo responden a “cómo se declara el estado”.
- Cada control ofrece únicamente los modos que soporta. Un control manual o
  read-only no debe tener un archivo `remediation.yml` vacío.
- Las rutas técnicas existentes se conservan durante la migración para no
  romper consumidores ni gates.

## Convención de rutas

```text
tasks/sections/section_<NN>_<dominio>/<ID_con_guiones_bajos>_<nombre>/<modo>.yml
```

Ejemplo de consumo desde un adaptador:

```yaml
- name: Audit platform CIS 3.1.1
  ansible.builtin.import_role:
    name: cis_linux_common
    tasks_from: sections/section_03_network/3_1_1_ipv6_status/audit.yml
  vars:
    cis_linux_common_control_id: "3.1.1"
    cis_linux_common_platform: example_platform
    cis_linux_common_benchmark: Example benchmark
    cis_linux_common_ipv6_site_policy: undecided
```

Los contratos se suministran desde el adaptador. No deben trasladarse a
`vars/`, porque eso cambiaría su precedencia y dificultaría ajustes explícitos.

## Regla para añadir un control

1. Confirmar equivalencia en ambos benchmarks.
2. Crear la entrada bajo `sections/`.
3. Reutilizar o crear un mecanismo técnico pequeño.
4. Mantener audit, remediation y verification separados.
5. Conservar tags y gates en cada adaptador.
6. Ejecutar syntax-check, `--check --diff`, convergencia, idempotencia,
   verification y el gate específico.
7. Documentar evidencia y recuperación.

La migración se realiza control por control y en commits independientes. No se
mueven varias secciones ni se cambia comportamiento durante una sesión de
reorganización.
