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
