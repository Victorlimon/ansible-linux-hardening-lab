## Exploración: integración administrada de hardening Wazuh → Ansible

### Estado actual

La integración comprobada es segura pero deliberadamente limitada. La release sellada `lab_v9` demostró en Wazuh local 4.14.8 el transporte completo manager → agente `001` (`ansible-control`) → Ansible → Ubuntu 24.04/Debian 12 para siete trabajos fijos. Todas las solicitudes llegaron a estado terminal; cinco finalizaron correctamente y las dos verificaciones fallaron por un `sysctl` persistente incumplido en nodos aún no endurecidos. Esta evidencia prueba el flujo en modo `check`, no una aplicación real ni conformidad CIS completa.

`integration/wazuh/managed_job.py` mantiene tres barreras explícitas:

- `issue_approval()` siempre rechaza la emisión de aprobaciones.
- `run_job()` rechaza todo `approval_id` distinto de `none`.
- `run_locked_job()` fija `mode = "check"` y añade siempre `--check --diff`.

La política v2 fija una sola ruta de inventario dentro de la release sellada, limita los destinos a alias revisados y solo permite `cron_hourly` y `cron_daily` como controles de hardening. Es una base correcta contra rutas, patrones, playbooks o variables arbitrarias, pero no modela perfiles por host/sección ni el alcance completo solicitado.

Las primitivas `execution_state.py`, `execution_observation.py`, `retained_observation.py` y `launch_claim.py` cubren reservas durables, identidad de unidad, evidencia del manager/cgroup y claims de un solo uso. Son módulos inertes: el gateway no los importa, no existe lanzador supervisado, no hay reconciliación autorizada ni eliminación segura de reservas. Por tanto, todavía no existe exclusión recuperable ante caída del gateway, reinicio o descendientes vivos.

Los roles Ansible sí contienen rutas de auditoría, remediación y verificación para las secciones CIS 1–7, con master gates y gates por control. El catálogo clasifica sin equiparar categorías:

| Plataforma | Total | Automatizados | Condicionados (`gated_unsafe`) | Manuales | No aplicables |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ubuntu 24.04 | 311 | 142 | 98 | 19 | 52 |
| Debian 12 | 310 | 145 | 95 | 20 | 50 |

Los controles manuales requieren evidencia humana y los `na` una justificación de aplicabilidad; ninguno debe publicarse como automatizado o remediado. El árbol de trabajo ya contiene cambios no confirmados en gates, tags SSH, perfil UFW y pruebas estáticas; esta exploración los trata como estado de trabajo y no los modifica.

La cobertura de firewall actual valida estructura, CIDR, puertos y orden previo a mutación. No demuestra todavía la política efectiva en una VM: conservación de acceso SSH, apertura de servicios aprobados, bloqueo de orígenes/puertos no aprobados, convergencia ni reversión.

Wazuh 4.12.0 solo tiene revisión documental del contrato. No existe prueba aislada viva equivalente a la evidencia 4.14.8 ni evidencia sobre RBAC, payload, alertas y semántica terminal en esa versión.

### Áreas afectadas

- `integration/wazuh/managed_job.py` — gateway check-only, catálogo fijo, política sellada, validación de inventario y guardas de aplicación.
- `integration/wazuh/execution_state.py` — reserva durable por solicitud y predicados conservadores de terminación.
- `integration/wazuh/execution_observation.py` — captura acotada de systemd/cgroup, sin autoridad de retiro.
- `integration/wazuh/retained_observation.py` — clasificación de unidades retenidas, sin probar vaciado del cgroup ni éxito de aplicación.
- `integration/wazuh/launch_claim.py` — claim de un solo uso, todavía sin lanzador ni integración con el gateway.
- `integration/wazuh/config/jobs.*.json.example` — política actual de release, inventario, destinos y dos controles cron.
- `integration/wazuh/tests/` — contratos unitarios de fail-closed; faltan pruebas integradas del supervisor y compatibilidad viva 4.12.
- `ansible/cis/catalog/disposition-matrix.yml` — autoridad para automatizado, condicionado, manual y no aplicable.
- `ansible/roles/cis_{ubuntu_2404,debian_12}/` — rutas y gates por control en las siete secciones.
- `ansible/inventories/*/group_vars/` — variables actuales; los ejemplos de producción aún no constituyen perfiles aprobados.
- `ansible/tests/test_remediation_gates.py` — cobertura estática de gates, sin ejecución real de controles.
- `ansible/tests/test_firewall_allowlist.py` — valida forma y routing UFW, no comportamiento de red efectivo.
- `docs/INTEGRACION_WAZUH_ANSIBLE.md` — evidencia actual, límites y base de supervisión no activada.

### Enfoques

1. **Desbloqueo mínimo dentro del gateway actual** — habilitar `issue_approval()`, consumir la aprobación existente y omitir `--check` cuando corresponda.
   - Ventajas: menor cambio inicial; reutiliza el catálogo y el bloqueo por host.
   - Desventajas: el proceso Ansible puede sobrevivir al gateway y al lock cooperativo; una caída deja estado ambiguo; las primitivas inertes no cierran launch/restart/deployment exclusion. No satisface la seguridad exigida para aplicación real.
   - Esfuerzo: medio; riesgo residual crítico.

2. **Supervisor root-local recuperable con perfiles sellados** — integrar las primitivas existentes en una transacción supervisada systemd por solicitud, con aprobación de un solo uso vinculada a release, perfil, host, sección y cambio.
   - Ventajas: mantiene el diseño fail-closed, evita rutas y extra-vars libres, permite reconciliación después de caída y conserva la separación Wazuh/Ansible. Facilita evidencia reproducible por host y sección.
   - Desventajas: requiere diseñar el ciclo completo reserva → claim → launch → observación → reconciliación → retiro; las pruebas de fallos y recuperación son obligatorias antes de habilitar apply.
   - Esfuerzo: alto; es el único enfoque compatible con el objetivo y las barreras actuales.

3. **Delegar la ejecución a Automation Controller/AWX** — usar Wazuh solo como solicitante y trasladar inventarios, credenciales, aprobaciones y ejecución a un controlador externo.
   - Ventajas: capacidades maduras de inventario, RBAC, job templates y auditoría.
   - Desventajas: cambia la arquitectura solicitada, añade otra plataforma y no aprovecha directamente el modelo sellado local; desplaza, no elimina, la validación de variables, gates y controles CIS.
   - Esfuerzo: alto y con mayor alcance operativo.

### Recomendación

Adoptar el enfoque 2 y mantener `lab_v9` intacta como línea base check-only. La secuencia segura es:

1. **Cerrar evidencia externa y contratos:** investigar la semántica exacta de Active Response/RBAC en 4.12.0 y preparar un manager 4.12 aislado, sin tocar producción.
2. **Definir perfiles sellados:** introducir identificadores, no rutas, para `inventory_profile`, `host_profile` y `section_profile`. Cada manifest debe resolver dentro de la release a un inventario y archivos de variables revisados, con digest, plataforma, host, sección, tags, puertos, protocolos, orígenes y gates permitidos. Wazuh solo enviará IDs canónicos.
3. **Modelar cobertura honesta:** generar por plataforma/sección una lista de controles `automated`, `gated_unsafe`, `manual` y `na`. Apply solo podrá incluir los dos primeros; cada manual tendrá una evidencia humana y cada `na` una justificación revisada.
4. **Completar la supervisión:** vincular aprobación única a `(release_digest, inventory_profile, host, section, change_id, expiry)`, reservar antes de lanzar, crear una unidad systemd transitoria con límites y `KillMode=control-group`, persistir el claim antes del hijo y reconciliar bajo exclusión. Ninguna evidencia aislada autoriza reintento o limpieza.
5. **Probar fail-closed antes de apply:** cubrir muerte del gateway antes/después del claim, timeout, reinicio, unidad reemplazada, descendientes vivos, cambios de release/perfil, aprobación vencida/reutilizada y reconciliación. Solo después retirar el rechazo global de apply.
6. **Ejecutar el laboratorio por host y sección:** para Ubuntu y Debian, realizar audit → check/diff → aprobación independiente → apply → verify → segunda ejecución idempotente. Avanzar sección por sección; controles SSH, PAM, sudo, firewall, kernel y acciones destructivas necesitan rollback y comprobación de acceso fuera de banda.
7. **Probar firewall de forma efectiva:** levantar servicios simulados solo en puertos aprobados, comprobar desde orígenes permitidos y no permitidos, preservar SSH desde `ansible-control`, demostrar bloqueo de puertos no declarados, validar reglas efectivas y ejecutar rollback sobre snapshot. Las pruebas estáticas actuales siguen siendo necesarias pero no suficientes.
8. **Repetir E2E en 4.14.8 y 4.12 aislado:** exigir correlación API → agente → solicitud → unidad → Ansible → verify → alertas, con resultados equivalentes y diferencias documentadas. Solo entonces preparar una adaptación de producción con inventario, SSH, RBAC y perfiles institucionales revisados; no ejecutar producción sin autorización remota explícita.

La implementación debe dividirse en unidades revisables por debajo de 400 líneas modificadas: perfiles/validadores, supervisor/estado, aprobación/reconciliación, slices de Ansible por sección, pruebas E2E 4.14.8, compatibilidad 4.12 y documentación/evidencia.

### Riesgos

- **Pérdida de acceso:** firewall, SSH, PAM y sudo son críticos aunque el cambio sea pequeño; necesitan snapshot, acceso fuera de banda y rollback probado.
- **Estado ambiguo tras fallo:** habilitar apply antes de integrar supervisión puede permitir procesos vivos con aprobaciones consumidas o reintentos inseguros.
- **Explosión de perfiles:** aceptar variables libres o un perfil monolítico vuelve irrevisable la matriz host/sección. Los perfiles deben ser pequeños, tipados, sellados y deduplicados.
- **Cobertura falsa:** 7/7 trabajos Wazuh no equivale a siete secciones CIS ni a 311/310 controles conformes.
- **Pruebas insuficientes de firewall:** la validación YAML no demuestra reachability ni bloqueo efectivos.
- **Deriva de versión:** 4.14.8 no prueba 4.12.0; la compatibilidad debe demostrarse con un manager aislado de la versión exacta.
- **Árbol sucio:** cambios preexistentes y el cambio OpenSpec archivado deben mantenerse separados de las nuevas unidades de trabajo.
- **Catálogo pendiente:** la clave duplicada de banner Debian documentada debe resolverse antes de declarar el catálogo apto para producción.

### Listo para propuesta

Sí, con una condición explícita: la propuesta puede avanzar sin seleccionar la fase opcional `sdd-research`, siempre que trate la compatibilidad con Wazuh 4.12.0 como un criterio de aceptación todavía no demostrado. El cambio deberá exigir una prueba viva en un manager 4.12.0 aislado, documentar cualquier diferencia frente a 4.14.8 y bloquear toda adaptación de producción hasta que esa evidencia exista. La propuesta no puede afirmar compatibilidad 4.12.0, reutilizar la prueba 4.14.8 como sustituto ni otorgar autoridad sobre el manager institucional.
