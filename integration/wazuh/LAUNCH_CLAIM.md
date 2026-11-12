# Reserva de lanzamiento: persistencia sin activación

**NO-GO para aplicar:** `launch_claim.py` es una primitiva inerte. No ejecuta
Ansible, systemd ni comandos remotos; no habilita aprobaciones ni el gateway.
Persistir una identidad no demuestra que proceda del administrador de servicios.

## Contrato local

Los marcadores pendientes v2 agregan `job_id` y `approval_id` a la solicitud,
objetivo, control, huella de release, arranque y unidad exacta. Los v1 continúan
siendo legibles, pero no permiten reclamar un lanzamiento. No hay migración
automática. `claim` lee la identidad esperada del marcador pendiente privado;
el evento Wazuh no puede suministrar una identidad esperada alternativa.

La reserva almacena el binding completo de `retained_observation`: identidad,
`InvocationID` exacto y límites de ejecución/parada. Requiere directorios
preexistentes privados de root y ancestros sin escritura de grupo/otros.
La apertura relativa a descriptores rechaza enlaces simbólicos; la creación
exclusiva rechaza cualquier entrada previa. La lectura también rechaza enlaces
duros, objetos no regulares, permisos abiertos y JSON incompleto o duplicado.

Orden antes de devolver éxito: crear con `O_EXCL` y modo `0600`, sincronizar
directorio, escribir todo el contenido, sincronizar archivo y directorio.
Un fallo conserva la entrada; incluso una reserva incompleta bloquea otro
intento. Tras un fallo de sincronización no se afirma durabilidad. Una lectura
posterior válida nunca autoriza reanudar ni lanzar. No hay borrado ni recuperación.

## Integración pendiente

El futuro supervisor debe mantener exclusión de despliegue, trabajo y
lanzamiento/reinicio; autenticar arranque, unidad e `InvocationID` mediante el
administrador; y completar una llamada **nueva y exitosa** a `claim` antes del
primer hijo Ansible. La unidad puede existir antes, pero el hijo no debe hacerlo.
Esta secuencia exige una barrera real en el gateway todavía no implementada.
No reutilizar una reserva leída después de una caída. Falta probar esa barrera,
retención y exclusión en ejecución antes de retirar el NO-GO.

## Verificación y reversión

Pruebas locales: `python -m unittest integration.wazuh.tests.test_launch_claim`.
Los casos reales de propiedad, concurrencia y `fsync` requieren Linux como root;
en Windows se omiten, no se consideran aprobados. No se ejecuta un harness de
servicios: queda fuera de esta entrega de código fuente.

Reversión: retirar el módulo y sus pruebas, y revertir únicamente la extensión
v2 y la adaptación de `retained_observation`. No borrar marcadores persistidos
ni revertir otros cambios locales; cualquier estado existente queda bloqueante.
