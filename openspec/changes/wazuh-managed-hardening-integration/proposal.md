# Propuesta: órdenes Wazuh para los playbooks CIS existentes

## Intención

Completar la integración: Wazuh ordena y observa; `ansible-control` ejecuta los playbooks existentes. El puente actual sólo permite vista previa, no aplicación real.

## Alcance

- Ejecutar el playbook de hardening completo o seleccionar roles/tags **existentes** de las siete secciones, en uno o varios hosts de inventarios autorizados.
- Admitir parámetros tipados, acotados y revisados por plataforma (por ejemplo, puerto SSH y reglas UFW), sin editar el inventario desde Wazuh. Los valores por ejecución complementan el inventario que administra `ansible-control`.
- Conservar comprobación/diff y aprobación humana separada por host y alcance exacto antes de aplicar. En lotes, cada host genera su propio check, aprobación y resultado.
- Publicar en Wazuh eventos JSONL correlacionados de aceptación, inicio, progreso resumido, recapitulación, fallo y terminal; conservar el registro completo privado.
- Probar el recorrido real en Docker 4.14.8; validar 4.12.0 por separado antes de declararlo compatible.

Excluido: crear o modificar playbooks CIS para hacer funcionar el puente; ejecutar en producción institucional; aceptar rutas, comandos, grupos, tags o variables libres; prometer cumplimiento CIS por un `exit 0`.

## Capacidades

### Nuevas

- `sealed-hardening-profiles`: solicitud tipada y catálogo revisado de playbook, inventario, selección y variables admitidas.
- `recoverable-managed-execution`: despacho único seguro y resultado terminal recuperable.
- `single-use-hardening-approval`: autorización de un uso por host y solicitud normalizada.
- `cis-section-lifecycle`: ciclo check/diff → aprobación → aplicación → verificación con los roles existentes.
- `wazuh-version-e2e-evidence`: eventos observables y prueba independiente por versión.

### Modificadas

Ninguna especificación vigente en `openspec/specs/`.

## Enfoque

Reutilizar gateway, release sellada, runner y playbooks actuales. La API de Wazuh envía `arguments`; el agente entrega `extra_args` al gateway. Un JSON compacto y versionado indica IDs, hosts, selección y overrides. Root resuelve rutas/argumentos, valida el inventario efectivo y la política, deriva digest y ejecuta con argv fijo sin shell. Respuesta HTTP de envío no equivale a éxito Ansible. Mantener el protocolo legado de cuatro argumentos sólo en check.

## Riesgos y reversión

SSH/firewall/PAM pueden cortar acceso: check previo, autorización granular, snapshot y acceso fuera de banda. Si el proceso cae o falta estado terminal, bloquear reintento automático; conservar evidencia y decidir recuperación. Volver al gateway check-only revocando nuevas aprobaciones, sin borrar registros.

## Criterios de éxito

- [ ] Ubuntu y Debian: playbook completo y selección de tags existentes llegan a terminal real desde Wazuh.
- [ ] Inventario multi-host y reglas de puertos aprobadas no amplían otros destinos.
- [ ] Aprobación caducada, replay, variable/tag inerte o destino no autorizado no ejecutan apply.
- [ ] Eventos y alertas muestran cada host, estado y recapitulación sin secretos.
- [ ] 4.14.8 E2E probado; 4.12.0 se declara compatible sólo tras prueba propia.
