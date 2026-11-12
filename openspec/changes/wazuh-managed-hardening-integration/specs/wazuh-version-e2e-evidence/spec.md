# Especificación de observabilidad y versiones Wazuh

## Propósito

Mostrar en Wazuh lo que efectivamente hizo Ansible, sin publicar el transcript secreto.

## Requisitos

### Requisito: Eventos visibles y correlacionados

El gateway DEBE escribir JSONL estructurado y acotado para `accepted`, `started`, progreso de tareas resumido, recap, `failed` y terminal por host, con `request_id`, `change_id`, playbook, inventario, selección y digest de variables. El agente Wazuh DEBE recogerlo con `localfile` `log_format=json`; reglas/alertas DEBEN hacer consultables el estado y fallos. La salida Ansible íntegra permanece root-only; los eventos DEBEN omitir secretos y valores sensibles.

#### Escenario: Resultado visible
- DADO un apply con dos hosts
- CUANDO finalizan por separado
- ENTONCES Wazuh muestra dos recibos/terminales correlacionables, recap y fallos sin log bruto

#### Escenario: HTTP 200 sin terminal
- DADO que la API aceptó enviar Active Response pero no hay evento terminal
- CUANDO se consulta Wazuh
- ENTONCES se muestra enviado/en curso o incompleto, jamás éxito

### Requisito: E2E 4.14.8 y compatibilidad 4.12.0

En 4.14.8 DEBE probarse API → manager → agente → gateway → Ansible → nodo → JSONL → alerta/terminal para full Ubuntu, full Debian, selección parcial, multi-host, variables y rechazo. Wazuh 4.12.0 DEBE probarse de modo independiente antes de afirmar compatibilidad; una versión no prueba la otra.

#### Escenario: Laboratorio completo
- DADO Docker 4.14.8 y Vagrant autorizados
- CUANDO se envían órdenes de check y apply
- ENTONCES cada salto tiene evidencia con el mismo ID y resultado de nodo

#### Escenario: 4.12.0 no disponible
- DADO que falta manager 4.12.0 aislado
- CUANDO se prepara la presentación
- ENTONCES se declara compatibilidad no validada, no soporte comprobado

### Requisito: Aislamiento

Las pruebas DEBEN limitarse al laboratorio; producción institucional requiere configurar RBAC/Active Response e inventario local institucional con el responsable. Ningún resultado de laboratorio otorga autorización productiva.

#### Escenario: Destino institucional
- DADO un alias o manager externo al laboratorio
- CUANDO se intenta usar en E2E
- ENTONCES se rechaza sin operación remota
