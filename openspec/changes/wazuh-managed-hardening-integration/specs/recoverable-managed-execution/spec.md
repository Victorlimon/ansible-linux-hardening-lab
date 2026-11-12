# Especificación de ejecución administrada

## Propósito

Ejecutar los playbooks existentes una vez por host autorizado y registrar el resultado real.

## Requisitos

### Requisito: Despacho fijo y acotado

Root DEBE usar gateway, release y runner verificados de `ansible-control`; no construirá comandos de shell desde JSON. Tras validar inventario, playbook, tags y variables, DEBE generar argv fijo de `ansible-playbook` para check/diff o apply, con `--limit` exacto por host. El modo check usa `--check --diff`; apply no. Los gates del playbook/roles siguen vigentes y no se eluden mediante variables de Wazuh.

#### Escenario: Playbook completo
- DADO un host Ubuntu autorizado y `selection=full`
- CUANDO llega apply aprobado
- ENTONCES el playbook de hardening existente corre sin `--check` y produce un terminal

#### Escenario: Tag y rol
- DADO una selección de rol/tag presente en la release
- CUANDO root arma argv
- ENTONCES ejecuta sólo esa selección, conserva preflight y rechaza una selección vacía

### Requisito: Exclusión y terminal durables

Cada host DEBE tener reserva y recibo persistentes que impidan concurrencia/replay. Inicio, PID/unidad si aplica, resultado, recapitulación y verificación DEBEN poder correlacionarse. Caída, timeout, descendiente vivo o falta de terminal DEBEN quedar `ambiguous` sin relanzar ni liberar automáticamente. Se permite reutilizar la unidad supervisada ya esbozada; esta especificación NO exige crear un orquestador genérico.

#### Escenario: Proceso interrumpido
- DADO un apply iniciado sin terminal durable
- CUANDO se reconcilia
- ENTONCES conserva reserva y evidencia y requiere decisión humana

#### Escenario: Terminal confirmado
- DADO Ansible finalizado, estado y descendientes verificados
- CUANDO se persiste el recibo
- ENTONCES la reserva se libera sólo tras resultado terminal durable

### Requisito: Estado por host

HTTP 200 de la API de Wazuh DEBE significar sólo envío; éxito/fallo de Ansible se decide por exit code, recapitulación y verify observados. Fallo o `unreachable` en cualquier host DEBE producir terminal no exitoso de ese host; no se declara éxito global parcial.

#### Escenario: Orden enviada pero Ansible falla
- DADO respuesta de API de envío satisfactoria
- CUANDO Ansible devuelve fallo o unreachable
- ENTONCES el recibo y evento Wazuh marcan fallo, no éxito
