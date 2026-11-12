# Especificación de órdenes tipadas de hardening

## Propósito

Wazuh elige trabajo; sólo la política root-local de `ansible-control` decide qué puede ejecutarse.

## Requisitos

### Requisito: Orden versionada y acotada

El sistema DEBE aceptar `extra_args=["managed-v2", "<JSON>"]` con JSON canónico y límite de tamaño que contenga `mode` (`check` o `apply`), `request_id`, `change_id`, `release_id`, `playbook_id`, `inventory_profile_id`, `targets`, `selection`, `extra_vars` y, sólo en apply, `approvals` por host. DEBE rechazar campos adicionales, duplicados, IDs mal formados, destinos vacíos y órdenes de tamaño excesivo antes de lanzar procesos. El contrato legado de cuatro strings permanece check-only; `managed-apply-v1` NO DEBE habilitar remediación.

#### Escenario: Orden completa válida
- DADO el ID del playbook Ubuntu, inventario autorizado y `selection=full`
- CUANDO root valida la orden de check
- ENTONCES prepara el playbook existente y un registro por host

#### Escenario: Entrada libre
- DADO una ruta, opción de CLI, comando, shell, entorno, campo no reconocido o JSON duplicado
- CUANDO se recibe la orden
- ENTONCES se rechaza antes de reservar o ejecutar

### Requisito: Resolución de alcance real

Root DEBE resolver `playbook_id` a una entrada sellada existente de Ubuntu 24.04 o Debian 12, `inventory_profile_id` a inventario administrado y `targets` a alias/grupos revisados. `selection` admite `full` o listas de roles/tags existentes y verificadas en la release; tags especiales `always`, `never`, `all`, `tagged`, `untagged` y tags inexistentes no son seleccionables libremente. Para varios hosts, DEBE expandir y fijar una lista exacta antes del check; un miembro ajeno bloquea toda la orden.

#### Escenario: Selección existente
- DADO un tag CIS presente y permitido para el playbook Debian
- CUANDO se resuelve el inventario
- ENTONCES sólo los hosts y tareas autorizados entran al plan

#### Escenario: Alias o tag inerte
- DADO un grupo que incluye otro entorno o un tag sin tareas efectivas
- CUANDO se valida el plan
- ENTONCES se rechaza sin considerar éxito un no-op

### Requisito: Variables operativas revisadas

`extra_vars` DEBE aceptar sólo claves con esquema por plataforma, tipos y rangos revisados, probadas como efectivas en los roles seleccionados. Para Ubuntu UFW, el esquema incluye `cis_ufw_ssh_port`, `cis_ufw_ssh_allowed_sources` y `cis_ufw_allowed_in_rules`; una regla exige puerto 1–65535, protocolo permitido y origen CIDR o `any` sólo cuando la política lo permita. Variables de gates críticos, secretos, estructuras arbitrarias o claves inertes DEBEN rechazarse. Debian nftables requiere un perfil de configuración revisado; no se convierte texto nft libre de Wazuh en `cis_nftables_config`.

#### Escenario: Puerto de servicio aprobado
- DADO una regla UFW tipada para un servicio y origen autorizados
- CUANDO se normaliza check
- ENTONCES el valor efectivo y su digest quedan ligados al host y aprobación

#### Escenario: Gate o variable sin efecto
- DADO una clave de gate, un puerto fuera de rango o una clave no consumida
- CUANDO se valida `extra_vars`
- ENTONCES se rechaza antes de invocar Ansible
