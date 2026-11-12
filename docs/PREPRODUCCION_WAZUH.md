# Preparación de preproducción: Wazuh → ansible-control

Wazuh **envía la orden** al agente de `ansible-control`. Solo ese servidor ejecuta los playbooks Ansible existentes sobre Debian 12 y Ubuntu 24.04. No se necesitan siete playbooks nuevos: el mismo playbook acepta un selector de alcance. Esta guía describe el código fuente; **los cambios de selección de secciones aún no están instalados ni probados de extremo a extremo en el laboratorio**.

## Selección disponible en la release nueva

| `selection` | Resultado |
| --- | --- |
| `{"kind":"full","names":[]}` | Todas las secciones 1–7 del rol de la plataforma. |
| `{"kind":"sections","names":["4"]}` | Controles remediables de la sección 4 (firewall, según el sistema operativo). |
| `{"kind":"sections","names":["5.1"]}` | Controles remediables del subgrupo SSH 5.1; no ejecuta toda la sección 5. |
| `{"kind":"sections","names":["1","3","7"]}` | Esas secciones, en una misma orden y para los hosts aprobados. |
| `{"kind":"tags","names":["cis_5_1_2"]}` | Un control CIS concreto con tarea válida en la release instalada. |
| `{"kind":"roles","names":["cis_ubuntu_2404"]}` | Rol completo de la plataforma indicada por el playbook. |

`sections` acepta 1–7 y subgrupos con un nivel decimal, como `5.1`; rechaza secciones sin tareas. La expansión toma tags de los imports de la **release sellada en ansible-control** y falla si encuentra un import sin tag seleccionable. Los controles que solo tienen auditoría o verificación **no se convierten en remediaciones**. Las listas de tags se validan contra tareas concretas; no se aceptan `all`, `always`, rutas, comandos ni tags libres.

## Orden desde la API Console de Wazuh

El operador dirige la orden al **agente de `ansible-control`**, no al agente del nodo que se endurecerá:

```text
PUT /active-response?agents_list=001
```

Ejemplo de `CHECK` para la sección 4 de Ubuntu:

```json
{"command":"!ansible-job","arguments":["managed-v2","{\"change_id\":\"CHG_PREPROD_001\",\"extra_vars\":{},\"inventory_profile_id\":\"ubuntu_staging\",\"mode\":\"check\",\"playbook_id\":\"ubuntu_hardening\",\"release_id\":\"staging_v1\",\"request_id\":\"11111111-2222-4333-8444-555555555555\",\"selection\":{\"kind\":\"sections\",\"names\":[\"4\"]},\"targets\":[\"ubuntu24\"]}"]}
```

El segundo elemento de `arguments` debe ser **JSON canónico compacto** (claves ordenadas, sin espacios). El UUID, cambio, release, perfil, alias y agente del ejemplo se reemplazan por los aprobados en preproducción; no es una orden ejecutable tal cual. Para Debian se usa `debian_hardening` y su perfil/alias sellados. Para SSH cambie solo `selection` a `{"kind":"sections","names":["5.1"]}`; para un control, a `{"kind":"tags","names":["cis_5_1_2"]}`; para todo el playbook, a `{"kind":"full","names":[]}`. Genere un `request_id` nuevo por trabajo y conserve exactamente el mismo alcance entre `CHECK` y `APPLY`.

Un acuse HTTP no es evidencia de hardening. Compruebe el evento `accepted`, el resultado terminal `completed` o `failed`, el recap Ansible y las alertas correlacionadas por `request_id` en Wazuh.

## Puerta de aplicación

1. Audite cada host: servicios, puertos, dependencias, SSH, firewall y acceso de recuperación. Prepare **antes** el inventario, variables y release de `ansible-control`; Wazuh no envía rutas ni variables arbitrarias. La orden solo admite las variables UFW/SSH de Ubuntu expresamente validadas por el gateway.
2. Envíe `CHECK` desde Wazuh y revise el diff y la selección efectiva. Cree respaldo y evidencia de recuperación fuera de banda para **cada host**.
3. Un aprobador separado registra el archivo de seguridad y emite la aprobación de un solo uso en `ansible-control`, vinculada a host, release, alcance, cambio y diff. **El operador de Wazuh no puede emitir esa aprobación desde la API Console actual.** No elimine esta separación para simplificar la interfaz.
4. Envíe `APPLY` desde Wazuh con el mismo `request_id` y un mapa `approvals` que contenga un token distinto por host. Verifique el evento terminal; no repita a ciegas si faltan eventos.

## Criterio de entrada a preproducción

- [ ] Instalar una release sellada nueva con este gateway y sus playbooks en el `ansible-control` de preproducción; comprobar Ansible Core **2.21.2** y la conectividad existente sin modificar Vagrant.
- [ ] Completar los inventarios/perfiles de preproducción con los hosts, servicios y puertos **reales**. Los `hosts.yml` de staging y producción del repositorio están vacíos deliberadamente.
- [ ] Probar `CHECK → aprobación → APPLY → auditoría/verificación` para secciones **1, 2, 3, 4, 5, 6 y 7**, por separado, en **Debian 12 y Ubuntu 24.04**; también `full`, un control de firewall y uno de SSH.
- [ ] Confirmar tareas efectivamente ejecutadas, no solo `--list-tasks`: los includes dinámicos se expanden durante la ejecución. Comprobar SSH, sudo, agentes Wazuh, servicios y puertos de negocio después de cada aplicación.
- [ ] Repetir la ejecución para medir idempotencia y verificar recuperación/rollback ante fallo antes de autorizar producción.

**Evidencia actual:** el laboratorio completó `FULL APPLY` en ambos nodos con Wazuh 4.12.0 y Ansible Core 2.21.2; el selector `sections` y la corrección de tags de includes cuentan con pruebas locales de contrato, **no** con una ejecución en nodos de preproducción. No se afirma cumplimiento CIS completo ni compatibilidad institucional hasta ejecutar la matriz anterior.
