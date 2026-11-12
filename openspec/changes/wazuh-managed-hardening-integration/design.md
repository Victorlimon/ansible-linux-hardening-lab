# Diseño: Wazuh ordena; ansible-control ejecuta

## Ruta mínima

`PUT /active-response?agents_list=<agente-ansible-control>` con `{"command":"!ansible-job","arguments":["managed-v2","<JSON>"]}` → manager → agente → gateway root → política/release → `ansible-playbook` existente → JSONL/alertas Wazuh. El HTTP 200 sólo acredita envío. `ansible-control` posee inventarios, claves, playbooks y ejecución; Wazuh no ejecuta SSH a los nodos.

## Contrato de orden

JSON canónico, sin claves duplicadas y máximo 8 KiB:
`{"mode":"check|apply","request_id":"UUID","change_id":"ID","release_id":"ID","playbook_id":"ubuntu_hardening|debian_hardening","inventory_profile_id":"ID","targets":["alias_o_grupo"],"selection":{"kind":"full|tags|roles","names":["tag"]},"extra_vars":{},"approvals":{"host":"UUID"}}`.
`approvals` sólo en apply. Root expande grupos a hosts exactos, verifica pertenencia/plataforma y fija orden canónico; tope de hosts configurable en política. Cada host recibe check/diff, evidencia, aprobación y recibo propios. Si falta una aprobación, apply del lote se rechaza íntegro antes de empezar. Legado cuatro strings y `managed-check-v1` siguen check-only; `managed-apply-v1` nunca autoriza apply.

## Decisiones

| Frontera | Decisión |
|---|---|
| Playbooks | IDs a `ansible/playbooks/hardening/cis_ubuntu_2404.yml` y `cis_debian_12.yml` en release sellada; no rutas en JSON. |
| Selección | `full` sin `--tags`; tags/roles sólo de allowlist por playbook y con tareas efectivas. El rol CIS se selecciona mediante tag existente, no con otro playbook. Preflight `always` no se puede omitir. |
| Inventario | Root resuelve perfil al inventario administrado y valida expansión del grupo/alias; `--limit` recibe un host exacto por ejecución, no `all` libre. |
| Variables | Sólo esquema por SO de variables realmente consumidas. Overrides de ejecución, NO escritura del inventario. JSON root-only `--extra-vars @<archivo>`, sin secretos en argv/eventos. `cis_ufw_ssh_port` 1–65535, fuentes CIDR no /0 para SSH y `cis_ufw_allowed_in_rules` tipadas; `cis_nftables_config` libre prohibida. Otros nombres se agregan tras revisar rol/precedencia y pruebas. Gates peligrosos requieren política y precondiciones root-local, no sólo flag Wazuh. |
| Autoridad | Check/diff inmutable liga request, host, release, playbook, inventario, selección, valores efectivos y diff digests. Aprobación humana separada por host+alcance, expiración y consumo único; Wazuh envía ID, no autoridad. |
| Ejecución | Reusar `managed_job.py`, `managed_profiles.py`, `local_executor.py` y release/runtime existentes; process `shell=False`, entorno fijo, reserva por host, salida privada acotada. Usar supervisión ya disponible sólo donde haga falta para no relanzar después de caída. |
| Observabilidad | Evento JSONL saneado por request/host: `accepted`, `started`, progreso de tarea resumido, `recap`, `failed`, terminal `completed|noncompliant|blocked|ambiguous`. Raw/diff quedan root-only. `localfile log_format=json` y reglas Wazuh permiten filtrar por request_id; no transcript secreto en alertas. |

## Pruebas y reversión

RED: campo/argv/ruta/variable desconocida, tag inerte, grupo con host ajeno, puerto inválido, SSH /0, digest distinto, aprobación ausente/vencida/replay, caída sin terminal, JSONL secreto/ausente. GREEN: check y apply real para Ubuntu/Debian completos; selección parcial, lote dos hosts, variable UFW permitida, salida/recap y alerta. `verify` distingue ejecutado de conforme; fallo conserva evidencia. Antes de firewall/SSH/PAM: snapshot y acceso fuera de banda. Reversión detiene nuevas aprobaciones, retiene estado y vuelve a check-only; sin limpieza automática de ambigüedad.

## Compatibilidad

4.14.8 local: probar API→agente→nodo→JSONL→alerta. 4.12.0 institucional: pruebas E2E aisladas con responsable y RBAC, no inferir compatibilidad de 4.14.8 ni tocar producción. Referencias: [API Wazuh](https://documentation.wazuh.com/current/user-manual/api/reference.html), [Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html), [localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), `docs/ansible-documentation/docs/docsite/rst/playbook_guide/playbooks_{tags,variables}.rst`.
