# Integración con Wazuh

> Estado: **diseño/planificación**. El código de integración aún no está en este
> repositorio. Este documento fija la arquitectura de referencia y, sobre todo,
> cómo Wazuh guarda los logs, para que la implementación posterior sea precisa.

## Arquitectura de Wazuh

Wazuh se compone de cuatro piezas:

1. **Wazuh agent** — corre en cada endpoint. Recolecta logs, eventos del sistema
   de archivos, syscalls e inventario, y los envía al server.
2. **Wazuh server (manager)** — motor de análisis: decodifica (`decoders`) y
   empareja contra `rules`. Genera **alertas** cuando un evento dispara una regla.
3. **Wazuh indexer** — motor de búsqueda y almacenamiento (basado en
   OpenSearch). Recibe alertas y eventos vía **Filebeat**.
4. **Wazuh dashboard** — interfaz web de visualización y consulta.

```
endpoint ──(1514)──▶ Wazuh server ──▶ alerts/archives (archivos)
                              │
                              └──▶ Filebeat ──(9200, TLS)──▶ Wazuh indexer ──▶ dashboard
```

## Cómo Wazuh guarda los logs

Hay **dos capas** de almacenamiento: archivos en el server y documentos en el
indexer.

### 1. Archivos en el server (`/var/ossec/logs/`)

| Archivo | Origen | Contenido |
|---|---|---|
| `ossec.log` | Interno | Logs informativos del propio server |
| `api.log` | Interno | Interacciones con la API del server |
| `cluster.log` | Interno | Actividad del cluster |
| `integrations.log` | Interno | Módulo de integración con terceros |
| `active-responses.log` | Interno | Ejecuciones de active response |
| `alerts/alerts.json` y `alerts.log` | Externo | **Solo** eventos que dispararon una regla (alertas) |
| `archives/archives.json` y `archives.log` | Externo | **Todos** los eventos recibidos (archivos) |

Reglas clave:

- **Alerts** guarda únicamente lo que disparó una regla; **archives** guarda
  todo (alerte o no). Los archives están **deshabilitados por defecto** (consumen
  mucho disco) y se habilitan en `/var/ossec/etc/ossec.conf`:

  ```xml
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>        <!-- archives.log (formato syslog) -->
    <logall_json>yes</logall_json> <!-- archives.json (formato JSON) -->
  </global>
  ```

  Solo `logall_json=yes` permite indexar los archives en el dashboard.
- Los logs se **rotan y comprimen a diario** (y por tamaño/antigüedad) y se
  **firman digitalmente** con MD5/SHA1/SHA256. Se conservan de forma indefinida
  salvo política de retención explícita.

### 2. Documentos en el indexer (índices)

Filebeat reenvía alerts (y archives si están habilitados) al indexer por TLS. El
indexer organiza los datos en índices por fecha:

| Índice | Contenido |
|---|---|
| `wazuh-alerts-*` | Alertas generadas por el server |
| `wazuh-archives-*` | Todos los eventos (si archives está habilitado) |
| `wazuh-monitoring-*` | Estado de conexión de los agentes (cada ~15 min) |
| `wazuh-statistics-*` | Estadísticas de rendimiento del server (cada ~5 min) |

Los índices se crean por día (`wazuh-alerts-4.x-2026.03.17`). Para ver los
archives en el dashboard hay que habilitarlos también en
`/etc/filebeat/filebeat.yml` (`archives: enabled: true`) y crear el index
pattern `wazuh-archives-*`.

### Puertos principales

| Componente | Puerto | Protocolo | Propósito |
|---|---|---|---|
| Server | 1514 | TCP (UDP opcional) | Conexión de agentes |
| Server | 1515 | TCP | Enrolamiento de agentes |
| Server | 1516 | TCP | Daemon de cluster |
| Server | 514 | UDP/TCP | Colector syslog |
| Server | 55000 | TCP | API REST del server |
| Indexer | 9200 | TCP | API REST del indexer |
| Indexer | 9300-9400 | TCP | Comunicación del cluster |
| Dashboard | 443 | TCP | Interfaz web |

## Cómo se integra este proyecto (playbook de hardening)

El objetivo es que Wazuh sea la capa de **auditoría continua** y este proyecto la
capa de **remediación**. El flujo recomendado:

1. **Auditoría (Wazuh SCA).** El módulo *Security Configuration Assessment*
   (SCA) corre políticas CIS (archivos YAML en el agent) y reporta pass/fail por
   control como **alertas SCA** (índice `wazuh-alerts-*`, tipo `sca`). Esto da el
   "qué está incumplido" en tiempo real, sin modificar nada.
2. **Remediación (Ansible).** Cuando se detecta desvío (o por mantenimiento
   programado), se invoca el playbook de hardening de este proyecto:

   ```bash
   ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
     --limit <host> --tags <control> \
     -e cis_ubuntu_2404_remediation_enabled=true
   ```

   Los mecanismos de disparo posibles:
   - **Active response** del Wazuh server/agent que ejecuta el playbook ante una
     alerta (cuidado con loops: el playbook debe ser idempotente).
   - **Integración/`command`** en `ossec.conf` que llama al runner de Ansible.
   - **Orquestador externo** (CI/CD) que consulta la API del Wazuh server
     (`:55000`) y decide cuándo remediar.
3. **Verificación de cierre.** El playbook de `verify/` confirma que el control
   quedó conforme; Wazuh re-evalúa SCA y la alerta baja a `passed`, cerrando el
   ciclo (audit → remediate → verify).

### Dónde quedan las evidencias

- Los resultados de cada corrida se guardan en `ansible/evidence/cis/<fecha>/`
  (recibos de audit/hardening/verify con recaps `ok/changed/failed`).
- Si querés que Wazuh ingiera los resultados del playbook, agregá un
  `localfile` en el `ossec.conf` del agent que lea el log de evidencia JSON del
  playbook; un decoder/rule custom convierte cada control en una alerta de
  cumplimiento.

## Consideraciones de diseño

- **Kernel compartido / alcance**: este proyecto endurece el host. Los controles
  de kernel (sysctl, módulos, auditd) son responsabilidad del host, no de los
  contenedores. La integración Wazuh hereda esa separación (ver SUPPORT.md para
  el estado no-soportado de Docker).
- **Idempotencia obligatoria**: el playbook ya exige segunda corrida con
  `changed=0`; es condición para que un active response no provoque reintentos.
- **Secretos**: el nodo de control de Wazuh que dispare Ansible necesita acceso
  SSH al objetivo (`ansible` + clave); gestioná esa credencial con el mismo rigor
  que las del inventario de producción.
