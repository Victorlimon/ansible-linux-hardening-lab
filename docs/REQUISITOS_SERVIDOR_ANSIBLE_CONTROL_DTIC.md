# Requisitos del servidor ansible-control (nodo central)

**Solicitud de aprovisionamiento a DTIC · Versión 2.0 · 11 de noviembre de 2026 · Zona horaria America/La_Paz**

## 1. Resumen de la solicitud

Se solicita a DTIC **una máquina virtual dedicada con Ubuntu Server 24.04 LTS**
para alojar el nodo central de Ansible del proyecto de endurecimiento CIS. Desde
este servidor se aplicará el endurecimiento CIS Benchmark, se verificarán los
controles y se conservarán las evidencias de **hasta 8 nodos cliente Linux**
(Ubuntu 24.04 y Debian 12).

| Recurso | Solicitud |
| --- | --- |
| Sistema operativo | Ubuntu Server 24.04 LTS, instalación mínima, sin interfaz gráfica |
| Procesador | **4 vCPU** |
| Memoria | **8 GB de RAM** |
| Almacenamiento | **100 GB** en un único disco virtual |
| Red | Una interfaz en la red institucional con alcance SSH hacia los 8 nodos |
| Uso | Exclusivo para el nodo central; no se comparte con otros servicios |
| Cantidad | **Una sola VM** |

## 2. Cómo funcionará el nodo central

```text
 Administrador autorizado
          │ SSH (llave)
          ▼
 ┌──────────────────────────┐        SSH TCP 22         ┌────────────────────┐
 │  ansible-control         │ ────────────────────────▶ │  Hasta 8 nodos     │
 │  Ubuntu 24.04 LTS        │                           │  Ubuntu 24.04 /    │
 │  Ansible Core 2.21.2     │                           │  Debian 12         │
 │  Playbooks CIS + evidencia│                          └────────────────────┘
 └──────────────────────────┘
          │ agente Wazuh (TCP 1514/1515, salida)
          ▼
 Wazuh manager institucional (medición SCA y orden de ejecución)
```

1. El administrador ingresa al nodo central por SSH con llave.
2. El nodo central se conecta por SSH a cada nodo cliente y aplica los controles
   CIS. Los nodos **no necesitan software adicional**: solo SSH y Python, que ya
   vienen en Ubuntu y Debian.
3. Cada ejecución sigue el mismo ciclo: **aplicar → repetir sin cambios
   (idempotencia) → verificar**. Las salidas quedan guardadas como evidencia.
4. Wazuh mide el resultado con su evaluación SCA. Opcionalmente, Wazuh puede
   solicitar una ejecución mediante *Active Response* al agente instalado en el
   nodo central. Wazuh **no** se conecta por SSH a los nodos ni ejecuta el
   endurecimiento; el nodo central valida la orden y ejecuta los playbooks.

Si el nodo central no está disponible, solo se detienen las ejecuciones
automatizadas; los nodos cliente siguen funcionando normalmente.

## 3. Justificación de los recursos

### Procesador: 4 vCPU

Ansible ejecuta cada tarea en paralelo sobre varios nodos mediante *forks*
(5 por defecto). Con 8 nodos se configurarán **8 forks**, de modo que todos los
nodos se procesen en la misma pasada y no en dos tandas. Cada fork es un proceso
Python independiente en el controlador. Con 4 vCPU hay capacidad para atender
los 8 forks y, al mismo tiempo, el sistema, el agente Wazuh y la verificación de
evidencias. Referencia: [configuración de forks](https://docs.ansible.com/projects/ansible-core/devel/reference_appendices/config.html#default-forks).

### Memoria: 8 GB

Ubuntu Server 24.04 sugiere **3 GB o más** para el propio sistema
([requisitos de Ubuntu Server](https://ubuntu.com/server/docs/system-requirements/)).
Los 8 GB dan margen para los 8 procesos de Ansible en paralelo, la recolección
de datos de cada nodo (*facts*), el agente Wazuh y los picos de las ejecuciones
de verificación. Como referencia, en el laboratorio el controlador funcionó con
1 vCPU y 1 GB para 2 nodos; la solicitud dimensiona para 8 nodos con holgura.

### Almacenamiento: 100 GB

| Uso estimado | Espacio |
| --- | --- |
| Sistema operativo, actualizaciones y paquetes | 25 GB |
| Entorno de Ansible, colecciones y repositorio del proyecto | 10 GB |
| Evidencias de ejecución y registros (journal, `ansible.log`, auditd) | 45 GB |
| Espacio libre de reserva (mínimo) | 20 GB |
| **Total** | **100 GB** |

El reparto es ilustrativo y no exige particiones especiales. DTIC puede usar su
esquema estándar. La retención de registros se ajustará según el crecimiento
real medido.

### Sistema operativo: Ubuntu Server 24.04 LTS

Tiene soporte estándar hasta 2029 ([ciclo de Ubuntu](https://ubuntu.com/about/release-cycle))
e incluye Python 3.12, compatible con Ansible Core 2.21.2. Es la misma versión
que uno de los sistemas endurecidos por el proyecto, por lo que el nodo central
también recibirá su propio perfil de endurecimiento CIS.

## 4. Por qué un servidor dedicado y no un contenedor

El nodo central guarda las credenciales con privilegios sobre todos los nodos.
Por eso se solicita una VM dedicada y endurecida, y no un contenedor Docker:

- **Superficie mínima:** solo ejecuta Ansible y el agente Wazuh. Un host de
  contenedores agrega un motor, un socket con privilegios de root y una red
  adicional que también habría que proteger.
- **Medición directa:** el agente Wazuh evalúa el propio sistema operativo del
  nodo central con la política CIS de Ubuntu 24.04. En un contenedor, esa
  medición quedaría en el host y no en el controlador.
- **Auditoría y rescate:** auditd, journald y la consola de la VM registran y
  recuperan el servidor completo, sin capas intermedias.
- **Nivel de madurez:** el nodo central es el primer servidor endurecido con el
  mismo proceso que luego se aplica a los nodos.

## 5. Conectividad requerida

Los puertos indicados son los habituales. DTIC confirmará direcciones y reglas
reales antes de abrirlas.

| Flujo | Dirección | Puerto | Motivo |
| --- | --- | --- | --- |
| Administrador → nodo central | Entrada | TCP 22 (SSH) | Administración, solo desde la red o bastión autorizado |
| Nodo central → 8 nodos cliente | Salida | TCP 22 (SSH) | Ejecución de Ansible |
| Nodo central → Wazuh manager | Salida | TCP 1514 y 1515 | Agente Wazuh: eventos, SCA y Active Response |
| Nodo central → DNS institucional | Salida | UDP/TCP 53 | Resolución de nombres |
| Nodo central → servidor de hora | Salida | UDP 123 | Sincronización horaria (requisito CIS) |
| Nodo central → repositorios Ubuntu o proxy | Salida | TCP 80/443 | Actualizaciones de seguridad |

**No se requiere ningún puerto de entrada adicional.** Wazuh se comunica con el
nodo central a través de la conexión que abre su propio agente.

## 6. Acceso, rescate y respaldo

| Requisito | Motivo |
| --- | --- |
| Cuenta administrativa con sudo para el responsable del proyecto | Instalar y operar el controlador |
| Acceso SSH por llave desde un origen autorizado | El endurecimiento desactiva el acceso por contraseña de forma progresiva |
| **Consola de rescate** (consola del hipervisor o equivalente) | Recuperar el acceso si una regla de SSH o firewall queda mal configurada |
| Snapshot antes del endurecimiento | Volver al estado base si una prueba falla |
| Respaldo institucional periódico | Proteger el repositorio, el inventario y las evidencias |

## 7. Responsabilidades

**DTIC entrega** la VM base con los recursos indicados, la red, el acceso
administrativo, la consola de rescate y la política de respaldo. No necesita
instalar Ansible ni ningún software del proyecto.

**El administrador del proyecto** instala Ansible Core 2.21.2 en un entorno
virtual, prepara el inventario de los 8 nodos y las credenciales, aplica el
endurecimiento CIS al propio nodo central y luego opera sobre los nodos cliente
según el procedimiento técnico ([plan del controlador](ANSIBLE_CONTROL_HARDENING.md)).

## 8. Criterios de aceptación de la entrega

- [ ] Ubuntu Server 24.04 LTS instalado y actualizado, sin entorno gráfico.
- [ ] 4 vCPU, 8 GB de RAM y un disco de 100 GB asignados.
- [ ] Acceso SSH del administrador probado desde el origen autorizado.
- [ ] Consola de rescate probada.
- [ ] Conexión SSH (TCP 22) desde el nodo central hacia cada uno de los 8 nodos.
- [ ] Salida hacia el Wazuh manager (TCP 1514/1515), DNS, hora y repositorios.
- [ ] Snapshot inicial creado.

## 9. Datos que DTIC debe confirmar

| Dato | Valor |
| --- | --- |
| Nombre de host y dirección IP del nodo central | |
| Red o bastión de origen para la administración | |
| Direcciones IP y puertos SSH de los 8 nodos cliente | |
| Dirección del Wazuh manager | |
| Servidores DNS, NTP y proxy de actualizaciones | |
| Responsable de respaldos y de la consola de rescate | |

Este documento es una solicitud de infraestructura. No autoriza por sí mismo
cambios de firewall, accesos remotos ni ejecuciones sobre los nodos.
