# Preguntas y respuestas del proyecto de endurecimiento Linux

El proyecto completó el estudio de la línea base, el diseño de la solución, el desarrollo de la automatización y su comprobación en laboratorio para Debian 12 y Ubuntu Server 24.04. El trabajo comprendió las siete secciones de los benchmarks, con una matriz que orientó la implementación, pruebas unitarias por sección y una prueba integrada del conjunto, estas últimas confirmadas por el responsable.

La etapa concluida fue el desarrollo y la validación de laboratorio dentro del alcance ensayado. La preproducción institucional no se realizó y el despliegue en producción quedó pendiente de infraestructura, información de servicios y autorizaciones de DTIC. Esta distinción permite presentar los resultados alcanzados sin confundirlos con la aceptación de todos los controles de un perfil CIS ni con una implantación institucional ya efectuada.

## Sobre la línea base (Fase 1)

### 1. En la transcripción dices que te indicaron enfocarte en las secciones 3, 4 y 6. ¿Quién te lo indicó (Ing. Deyler u otra persona) y por qué esas secciones?

**El alcance desarrollado comprendió las siete secciones; todas se consideraron importantes para construir la línea base.** La mención aislada a las secciones 3, 4 y 6 no representó una exclusión de las restantes. El estudio abarcó la configuración inicial, los servicios, la red, el firewall, el acceso y la autenticación, la auditoría y el registro, y el mantenimiento del sistema. Esta cobertura permitió relacionar medidas que se complementan, en lugar de tratar el endurecimiento como un conjunto de ajustes independientes.

La matriz inicial organizó el trabajo por plataforma y sección. A partir de ella se desarrollaron los mecanismos de auditoría, remediación y verificación, considerando la aplicabilidad y el impacto de cada control. Por ello, la descripción académica del proyecto debe explicar el trabajo sobre las siete secciones, mientras que las decisiones sobre controles concretos se sustentan en su clasificación y en las condiciones del entorno.

No se cuenta con el fragmento contextualizado de la transcripción que identifique al autor y el motivo de aquella indicación. En consecuencia, no se atribuye al Ing. Deyler ni a otra persona. Lo confirmado por el responsable es el alcance de siete secciones efectivamente estudiadas y trabajadas, no una priorización exclusiva de tres de ellas.

**Fuentes:** aclaración del responsable; catálogo y matriz de controles [2–3].

### 2. ¿Implementaste las 7 secciones completas o solo algunos controles? El docente menciona que “solo vas a implementar controles de auditoría”, pero no me queda claro a qué se refiere. ¿Qué controles quedan fuera de tu línea base (por ejemplo AIDE o particiones) y por qué?

**Se desarrolló una línea base que abordó las siete secciones, con controles de auditoría, remediación y verificación; no se limitó a observar el sistema.** La auditoría identificó el estado de las configuraciones; la remediación implementó los cambios habilitados para el entorno; la verificación contrastó los resultados con las condiciones esperadas. El desarrollo y las pruebas por sección se completaron en laboratorio, con aplicación de los controles seleccionados según su pertinencia y sus requisitos técnicos.

Trabajar todas las secciones no significó modificar automáticamente todos los controles del catálogo. La línea base distinguió los controles automatizados, los que requirieron habilitación expresa por su riesgo, los de revisión manual y los no aplicables. Esta separación formó parte del diseño: una decisión sobre acceso administrativo, retiro de servicios o distribución del almacenamiento no podía resolverse únicamente por pertenecer a un benchmark, sin conocer la función y las dependencias del servidor.

| Tipo de control o decisión | Cobertura de la línea base y tratamiento |
| --- | --- |
| Configuraciones automatizables del sistema | Se incorporaron mecanismos para evaluar, aplicar y comprobar las configuraciones contempladas por la implementación y habilitadas en cada ejecución. |
| Integridad de archivos, incluido AIDE | Se incluyeron mecanismos y un perfil específico de laboratorio. Su tratamiento no se excluyó del estudio; la activación y la aprobación de una base de integridad dependieron de una configuración deliberada. |
| Particiones y sistemas de archivos separados | Se analizaron y contemplaron como requisitos de configuración. Su adecuación dependió del esquema de almacenamiento; no se declaró realizada una migración de particiones por el solo hecho de disponer de comprobaciones. |
| Acceso, autenticación, firewall y servicios | Se abordaron dentro de las secciones correspondientes, con habilitaciones y decisiones específicas para evitar cambios incompatibles con la administración o el servicio. |
| Controles manuales o dependientes del sitio | Se conservaron para revisión y decisión humana, especialmente cuando exigieron política institucional, conocimiento de aplicaciones o aceptación del responsable del sistema. |

La expresión docente «controles de auditoría» pudo referirse al modo de evaluación sin cambios o a los controles de registro y auditoría de eventos. Sin su contexto no se le asigna una intención concreta. En cualquier caso, el producto desarrollado incluyó remediación y verificación además de auditoría. La respuesta precisa es, por tanto, que se completó el desarrollo de alcance transversal sobre las siete secciones, no que todos los controles CIS quedaron remediados en todos los equipos. Las decisiones institucionales por servidor se completarán con la información de DTIC.

**Fuentes:** descripción del proyecto, matriz, guía de uso, soporte, despliegue y perfil AIDE de laboratorio [1, 3, 6–8, 23].

### 3. ¿Aplicaste Level 1, Level 2 o ambos? ¿Cuántos controles son automatizables y cuántos solo de observación?

**El estudio y la organización de la línea base incluyeron controles de Server Level 1 y Server Level 2.** La implementación utilizó esa clasificación para identificar el alcance y las implicaciones de los controles, pero la aplicación en laboratorio se realizó de acuerdo con los mecanismos y habilitaciones seleccionados. No se presenta ese resultado como aceptación íntegra de uno de los dos perfiles; el perfil institucional de aceptación deberá acordarse con DTIC según las funciones de sus servidores.

El catálogo local registró la siguiente composición. Level 2 expandido incluyó los controles de Level 1 y sus controles adicionales; las filas no son conjuntos que deban sumarse entre sí.

| Composición del catálogo de servidores | Ubuntu 24.04 | Debian 12 |
| --- | ---: | ---: |
| Controles únicos | 311 | 310 |
| Pertenencia directa a Server Level 1 | 250 | 248 |
| Controles adicionales de Server Level 2 | 61 | 62 |
| Server Level 2 expandido | 311 | 310 |

Para responder cuántos controles fueron automatizables se utilizaron dos clasificaciones distintas: el tipo de evaluación de la fuente y el tratamiento técnico adoptado por el proyecto. La primera indicó cómo podía evaluarse un control; la segunda, cómo se decidió atenderlo en la solución.

| Clasificación | Ubuntu 24.04 | Debian 12 |
| --- | ---: | ---: |
| Evaluación de la fuente: automatizada | 290 | 289 |
| Evaluación de la fuente: manual | 21 | 21 |
| Tratamiento del proyecto: automatizado | 164 | 167 |
| Tratamiento del proyecto: condicionado por riesgo (`gated_unsafe`) | 99 | 96 |
| Tratamiento del proyecto: manual | 32 | 33 |
| Tratamiento del proyecto: no aplicable | 16 | 14 |

Las cuatro últimas filas distribuyeron los 311 y 310 controles de cada catálogo. Los controles manuales del proyecto —32 en Ubuntu y 33 en Debian— requirieron observación o decisión humana; los no aplicables constituyeron una categoría separada. El ledger registró 263 rutas de remediación por plataforma, al sumar automatizadas y condicionadas. Esa cifra describió rutas mapeadas, no 263 controles ejecutados y aprobados en cada servidor. Del mismo modo, una evaluación automatizable no implicó una remediación automática.

Los recuentos proceden del catálogo y la matriz locales, cuyas identidades de fuente son Ubuntu 1.0.0 y Debian 1.1.0. No se dedujeron de la etiqueta interna Git `cis-v1.1.0` ni se presentan como una consulta de las últimas ediciones oficiales. Esta referencia común permite interpretar las cifras del documento sin mezclar catálogos, tareas ejecutadas y resultados de pruebas.

**Fuentes:** catálogo, matriz, ledger y política de soporte [2–4, 7].

### 4. ¿Qué resultado concreto dejó el estudio de cada benchmark (una lista de controles, una matriz, un documento)?

**El estudio produjo una matriz de análisis y trazabilidad que orientó el endurecimiento desde el inicio, según confirmó el responsable.** No quedó únicamente como una revisión bibliográfica: organizó los controles de Debian y Ubuntu por sección, nivel, tipo de evaluación y tratamiento previsto. Esa organización permitió trasladar el estudio al desarrollo y decidir qué requería automatización, autorización adicional o revisión manual.

El resultado se materializó en archivos con funciones complementarias. El catálogo conservó identificadores y perfiles; la matriz registró la clasificación y disposición de los controles; el ledger relacionó cada control con sus rutas de auditoría, remediación y verificación. El registro de revisión semántica aportó un soporte adicional para revisar la correspondencia entre la interpretación del control y su tratamiento. En conjunto, estos productos ofrecieron una base para explicar qué se estudió y cómo se incorporó al proyecto.

| Sección del benchmark | Ubuntu 24.04 | Debian 12 |
| --- | ---: | ---: |
| 1. Configuración inicial | 66 | 64 |
| 2. Servicios | 43 | 43 |
| 3. Configuración de red | 17 | 18 |
| 4. Firewall | 29 | 29 |
| 5. Acceso y autenticación | 71 | 71 |
| 6. Auditoría y registro | 62 | 62 |
| 7. Mantenimiento del sistema | 23 | 23 |
| **Total** | **311** | **310** |

La matriz facilitó además la organización de los sprints y las pruebas por sección. Para la memoria académica, el entregable del estudio puede describirse como una matriz técnica acompañada de un catálogo y un registro de trazabilidad hacia la implementación. Los resultados de ejecución se documentaron por separado: la existencia del registro de un control no se utilizó como sustituto de su evidencia de prueba.

**Fuentes:** aclaración del responsable; catálogo, matriz, ledger y revisión semántica [2–5].

## Sobre el diseño (Fase 2)

### 5. ¿El diseño de producción existe o hay que crearlo? Es decir, ¿cómo quedaría el nodo Ansible central en la DTIC, dónde se instalaría y cómo se conectaría a Wazuh y a los servidores reales?

**Se elaboró el diseño lógico institucional y la solicitud de infraestructura para un controlador central dedicado.** La referencia definida fue una máquina virtual `ansible-control` con Ubuntu Server 24.04 LTS, alojada en la infraestructura que DTIC determine. Su función sería centralizar inventarios, ejecución de Ansible y registros técnicos. No se diseñó como servidor de aplicaciones ni como alojamiento de servicios de negocio; Wazuh se mantuvo en un servidor separado dentro de la arquitectura institucional.

El diseño asignó a DTIC la provisión de la VM base, la conectividad y los medios institucionales de acceso y recuperación. Después de recibirla, el administrador del proyecto prepararía Ansible Core 2.21.2, dependencias, inventarios y credenciales. Desde el controlador se establecerían las conexiones SSH a los servidores autorizados. La integración con Wazuh utilizaría el agente instalado en el controlador para recibir órdenes supervisadas y remitir los eventos de ejecución al sistema central de monitoreo.

Como criterio de capacidad, se estableció el objetivo de **endurecer hasta ocho servidores de forma concurrente**. No se definió con ello el tamaño de la flota institucional ni un rendimiento garantizado. La validación de esa concurrencia quedó pendiente: registrar ocho equipos en un inventario no demuestra que se hayan aplicado cambios simultáneamente sobre los ocho. Su comprobación requerirá una carga representativa y observar consumo de recursos, tiempos, conectividad y continuidad de los servicios.

El diseño lógico quedó disponible, pero su adaptación física y de red no se cerró. Ubicación institucional: **____________ — pendiente de información DTIC**. Segmento e IP del controlador: **____________ — pendiente de información DTIC**. Servidores y servicios administrados: **____________ — pendiente de información DTIC**. Estos datos completarán el diseño sin reemplazarlo por direcciones o equipos supuestos.

**Fuentes:** solicitud y plan del controlador, integración y plantilla de inventario de producción [10–12, 15–17, 25]. El objetivo de ocho servidores corresponde a la aclaración actual del responsable y sustituye, para esta respuesta, estimaciones anteriores de cantidad de nodos.

### 6. ¿Cuál es el hardware real del laboratorio (tu laptop: CPU, RAM, disco)? ¿Y el del nodo central y los servidores de producción en la DTIC?

**El laboratorio se desarrolló sobre una laptop física ASUS con Windows, que alojó las máquinas virtuales y la plataforma de contenedores.** Los datos del equipo proceden de consultas locales de solo lectura ya documentadas. Se presentan separados de las asignaciones virtuales y de los recursos solicitados a DTIC para evitar interpretar una solicitud como hardware recibido.

| Equipo físico de laboratorio | Característica registrada |
| --- | --- |
| Modelo | ASUS TUF Gaming F15 FX506LH |
| Procesador | Intel Core i5-10300H a 2,50 GHz; 4 núcleos y 8 procesadores lógicos |
| Memoria | 17.008.951.296 bytes reportados por Windows: aproximadamente 15,84 GiB, correspondientes a la capacidad nominal de 16 GB |
| Disco | SSD Micron 2210, modelo MTFDHBA512QFD; 512.110.190.592 bytes, aproximadamente 512 GB comerciales |
| Función | Equipo anfitrión de VirtualBox/Vagrant y de Docker para el laboratorio |

| Recurso virtual de laboratorio | Sistema o componente | Asignación declarada |
| --- | --- | --- |
| `ansible-control` | Ubuntu 24.04; controlador Ansible | 1 vCPU y 1.024 MB de RAM |
| `debian12` | Debian 12; servidor administrado | 1 vCPU y 1.024 MB de RAM |
| `ubuntu24` | Ubuntu 24.04; servidor administrado | 1 vCPU y 1.024 MB de RAM |
| Wazuh en Docker | Manager, indexer y dashboard | Recursos compartidos del anfitrión; no se documentó aquí una asignación total independiente por contenedor |

Las tres asignaciones de VM corresponden al `Vagrantfile`, no a una medición de consumo ni a una comprobación de encendido actual. Wazuh se ejecutó mediante contenedores en el equipo anfitrión; la definición de una cuarta VM Wazuh está comentada en el `Vagrantfile` y no se utilizó como descripción de la arquitectura desplegada. Tampoco se equiparó la memoria de una JVM con la memoria total de un contenedor.

| Infraestructura institucional | Solicitud o dato por completar |
| --- | --- |
| Controlador solicitado | VM base Ubuntu Server 24.04 LTS; 2 vCPU iniciales, ampliables a 4 si las mediciones lo justifican; 8 GiB de RAM recomendados; disco virtual de **100 GB totales** para sistema, herramientas y registros |
| Recursos efectivamente entregados al controlador | ____________ — pendiente de información DTIC |
| Hardware y capacidad del servidor Wazuh separado | ____________ — pendiente de información DTIC |
| Hardware de servidores clientes | ____________ — pendiente de información DTIC |
| Sistemas operativos, aplicaciones y servicios de clientes | ____________ — pendiente de información DTIC |

La solicitud del controlador constituyó una referencia inicial de aprovisionamiento, no una garantía de capacidad para ocho intervenciones simultáneas. Su dimensionamiento deberá contrastarse con la prueba de concurrencia prevista y con la carga real de los servidores. Los 100 GB solicitados correspondieron al disco completo de la VM, no a una reserva exclusiva para registros.

**Fuentes:** consultas locales históricas de hardware; `Vagrantfile`, guía de laboratorio y solicitud institucional [9, 11, 22].

### 7. ¿Tienes el diagrama de arquitectura hecho? Si no, lo preparo con IPs ficticias.

**La arquitectura del laboratorio quedó definida y se representa a continuación con sus componentes y flujos.** El esquema distingue la laptop física, las tres VM administradas con Vagrant/VirtualBox y los tres contenedores Wazuh. Las direcciones `192.168.56.x` corresponden exclusivamente al laboratorio; se muestran para explicar esa topología y no representan direcciones institucionales.

```text
LAPTOP FÍSICA ASUS / WINDOWS
│
├─ Operador del laboratorio
│    ├─ Administración del entorno con Vagrant / VirtualBox
│    ├─ Consulta del dashboard Wazuh
│    └─ Orden manual autorizada a la API de Wazuh
│
├─ Docker: plataforma Wazuh 4.12.0
│    ┌────────────────────────────────────────────────────────────┐
│    │ Manager ── eventos / alertas ──► Indexer ──► Dashboard       │
│    │    │ API y Active Response                                 │
│    └────┼───────────────────────────────────────────────────────┘
│         │ Acceso de las VM al manager a través del anfitrión
│         │ Interfaz host-only del anfitrión: 192.168.56.1
│         │
├─ VirtualBox / Vagrant: red privada host-only 192.168.56.0/24
│    │
│    ├─ ansible-control / Ubuntu 24.04 / 192.168.56.10
│    │    ├─ Agente Wazuh: recibe Active Response y envía registros
│    │    ├─ Gateway Python: valida trabajo, destino y autorización
│    │    ├─ Ansible Core 2.21.2: ejecuta auditoría y endurecimiento
│    │    └─ Eventos JSONL: ejecución y resultado hacia Wazuh
│    │           │
│    │           ├── SSH ──► debian12 / Debian 12 / 192.168.56.11
│    │           │              └─ Agente Wazuh ──► Manager
│    │           └── SSH ──► ubuntu24 / Ubuntu 24.04 / 192.168.56.12
│    │                          └─ Agente Wazuh ──► Manager
│    │
│    └─ Repositorio compartido solo con ansible-control:
│       /home/vagrant/ansible
│
└─ Adaptadores NAT de las VM: salida para dependencias y actualizaciones;
   acceso de Vagrant por SSH con puertos locales asignados automáticamente.
```

**Lectura del esquema.** Las VM proporcionaron sistemas operativos independientes para el controlador y los dos destinos. Los contenedores separaron los servicios de Wazuh sin constituir tres servidores físicos adicionales. La red privada permitió la administración entre las VM y el acceso al anfitrión; NAT cubrió la salida del entorno virtual. El repositorio se compartió únicamente con el controlador, mientras que los clientes recibieron las operaciones por SSH, sin una carpeta de proyecto sincronizada.

El flujo de control comenzó con la solicitud del operador a Wazuh y continuó mediante Active Response hacia el agente del controlador. Allí el gateway validó la solicitud y Ansible operó sobre los destinos autorizados. El flujo de información recorrió el camino de retorno: registros de agentes y eventos JSONL hacia el manager, alertas al indexer y consulta en el dashboard. El agente de los clientes sirvió para observación; no sustituyó la conexión SSH utilizada por Ansible.

El esquema institucional conservó la separación funcional, pero trasladó el controlador a una VM dedicada de DTIC y Wazuh a un servidor separado:

```text
Operador autorizado
       │ orden supervisada
       ▼
Servidor Wazuh separado ── Active Response ──► ansible-control dedicado
       ▲                                          │ gateway + Ansible
       │ eventos, registros y resultados          │ SSH
       └───────────────────────────────────────────┤
                                                  ▼
                                     Servidores Linux autorizados
                               Objetivo: hasta 8 de forma concurrente
                                     Validación de capacidad pendiente
```

Este segundo esquema es un diseño lógico, no una red institucional instalada. Sus IP, ubicación y servicios se mantienen en blanco hasta recibir información de DTIC. La representación de los flujos del laboratorio recoge la implementación y la evidencia histórica; no constituye una comprobación de disponibilidad actual de los agentes o servicios.

**Fuentes:** topología de laboratorio, `Vagrantfile`, documentación Wazuh e integración [9–10, 15–17, 22].

## Sobre desarrollo y pruebas de laboratorio (Fase 3) y preproducción prevista (Fase 4)

### 8. ¿Hay evidencias disponibles (capturas de make up, salida de Ansible con changed=0, estructura de carpetas, consola de Wazuh)? ¿Qué tienes y qué falta tomar?

**Se dispuso de evidencias de desarrollo y pruebas, y el responsable confirmó capturas de las sesiones de endurecimiento, pruebas unitarias de cada sección y una prueba integrada de las siete secciones.** La preparación de la memoria requiere reunirlas en un índice que relacione cada imagen o salida con la plataforma, sección, versión del código y ejecución correspondiente. Las capturas confirmadas por el responsable no fueron inspeccionadas durante esta edición documental.

| Evidencia | Disponibilidad y utilidad para la memoria |
| --- | --- |
| Preparación y arranque del laboratorio | Se contó con el procedimiento documentado. Queda seleccionar e identificar la captura concreta de `make up` o del arranque equivalente. |
| Sesiones de endurecimiento por sección | Capturas existentes según confirmación del responsable. Queda vincularlas con las siete secciones y sus resultados. |
| Organización del proyecto | La estructura incluyó playbooks, roles, inventarios, catálogo, pruebas e integración. Queda seleccionar una representación legible para la memoria. |
| Pruebas unitarias por sección | Realización confirmada por el responsable. Queda ordenar los resultados por sección y plataforma, sin utilizar un recuento histórico como tamaño actual de la suite. |
| Prueba integrada de las siete secciones | Realización confirmada por el responsable. Queda asociar la salida completa y su versión con el índice de evidencias. |
| Verificación e idempotencia | Se conservaron resultados históricos con alcance delimitado. Cada salida debe indicar qué selección se ejecutó y si correspondió a aplicación, segunda aplicación o verificación. |
| Integración y consola Wazuh | Se documentaron trabajos `FULL CHECK` y `FULL APPLY`, eventos y alertas correlacionados. Queda vincular las capturas de consola a sus solicitudes y resultados. |

Como referencia histórica, el registro del 28 de octubre de 2026 recogió verificaciones con `ok=1879` en Debian y `ok=1983` en Ubuntu, ambas con `failed=0`, y un recuento de 395 pruebas unitarias. Estos datos describieron aquella ejecución y su selección; no se presentan como el número actual de pruebas ni como un recuento de controles CIS aprobados. La evidencia del 21 de octubre documentó además el flujo de integración y aplicaciones satisfactorias por separado en ambos sistemas. El antecedente de `changed=0` sobre el subconjunto `sysctl` tuvo un alcance más acotado y no se extendió a toda la línea base.

Para su presentación, cada evidencia debe conservar una ficha breve: identificador, sección o alcance, plataforma, versión, fecha, resultado y archivo asociado. Una segunda aplicación sin cambios demuestra idempotencia del alcance ejecutado; una verificación sin fallos demuestra el resultado de sus comprobaciones. Ninguna de ellas, por sí sola, acredita compatibilidad con servicios institucionales todavía desconocidos. No se declara realizada una prueba de reinicio ni una prueba de ocho servidores concurrentes: ambas validaciones permanecen pendientes dentro del plan de continuidad del proyecto.

**Fuentes:** confirmación del responsable; laboratorio, evidencia de ciclo de vida, integración y directorios de pruebas [9, 16, 19–21]. Los valores del 28 de octubre corresponden al antecedente histórico comunicado, no a pruebas ejecutadas para redactar este documento.

### 9. En la preproducción, ¿qué significa “simular los servidores de la DTIC”? ¿Son las mismas VMs del laboratorio o algo distinto?

**La preproducción se definió como una etapa distinta del laboratorio y todavía no se realizó.** Su propósito fue preparar un entorno limpio y representativo de las condiciones institucionales, no cambiar el nombre de las VM de desarrollo ni asumir que estas ya reprodujeron los servicios de DTIC. El laboratorio permitió desarrollar y ensayar controles de Debian y Ubuntu; la representación de cargas de negocio exige conocer aplicaciones, puertos, dependencias y necesidades de disponibilidad reales.

La referencia inicial acordada para esa etapa fue un `ansible-control` limpio, dedicado y sin Vagrant, sin aplicaciones ni servicios de negocio. En él se prepararía el entorno de administración bajo las condiciones institucionales. Esta referencia no debe confundirse con una lista de servicios ya entregada: DTIC aún no proporcionó esa información. La comprobación del controlador será una parte de la preproducción, no una sustitución de las pruebas funcionales que luego correspondan a los servidores clientes.

Para representar a los servidores administrados se necesitará un inventario propio y una configuración separada del laboratorio. La selección de sistemas, servicios y datos de prueba deberá responder a lo que DTIC comunique, junto con criterios de recuperación y aceptación. Por tanto, no se reutilizarán supuestos del laboratorio como si fueran características institucionales confirmadas; los datos pendientes se completarán antes de esa ejecución.

**Fuentes:** aclaración del responsable; guía de preproducción, laboratorio y plantilla de inventario `staging` [9, 17, 24].

### 10. ¿Las pruebas en producción se van a hacer? ¿Con cuántos servidores reales y cuándo?

**La aplicación institucional se mantuvo como una etapa posterior al desarrollo de laboratorio; no se realizó ni se fijó una fecha autorizada.** La cantidad real de equipos, los sistemas y servicios incluidos y la ventana de intervención no fueron proporcionados por DTIC. Estos campos no se sustituyen por una estimación de flota ni por fechas académicas que pudieran interpretarse como compromisos operativos.

La solución se planteó con una capacidad objetivo de hasta ocho servidores endurecidos concurrentemente. Ese criterio orienta la validación futura y no responde a cuántos servidores reales fueron entregados. Para considerarlo demostrado deberá realizarse una prueba explícita de simultaneidad sobre destinos autorizados, con alcance definido y observación de recursos y resultados; no bastará con incluir ocho nombres en el inventario o ejecutar los equipos de manera secuencial.

La preparación del despliegue requerirá cerrar la preproducción, acordar el alcance por servidor y obtener autorización de los responsables de los servicios. Un piloto gradual constituye una propuesta de despliegue para esa etapa, no una prueba realizada ni una aprobación existente. Cantidad de servidores reales: **____________ — pendiente de información DTIC**. Fecha y ventana de intervención: **____________ — pendiente de información DTIC**. Autorización y responsable institucional: **____________ — pendiente de información DTIC**.

**Fuentes:** aclaración actual del responsable; solicitud del controlador, preproducción, soporte e inventario de producción [7, 11, 17, 25].

### 11. ¿Cómo funciona exactamente la integración con Wazuh (active response, webhook, script)? Necesito saberlo para la parte que sigue en proceso.

**La integración se implementó mediante una orden manual a la API de Wazuh, Active Response en el agente del controlador y un gateway personalizado en Python que preparó la ejecución de Ansible.** No se diseñó como un webhook público ni como una remediación indiscriminada a partir de cualquier alerta. Se separaron la solicitud de trabajo, la autorización para aplicar cambios y la ejecución sobre los servidores.

| Paso | Recorrido y responsabilidad |
| --- | --- |
| 1. Solicitud | El operador solicitó `CHECK` o `APPLY` mediante `PUT /active-response`, dirigido al agente de `ansible-control`, con el comando `!ansible-job` y el contrato JSON `managed-v2`. |
| 2. Recepción y validación | Active Response entregó la solicitud al gateway Python del controlador. Este validó el formato, la versión preparada del código, el perfil de inventario, los destinos y el alcance permitido. |
| 3. Autorización de cambios | Para `APPLY` se requirió una aprobación independiente, de un solo uso por host y vinculada al alcance. La solicitud a la API no reemplazó esa aprobación administrativa. |
| 4. Ejecución | Ansible Core 2.21.2 se ejecutó en el controlador y se conectó por SSH a los destinos autorizados. El servidor Wazuh no asumió la ejecución de playbooks ni necesitó conectarse por SSH a esos destinos. |
| 5. Registro y consulta | El gateway generó eventos JSONL de aceptación, inicio, progreso, recapitulación y cierre. El agente los remitió al manager, cuyas alertas se enviaron al indexer para su consulta en el dashboard. |

Los componentes propios incluyeron el manejador `managed_job.py`, perfiles y mecanismos de supervisión. La recolección contempló `/var/log/ansible-wazuh-jobs.jsonl`, y un identificador de solicitud permitió correlacionar la orden con su recorrido y resultado. Esta integración complementó el registro del sistema y los agentes de los clientes: Wazuh aportó observabilidad y canal de operación supervisada; Ansible conservó la responsabilidad de ejecutar la configuración.

La evidencia del 21 de octubre de 2026 documentó `FULL CHECK` y `FULL APPLY` sobre Debian y Ubuntu por separado, con aplicaciones sin tareas fallidas. Ese resultado respaldó el flujo implementado para la versión ensayada. Los selectores posteriores por sección o control conservaron una validación de contrato diferenciada de su prueba de despliegue extremo a extremo. El resultado de una solicitud debía interpretarse mediante el evento terminal, el resumen Ansible y la verificación posterior, no solo por una respuesta HTTP satisfactoria. La descripción recoge la arquitectura y las pruebas históricas; no afirma disponibilidad actual del agente ni despliegue institucional.

Estos ensayos del prototipo en laboratorio no constituyeron la ejecución formal de la Fase 4. La integración y simulación representativa de producción, en un entorno limpio sin Vagrant, permanecen como actividades futuras de esa fase.

**Fuentes:** documentación de integración, componente Python, configuración de Active Response y recolección, evidencia y preproducción [10, 15–18].

## Sobre el cronograma

### 12. ¿Cuántas semanas quieres en total? Con 5 fases el Gantt crece, y en el perfil se habló de 4 meses (16 semanas). Además, en Condiciones Laborales figuran 4 horas diarias, es decir 320 horas, mientras que el cronograma hablaba de 640. ¿Cuál es la cifra correcta?

**La duración de planificación actualizada por decisión del responsable es de 18 semanas, con una dedicación de cuatro horas diarias durante cinco días laborables por semana: 360 horas.** La pregunta conserva la referencia original de 16 semanas para mantener su contexto; la respuesta vigente utiliza las 18 semanas acordadas. Este plazo es una base de planificación, no una afirmación de que las 18 semanas ya transcurrieron o de que se ejecutaron las etapas institucionales pendientes.

| Referencia | Cálculo | Interpretación |
| --- | --- | --- |
| Planificación actual | **18 semanas × 5 días × 4 horas = 360 horas** | Duración y dedicación vigentes para actualizar el cronograma |
| Referencia anterior de la pregunta | 16 semanas × 5 días × 4 horas = 320 horas | Cifra coherente con el plazo anterior, ya sustituido en esta respuesta |
| Cifra de 640 horas | 16 semanas × 5 días × 8 horas = 640 horas | No corresponde a la jornada de cuatro horas establecida |

Las cinco fases organizan el contenido del proyecto, pero no multiplican la jornada. Dentro de las 360 horas debe distribuirse el esfuerzo de estudio, diseño, desarrollo, pruebas y documentación, identificando las actividades institucionales que dependan de terceros. Si una autorización o la entrega de infraestructura queda fuera del periodo disponible, se reflejará como dependencia pendiente, sin presentarla como actividad cumplida.

Las fechas de inicio y cierre deberán incorporarse al Gantt cuando se complete el calendario. Este documento no reconstruye fechas históricas ni asigna retrospectivamente duraciones a las secciones. Fecha de inicio: **____________**. Fecha de cierre planificada: **____________**. Confirmación académica del Gantt detallado: **____________**.

**Base:** decisión actual del responsable sobre 18 semanas; dedicación de cuatro horas diarias y cinco días laborables; comprobación aritmética. No se modificó el archivo del Gantt.

### 13. ¿Quieres que cada sprint siga durando 1 a 2 semanas como en el Gantt actual?

**La organización confirmada de los sprints correspondió al desarrollo de cada una de las siete secciones y a sus propias pruebas unitarias; después se realizó la prueba integrada de las siete.** Por ello, el cronograma no debe representarse como ocho bloques genéricos de dos semanas sin relación con los entregables técnicos. La unidad de trabajo fue la sección, con implementación y comprobación asociadas.

| Sprint o bloque de desarrollo por sección | Trabajo desarrollado y prueba asociada |
| --- | --- |
| Sección 1: configuración inicial | Desarrollo de los mecanismos de la sección y pruebas unitarias propias sobre el alcance implementado. |
| Sección 2: servicios | Desarrollo de los controles de servicios y sus decisiones de aplicabilidad, con pruebas unitarias de la sección. |
| Sección 3: configuración de red | Desarrollo de las configuraciones de red contempladas y pruebas unitarias correspondientes. |
| Sección 4: firewall | Desarrollo de los mecanismos de firewall y su comprobación mediante pruebas unitarias de la sección. |
| Sección 5: acceso y autenticación | Desarrollo de los controles de acceso y autenticación incluidos y pruebas unitarias de la sección. |
| Sección 6: auditoría y registro | Desarrollo de los mecanismos de auditoría y registro, acompañado de sus pruebas unitarias. |
| Sección 7: mantenimiento del sistema | Desarrollo de las comprobaciones y configuraciones de mantenimiento contempladas y sus pruebas unitarias. |
| Integración posterior | Prueba integrada del conjunto de las siete secciones, confirmada por el responsable, para comprobar su funcionamiento combinado dentro del alcance de laboratorio. |

La referencia de una a dos semanas puede conservarse como criterio de planificación donde resulte compatible con el esfuerzo de cada sección, pero no se dispone de duraciones históricas confirmadas para asignar una cifra a cada sprint. El estudio, el diseño, la integración, la preparación de evidencias y la documentación también deben figurar en el cronograma de 18 semanas, sin suponer que todas las secciones exigieron el mismo tiempo.

La actualización detallada del Gantt deberá respetar esa secuencia y distinguir el desarrollo realizado de la preproducción y producción pendientes. No se propone aquí una distribución semanal retrospectiva ni se declara aprobado un reparto de las 360 horas por sección. La corrección central consiste en vincular cada sprint con su sección y sus pruebas, y situar la prueba integrada después del desarrollo del conjunto.

**Base:** aclaración del responsable sobre desarrollo por sección, pruebas unitarias e integración; planificación actualizada de la pregunta 12.

## Aclaraciones posteriores

### 14. ¿Estas excepciones pueden resolverse de una vez en el laboratorio para dejarlo completo?

**Las adecuaciones pendientes pueden abordarse en el laboratorio, pero su viabilidad y cierre dependen de las decisiones técnicas correspondientes y de su comprobación posterior.** El responsable indicó que atenderá posteriormente los dos asuntos de laboratorio pendientes; esta respuesta no los declara corregidos ni convierte esa intención en una aceptación completa del perfil. Su resolución debe conservar la posibilidad de administración y recuperación, y verificarse en el alcance intervenido.

Completar esas adecuaciones mejoraría el entorno de prueba, pero no reemplazaría la preproducción institucional, la validación de concurrencia o la información de los servicios reales. El desarrollo y las pruebas de las siete secciones ya realizados se mantienen como resultados del laboratorio, sin trasladar a esa etapa logros de despliegue que todavía no ocurrieron.

## Fase 3: desarrollo y pruebas de los playbooks

La Fase 3 se considera concluida en el alcance implementado y ensayado: desarrollo de las siete secciones, pruebas unitarias asociadas a cada sección y prueba conjunta de las siete en laboratorio, según la confirmación del responsable. Las respuestas siguientes precisan qué acredita el código, qué procede de antecedentes históricos y qué requiere transcripción de las evidencias ya existentes. Completar esa trazabilidad documental no equivale a declarar que las pruebas de Fase 3 no se realizaron. Tampoco convierte el cierre del desarrollo en una certificación de los 311 controles ni en la ejecución de la Fase 4.

### 15. Pruebas unitarias. ¿Cómo se ejecutan (qué comando) y qué comprueban? Quiero explicarlo con precisión, porque es la evidencia de cada sprint. ¿Están en ansible/tests/?

**Sí. Las pruebas de la línea base se encuentran en `ansible/tests/` y utilizan `unittest`, de la biblioteca estándar de Python.** Los archivos definen clases derivadas de `unittest.TestCase`; no se dedujo el marco de pruebas de la existencia de una caché de pytest. El comando de descubrimiento figura en `test_remediation_gates.py` y `test_ssh_tag_routing.py`; los encabezados de las familias PAM documentan además el intérprete del entorno virtual del controlador.

Para descubrir la suite completa de ese directorio, el directorio de trabajo es **`/home/vagrant/ansible`**, raíz del repositorio compartido en `ansible-control`, y el comando es:

```bash
cd /home/vagrant/ansible
export PATH="/home/vagrant/.venvs/ansible-cis/bin:$PATH"
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_*.py' -v
```

Si se trabaja desde **`/home/vagrant/ansible/ansible`**, la forma equivalente es:

```bash
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Para ejecutar una familia real y delimitada, desde la raíz del repositorio:

```bash
/home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover -s ansible/tests -p 'test_cis_pam_faillock_family.py' -v
```

Estos comandos se documentan a partir del código; **no se ejecutaron para preparar estas respuestas**. El intérprete debe disponer de **PyYAML** y **Jinja2**, utilizados para leer las tareas YAML y evaluar plantillas, condiciones y datos de prueba. Para la comprobación local de enrutamiento SSH también se necesita `ansible-playbook` en `PATH`: `test_ssh_tag_routing.py` lo busca expresamente y omite sus casos si no lo encuentra. Por eso el primer bloque prepara explícitamente esa ruta; las formas alternativas presuponen la misma preparación. Elegir el Python del entorno virtual no garantiza, por sí solo, que `PATH` señale al mismo Ansible. El runtime exigido por el proyecto es Core 2.21.2; no se inspeccionó ni se ejecutó su binario en esta revisión documental. El `Makefile` raíz no contiene un objetivo canónico de pruebas unitarias: sus objetivos administran el laboratorio.

Las pruebas no están distribuidas en siete carpetas independientes. Se agrupan por mecanismos, contratos y regresiones; una familia compartida puede aportar evidencia a varias secciones. Por tanto, la asociación de un sprint con sus pruebas debe identificar los casos pertinentes, no atribuir todo un archivo exclusivamente a una sección.

| Sección | Ejemplos existentes en `ansible/tests/` | Qué comprueban dentro de su alcance |
| --- | --- | --- |
| 1. Configuración inicial | `test_mount_options_controls.py`, `test_kernel_module_disabled.py`, `test_cis_section17_gdm.py` | Clasificación de montajes y opciones; estados ilegibles; nombres y estados de módulos; contratos GDM, aplicabilidad y habilitaciones. |
| 2. Servicios | `test_section2_lab_gates.py`, `test_time_sync_selection.py`, `test_service_enabled_oneshot.py` | Habilitaciones del laboratorio; selección de un único sincronizador horario; interpretación de servicios de ejecución puntual. |
| 3. Configuración de red | `test_logging_sysctl_consistency.py`, `test_remediation_gates.py` | En los casos pertinentes, precedencia de configuraciones sysctl relacionadas con UFW y presencia de condiciones de selección en las rutas de remediación. No representan por sí solos una prueba exhaustiva de toda la sección. |
| 4. Firewall | `test_firewall_allowlist.py`, `test_ufw_loopback_control.py`, `test_nftables_pattern_matching.py`, `test_single_firewall_utility.py` | Orígenes autorizados, reglas de loopback, patrones de nftables y selección de herramienta de firewall. |
| 5. Acceso y autenticación | `test_sudoers_config_line.py`, `test_config_line_effective_command.py`, `test_cis_pam_faillock_family.py`, `test_cis_pam_pwhistory_family.py`, `test_cis_pwquality_family.py` | Permisos y validación de sudoers; conexión con `sshd -T`; contratos, orden y expresiones de las familias PAM. |
| 6. Auditoría y registro | `test_audit_log_group_policy.py`, `test_journal_upload_destination.py`, `test_privileged_commands_audit.py`, `test_fixed_file_set_mechanism.py` | Política de grupo de registros, destino de envío, contratos de reglas de comandos privilegiados y conjuntos de archivos de auditoría. |
| 7. Mantenimiento del sistema | `test_fixed_file_set_mechanism.py`, `test_fixed_file_check_mode.py`, `test_remediation_gates.py` | En sus casos pertinentes, contratos de permisos, comparación de modos, tratamiento del modo de comprobación y selección de rutas. No equivalen a comprobar todas las cuentas de un servidor real. |

En términos metodológicos, se contrastan rutas de control, variables transmitidas por los adaptadores, habilitaciones de seguridad, expresiones regulares, representación de valores y casos límite. Algunos casos utilizan datos simulados y funciones auxiliares importadas de otros archivos de pruebas. La prueba de enrutamiento SSH crea sustitutos temporales de tareas que solo emiten mensajes en `localhost`: utiliza Ansible real para comprobar la selección, **sin ejecutar los cuerpos originales de remediación, el inventario de destinos ni sus handlers**. Ese resultado es evidencia de enrutamiento, no de endurecimiento remoto.

Una salida `OK` de `unittest` acredita que los casos descubiertos y no omitidos satisficieron sus aserciones. Deben registrarse también errores, fallos y omisiones; no basta con copiar la última palabra de la salida. Estas pruebas no demuestran reinicio satisfactorio, continuidad de servicios de negocio, transacciones reales de contraseña, acceso SSH posterior al cambio ni compatibilidad con producción. Tales propiedades requieren evidencia operacional separada. El antecedente de **395 pruebas del 28 de octubre de 2026** corresponde a aquella versión y ejecución; no es un recuento actual de casos ni un resultado obtenido durante esta edición.

**Fuentes:** `Makefile`; encabezados, importaciones y aserciones de los archivos citados en `ansible/tests/`; requisito de runtime del `README.md`; antecedente histórico del 28 de octubre, registro Engram n.º 1531.

### 16. Alcance por sección. De los 311 controles de Ubuntu, ¿cuáles aplicaste de verdad en el laboratorio en cada sección y cuáles quedaron en observación o condicionados? Si tienes una lista por sección, me sirve más que el total.

**Se puede identificar exactamente la clasificación declarada de los 311 controles, pero no recuperar de las fuentes revisadas una lista completa de los identificadores efectivamente aplicados en cada ejecución histórica.** El responsable confirmó el trabajo y las pruebas de las siete secciones; para convertir esa confirmación en una lista de aplicaciones por host se necesitan las salidas correspondientes, sus selectores y variables. Una ruta implementada, un selector habilitado o una clasificación de catálogo no prueban por separado que un control se haya ejecutado y modificado un equipo.

La lectura de `ansible/cis/catalog/disposition-matrix.yml` conserva la distribución siguiente. Se contabiliza cada identificador una sola vez en su disposición del proyecto, no por número de tareas Ansible ni por tipo de evaluación del benchmark.

| Sección de Ubuntu | Automatizados | Condicionados (`gated_unsafe`) | Manuales | No aplicables (`na`) | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1. Configuración inicial | 38 | 10 | 18 | 0 | 66 |
| 2. Servicios | 16 | 26 | 1 | 0 | 43 |
| 3. Configuración de red | 9 | 7 | 1 | 0 | 17 |
| 4. Firewall | 7 | 5 | 1 | 16 | 29 |
| 5. Acceso y autenticación | 34 | 34 | 3 | 0 | 71 |
| 6. Auditoría y registro | 50 | 5 | 7 | 0 | 62 |
| 7. Mantenimiento del sistema | 10 | 12 | 1 | 0 | 23 |
| **Total** | **164** | **99** | **32** | **16** | **311** |

#### Identificadores por sección y disposición declarada

**Esta lista es una clasificación de implementación declarada, no una lista recuperada de aplicación real.** Para hacerla legible se utilizan intervalos únicamente cuando están presentes todos los identificadores intermedios. En cada intervalo cambia solo el último componente: `1.1.1.1–1.1.1.5` comprende cinco identificadores; no incluye sus posibles descendientes. «No aplicable» reproduce la disposición de la matriz para su línea base, no una evaluación universal de cualquier servidor Ubuntu.

| Sección | Disposición | Identificadores exactos o intervalos completos |
| --- | --- | --- |
| 1 | Automatizados (38) | `1.1.1.1–1.1.1.5`; `1.1.2.1.1–1.1.2.1.4`; `1.1.2.2.1–1.1.2.2.4`; `1.1.2.5.1–1.1.2.5.4`; `1.3.1.1–1.3.1.2`; `1.4.2`; `1.5.1–1.5.3`; `1.6.1–1.6.6`; `1.7.2–1.7.10`. |
| 1 | Condicionados (10) | `1.1.1.6–1.1.1.9`; `1.3.1.3–1.3.1.4`; `1.4.1`; `1.5.4–1.5.5`; `1.7.1`. |
| 1 | Manuales (18) | `1.1.1.10`; `1.1.2.3.1–1.1.2.3.3`; `1.1.2.4.1–1.1.2.4.3`; `1.1.2.6.1–1.1.2.6.4`; `1.1.2.7.1–1.1.2.7.4`; `1.2.1.1–1.2.1.2`; `1.2.2.1`. |
| 2 | Automatizados (16) | `2.1.21`; `2.3.1.1`; `2.3.2.1–2.3.2.2`; `2.3.3.1–2.3.3.3`; `2.4.1.1–2.4.1.8`; `2.4.2.1`. |
| 2 | Condicionados (26) | `2.1.1–2.1.20`; `2.2.1–2.2.6`. |
| 2 | Manuales (1) | `2.1.22`. |
| 3 | Automatizados (9) | `3.3.1–3.3.6`; `3.3.8–3.3.10`. |
| 3 | Condicionados (7) | `3.1.2–3.1.3`; `3.2.1–3.2.4`; `3.3.7`. |
| 3 | Manuales (1) | `3.1.1`. |
| 4 | Automatizados (7) | `4.1.1`; `4.2.1–4.2.4`; `4.2.6–4.2.7`. |
| 4 | Condicionados (5) | `4.3.1–4.3.2`; `4.4.1.1–4.4.1.3`. |
| 4 | Manuales (1) | `4.2.5`. |
| 4 | No aplicables (16) | `4.3.3–4.3.10`; `4.4.2.1–4.4.2.4`; `4.4.3.1–4.4.3.4`. |
| 5 | Automatizados (34) | `5.1.1–5.1.3`; `5.1.5–5.1.22`; `5.2.1–5.2.6`; `5.3.1.1–5.3.1.3`; `5.3.3.4.1–5.3.3.4.4`. |
| 5 | Condicionados (34) | `5.2.7`; `5.3.2.1–5.3.2.4`; `5.3.3.1.1–5.3.3.1.3`; `5.3.3.2.1–5.3.3.2.2`; `5.3.3.2.4–5.3.3.2.8`; `5.3.3.3.1–5.3.3.3.3`; `5.4.1.1`; `5.4.1.3–5.4.1.6`; `5.4.2.1–5.4.2.8`; `5.4.3.1–5.4.3.3`. |
| 5 | Manuales (3) | `5.1.4`; `5.3.3.2.3`; `5.4.1.2`. |
| 6 | Automatizados (50) | `6.1.1.1`; `6.1.1.4`; `6.1.2.1.1`; `6.1.2.1.3–6.1.2.1.4`; `6.1.2.2–6.1.2.4`; `6.1.3.1–6.1.3.4`; `6.1.3.7`; `6.1.4.1`; `6.2.1.1–6.2.1.4`; `6.2.2.1–6.2.2.2`; `6.2.2.4`; `6.2.3.1–6.2.3.19`; `6.2.4.1–6.2.4.10`. |
| 6 | Condicionados (5) | `6.2.2.3`; `6.2.3.20`; `6.3.1–6.3.3`. |
| 6 | Manuales (7) | `6.1.1.2–6.1.1.3`; `6.1.2.1.2`; `6.1.3.5–6.1.3.6`; `6.1.3.8`; `6.2.3.21`. |
| 7 | Automatizados (10) | `7.1.1–7.1.10`. |
| 7 | Condicionados (12) | `7.1.11–7.1.12`; `7.2.1–7.2.10`. |
| 7 | Manuales (1) | `7.1.13`. |

Las secciones 1, 2, 3, 5, 6 y 7 no contienen identificadores con disposición `na` en esta matriz. La clasificación no sustituye la lectura de las rutas actuales: por ejemplo, la matriz conserva `5.1.4` como manual, mientras el registro histórico del 28 de octubre documenta una remediación desarrollada para ese control. Por ello, tampoco se debe convertir la matriz en una afirmación de que los manuales carecen necesariamente de cualquier implementación posterior, ni modificar retrospectivamente sus cifras sin una conciliación de metadatos.

#### Evidencia de aplicación y condiciones observables

| Evidencia o condición | Qué puede afirmarse | Qué no se recuperó o no se demuestra |
| --- | --- | --- |
| Desarrollo y pruebas de las siete secciones | El responsable confirma pruebas unitarias por sección y una prueba integral de laboratorio. | No se inspeccionaron las capturas ni se reconstruyó una lista de identificadores aplicados por host. |
| Ciclo de vida del 29 de septiembre | Hubo aplicación e idempotencia de un subconjunto sysctl en Debian y Ubuntu, con los valores de la pregunta 17. | El resumen no enumera la selección íntegra de identificadores ni acredita el cierre de los siete sprints. |
| Verificación completa histórica del 28 de octubre | Se registraron las recapitulaciones indicadas en las preguntas 8 y 17 para la selección ensayada. | Una verificación satisfactoria no distingue por sí sola controles modificados, previamente conformes, exceptuados u omitidos. |
| Selectores locales de tiempo y sudo | En ambos inventarios de grupo están desactivados `2.3.1.1`, `2.3.2.1`, `2.3.2.2` y `5.2.4`. | Es una configuración de laboratorio observable, no prueba de que esas variables fueran las efectivas en toda ejecución histórica. La omisión de `5.2.4` documenta una no conformidad, no un `PASS`. |
| Almacenamiento local | Se desactivan los selectores de partición correspondientes a `1.1.2.3.1`, `1.1.2.4.1`, `1.1.2.6.1` y `1.1.2.7.1`, por el diseño de un disco del laboratorio. | No se demuestra creación de particiones separadas; las opciones de montaje tienen su propia aplicabilidad y no deben contarse como aprobadas por esta omisión. |
| Alternativas horarias y de registro | Los defaults seleccionan timesyncd frente a chrony y journald frente a rsyslog; además, el laboratorio exceptúa los selectores horarios citados. | No corresponde sumar como aplicados todos los controles de alternativas excluyentes por figurar como automatizados. |

El registro definitivo de aplicación debe asociar **plataforma, host, fecha, revisión del código, comando, variables efectivas, identificador del control, resultado de auditoría, cambio y verificación**. Para la lista completa por sección, el estado documental actual es: **identificadores realmente aplicados por host: no recuperables de las fuentes examinadas; requieren vinculación con las evidencias de ejecución existentes**. No se rellenan con los 164 automatizados ni con la suma de rutas automatizadas y condicionadas.

**Fuentes:** matriz local [3]; inventarios `ansible/inventories/local/group_vars/{ubuntu_2404,debian_12}.yml`; defaults de ambos adaptadores; evidencia de ciclo de vida [19]; confirmación del responsable y antecedente histórico Engram n.º 1531. Solo se reproducen identificadores y clasificación del proyecto, no el texto licenciado de los controles.

### 17. Resultados por sprint. ¿Qué muestran tus capturas de cada sección? Por ejemplo ok, changed y failed de la ejecución, o una verificación sin fallos. Con eso redacto el resultado sin inventar cifras.

**El responsable confirmó capturas y pruebas de las siete secciones, pero no se examinó el contenido de esas imágenes durante esta revisión.** Por tanto, se puede documentar la realización confirmada y preparar su trazabilidad, sin asignar `failed=0`, cantidades de cambios o tiempos a sprints cuyas salidas no se han transcrito.

| Sprint | Evidencia confirmada por el responsable | Plataforma, fecha y archivo | `ok` / `changed` / `failed` y resultado unitario |
| --- | --- | --- | --- |
| 1. Configuración inicial | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| 2. Servicios | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| 3. Configuración de red | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| 4. Firewall | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| 5. Acceso y autenticación | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| 6. Auditoría y registro | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| 7. Mantenimiento del sistema | Desarrollo y pruebas de la sección | Pendiente de transcripción | Pendiente de transcripción |
| Prueba conjunta de las siete | Realización confirmada en laboratorio | Vincular salida y versión de la prueba confirmada | No sustituir por resultados de otra fecha sin establecer su correspondencia |

La recapitulación Ansible cuenta **tareas por host**, no controles CIS únicos. `ok` registra tareas satisfactorias y comprende las que informaron cambios; `changed` señala las que declararon una modificación o, en modo de comprobación, una modificación prevista. `failed` representa fallos no resueltos según el tratamiento de errores; `unreachable` identifica problemas de conexión; `skipped` indica tareas omitidas por sus condiciones o selección. `rescued` y `ignored` requieren examinar el fallo recuperado o ignorado: su presencia impide interpretar una recapitulación superficial como ausencia de incidentes. El código de salida del proceso debe conservarse con el resumen y el contexto; una captura que no lo muestra no permite deducirlo retrospectivamente.

También importa el modo de ejecución. Una auditoría puede emitir una clasificación `FAIL` en un mensaje sin hacer fallar el playbook; en cambio, una verificación que utiliza `ansible.builtin.assert` puede detenerse ante una condición incumplida. Por eso, «auditoría con `failed=0`» y «verificación satisfactoria» no son afirmaciones equivalentes. `changed=0` en una segunda aplicación comparable sustenta idempotencia de esa selección; `changed=0` en auditoría, en una ejecución omitida o en una selección vacía no acredita lo mismo.

Los antecedentes que sí tienen cifras delimitadas son los siguientes:

| Fecha y procedencia | Resultado conservado | Alcance de la afirmación |
| --- | --- | --- |
| 29-09-2026, archivo de ciclo de vida [19] | Auditoría Debian: `ok=1083 changed=0 failed=0 skipped=1642`; Ubuntu: `ok=1143 changed=0 failed=0 skipped=1585`. | Auditorías históricas; no siete resultados finales de sprint. |
| 29-09-2026, mismo archivo | Sysctl Debian: primera aplicación `changed=21 failed=0`, segunda `changed=0 failed=0`; Ubuntu: primera `changed=19 failed=0`, segunda `changed=0 failed=0`. | Convergencia e idempotencia del subconjunto sysctl, no de toda la línea base. |
| 29-09-2026, mismo archivo | La verificación detectó un incumplimiento antes del cambio; después pasó sysctl y el fallo se desplazó al siguiente contrato de permisos todavía no aplicado. | Evidencia de una verificación capaz de rechazar incumplimientos, no un cierre integral satisfactorio en esa fecha. |
| 28-10-2026, registro histórico Engram n.º 1531 | Verificación completa registrada: Debian `ok=1879 failed=0`; Ubuntu `ok=1983 failed=0`; 395 pruebas unitarias satisfactorias. | Antecedente de aquella selección y versión. No se dispone aquí de todos los campos de su recapitulación ni de su desglose por sección; no se presenta como una nueva ejecución o inspección de capturas. |

Para redactar el resultado de cada sprint se debe incorporar una ficha con sección, plataforma, revisión, modo, selección, resultado unitario con omisiones, recapitulación por host y archivo de evidencia. Hasta vincularla, la formulación defendible es: **«Se desarrolló y probó la sección dentro del alcance del laboratorio, según la confirmación del responsable; las cifras específicas se incorporarán desde su evidencia correspondiente»**. La tarea restante es documental, no una negación de las pruebas ya realizadas.

### 18. Problemas y soluciones. Además de config_line y ufw_rule, ¿hubo otros errores que solo aparecieron al ejecutar? ¿Qué aprendiste de ellos? El docente pidió resultados, y esto aporta mucho valor.

**Sí hubo defectos documentados mediante ejecución real, además de regresiones comprobables en el código.** Se separan ambas clases para no presentar una prueba con datos simulados como si fuera un incidente de un servidor. Las correcciones que se describen son antecedentes del desarrollo; no se afirma que los errores sigan presentes ni que se haya repetido su validación en esta edición.

| Problema y procedencia | Causa identificada | Solución documentada y comprobable en las fuentes | Aprendizaje |
| --- | --- | --- | --- |
| Contrato incompleto de sysctl `3.3.7`, ciclo de vida real del 29-09-2026 [19] | Faltaban `runtime_path` y `file` en la delegación. | Se completó el contrato mediante un bucle para IPv4 `all` y `default`; el registro identifica el commit `40087f7`. | Una tarea puede ser YAML válido y fallar al recibir variables incompletas; el contrato entre control y mecanismo debe comprobarse explícitamente. |
| Patrón de puerto SSH de tipo entero, mismo ciclo de vida [19] | El valor nativo `22` alcanzaba `re.compile` en `ufw_rule_match`, que esperaba texto. | Conversión explícita con `\| string`; commit `471ab48`. | No debe suponerse que una expresión de plantilla produce siempre una cadena: los tipos nativos forman parte del contrato. |
| Oscilación de permisos en `config_line`, fixture real con Core 2.21.2 registrado el 21-10-2026, Engram n.º 1270 | Imponer `0644` a archivos existentes alteraba permisos de SSH y auditoría y provocaba cambios posteriores para restaurarlos. | El mecanismo consulta `stat`, conserva el modo existente en archivos ajenos a sudoers, fija `0644` solo al crearlos y exige `0440` más `visudo` para sudoers. La regresión está en `test_sudoers_config_line.py`. | La idempotencia debe considerar interacciones entre mecanismos, no solo la repetición aislada de una tarea. El fixture no equivale a una aplicación integral de producción. |
| Montaje de `/tmp` con error `No start of json char found`, laboratorio del 30-10-2026, Engram n.º 1599 | El montaje era válido, pero cubría el directorio temporal donde Ansible había preparado su propio módulo y dañaba la devolución del resultado. | `mount_options/remediation.yml` establece `TMPDIR: /run` tanto al montar como al remontar. `test_mount_options_controls.py` conserva la regresión. | Una operación puede modificar correctamente el sistema y perder su canal de respuesta; es necesario proteger los recursos que utiliza la propia automatización. |
| Diferente salida de `systemctl is-enabled`, mismo antecedente del 30-10-2026 | Debian con systemd 252 y Ubuntu con systemd 255 no comunicaban igual una unidad inexistente. | `mount_options/inspect.yml` reconoce estados admitidos por tokens; no toma un código de retorno como regla universal. La exigencia de unidad se determina por control. | La compatibilidad depende de la semántica y la versión de herramientas, no solo del nombre de la distribución. |
| Banners que conservaban información del sistema, ejecución histórica del 28-10-2026, Engram n.º 1531 | Añadir una advertencia no retiraba el contenido anterior que revelaba el sistema operativo. | La remediación de `1.6.2` reemplaza el archivo mediante `copy`; `test_config_line_effective_command.py` contiene casos de banners. | Agregar el valor deseado no basta cuando el requisito también prohíbe contenido previo. |
| Variable opcional en `account_integrity`, mismo registro del 28-10-2026 | La comprobación con `is defined` no resolvía adecuadamente la variable utilizada mediante `import_role`. | La clasificación de `account_integrity/audit.yml` usa `default('')` antes de decidir la semántica de la salida. | Los parámetros opcionales deben tener un contrato explícito de ausencia y evaluarse sin errores de variables indefinidas. |

Para el caso de systemd, el registro histórico distingue Debian con `rc=1`, salida estándar vacía y diagnóstico por stderr, de Ubuntu con `not-found` por stdout y `rc=4`. Tras crear la entrada de fstab y recargar systemd pueden aparecer unidades `generated`. `/dev/shm` no exige una unidad independiente en su contrato: no debe imponerse el requisito de `/tmp` a todos los montajes. Estas observaciones se recogen en el mecanismo y sus pruebas, sin ejecutar sondeos nuevos.

Existe además una clase distinta de resultados: **correcciones semánticas sustentadas por pruebas de contrato**. Por ejemplo, `test_config_line_effective_command.py` comprueba que los controles SSH deleguen en `sshd -T` y contrasten sus valores efectivos; una línea aparentemente correcta en un archivo no asegura que el servicio la utilice. `test_overlayfs_module_mapping.py` comprueba que se opere sobre el módulo `overlay`, no sobre el nombre descriptivo `overlayfs`. Esos archivos acreditan la regresión y el comportamiento esperado del código; por sí solos no permiten afirmar que el primer hallazgo ocurrió en una ejecución remota. No se asignan a un sprint o una fecha de incidente sin su registro correspondiente.

**Fuentes:** archivo de ciclo de vida [19]; mecanismos `sysctl_parameter`, `mount_options`, `config_line` y `account_integrity` de `cis_linux_common`; control común `1_6_2_issue_banner`; archivos de pruebas citados; antecedentes históricos Engram n.º 1270, 1531 y 1599, con sus fechas indicadas.

### 19. Revisiones de cada sprint. ¿Qué observaciones te hizo el Ing. Deyler al cierre de los sprints, o simplemente aprobaba? Si hubo cambios por sus comentarios, conviene mencionarlos.

**No se dispone en las fuentes examinadas de actas, comentarios o aprobaciones que permitan atribuir al Ing. Deyler observaciones concretas al cierre de cada sprint.** La confirmación del responsable sobre el desarrollo y las pruebas no sustituye la evidencia de revisión docente. Tampoco es correcto deducir una aprobación porque una prueba técnica terminó satisfactoriamente.

La memoria puede explicar la organización del trabajo por secciones y sus comprobaciones, pero debe dejar la participación docente pendiente de confirmación documental. Si existió una observación, conviene describir el problema señalado, el cambio efectivamente realizado y la evidencia que relaciona ambos; si hubo únicamente validación de avances, se consignará ese hecho solo cuando el responsable lo confirme. No se inventan reuniones, fechas, firmas ni aprobaciones generales.

| Sprint | Observación del docente | Cambio realizado | Evidencia |
| --- | --- | --- | --- |
| 1. Configuración inicial | ____________ | ____________ | ____________ |
| 2. Servicios | ____________ | ____________ | ____________ |
| 3. Configuración de red | ____________ | ____________ | ____________ |
| 4. Firewall | ____________ | ____________ | ____________ |
| 5. Acceso y autenticación | ____________ | ____________ | ____________ |
| 6. Auditoría y registro | ____________ | ____________ | ____________ |
| 7. Mantenimiento del sistema | ____________ | ____________ | ____________ |

**Estado:** campos a completar mediante confirmación del responsable y, cuando exista, registro docente. No representan observaciones emitidas ni cambios solicitados que ya se hayan acreditado.

### 20. Diferencias entre Ubuntu y Debian. ¿En qué secciones se notaron más, además del firewall y la sección 3? ¿Y cómo funciona la configuración (el adaptador de cada distribución)?

**La solución utiliza adaptadores por distribución y una biblioteca modular compartida; no son dos implementaciones completas e independientes que deban duplicar cada mecanismo.** Las entradas canónicas están en `ansible/playbooks/{audit,hardening,verify}/cis_ubuntu_2404.yml` y `cis_debian_12.yml`. Los playbooks fijan el modo y convocan `cis_platform_preflight` antes del rol correspondiente. En remediación, ambos emplean `serial: 1` y `any_errors_fatal: true`; por ello esas entradas no constituyen una demostración de ocho intervenciones simultáneas.

El recorrido de configuración es el siguiente:

1. **Entrada y comprobación de plataforma.** El playbook selecciona los hosts y el modo. Preflight valida la plataforma admitida y su estado de soporte; el adaptador comprueba la distribución, versión y arquitectura. Las entradas de hardening permiten estado `released` para Ubuntu y `canary` o `released` para Debian.
2. **Defaults y contexto del inventario.** `ansible/roles/cis_ubuntu_2404/defaults/main.yml` y `cis_debian_12/defaults/main.yml` definen selectores y valores predeterminados, con prefijos distintos por distribución. Los archivos de `ansible/inventories/local/group_vars/` concretan el laboratorio; no son una política universal para producción. Las variables de la ejecución también deben conservarse para conocer el valor efectivo.
3. **Selección y habilitaciones.** El `tasks/main.yml` del adaptador importa rutas por control y modo con condiciones `when` y etiquetas. La remediación requiere el selector general y el del control; las familias sensibles pueden exigir una habilitación adicional. Debian requiere además `cis_debian_12_canary_confirmed=true` y una selección explícita de etiquetas. No existe equivalencia entre activar un selector y superar todos esos requisitos.
4. **Delegación al código compartido.** Los archivos del control transmiten identificador, plataforma, paquetes, rutas y parámetros mediante variables `cis_linux_common_*` e `ansible.builtin.import_role` con `tasks_from`. La sección común delega, cuando corresponde, al mecanismo de `cis_linux_common/tasks/mechanisms/`. El catálogo de `ansible/cis/` es metadato de trazabilidad: el runtime no lo utiliza como motor automático de aplicación.
5. **Aplicación y comprobación separadas.** Auditoría observa y clasifica; remediación cambia lo habilitado; verificación evalúa el contrato. No se presupone un reinicio o handler genérico por distribución: los efectos sobre servicios se comprueban en la tarea concreta. Los roles examinados no justifican describir una capa universal de handlers como parte del adaptador.

Fuera del firewall y la red, las diferencias y condiciones más relevantes sustentadas por las fuentes son:

| Sección o aspecto | Diferencia o condición comprobable | Consecuencia para el desarrollo |
| --- | --- | --- |
| 1. Montajes y systemd | El antecedente del 30 de octubre documenta respuestas diferentes de systemd 252 y 255 ante unidades inexistentes. La exigencia de unidad depende del control. | Se normalizan estados y se comprueba el montaje real; no se iguala cualquier retorno no nulo a una condición universal. |
| 1. Reporte de errores | El inventario Ubuntu habilita la remediación de Apport; `test_reboot_conflicts.py` comprueba la configuración persistente `enabled=0` en `/etc/default/apport`. | Es una decisión específica del laboratorio Ubuntu para evitar contradicción con `fs.suid_dumpable`, no una diferencia que deba trasladarse automáticamente a Debian o producción. La prueba de fuente no demuestra un reinicio realizado. |
| 1. Módulos, AppArmor y GDM | Los defaults contemplan AppArmor y sus habilitaciones; las pruebas de módulos y GDM ejercitan ambos adaptadores. El nombre operativo de overlay es `overlay` en ambos. | La presencia de paquetes, módulos o escritorio determina aplicabilidad. No se afirma que uno de los sistemas utilice por defecto otro mecanismo ni que GDM estuviera instalado en las VM históricas. |
| 2. Sincronización y presencia de servicios | Los dos defaults seleccionan timesyncd y desactivan la alternativa chrony; ambos inventarios locales exceptúan los tres selectores horarios citados en la pregunta 16. Las pruebas modelan servicios presentes, ausentes y de ejecución puntual. | No se sostiene que Ubuntu use timesyncd y Debian chrony en esta línea base. Se comprueba el estado real y se separa la excepción de virtualización de la configuración institucional. |
| 5. PAM y algoritmos | Los wrappers de `5.3.3.4.3` de ambas plataformas transmiten `/etc/pam.d/common-password`, `libpam-runtime` y una línea con `yescrypt`. Las familias PAM validan contratos y orden. | No hay base para redactar una oposición «Ubuntu yescrypt / Debian SHA-512» en este control. Compartir parámetros tampoco demuestra transacciones reales de autenticación. |
| 6. Propiedad de registros | El antecedente del 28 de octubre documenta una comprobación demasiado restrictiva ante usuarios de servicio sin inicio de sesión, como `_aide` o `Debian-exim`; las pruebas actuales examinan conjuntos y clases de archivos. | Se evita confundir una identidad de servicio permitida con un incumplimiento. No se supone que todos los hosts tengan los mismos usuarios o paquetes. |
| 7. Correspondencia entre identificador y archivo | `test_fixed_file_set_mechanism.py` comprueba expresamente que Ubuntu `7.1.3` apunte a `/etc/group`, aunque el nombre histórico de su directorio incluya `group_backup`. | No se debe inferir el destino únicamente del nombre de una carpeta ni trasladar controles entre catálogos sin revisar su contrato. |

Para GRUB, AppArmor o rutas de configuración no se introducen diferencias adicionales por conocimiento general de las distribuciones: deben proceder de los parámetros y condiciones de cada control. En las fuentes revisadas predominan mecanismos comunes con contratos específicos, además de diferencias de disponibilidad y versión. **Ubuntu figura como lanzado únicamente para el subconjunto calificado; Debian continúa bajo el régimen canario.** El desarrollo y las pruebas de ambas plataformas no equivalen a certificación completa de sus perfiles.

**Fuentes:** `README.md`, `docs/IMPROVING.md` y `docs/SUPPORT.md`; playbooks canónicos de hardening; `tasks/main.yml` y defaults de los adaptadores; wrappers de `5.3.3.4.3`; inventarios locales; mecanismos y pruebas citados; antecedentes históricos del 28 y 30 de octubre.

### 21. Laboratorio sin Vagrant. Mencionaste que lo harás. ¿Va dentro de la Fase 3 como parte de la configuración del laboratorio, o lo dejamos para la Fase 4 (preproducción)?

**El laboratorio limpio sin Vagrant corresponde a la Fase 4: integración y simulación de condiciones representativas de producción. Esa fase no se ha ejecutado.** No se incorpora retrospectivamente como una prueba faltante de la Fase 3. Esta última comprende el desarrollo de las siete secciones y sus pruebas unitarias, más la prueba conjunta en el laboratorio de desarrollo, confirmadas por el responsable dentro del alcance implementado y ensayado.

La separación no depende únicamente de la herramienta de virtualización. Vagrant facilitó la construcción reproducible del entorno de desarrollo; retirar Vagrant, por sí solo, no vuelve representativo un servidor. La Fase 4 deberá preparar un controlador limpio y dedicado, un inventario separado y condiciones de conectividad, acceso, servicios y recuperación que respondan al entorno institucional. Wazuh se considera aquí como contexto de integración de esa fase, no como evidencia de una edición posterior de endurecimiento ni como prueba de producción ya realizada.

| Fase | Alcance y estado |
| --- | --- |
| Fase 3: desarrollo | Concluida dentro del alcance implementado y ensayado: siete secciones, pruebas unitarias asociadas y prueba conjunta de laboratorio confirmadas por el responsable. La organización y transcripción de evidencias no modifica ese estado técnico declarado. |
| Antecedentes del prototipo | Se conservan los ensayos de integración ya descritos en las preguntas 8 y 11, sin presentarlos como la ejecución formal de Fase 4. |
| Fase 4: integración y simulación de producción | Futura y no ejecutada: entorno limpio sin Vagrant, configuración representativa y validaciones operacionales con datos y autorizaciones institucionales. |

En esa etapa futura corresponderá definir y ejecutar las comprobaciones de continuidad de servicios, reinicio y recuperación, acceso administrativo y capacidad concurrente que se aprueben. El objetivo sigue siendo **hasta ocho servidores concurrentes**, todavía no demostrado. Servicios reales: **____________ — pendiente de información DTIC**. Hardware de clientes: **____________ — pendiente de información DTIC**. Datos y criterios de aceptación: **____________ — pendiente de información DTIC**.

La conclusión académica es que **se cerraron los entregables de desarrollo de Fase 3 dentro del alcance ensayado, sin convertir las actividades futuras de Fase 4 en código faltante de Fase 3**. Esto no elimina las excepciones del laboratorio ni permite afirmar que todos los controles se aplicaron o que no existe ninguna limitación técnica. La referencia histórica de las adecuaciones mencionadas en la pregunta 14 se conserva sin declararlas resueltas por esta aclaración. La planificación general de **18 semanas y 360 horas** permanece sin cambios; no se inventan fechas de ejecución para la fase futura.

**Base:** aclaración actual del responsable sobre las fases; alcance y límites de las preguntas 8–14; inventarios separados de laboratorio, preproducción y producción. No se efectuaron cambios de infraestructura ni validaciones remotas para redactar esta respuesta.

## Datos institucionales y documentales por completar

Los siguientes campos permiten cerrar la memoria y adaptar el diseño sin inventar datos institucionales. No representan infraestructura entregada ni autorizaciones concedidas.

| Información | Campo pendiente |
| --- | --- |
| Ubicación y plataforma de alojamiento del controlador | ____________ — pendiente de información DTIC |
| CPU, RAM y disco efectivamente asignados al controlador | ____________ — pendiente de información DTIC |
| IP, segmento y acceso administrativo del controlador | ____________ — pendiente de información DTIC |
| Servidor Wazuh institucional: ubicación, recursos y conectividad | ____________ — pendiente de información DTIC |
| Inventario real de clientes: cantidad, hardware y sistemas operativos | ____________ — pendiente de información DTIC |
| Aplicaciones, servicios, puertos y dependencias de clientes | ____________ — pendiente de información DTIC |
| Perfil de aceptación y decisiones por servidor | ____________ — pendiente de información DTIC |
| Responsables, autorizaciones y ventanas de preproducción y producción | ____________ — pendiente de información DTIC |
| Política de respaldo y recuperación institucional | ____________ — pendiente de información DTIC |
| Índice de capturas y resultados por sección e integración | ____________ — pendiente de organización documental |
| Fechas y distribución detallada del Gantt de 18 semanas / 360 horas | ____________ — pendiente de actualización documental |

La capacidad de hasta ocho servidores concurrentes queda como objetivo de diseño con validación pendiente, no como dato que DTIC deba confirmar sobre una prueba ya realizada. La preproducción permanece sin ejecutar. Para concluir el documento académico falta incorporar los datos institucionales que se reciban, organizar las evidencias confirmadas y actualizar el calendario detallado, manteniendo la separación entre resultados de laboratorio y despliegue posterior.

## Referencias y trazabilidad

Las rutas se expresan desde la raíz del repositorio. Las referencias técnicas describen alcance, configuración o evidencia histórica; las confirmaciones de capturas y pruebas por sección se atribuyen al responsable cuando no se inspeccionó su material en esta edición.

| N.º | Documento o ubicación | Uso en estas respuestas |
| --- | --- | --- |
| 1 | `README.md` | Descripción y alcance del proyecto |
| 2 | `ansible/cis/catalog/pinned-corpora.yml` | Identificadores, perfiles y composición del catálogo |
| 3 | `ansible/cis/catalog/disposition-matrix.yml` | Clasificación y tratamiento de controles |
| 4 | `ansible/cis/catalog/control-ledger.yml` | Trazabilidad de auditoría, remediación y verificación |
| 5 | `ansible/cis/catalog/semantic-review.yml` | Registro de revisión semántica |
| 6 | `docs/USAGE.md` | Modos de uso, selectores y habilitaciones |
| 7 | `docs/SUPPORT.md` | Alcance de soporte y límites de los resultados publicados |
| 8 | `docs/ROLLOUT.md` | Procedimiento de aplicación gradual |
| 9 | `docs/LAB.md` | Preparación y topología del laboratorio |
| 10 | `docs/WAZUH.md` | Integración y registro de eventos |
| 11 | `docs/REQUISITOS_SERVIDOR_ANSIBLE_CONTROL_DTIC.md` | Solicitud de recursos del controlador; no constancia de entrega |
| 12 | `docs/ANSIBLE_CONTROL_HARDENING.md` | Preparación prevista del controlador institucional |
| 13 | `ansible/inventories/local/` | Inventario del laboratorio |
| 14 | `ansible/playbooks/` | Organización de las entradas de ejecución |
| 15 | `integration/wazuh/README.md` | Arquitectura y contrato de la integración |
| 16 | `docs/INTEGRACION_WAZUH_ANSIBLE.md` | Evidencia histórica del flujo ensayado |
| 17 | `docs/PREPRODUCCION_WAZUH.md` | Preparación y validaciones institucionales pendientes |
| 18 | `integration/wazuh/managed_job.py`; `integration/wazuh/config/ansible_job_command.xml`; `integration/wazuh/config/ansible_job_localfile.xml` | Gateway, comando Active Response y recolección de eventos |
| 19 | `ansible/evidence/cis/lifecycle-2026-09-29.md` | Antecedente de ciclo de vida e idempotencia de alcance delimitado |
| 20 | `ansible/tests/` | Pruebas de la automatización |
| 21 | `integration/wazuh/tests/` | Pruebas de la integración |
| 22 | `lab/vagrant/Vagrantfile` | Definición de las tres VM, recursos, red privada y carpeta compartida |
| 23 | `ansible/profiles/ubuntu_2404_aide_lab.yml` | Perfil de integridad de laboratorio |
| 24 | `ansible/inventories/staging/hosts.yml` | Plantilla de preproducción, no entorno ejecutado |
| 25 | `ansible/inventories/production/hosts.yml` | Plantilla de producción, no inventario institucional confirmado |
