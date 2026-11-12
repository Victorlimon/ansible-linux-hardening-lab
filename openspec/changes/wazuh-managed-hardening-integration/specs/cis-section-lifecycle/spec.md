# Especificación de selección CIS existente

## Propósito

Cubrir las siete secciones mediante los playbooks y roles ya construidos, sin duplicarlos.

## Requisitos

### Requisito: Cobertura total y parcial

El puente DEBE poder solicitar el playbook de hardening completo de Ubuntu 24.04 o Debian 12, o un subconjunto revisado de roles/tags existentes correspondiente a secciones 1–7. El catálogo de selección DEBE derivarse de la release sellada y comprobar que produce tareas efectivas. No se crearán playbooks nuevos para completar este puente.

#### Escenario: Ubuntu completo
- DADO Ubuntu autorizado y selección full
- CUANDO se ejecuta desde Wazuh con aprobación
- ENTONCES corre el playbook Ubuntu existente y se archivan recap y terminal

#### Escenario: Debian y sección parcial
- DADO Debian autorizado y tag CIS de sección 4 existente
- CUANDO se ejecuta con aprobación de ese alcance
- ENTONCES corren sólo tareas permitidas y se identifica la sección en el recibo

### Requisito: Gates y resultados honestos

La integración NO DEBE suponer que un control manual/NA fue remediado ni saltar gates de plataforma, producción, firewall, SSH, PAM, sudo o preflight. Check/diff, apply y verify DEBEN distinguir ejecución, cambios y cumplimiento. Si los playbooks actuales no permiten una selección efectiva o un gate no está satisfecho, el puente informa `blocked` o `partial`; no modifica silenciosamente los roles ni declara éxito.

#### Escenario: Gate de producción no satisfecho
- DADO un playbook que termina sin remediar por gate cerrado
- CUANDO se analiza el resultado
- ENTONCES no se declara hardening completo; se registra el gate/alcance no realizado

#### Escenario: Verify no conforme
- DADO apply terminado y verify que detecta incumplimiento
- CUANDO se emite el terminal
- ENTONCES se marca no conforme y se preserva evidencia para reversión

### Requisito: Riesgo crítico y rollback

SSH, PAM, sudo, firewall, kernel y acciones destructivas DEBEN exigir comprobación previa, evidencia de acceso fuera de banda y plan de reversión por host. La integración no habilita automáticamente tales controles por aceptar un tag.

#### Escenario: Firewall sin acceso alternativo
- DADO selección firewall sin precondiciones operativas
- CUANDO se pide apply
- ENTONCES se bloquea antes de la mutación
