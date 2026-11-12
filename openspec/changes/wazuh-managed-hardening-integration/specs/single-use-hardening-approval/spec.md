# Especificación de aprobación manual por host y alcance

## Propósito

Separar orden de Wazuh de autorización humana de aplicación.

## Requisitos

### Requisito: Evidencia previa y aprobación exacta

Root DEBE crear evidencia check/diff inmutable por `request_id + change_id + host`, ligada a release, playbook, inventario expandido, selección normalizada y digest de variables efectivas. Una persona distinta de la orden DEBE aprobar cada host y alcance exacto; la aprobación registra emisor, motivo, caducidad y `diff_digest`. Un lote NO DEBE heredar una aprobación global.

#### Escenario: Lote aprobado separadamente
- DADO dos hosts con check completo y dos aprobaciones coincidentes
- CUANDO llega apply con ambas identidades
- ENTONCES cada host dispone de autorización y recibo independientes

#### Escenario: Falta una aprobación
- DADO un lote con un host no aprobado
- CUANDO se valida apply
- ENTONCES ningún host comienza; no se crea autorización implícita

### Requisito: Consumo único y protección contra replay

Apply DEBE cotejar la solicitud normalizada, digests, evidencia, host y aprobación vigente antes de consumirla durablemente una sola vez. Repetir `request_id` idéntico consulta estado sin relanzar; colisión, cambio de puerto/tag/host, aprobación vencida o consumida DEBEN fallar cerrados. Un UUID recibido de Wazuh NO es autoridad.

#### Escenario: Cambió el puerto después del check
- DADO un check para un puerto y una orden apply con otro valor
- CUANDO se compara el digest normalizado
- ENTONCES no se consume ni ejecuta

#### Escenario: Replay
- DADO una ejecución aplicada con recibo terminal
- CUANDO llega la misma orden
- ENTONCES se consulta el recibo sin un segundo proceso

### Requisito: Legado sin elevación

El contrato de cuatro argumentos y cualquier `managed-check-v1` existente PUEDEN permanecer como check-only; `managed-apply-v1` NO DEBE franquear apply por contener un UUID.

#### Escenario: UUID legado
- DADO un cuarto argumento legado con UUID
- CUANDO Wazuh envía la orden
- ENTONCES sólo se ejecuta check/diff
