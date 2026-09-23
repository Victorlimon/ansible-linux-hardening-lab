# Referencia local de Ansible

Antes de crear o modificar playbooks, roles, inventarios o configuracion de
Ansible, consulta `docs/ansible-documentation/`. Es una copia local, de solo
lectura, del repositorio oficial `ansible/ansible-documentation`.

- Usa `docs/ansible-documentation/docs/docsite/rst/` para sintaxis YAML,
  inventarios, playbooks, variables, vault, colecciones y buenas practicas.
- Usa `ansible-doc <modulo>` para confirmar los parametros, valores admitidos y
  el comportamiento de modulos/plugins instalados: su documentacion fuente
  pertenece al repositorio `ansible/ansible`, no a esta copia.
- El proyecto requiere Ansible Core 2.16 o posterior. No adoptes funciones de
  versiones mas recientes sin comprobar la version con `ansible --version`.
- No modifiques ni incluyas `docs/ansible-documentation/` en los commits del
  proyecto. Actualizala solo con `git -C docs/ansible-documentation pull --ff-only`.

## Routing por riesgo y profundidad de revisión (Gentle Orchestrator)

Política obligatoria del orquestador para este proyecto. La clasificación de
riesgo depende del IMPACTO y la SENSIBILIDAD del cambio, nunca de la cantidad
de líneas modificadas. Una sola línea en `sshd_config`, PAM, sudo o firewall
puede ser CRITICAL.

### Clasificación de riesgo

| Nivel | Criterio (ejemplos) |
|---|---|
| LOW | Documentación, comentarios, formato, variables triviales, sin cambio de comportamiento. |
| MEDIUM | Cambio funcional de complejidad moderada, rol/módulo nuevo, configuración reversible. |
| HIGH | Seguridad adyacente reversible (auditd, logging, permisos no críticos), refactor transversal con riesgo de idempotencia. |
| CRITICAL | SSH, PAM, sudo, firewall, autenticación, permisos sensibles, kernel/sysctl, cambios destructivos, posible pérdida de acceso, rollback complejo, validación final importante, release/entrega final. |

### Profundidad de revisión según riesgo

| Nivel | Cadena de revisión |
|---|---|
| LOW | sdd-apply → sdd-verify |
| MEDIUM | sdd-apply → sdd-verify → R3 (reliability) + R2 (readability) |
| HIGH | sdd-apply → sdd-verify → R1 (risk) + R4 (resilience) |
| CRITICAL | sdd-apply → sdd-verify → R1 → R2 → R3 → R4 → refuter → validator → Judgment Day |

### Reglas duras

- Judgment Day (jd-judge-a/b + jd-fix-agent) SOLO en CRITICAL; nunca para cambios triviales.
- Independencia de verificación: en HIGH y CRITICAL la familia del implementador
  debe diferir de la del verificador; preferible también en MEDIUM.
- Escalamiento L1→L2→L3→L4: subir de tier ante incertidumbre, fallo, resultado
  inconsistente, debugging complejo, decisión arquitectónica, riesgo de
  seguridad, control CIS delicado, no-idempotencia o cambio destructivo.
  Máximo 1 reintento en el mismo tier antes de escalar.
- Piso de seguridad: review-risk (R1) nunca baja de L3, en ningún preset.
- Fallback: mismo tier con familia distinta; si no funciona, escalar.
- Regla de oro: usar el modelo más barato que complete fiablemente la tarea;
  los pisos de seguridad tienen prioridad sobre el ahorro.
