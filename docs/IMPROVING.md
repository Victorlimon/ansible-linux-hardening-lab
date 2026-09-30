# Cómo mejorar el proyecto

Guía para quienes van a extender o mantener la automatización: el pipeline de
calificación, el spine de metadatos, cómo agregar un control y la deuda conocida.

## Anatomía de un control

Cada control sigue el patrón **auditoría / remediación / verificación**:

```text
ansible/roles/cis_<plataforma>/tasks/
├── main.yml                          # orquesta: importa secciones y aplica tags
├── sections/
│   └── section_05_access/…/5_1_4_ssh_config/
│       ├── audit.yml                 # observa, no cambia
│       ├── remediation.yml           # aplica (detrás de gates)
│       └── verification.yml          # valida contra el contrato, falla si desvía
└── mechanisms/                       # mecanismos propios del adaptador
```

Los mecanismos reutilizables viven en `cis_linux_common/tasks/mechanisms/`
(`sysctl_parameter`, `config_line`, `package_absent`, `ufw_rule`,
`fixed_file_permissions`, etc.). El adaptador los invoca con `import_role` +
`tasks_from` y variables de contrato `cis_linux_common_*`. `cis_linux_common` no
se ejecuta directo (su `main.yml` falla a propósito).

Los **tags** se declaran en las líneas de import de `tasks/main.yml`, no en los
archivos de sección. Mantené la forma con guion bajo para el control
(`cis_5_1_4`) y agregá el tag de mecanismo (`config_line`) y de seguridad
(`gated_unsafe` cuando corresponda).

## Pipeline de metadatos y calificación

El runtime de Ansible **no** lee `ansible/cis/`; es un spine de metadatos
body-free (sin texto licenciado del benchmark) que da trazabilidad y
reproducibilidad.

| Script | Argumentos | Produce | Qué valida |
|---|---|---|---|
| `generate_cis_catalog.py` | `--ubuntu-source N=ruta`, `--debian-source N=ruta`, `--catalog-output`, `--provenance-output` | `pinned-corpora.yml` + provenance | Parsea el benchmark privado a un catálogo sin cuerpo, con `source_sha256` y sin solapamiento de 12 n-gramas |
| `generate_ledger.py` | (sin argumentos, rutas fijas) | `control-ledger.yml` + `semantic-review.yml` | Una ruta por plataforma/versión/control/modo; asigna mecanismos vía `MECHANISM_RULES` |
| `validate_cis_catalog.py` | `--root`, `--catalog` | validación | Rechaza claves de privacidad (`title`/`body`/`recommend*`), duplicados e identidad de fuente |
| `qualify_cis_profile.py` | `--root` + (`--routing-only` \| `--schema-contracts` \| `--production-documents`) | recibo de calificación | Digests de esquemas, binding catálogo↔ledger, unicidad de rutas, cobertura, claves de privacidad |

Ejemplo de calificación de routing:

```bash
cd ansible
python scripts/qualify_cis_profile.py --root . --routing-only \
  --catalog cis/catalog/pinned-corpora.yml \
  --ledger cis/catalog/control-ledger.yml
# ROUTING_VALID corpora=2 routes=621
```

Los tres modos son excluyentes. El calificador de esquemas valida los 4
`urn:cis:*:v1` de `cis/schemas/` y el de documentos de producción valida las
plantillas de producción.

## Agregar un control nuevo (resumen)

1. Creá `sections/section_XX_…/<id>/{audit,remediation,verification}.yml`.
2. Importá el control en `tasks/main.yml` con sus tags (control + mecanismo +
   `gated_unsafe` si es disruptivo).
3. Si reutiliza un mecanismo común, pasá las variables `cis_linux_common_*` e
   `import_role`; si no, implementá el mecanismo en `mechanisms/`.
4. Si cambió el catálogo, regenerá el ledger: `python scripts/generate_ledger.py`.
5. Corré los tres modos del calificador y revisá que `ROUTING_VALID` siga verde.
6. Probá el ciclo completo en el lab: `audit` → `hardening --check` → `hardening`
   → `hardening` (idempotencia `changed=0`) → `verify`.

## Deuda técnica conocida

Cosas detectadas en el relevamiento que conviene corregir (no bloquean, pero
ensucian):

1. **Variables de firewall legadas sin consumir.** En
   `ansible/inventories/local/group_vars/ubuntu_2404.yml` hay
   `cis_section4_firewall`, `cis_firewall_engine`,
   `cis_ufw_ssh_allowed_sources`, `cis_ufw_authoritative_reset_confirmed`,
   `cis_ufw_allowed_in_rules` y `cis_ufw_allowed_out_ports` que **ninguna tarea
   consume**. El motor real es `cis_firewall` (+ `cis_ufw_ssh_port`). Hay que
   reconciliar esas variables con el código o eliminarlas.
2. **Patrón de hosts inconsistente en `verify`.** Los plays `verify` de Ubuntu
   apuntan al grupo `ubuntu_2404` mientras `audit`/`hardening` usan `ubuntu`.
   Revisá `playbooks/verify/cis_ubuntu_2404.yml`.
3. **Default de modo sospechoso.** `cis_ubuntu_2404/defaults/main.yml` declara
   `cis_ubuntu_2404_execution_mode: remediation`; los playbooks lo pisan, pero el
   default debería ser el modo menos destructivo (`audit`) para defensa en
   profundidad.
4. **Tags de sección incompletos.** Solo `cis_3` y `cis_7` (y subsecciones) tienen
   tag de sección; las secciones 1, 2, 4, 5 y 6 no. Si querés acotar por sección,
   hoy hay que usar tags de control o de mecanismo. Podría homogeneizarse.
5. **Texto del benchmark.** Los archivos de benchmark licenciado que estaban en
   `docs/` se movieron a `backups-limpia/docs/` (ya ignorados por git). No vuelvas
   a incorporarlos al repo; usá el catálogo body-free.

Antes de tocar cualquiera de estos puntos, leé [SUPPORT.md](SUPPORT.md) para no
ampliar las afirmaciones de soporte sin evidencia.
