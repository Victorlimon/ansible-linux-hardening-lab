# Manual de uso

Cómo ejecutar el proyecto con precisión: modos, tags reales, gates y variables.
Todo lo descrito acá está verificado contra el código actual; si algo no coincide,
la fuente de verdad son los archivos citados, no este documento.

## Estructura real del árbol

```text
ansible/
├── ansible.cfg                 # remote_user, inventario, become, roles_path
├── requirements.yml            # colecciones fijadas
├── playbooks/
│   ├── cis_debian_12_preflight.yml
│   ├── audit/{cis_ubuntu_2404,cis_debian_12}.yml
│   ├── hardening/{cis_ubuntu_2404,cis_debian_12}.yml
│   └── verify/{cis_ubuntu_2404,cis_debian_12}.yml
├── inventories/
│   ├── local/hosts.yml + group_vars/
│   ├── staging/hosts.yml       # vacío (plantilla)
│   └── production/hosts.yml    # vacío (plantilla)
├── roles/
│   ├── cis_platform_preflight/ # valida SO/arch/release-status
│   ├── cis_linux_common/       # biblioteca de mecanismos (no se ejecuta directo)
│   ├── cis_ubuntu_2404/        # adaptador canónico Ubuntu
│   └── cis_debian_12/          # adaptador canónico Debian
├── cis/                        # catálogo/ledger/esquemas (metadatos, no runtime)
└── scripts/                    # calificación y generación de metadatos
```

No existe un rol `cis_benchmark`: la orquestación Ubuntu vive en
`cis_ubuntu_2404/tasks/main.yml`, que importa 7 carpetas de secciones y 25
mecanismos.

## Modos de ejecución

Cada playbook fija una variable de modo que el adaptador valida al arrancar:

| Playbook | Variable de modo | Valor |
|---|---|---|
| `audit/cis_*.yml` | `cis_<plataforma>_execution_mode` | `audit` |
| `hardening/cis_*.yml` | `cis_<plataforma>_execution_mode` | `remediation` |
| `verify/cis_*.yml` | `cis_<plataforma>_execution_mode` | `verification` |

- **Auditoría** observa y reporta sin cambiar nada.
- **Verificación** compara el estado real contra el contrato y falla si hay
  desvío (es una comprobación, no cambia nada).
- **Remediación** aplica cambios; está detrás del master gate y, en Debian, del
  gate canario.

Los mecanismos de solo lectura (por ejemplo `manual_observation`, `ipv6_status`)
no tienen etapa de remediación.

## Tags reales

⚠️ **Los tags `cis_sec1`..`cis_sec7` NO existen.** Tampoco los tags con punto
(`cis_5.1.4`). El vocabulario real es:

### Tags de plataforma y modo

- `cis_ubuntu_2404`, `cis_ubuntu_2404_audit`, `cis_ubuntu_2404_remediation`,
  `cis_ubuntu_2404_verification`.
- `cis_debian_12`, `cis_debian_12_audit`, `cis_debian_12_remediation`,
  `cis_debian_12_verification`.

### Tags de control (forma con guion bajo)

Cada control usa su ID CIS con guion bajo: `cis_5_1_4` (SSH), `cis_4_2_6` (UFW),
`cis_3_3_8` (sysctl), `cis_1_1_2_1_1` (partición), etc. Descubrí el nombre real
antes de ejecutar:

```bash
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --list-tags --limit ubuntu24
```

### Tags de sección (incompletos)

Solo existen tags de sección sueltos para **3** y **7**: `cis_3`, `cis_3_1`,
`cis_3_3`, `cis_7`, `cis_7_1`. Las secciones 1, 2, 4, 5 y 6 **no tienen tag de
sección**; para acotar su alcance usá tags de control o de mecanismo.

### Tags de mecanismo / familia

Son la forma más estable de seleccionar alcance transversal:

`sysctl`, `sysctl_parameter`, `config_line`, `fixed_file_permissions`,
`package_absent`, `package_installed`, `service_disabled`, `service_enabled`,
`line_absent`, `ufw_rule`, `ufw_policy`, `nftables_config`, `gated_unsafe`,
`manual`, `manual_observation`, `apparmor_enforcing`, `world_writable_files`,
`orphan_files`, `account_integrity`, `single_daemon`, `firewall_single_utility`,
`wireless_disabled`, `allow_deny_restriction`, `process_user`,
`grub_boot_parameter`, `bootloader_password`, `ipv6_status`, `ipv6`, `network`,
`banners`, `issue`, `sudo`, `cron`, `sshd`, `tcp_syncookies`, `level_1`.

### Tags de seguridad

`always`, `safety`, `platform`, `preflight` — las tareas de gate y recolección de
facts los llevan para ejecutarse aunque selecciones un control suelto.

## Gates

### Preflight (siempre)

`cis_platform_preflight` rechaza objetivos que no sean `x86_64`, plataforma
desconocida, o release-status fuera del allowlist. El catálogo de plataformas
está en `cis_platform_preflight/vars/main.yml` (Ubuntu 24.04 = `released`,
Debian 12 = `canary`).

### Master gate de remediación (Ubuntu)

En `cis_ubuntu_2404/tasks/main.yml` (primeras tareas, `tags: [always, ...]`):

- `cis_ubuntu_2404_execution_mode` debe ser `audit`, `remediation` o `verification`.
- Si `cis_ubuntu_2404_remediation_enabled: true`, entonces el modo debe ser
  `remediation` **y** `'all' not in ansible_run_tags` (o sea, `--tags` explícito).

Resultado: con el gate habilitado, una corrida global sin `--tags` se rechaza
antes de modificar nada.

### Master gate + canario (Debian)

En `cis_debian_12/tasks/main.yml`, además de lo anterior:

- Si `cis_debian_12_remediation_enabled: true`, exige
  `cis_debian_12_canary_confirmed: true` **y** `--tags` explícito.

Los gates por control Debian vuelven a exigir `cis_debian_12_canary_confirmed`
en cada `when:` de remediación.

### Gates por control (negativos)

El modelo actual es por control, no por sección. Los selectores
`cis_<plataforma>_<id_control>` están casi todos en `true` por defecto; las
remediaciones **disruptivas** quedan opt-in detrás de un gate negativo
`<selector>_remediate: false` (alrededor de 70 controles). Ejemplos:
particiones y módulos de red (1.1.x), servicios (2.1/2.2), usuarios (5.4.x),
auditd/AIDE (6.2/6.3), montajes sensibles (7.1/7.2).

Para habilitar una remediación disruptiva, fijá el selector en el inventario:

```yaml
cis_ubuntu_2404_5_3_3_4_4_pam_unix_password_reuse_remediate: true
```

El nombre exacto del selector está en el `defaults/main.yml` de cada adaptador.
La auditoría de esos controles sigue activa aunque la remediación esté apagada.

## Variables clave

| Variable | Default | Dónde | Notas |
|---|---|---|---|
| `cis_ubuntu_2404_remediation_enabled` | `false` | defaults | Master gate Ubuntu |
| `cis_debian_12_remediation_enabled` | `false` | defaults | Master gate Debian |
| `cis_debian_12_canary_confirmed` | `false` | defaults | Gate canario Debian |
| `cis_firewall` | `ufw` (Ubuntu), `nftables` (Debian) | defaults | Motor de la sección 4; condiciona `when: cis_firewall == 'ufw'` / `'nftables'` |
| `cis_ufw_ssh_port` | `22` | defaults | Puerto SSH usado por las reglas |
| `cis_ubuntu_2404_ipv6_site_policy` | `enabled` | defaults | Política de sitio IPv6 Ubuntu |
| `cis_debian_12_ipv6_site_policy` | `undecided` | defaults | Política de sitio IPv6 Debian |

En Ubuntu, la remediación UFW 4.2.6 exige al menos una red de administración
IPv4/CIDR en `cis_ufw_ssh_allowed_sources` y aplica las reglas de servicios
de `cis_ufw_allowed_in_rules` (`from_ip`, puerto numérico y protocolo TCP/UDP).
Una lista SSH vacía o valores inválidos detienen el control antes de modificar
UFW. Esta ruta no habilita UFW ni elimina reglas preexistentes: verificá la
política efectiva y el acceso por consola antes de activar el firewall.
`from_ip: any` en una regla de servicio abre ese puerto a cualquier origen;
requiere revisión explícita. Una regla amplia ya existente puede seguir
permitiendo SSH aunque la nueva allowlist sea restrictiva.

⚠️ `cis_section4_firewall`, `cis_firewall_engine`,
`cis_ufw_authoritative_reset_confirmed` y `cis_ufw_allowed_out_ports` siguen
sin consumirse. El motor real es `cis_firewall`; Debian usa nftables por
defecto. Ver [IMPROVING.md](IMPROVING.md).

## Inventario y usuarios

`ansible/ansible.cfg` apunta a `inventories/local/hosts.yml`. En el laboratorio:

- `ubuntu24` = 192.168.56.12 (grupos `ubuntu` → `ubuntu_2404`).
- `debian12` = 192.168.56.11 (grupos `debian` → `debian_12`).
- `all.vars`: `ansible_user: ansible`, `ansible_become: yes`,
  `ansible_become_method: sudo`, clave privada `~/.ssh/id_rsa`, y una excepción
  SSH (`StrictHostKeyChecking=no`) **solo para el lab**.

En producción el inventario debe gestionar `known_hosts` y verificar la huella de
cada nodo. Los inventarios `staging` y `production` son plantillas vacías.

## Secuencia típica de una sección (ejemplo: sysctl)

```bash
# 1. Validaciones sin cambios
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --syntax-check
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --list-tags --limit ubuntu24
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --list-hosts --limit ubuntu24

# 2. Vista previa (check + diff)
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags sysctl --check --diff \
  -e cis_ubuntu_2404_remediation_enabled=true

# 3. Aplicación real
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags sysctl -e cis_ubuntu_2404_remediation_enabled=true

# 4. Segunda aplicación real (idempotencia: changed=0 esperado)
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags sysctl -e cis_ubuntu_2404_remediation_enabled=true

# 5. Verificación independiente
ansible-playbook playbooks/verify/cis_ubuntu_2404.yml --limit ubuntu24 --tags sysctl
```

El `--check` es una simulación: no es transaccional y algunos módulos no se
simulan. La prueba de idempotencia real es la **segunda aplicación real** con
`changed=0`, no el check mode.

## Recuperación

No hay rollback automático. Antes de cambios críticos (SSH, PAM, firewall, auditd,
AIDE, montajes): snapshot de la VM, consola de respaldo abierta y una segunda
sesión root/sudo activa. Los módulos con `backup: true` crean copias que pueden
restaurarse manualmente. Detalle completo en [ROLLOUT.md](ROLLOUT.md).
