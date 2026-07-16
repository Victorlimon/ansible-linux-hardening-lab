# 📚 Documentación Técnica - ansible-cis-benchmark

> Documentación interna del proyecto de hardening CIS Benchmark con Ansible.  
> Dirigida a desarrolladores, arquitectos DevOps y auditores de seguridad.

---

## 🗂️ Índice

1. [Arquitectura General](#-arquitectura-general)
2. [Flujo de Ejecución](#-flujo-de-ejecución)
3. [Diseño de Roles](#-diseño-de-roles)
4. [Variables y Configuración](#-variables-y-configuración)
5. [Tags y Ejecución Selectiva](#-tags-y-ejecución-selectiva)
6. [Idempotencia y Buenas Prácticas](#-idempotencia-y-buenas-prácticas)
7. [Multi-Distro Support](#-multi-distro-support)
8. [Auditoría y Reportes](#-auditoría-y-reportes)
9. [Testing y Validación](#-testing-y-validación)
10. [Troubleshooting](#-troubleshooting)

---

## 🏗️ Arquitectura General

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────────┐
│                    ansible_prod_ia/                          │
├─────────────────────────────────────────────────────────────┤
│  ansible/                                                    │
│  ├── playbooks/                                              │
│  │   ├── cis_hardening.yml  ← Entry point principal         │
│  │   └── cis_audit.yml      ← Entry point de auditoría      │
│  │                                                             │
│  ├── inventories/                                            │
│  │   ├── local/     ← Laboratorio Vagrant                   │
│  │   ├── staging/   ← Ambiente de pruebas                   │
│  │   └── production/← Ambiente productivo                   │
│  │                                                             │
│  ├── group_vars/                                             │
│  │   ├── all.yml          ← Variables globales              │
│  │   ├── local.yml        ← Overrides por ambiente          │
│  │   ├── staging.yml                                          │
│  │   └── production.yml                                       │
│  │                                                             │
│  └── roles/                                                  │
│      └── cis_benchmark/  ← Rol principal de hardening       │
│          ├── defaults/main.yml  ← Variables por defecto     │
│          ├── tasks/              ← Lógica de remediación    │
│          ├── handlers/           ← Handlers con validación  │
│          ├── templates/          ← Jinja2 templates         │
│          └── vars/               ← Variables internas       │
│                                                             │
│  lab/                                                        │
│  └── vagrant/  ← Laboratorio local con Vagrant              │
│      ├── Vagrantfile                                         │
│      ├── ssh/                                                │
│      └── scripts/                                            │
└─────────────────────────────────────────────────────────────┘
```

### Flujo de Datos

```
1. ansible-playbook cis_hardening.yml
   │
   ▼
2. Carga de inventario (-i inventories/XXX/hosts.yml)
   │
   ▼
3. Carga de variables (group_vars/all.yml + environment.yml)
   │
   ▼
4. Ejecución de rol cis_benchmark
   │
   ├──► Gather facts (package_facts, service_facts)
   │
   ├──► Import de secciones (section1, section2, ...)
   │    │
   │    ├──► Evaluación de when: cis_sectionX | default(true)
   │    │
   │    ├──► Import de sub-secciones (1.1, 1.2, ...)
   │    │
   │    └──► Ejecución de tasks con tags y condicionales
   │
   ├──► Notificación de handlers (si hubo cambios)
   │
   ▼
5. Generación de reportes (opcional, en rol audit/)
```

---

## 🔄 Flujo de Ejecución

### Playbook Principal: `cis_hardening.yml`

```yaml
---
- name: Aplicar hardening CIS
  hosts: all
  become: yes
  vars_files:
    - ../group_vars/{{ env | default('local') }}.yml
  roles:
    - cis_benchmark
```

**Características clave:**
- `become: yes`: Ejecución con privilegios root (requerido para hardening)
- `vars_files`: Carga dinámica de variables por ambiente (`env` variable)
- `roles`: Delegación de lógica al rol `cis_benchmark`

### Entry Point del Rol: `roles/cis_benchmark/tasks/main.yml`

```yaml
---
# Gather facts primero (requerido para condicionales)
- name: Gather package facts
  package_facts:
    manager: auto

- name: Gather service facts
  service_facts:

# Import de secciones con tags heredados
- name: Include section 1 initial setup
  when: cis_section1_initial_setup | default(true)
  ansible.builtin.import_tasks: section1_initialsetup/main.yml
  tags: [cis_1, cis_sec1, initial_setup, ...]
```

**Por qué `import_tasks` en lugar de `include_tasks`:**
- Los tags se heredan automáticamente a tasks anidados
- Mejor para estructura estática conocida (CIS Benchmark)
- Permite filtrado con `--tags` a cualquier nivel de profundidad

---

## 🧩 Diseño de Roles

### Estructura de Directorios

```
roles/cis_benchmark/
├── defaults/main.yml          # Variables con valores por defecto
├── vars/main.yml              # Variables internas (no overrideables)
├── tasks/
│   ├── main.yml               # Entry point con imports
│   ├── section1_initialsetup/
│   │   ├── main.yml           # Import de 1.1-1.7
│   │   ├── 1.1-configure_filesystem/
│   │   │   ├── main.yml       # Import de 1.1.1, 1.1.2
│   │   │   ├── 1.1.1-configure_kernel_modules.yml
│   │   │   ├── 1.1.2-configure_partitions/
│   │   │   │   ├── main.yml
│   │   │   │   ├── 1.1.2.1-configure_tmp.yml
│   │   │   │   └── ...
│   │   │   └── _disable_module.yml  # Helper interno
│   │   └── ...
│   └── ...
├── handlers/main.yml          # Handlers con validación
├── templates/                 # Jinja2 templates (.j2)
└── files/                     # Archivos estáticos
```

### Naming Convention

| Elemento | Formato | Ejemplo |
|----------|---------|---------|
| **Archivo de task** | `{numero}-{accion}-{objeto}.yml` | `1.1.1-configure_kernel_modules.yml` |
| **Variable** | `cis_<seccion>_<subseccion>_<control>` | `cis_1_1_1_disable_cramfs` |
| **Tag principal** | `cis_secX` | `cis_sec1` |
| **Tag específico** | `cis_X.Y.Z` | `cis_1.1.1` |
| **Handler** | `<accion>_<objeto>` | `restart_sshd`, `update_grub` |

### Patrón de Task CIS

```yaml
- name: "CIS X.Y.Z | <Auditoría/Remediation> | Descripción clara"
  ansible.builtin.<modulo>:
    # Parámetros del módulo
  when:
    - cis_X_Y_Z_flag | default(true)      # Flag granular
    - condicion_adicional                 # Ej: "'pkg' in ansible_facts.packages"
  notify: <handler_si_aplica>             # Opcional
  tags:                                   # Obligatorio
    - cis_secX                           # Sección principal
    - cis_X.Y.Z                          # Control específico
    - NIST800-53R5_*                     # Mapeo NIST (si aplica)
    - level1                             # o level2 según CIS
    - <componente>                       # ssh, firewall, pam, etc.
```

---

## ⚙️ Variables y Configuración

### Jerarquía de Variables (de menor a mayor prioridad)

1. `defaults/main.yml` - Valores por defecto del rol
2. `group_vars/all.yml` - Variables globales del proyecto
3. `group_vars/<ambiente>.yml` - Overrides por ambiente
4. `host_vars/<hostname>.yml` - Overrides por host específico
5. `-e "variable=value"` - Variables en línea de comandos
6. `--extra-vars @file.yml` - Variables desde archivo externo

### Variables Granulares por Control

```yaml
# defaults/main.yml - Ejemplo Sección 5.1 (SSH)
cis_section5_1_ssh_server: true          # Habilitar toda la subsección

cis_ssh_config:
  config_files: true                     # 5.1.1
  host_keys: true                        # 5.1.2
  access_control: true                   # 5.1.4
  use_allow_list: true                   # Usar AllowUsers vs DenyUsers
  allowed_users_groups: "sshusers"       # Lista de usuarios/grupos
  banner: true                           # 5.1.5
  ciphers: true                          # 5.1.11
  # ... resto de flags
```

**Ventajas:**
- ✅ Activar/desactivar controles individualmente sin modificar código
- ✅ Overrides por ambiente: `production.yml` puede desactivar reglas no aplicables
- ✅ Testing selectivo: `--tags cis_5.1.4` ejecuta solo un control

### Variables Sensibles con Ansible Vault

```bash
# 1. Generar hash de contraseña GRUB
grub-mkpasswd-pbkdf2
# Output: grub.pbkdf2.sha512.10000.XXXXX...

# 2. Cifrar con ansible-vault
echo "grub.pbkdf2.sha512.10000.XXXXX..." | \
  ansible-vault encrypt_string --stdin-name 'cis_grub_password'

# 3. Usar en playbook
ansible-playbook playbooks/cis_hardening.yml --ask-vault-pass
```

**Variables que requieren vault:**
- `cis_grub_password` - Contraseña de bootloader
- `cis_ssh_config.PasswordAuthentication` - Si se usa autenticación por contraseña
- Cualquier credencial de servicio externo

---

## 🏷️ Tags y Ejecución Selectiva

### Sistema de Tags

```
cis_sec1                    # Todas las tareas de Sección 1
├─ cis_1.1                  # Filesystem Configuration
│  ├─ cis_1.1.1             # Kernel Modules
│  └─ cis_1.1.2             # Partitions
├─ cis_1.2                  # Package Management
└─ ...

NIST800-53R5_AC-3          # Mapeo a controles NIST
level1                      # Controles CIS Level 1
level2                      # Controles CIS Level 2 (estrictos)
ssh                         # Componente específico
firewall                    # Componente específico
```

### Comandos de Ejecución

```bash
# Ejecutar toda la Sección 5 (Access Control)
ansible-playbook playbooks/cis_hardening.yml --tags cis_sec5

# Ejecutar solo SSH hardening
ansible-playbook playbooks/cis_hardening.yml --tags cis_5.1

# Ejecutar controles Level 1 de todas las secciones
ansible-playbook playbooks/cis_hardening.yml --tags level1

# Ejecutar controles NIST AC-3 (Access Control)
ansible-playbook playbooks/cis_hardening.yml --tags NIST800-53R5_AC-3

# Combinar tags (OR lógico)
ansible-playbook playbooks/cis_hardening.yml --tags "cis_5.1,cis_4.2"

# Excluir tags (NOT lógico)
ansible-playbook playbooks/cis_hardening.yml --skip-tags cis_7

# Listar tasks por tag
ansible-playbook playbooks/cis_hardening.yml --list-tags
ansible-playbook playbooks/cis_hardening.yml --list-tasks --tags cis_5.1
```

---

## ✅ Idempotencia y Buenas Prácticas

### Patrones de Idempotencia

```yaml
# ✅ Usar facts para condicionar ejecución
- name: "CIS X.X.X | Remediation | Ensure package is installed"
  ansible.builtin.apt:
    name: some-package
    state: present
  when: "'some-package' not in ansible_facts.packages"
  changed_when: false

# ✅ Usar stat para verificar existencia de archivos
- name: "CIS X.X.X | AUDIT | Check if file exists"
  ansible.builtin.stat:
    path: /etc/some/config
  register: _cis_file_stat

- name: "CIS X.X.X | Remediation | Configure file if exists"
  ansible.builtin.lineinfile:
    path: /etc/some/config
    ...
  when: _cis_file_stat.stat.exists

# ✅ Usar backup en configs críticas
- name: "CIS X.X.X | Remediation | Modify critical config"
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    ...
    backup: yes
    validate: 'sshd -t -f %s'  # Validar sintaxis antes de aplicar
```

### Manejo de Errores en Entornos Variables

```yaml
# Para servicios que pueden no existir en todas las instalaciones
- name: "CIS X.X.X | Remediation | Configure optional service"
  ansible.builtin.systemd:
    name: optional-service
    state: restarted
  ignore_errors: true
  failed_when: false
  when: "'optional-service.service' in ansible_facts.services"
```

### Validación de Cambios Críticos

```yaml
# GRUB configuration
- name: "CIS 1.4.2 | Remediation | Set grub.cfg permissions"
  ansible.builtin.file:
    path: /boot/grub/grub.cfg
    mode: '0600'
  notify: validate_grub_permissions  # Handler que verifica el cambio

# En handlers/main.yml:
- name: validate_grub_permissions
  ansible.builtin.stat:
    path: /boot/grub/grub.cfg
  register: _grub_check
  failed_when:
    - _grub_check.stat.mode != '0600'
    - cis_1_4_2_grub_permissions | default(true)
```

---

## 🐧🍥 Multi-Distro Support

### Detección Automática de Distribución

```yaml
# defaults/main.yml
cis_firewall_engine: "{{ 'ufw' if ansible_facts.distribution == 'Ubuntu' else 'nftables' }}"
cis_nftables_family: "{{ 'inet' if ansible_facts.distribution == 'Debian' else 'ip' }}"
```

### Implementación por Sección

```yaml
# section4_firewall/main.yml
- name: Include 4.2 configure uncomplicated firewall
  when: cis_firewall_engine == 'ufw'  # Solo Ubuntu
  ansible.builtin.import_tasks: 4.2-configure_uncomplicated_firewall.yml

- name: Include 4.3 configure nftables
  when: cis_firewall_engine == 'nftables'  # Solo Debian
  ansible.builtin.import_tasks: 4.3-configure_nftables.yml
```

### Override Manual por Host

```yaml
# group_vars/ubuntu_servers.yml
ansible_facts:
  distribution: Ubuntu
cis_firewall_engine: ufw

# group_vars/debian_servers.yml
ansible_facts:
  distribution: Debian
cis_firewall_engine: nftables

# group_vars/legacy_servers.yml (forzar iptables)
cis_firewall_engine: iptables
cis_4_4_iptables: true
```

---

## 📊 Auditoría y Reportes

### Rol de Auditoría: `audit/`

```
roles/audit/
├── tasks/
│   ├── main.yml                    # Entry point
│   ├── section1_audit.yml          # Auditoría Sección 1
│   ├── section2_audit.yml          # Auditoría Sección 2
│   └── ...
├── templates/
│   └── audit_report.json.j2        # Template de reporte JSON
└── files/
```

### Estructura de Reporte JSON

```json
{
  "audit_timestamp": "2026-05-17T12:00:00Z",
  "target_host": "ubuntu-server",
  "cis_benchmark_version": "v1.0.0",
  "results": [
    {
      "control_id": "cis_1.1.1.1",
      "control_name": "Ensure cramfs kernel module is disabled",
      "status": "PASS",
      "severity": "medium",
      "remediation": "Add 'install cramfs /bin/true' to /etc/modprobe.d/cis_cramfs.conf",
      "actual_value": "cramfs module is blacklisted",
      "expected_value": "cramfs module should be disabled"
    },
    {
      "control_id": "cis_5.1.4",
      "control_name": "Ensure sshd access is configured",
      "status": "FAIL",
      "severity": "high",
      "remediation": "Configure AllowUsers in /etc/ssh/sshd_config",
      "actual_value": "No access control configured",
      "expected_value": "AllowUsers or AllowGroups should be set"
    }
  ],
  "summary": {
    "total_controls": 150,
    "passed": 142,
    "failed": 8,
    "not_applicable": 0,
    "compliance_percentage": 94.7
  }
}
```

### Generación de Reportes

```bash
# Ejecutar auditoría y generar reporte
ansible-playbook playbooks/cis_audit.yml \
  -i inventories/production/hosts.yml \
  --tags cis_sec5 \
  -e "audit_output_dir=/tmp/reports"

# Ver reporte generado
cat /tmp/reports/audit_ubuntu-server_2026-05-17.json | jq '.summary'
```

---

## 🧪 Testing y Validación

### Ansible Lint Configuration

```yaml
# .ansible-lint (en raíz del proyecto)
---
skip_list:
  - name[casing]          # Permitir nombres de tasks con CIS X.Y.Z format
  - risky-shell-pipe      # Permitir pipes en shell commands de auditoría

exclude_paths:
  - reports/
  - .vagrant/
```

### Comandos de Validación

```bash
# 1. Validación de sintaxis
ansible-playbook playbooks/cis_hardening.yml --syntax-check

# 2. Ansible Lint
ansible-lint playbooks/cis_hardening.yml -c .ansible-lint

# 3. YAML Lint
yamllint -c .yamllint ansible/

# 4. Prueba de idempotencia
ansible-playbook playbooks/cis_hardening.yml --check --tags cis_5.1
ansible-playbook playbooks/cis_hardening.yml --check --tags cis_5.1
# Segunda ejecución debe mostrar: changed=0

# 5. Validación manual post-ejecución
ansible all -m shell -a "sshd -T | grep -E 'permitrootlogin|passwordauthentication'"
ansible all -m shell -a "ufw status verbose"
ansible all -m shell -a "aa-status"
```

### Molecule Testing (Para Desarrollo de Roles)

```bash
# Instalar molecule si no está
pip install molecule molecule-plugins[docker]

# Estructura básica de test
cd roles/cis_benchmark
molecule init scenario -d docker test-ssh-hardening

# Editar molecule.yml para definir la imagen de prueba
# Agregar tests en tests/test_default.py

# Ejecutar test
molecule test -s test-ssh-hardening
```

---

## 🔧 Troubleshooting

### Problemas Comunes y Soluciones

| Síntoma | Causa Probable | Solución |
|---------|---------------|----------|
| `Could not find or access 'template.j2'` | Ruta de template incorrecta | Verificar que el archivo esté en `roles/cis_benchmark/templates/` |
| `Variable 'cis_X_Y' is undefined` | Variable no definida en defaults | Agregar a `defaults/main.yml` con `| default(true)` en el task |
| `Task always reports changed=true` | Falta `changed_when` o condición basada en facts | Agregar `changed_when: false` o condicionar con `ansible_facts` |
| `SSH connection lost after hardening` | Política de firewall denegó SSH | Permitir puerto SSH antes de aplicar `default deny`, o usar `--step` para confirmación |
| `GRUB password task fails` | Hash no generado o no cifrado con vault | Generar hash con `grub-mkpasswd-pbkdf2` y cifrar con `ansible-vault` |
| `PAM configuration breaks login` | Sintaxis incorrecta en `/etc/pam.d/*` | Usar `validate` o probar en staging primero; tener acceso de respaldo (console) |

### Debugging de Tasks

```bash
# Ver variables cargadas para un host
ansible ubuntu-server -m debug -a "var=hostvars['ubuntu-server']"

# Ver facts específicos
ansible ubuntu-server -m setup -a "filter=ansible_facts.packages"
ansible ubuntu-server -m setup -a "filter=ansible_facts.services"

# Ejecutar task con verbosity para ver detalles
ansible-playbook playbooks/cis_hardening.yml --tags cis_5.1 -vvv

# Ejecutar paso a paso para confirmar cambios
ansible-playbook playbooks/cis_hardening.yml --tags cis_5.1 --step
```

### Rollback de Cambios

```bash
# 1. Usar backups generados por Ansible
ls -la /etc/ssh/sshd_config*  # Debe mostrar sshd_config.backup

# 2. Restaurar backup manual
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd

# 3. Para cambios sin backup (ej: servicios desinstalados)
# Re-ejecutar playbook con variables invertidas o usar apt install <package>

# 4. Snapshot de VM (si usas Vagrant/VirtualBox)
vagrant snapshot save ubuntu24 pre-hardening
# Para rollback: vagrant snapshot restore ubuntu24 pre-hardening
```

---

## 📞 Soporte y Contacto

- 🐛 [GitHub Issues](https://github.com/tu-usuario/ansible-cis-benchmark/issues) - Reportar bugs
- 💬 [GitHub Discussions](https://github.com/tu-usuario/ansible-cis-benchmark/discussions) - Preguntas y discusión
- 📧 tu-email@ejemplo.com - Contacto directo

---

> **Nota**: Esta documentación está en constante evolución. Si encuentras información desactualizada o faltante, por favor abre un issue o envía un PR.
