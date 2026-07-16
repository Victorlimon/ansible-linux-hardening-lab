# 🛡️ CIS Benchmark Hardening & Auditing - Ansible

[![Ansible](https://img.shields.io/badge/Ansible-2.16+-EE0000?logo=ansible&logoColor=white)](https://www.ansible.com/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v1.0.0-0052CC)](https://www.cisecurity.org/benchmark/ubuntu_linux)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Debian](https://img.shields.io/badge/Debian-12-A81D33?logo=debian&logoColor=white)](https://www.debian.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

> Automatización de **Hardening y Auditoría CIS Benchmark v1.0.0** para **Ubuntu 24.04 LTS** y **Debian 12** usando Ansible.  
> Diseñado para entornos de producción, multi-ambiente, idempotente y con cumplimiento NIST 800-53 R5.

---

## 📋 Tabla de Contenidos

- [🎯 Objetivo](#-objetivo)
- [🏗️ Arquitectura](#️-arquitectura)
- [📦 Requisitos](#-requisitos)
- [🚀 Inicio Rápido](#-inicio-rápido)
- [🔧 Configuración](#-configuración)
- [📊 Secciones CIS Implementadas](#-secciones-cis-implementadas)
- [🏃 Ejecución](#-ejecución)
- [📁 Estructura del Proyecto](#-estructura-del-proyecto)
- [🛡️ Buenas Prácticas](#️-buenas-prácticas)
- [🧪 Testing](#-testing)
- [🤝 Contribuir](#-contribuir)
- [📄 Licencia](#-licencia)

---

## 🎯 Objetivo

Automatizar la aplicación de controles de seguridad del **CIS Ubuntu Linux 24.04 LTS / Debian 12 Benchmark v1.0.0** de manera:

- ✅ **Idempotente**: Ejecuta múltiples veces sin efectos secundarios
- ✅ **Modular**: Activa/desactiva controles individualmente por ambiente
- ✅ **Auditable**: Genera reportes JSON con estado `PASS/FAIL` por control
- ✅ **Multi-ambiente**: Soporta `local`, `staging` y `production`
- ✅ **Multi-distro**: Ubuntu 24.04 (ufw) y Debian 12 (nftables)

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                     Ansible Control Node                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Playbooks   │  │  Group Vars  │  │  Roles & Tasks    │  │
│  │ (cis_hardening│  │ (local/      │  │ (cis_benchmark/   │  │
│  │  .yml)        │  │  staging/    │  │  audit/)          │  │
│  │               │  │  prod/)      │  │                   │  │
│  └───────┬───────┘  └───────┬───────┘  └─────────┬────────┘  │
│          │                  │                    │            │
│          └──────────────────┼────────────────────┘            │
│                             │                                 │
└─────────────────────────────┼─────────────────────────────────┘
                              │ SSH
┌─────────────────────────────▼─────────────────────────────────┐
│                      Managed Nodes                             │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐  │
│  │ Ubuntu 24.04│  │  Debian 12  │  │  Future: RHEL, CentOS│  │
│  │ (ufw)       │  │ (nftables)  │  │                      │  │
│  └─────────────┘  └─────────────┘  └──────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

---

## 📦 Requisitos

| Software | Versión | Propósito |
|----------|---------|-----------|
| **Ansible Core** | `>= 2.16` | Motor de automatización |
| **Python** | `>= 3.10` | Runtime de Ansible |
| **Vagrant** | `>= 2.3` | Laboratorio local (opcional) |
| **VirtualBox** | `>= 7.0` | Proveedor Vagrant (opcional) |

### Colecciones Ansible Requeridas

```bash
ansible-galaxy collection install ansible.builtin ansible.posix community.general
```

---

## 🚀 Inicio Rápido

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/ansible-cis-benchmark.git
cd ansible-cis-benchmark
```

### 2. Levantar el laboratorio (opcional)

```bash
# Desde la raíz del proyecto
make up              # Levanta VMs con Vagrant
make provision-lab   # Instala Ansible y configura usuarios
```

### 3. Configurar inventario

```bash
# Editar inventario según ambiente
cp ansible/inventories/local/hosts.yml.example ansible/inventories/local/hosts.yml
nano ansible/inventories/local/hosts.yml
```

### 4. Configurar variables

```bash
# Personalizar para tu ambiente
cp ansible/group_vars/all.yml.example ansible/group_vars/all.yml
nano ansible/group_vars/local.yml
```

### 5. Ejecutar validación

```bash
cd ansible
ansible-playbook playbooks/cis_hardening.yml --syntax-check
ansible all -m ping
```

### 6. Ejecutar hardening (Dry-Run)

```bash
ansible-playbook playbooks/cis_hardening.yml --check --diff --tags cis_sec1
```

---

## 🔧 Configuración

### Variables Principales (`group_vars/all.yml`)

```yaml
# Motor de firewall por distribución (auto-detectado)
cis_firewall_engine: auto  # ufw | nftables | auto

# Nivel de cumplimiento CIS
cis_level: 1  # 1 (recomendado) | 2 (estricto)

# Excepciones por ambiente
cis_exceptions:
  - rule: cis_1_1_1_disable_overlayfs
    reason: "Docker/Podman requiere overlayfs"
    environments: ["local", "staging"]
```

### Desactivar Reglas por Ambiente

```yaml
# group_vars/production.yml
cis_2_1_10_http_server: false  # Permitir Nginx en producción
cis_4_2_6_ufw_rules_for_open_ports:
  - { port: 443, proto: tcp }
  - { port: 80, proto: tcp }
  - { port: 22, proto: tcp }
```

### Variables Sensibles con Ansible Vault

```bash
# Cifrar contraseña GRUB
ansible-vault encrypt_string --stdin-name 'cis_grub_password'

# Ejecutar playbook con vault
ansible-playbook playbooks/cis_hardening.yml --ask-vault-pass
```

---

## 📊 Secciones CIS Implementadas

| Sección | Controles | Estado | Tags | Descripción |
|---------|-----------|--------|------|-------------|
| **1. Initial Setup** | 1.1-1.7 | ✅ Completo | `cis_1` | Filesystem, packages, AppArmor, bootloader, banners |
| **2. Services** | 2.1-2.4 | ✅ Completo | `cis_2` | Server/client services, time sync, job schedulers |
| **3. Network** | 3.1-3.3 | ✅ Completo | `cis_3` | Network protocols, kernel parameters, sysctl |
| **4. Firewall** | 4.1-4.4 | ✅ Completo | `cis_4` | UFW (Ubuntu) / nftables (Debian) / iptables |
| **5. Access Control** | 5.1-5.4 | ✅ Completo | `cis_5` | SSH hardening, sudo, PAM, user accounts |
| **6. Logging/Auditing** | 6.1-6.3 | ✅ Completo | `cis_6` | journald, rsyslog, auditd, AIDE |
| **7. System Maintenance** | 7.1-7.2 | ✅ Completo | `cis_7` | File permissions, user/group settings |

### Tags Disponibles

```bash
# Ejecutar por sección
ansible-playbook playbooks/cis_hardening.yml --tags cis_1
ansible-playbook playbooks/cis_hardening.yml --tags cis_2
ansible-playbook playbooks/cis_hardening.yml --tags cis_3

# Ejecutar por subsección
ansible-playbook playbooks/cis_hardening.yml --tags cis_1.1.1  # Kernel modules
ansible-playbook playbooks/cis_hardening.yml --tags cis_5.1    # SSH Server
ansible-playbook playbooks/cis_hardening.yml --tags cis_4.2    # UFW

# Ejecutar por compliance
ansible-playbook playbooks/cis_hardening.yml --tags level1
ansible-playbook playbooks/cis_hardening.yml --tags NIST800-53R5_AC-3

# Combinar tags
ansible-playbook playbooks/cis_hardening.yml --tags "cis_1,cis_5"
ansible-playbook playbooks/cis_hardening.yml --tags "cis_sec4,level1"
```

---

## 🏃 Ejecución

### Comandos Principales

| Comando | Descripción |
|---------|-------------|
| `--syntax-check` | Validar sintaxis YAML sin ejecutar |
| `--check --diff` | Dry-run: muestra cambios sin aplicar |
| `--tags cis_sec5` | Ejecutar solo Sección 5 |
| `--skip-tags cis_7` | Saltar Sección 7 |
| `-e cis_level=2` | Ejecutar Level 2 (estricto) |
| `-i inventories/prod/hosts.yml` | Usar inventario de producción |

### Pipeline de Ejecución Recomendada

```bash
cd ansible

# 1. Validar sintaxis
ansible-playbook playbooks/cis_hardening.yml --syntax-check

# 2. Dry-run completo (sin cambios)
ansible-playbook playbooks/cis_hardening.yml --check --diff

# 3. Ejecutar en staging primero
ansible-playbook playbooks/cis_hardening.yml \
  -i inventories/staging/hosts.yml \
  --tags cis_sec1,cis_sec2,cis_sec4

# 4. Verificar resultados
ansible all -m shell -a "sshd -T | grep permitrootlogin"

# 5. Ejecutar en producción (con confirmación)
ansible-playbook playbooks/cis_hardening.yml \
  -i inventories/production/hosts.yml \
  --ask-vault-pass \
  --step
```

### Ejecución Parcial por Sección

```bash
# Solo hardening de SSH
ansible-playbook playbooks/cis_hardening.yml --tags cis_5.1

# Solo configuración de firewall
ansible-playbook playbooks/cis_hardening.yml --tags cis_4

# Solo auditoría de logs
ansible-playbook playbooks/cis_audit.yml --tags cis_6

# Combinar hardening + auditoría
ansible-playbook playbooks/cis_hardening.yml --tags cis_5.1
ansible-playbook playbooks/cis_audit.yml --tags cis_5.1
```

---

## 📁 Estructura del Proyecto

```
ansible_prod_ia/
├── ansible/
│   ├── ansible.cfg                 # Configuración global de Ansible
│   ├── playbooks/
│   │   ├── cis_hardening.yml       # Playbook principal de hardening
│   │   ├── cis_audit.yml           # Playbook principal de auditoría
│   │   └── reports/                # Reportes JSON generados
│   ├── inventories/
│   │   ├── local/                  # Laboratorio Vagrant
│   │   │   ├── hosts.yml
│   │   │   ├── group_vars/
│   │   │   │   ├── all.yml
│   │   │   │   ├── local.yml
│   │   │   │   └── ...
│   │   │   └── host_vars/
│   │   ├── staging/                # Ambiente de staging
│   │   └── production/             # Ambiente de producción
│   ├── group_vars/
│   │   ├── all.yml                 # Variables globales
│   │   ├── local.yml               # Overrides laboratorio
│   │   ├── staging.yml             # Overrides staging
│   │   └── production.yml          # Overrides producción
│   ├── roles/
│   │   ├── cis_benchmark/          # Rol principal de hardening
│   │   │   ├── defaults/main.yml   # Variables por defecto (granulares)
│   │   │   ├── tasks/
│   │   │   │   ├── main.yml        # Entry point con imports por sección
│   │   │   │   ├── section1_initialsetup/    # 1.1-1.7
│   │   │   │   ├── section2_services/        # 2.1-2.4
│   │   │   │   ├── section3_network/         # 3.1-3.3
│   │   │   │   ├── section4_firewall/        # 4.1-4.4
│   │   │   │   ├── section5_access/          # 5.1-5.4
│   │   │   │   ├── section6_logging/         # 6.1-6.3
│   │   │   │   └── section7_system/          # 7.1-7.2
│   │   │   ├── handlers/main.yml   # Handlers (restart, reload)
│   │   │   ├── templates/          # Jinja2 templates
│   │   │   ├── files/              # Archivos estáticos
│   │   │   └── vars/main.yml       # Variables internas
│   │   └── audit/                  # Rol de auditoría y reportes
│   │       ├── tasks/
│   │       ├── templates/
│   │       └── files/
│   ├── library/                    # Módulos personalizados
│   ├── scripts/                    # Scripts de validación
│   └── reports/                    # Directorio para reportes
├── lab/
│   ├── vagrant/
│   │   ├── Vagrantfile             # Definición de máquinas virtuales
│   │   ├── ssh/                    # Claves SSH para Vagrant
│   │   └── scripts/                # Scripts de provisioning
│   └── scripts/                    # Scripts de automatización del lab
├── docs/                           # Documentación técnica (ver docs/README.md)
├── makefile                        # Comandos de automatización
├── README.md                       # Este archivo
├── CONTRIBUTING.md                 # Guía para contribuidores
├── CHANGELOG.md                    # Historial de versiones
├── LICENSE                         # Licencia MIT
└── .gitignore                      # Archivos ignorados por Git
```

---

## 🛡️ Buenas Prácticas

### 1. Idempotencia

Todos los tasks usan `changed_when`, `failed_when` y condicionales basados en `ansible_facts`:

```yaml
- name: "CIS X.X.X | Remediation | Ensure ..."
  ansible.builtin.apt:
    name: some-package
    state: present
  when: "'some-package' not in ansible_facts.packages"
  changed_when: false
```

### 2. Seguridad

- ✅ Variables sensibles cifradas con `ansible-vault`
- ✅ Validación de configs críticas (`validate: 'sshd -t -f %s'`)
- ✅ Backups automáticos antes de modificar (`backup: yes`)
- ✅ Permisos estrictos en archivos de configuración

### 3. Modularidad

```yaml
# Desactivar regla específica sin tocar código
# group_vars/production.yml:
cis_1_1_1_disable_overlayfs: false  # Docker/Podman compatible
cis_2_1_10_http_server: false       # Permitir Nginx
cis_4_2_6_ufw_rules_for_open_ports:
  - { port: 443, proto: tcp }
  - { port: 80, proto: tcp }
```

### 4. Multi-Distro

Detección automática del motor de firewall:

| Distribución | Motor | Variable |
|-------------|-------|----------|
| Ubuntu 24.04 | `ufw` | `cis_firewall_engine: ufw` |
| Debian 12 | `nftables` | `cis_firewall_engine: nftables` |

### 5. Testing y Validación

```bash
# Ansible Lint
ansible-lint playbooks/cis_hardening.yml

# YAML Lint
yamllint roles/cis_benchmark/tasks/

# Validación de sintaxis
ansible-playbook playbooks/cis_hardening.yml --syntax-check

# Dry-run con diff
ansible-playbook playbooks/cis_hardening.yml --check --diff
```

---

## 🧪 Testing

### Ansible Lint

```bash
ansible-lint playbooks/cis_hardening.yml
```

### Molecule (Testing de Roles)

```bash
cd roles/cis_benchmark
molecule test
```

### Manual Testing

```bash
# Verificar estado de servicios
sshd -T | grep -E 'permitrootlogin|passwordauthentication'
ufw status verbose
nft list ruleset
aa-status

# Verificar permisos
ls -la /etc/ssh/sshd_config
stat /boot/grub/grub.cfg

# Verificar políticas de password
grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS' /etc/login.defs
```

### Scripts de Validación Incluidos

```bash
# Validar sección 6.3 (AIDE)
./scripts/validate_section6_3.sh

# Validar tags de sección 6
./scripts/validate_section6_tags.sh
```

---

## 🤝 Contribuir

### Flujo de Trabajo

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/cis-3.2-network`)
3. Commit cambios (`git commit -m 'feat: CIS 3.2 network hardening'`)
4. Push (`git push origin feature/cis-3.2-network`)
5. Pull Request

### Estándares de Código

- ✅ Tasks nombrados: `CIS X.X.X | <Auditoría/Remediation> | Descripción`
- ✅ Tags: `cis_secX`, `cis_X.X.Y`, `NIST800-53R5_*`, `level1/level2`
- ✅ Variables: `snake_case`, prefijo `cis_`, booleanos `true/false`
- ✅ Comentarios: Documentar cada bloque con referencia CIS
- ✅ Idempotencia: Usar `changed_when`, `failed_when`, condicionales

### Estructura de Nuevos Controles

```yaml
- name: "CIS X.Y.Z | Remediation | Ensure ..."
  ansible.builtin.<modulo>:
    # parámetros
  when:
    - cis_X_Y_Z_flag | default(true)
    - condicion_adicional
  notify: <handler_si_aplica>
  tags: ['cis_secX', 'cis_X.Y.Z', 'NIST800-53R5_*', 'level1']
```

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

```text
MIT License

Copyright (c) 2024-2026 Victor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👥 Autores

- **Victor** - Desarrollo inicial y arquitectura
- [Tu Nombre](https://github.com/tu-usuario) - Mantenedor

---

## 📞 Soporte

- 🐛 Reportar bugs: [Issues](https://github.com/tu-usuario/ansible-cis-benchmark/issues)
- 💬 Discusiones: [Discussions](https://github.com/tu-usuario/ansible-cis-benchmark/discussions)
- 📧 Email: tu-email@ejemplo.com

---

## 🔄 Historial de Versiones

Ver [CHANGELOG.md](CHANGELOG.md) para el historial completo de cambios.

---

<div align="center">

**⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub ⭐**

</div>

---

> **Nota**: Este proyecto está diseñado para entornos controlados. Siempre prueba los cambios en un ambiente de staging antes de aplicarlos en producción.
