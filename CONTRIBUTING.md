# Contribuyendo a ansible-cis-benchmark

¡Gracias por tu interés en contribuir! Este documento describe el proceso y estándares para contribuir al proyecto de hardening CIS Benchmark con Ansible.

---

## 📋 Código de Conducta

- **Respeta a todos**: Trata a otros contribuyentes con cortesía y profesionalismo.
- **Sé constructivo**: Ofrece feedback útil y específico en revisiones de código.
- **Documenta tus cambios**: Explica el "por qué" detrás de las decisiones técnicas.
- **Prueba tus cambios**: Asegura que el código sea idempotente y no rompa funcionalidad existente.

---

## 🔄 Flujo de Trabajo para Contribuciones

### 1. Reportar un Issue o Proponer una Mejora

- Busca primero si el issue ya existe en [GitHub Issues](https://github.com/tu-usuario/ansible-cis-benchmark/issues).
- Si no existe, crea uno nuevo con:
  - Título descriptivo
  - Descripción clara del problema o propuesta
  - Pasos para reproducir (si aplica)
  - Versión de Ansible y sistema operativo
  - Logs o errores relevantes

### 2. Fork y Clonar el Repositorio

```bash
# Fork desde GitHub y luego clonar
git clone https://github.com/tu-usuario/ansible-cis-benchmark.git
cd ansible-cis-benchmark
```

### 3. Crear una Rama de Trabajo

```bash
# Formato: tipo/descripcion-corta
git checkout -b feat/cis-3.2-network-hardening
git checkout -b fix/section5-ssh-idempotency
git checkout -b docs/update-readme-examples
```

**Tipos de ramas:**
| Prefijo | Uso |
|---------|-----|
| `feat/` | Nueva funcionalidad o control CIS |
| `fix/` | Corrección de bug o error |
| `docs/` | Cambios en documentación |
| `refactor/` | Mejora de código sin cambiar funcionalidad |
| `test/` | Agregar o mejorar tests |
| `chore/` | Mantenimiento, configuración, dependencias |

### 4. Desarrollar y Validar

```bash
# En el host: no ejecutar Ansible
./scripts/check_host.sh

# Dentro de ansible-control: validar el catálogo y calificar rutas/contratos
python3 ansible/scripts/validate_cis_catalog.py --root ansible --catalog cis/catalog/pinned-corpora.yml
python3 ansible/scripts/qualify_cis_profile.py --root ansible --routing-only \
  --catalog cis/catalog/pinned-corpora.yml --ledger cis/catalog/control-ledger.yml

# Probar un control: check, dos aplicaciones reales y verificación funcional
ansible-playbook -i inventories/local/hosts.yml PLAYBOOK \
  --limit HOST --tags TAG --check --diff
ansible-playbook -i inventories/local/hosts.yml PLAYBOOK --limit HOST --tags TAG
ansible-playbook -i inventories/local/hosts.yml PLAYBOOK --limit HOST --tags TAG
```

### 5. Commit y Push

```bash
# Commit con mensaje convencional
git add .
git commit -m "feat(section5): add CIS 5.1.4 SSH access control

- Implement AllowUsers/AllowGroups configuration
- Add validation with sshd -t
- Add tags: cis_5.1.4, NIST800-53R5_AC-3
- Add variable cis_ssh_config.access_control for flexibility

Closes #123"

git push origin feat/cis-3.2-network-hardening
```

**Estándar de mensajes de commit:**
```
<tipo>(<sección>): <descripción corta>

<descripción detallada en párrafos>

- Cambio específico 1
- Cambio específico 2

Closes #<número-de-issue>
```

### 6. Crear Pull Request

1. Ve a tu fork en GitHub
2. Haz clic en "New Pull Request"
3. Selecciona la rama base correcta (`main` o `develop`)
4. Completa la plantilla de PR con:
   - Descripción de los cambios
   - Issue relacionado
   - Checklist de validación
   - Screenshots o logs si aplica

---

## 📐 Estándares de Código Ansible

### Naming de Tasks

```yaml
# ✅ CORRECTO:
- name: "CIS 5.1.4 | Remediation | Ensure sshd access is configured"
  ansible.builtin.lineinfile:
    ...

# ❌ INCORRECTO:
- name: Configure SSH
  lineinfile:
    ...
```

**Formato:** `"CIS X.Y.Z | <Auditoría/Remediation> | Descripción clara"`

### Tags Obligatorios

Cada task debe incluir:
```yaml
tags:
  - cis_secX              # Sección principal (cis_sec1, cis_sec2, etc.)
  - cis_X.Y.Z            # Control específico (cis_5.1.4)
  - NIST800-53R5_*       # Mapeo NIST (si aplica)
  - level1               # o level2 según CIS
  - <componente>         # ssh, firewall, pam, etc.
```

### Variables Granulares

```yaml
# ✅ CORRECTO:
# defaults/main.yml
cis_5_1_4_ssh_access_control: true  # snake_case, prefijo cis_

# En task:
when: cis_5_1_4_ssh_access_control | default(true)

# ❌ INCORRECTO:
cis_ssh_config.AccessControl_bol: yes  # mixed_case, sufijo inconsistente
```

### Idempotencia

```yaml
# ✅ Usar condicionales basados en facts:
- name: "CIS X.X.X | Remediation | Ensure package is installed"
  ansible.builtin.apt:
    name: some-package
    state: present
  when: "'some-package' not in ansible_facts.packages"
  changed_when: false

# ✅ Usar backup en configs críticas:
- name: "CIS X.X.X | Remediation | Configure sshd_config"
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    ...
    backup: yes
    validate: 'sshd -t -f %s'
```

### Manejo de Errores

```yaml
# Tratar explícitamente la aplicabilidad; no ocultar fallos de hardening:
- name: "CIS X.X.X | Remediation | Configure service"
  ansible.builtin.systemd_service:
    name: some-service
    state: restarted
  when: "'some-service.service' in ansible_facts.services"
```

---

## 🧪 Testing Requerido

Antes de enviar un PR, asegúrate de:

### 1. Validación de Sintaxis

```bash
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --syntax-check
```

### 2. Ansible Lint

```bash
ansible-lint playbooks/hardening/cis_ubuntu_2404.yml
# Debe pasar sin errores críticos
```

### 3. Idempotencia

```bash
# Vista previa
ansible-playbook -i inventories/local/hosts.yml playbooks/hardening/cis_ubuntu_2404.yml --limit ubuntu24 --check --diff --tags cis_X.Y

# Primera aplicación y segunda aplicación real
ansible-playbook -i inventories/local/hosts.yml playbooks/hardening/cis_ubuntu_2404.yml --limit ubuntu24 --tags cis_X.Y
ansible-playbook -i inventories/local/hosts.yml playbooks/hardening/cis_ubuntu_2404.yml --limit ubuntu24 --tags cis_X.Y
```

### 4. Prueba en Laboratorio

```bash
# Levantar lab si es necesario
make up

# Ejecutar contra VM de prueba
ansible-playbook -i inventories/local/hosts.yml playbooks/hardening/cis_ubuntu_2404.yml --limit ubuntu24 --tags cis_X.Y

# Verificar resultado manual
vagrant ssh ubuntu24 -c "sshd -T | grep permitrootlogin"
```

---

## 📚 Documentación

### Actualizar README.md

Si agregas:
- Nuevos controles CIS
- Nuevas variables
- Nuevos tags

Actualiza las secciones correspondientes en `README.md`.

### Documentar Variables

En `defaults/main.yml`, cada variable debe tener un comentario:

```yaml
# =================================================================
# CIS 5.1.4 - SSH Access Control
# =================================================================
# Habilitar configuración de AllowUsers/AllowGroups en sshd_config
cis_5_1_4_ssh_access_control: true

# Tipo de lista de acceso: 'AllowUsers' o 'AllowGroups'
cis_ssh_access_control_type: "AllowUsers"

# Usuarios o grupos permitidos (separados por espacio)
cis_ssh_allowed_users_groups: "admin deployer"
```

### Comentarios en Código

```yaml
# =============================================================================
# CIS 5.1.4 | Ensure sshd access is configured
# Referencia: CIS Ubuntu 24.04 LTS Benchmark v1.0.0, Section 5.1.4
# Nivel: Level 1
# NIST: AC-3, AC-6
# =============================================================================
```

---

## 🚫 Qué No Hacer

- ❌ No commitar archivos generados (`*.backup`, `*.retry`, reportes JSON)
- ❌ No modificar código de otras secciones sin coordinación
- ❌ No usar `shell`/`command` si existe un módulo nativo de Ansible
- ❌ No hardcodear valores que deben ser variables
- ❌ No omitir tags o comentarios de referencia CIS
- ❌ No romper idempotencia (tasks que siempre reportan `changed`)

---

## 🎁 Reconocimientos

Los contribuyentes serán reconocidos en:
- El archivo `README.md` en la sección de autores
- Los release notes en `CHANGELOG.md`
- El historial de commits de GitHub

---

## ❓ Preguntas Frecuentes

**P: ¿Puedo contribuir sin experiencia en Ansible?**  
R: ¡Sí! Comienza con issues etiquetados como `good first issue` o `docs`. Revisa los estándares de código y no dudes en preguntar en el PR.

**P: ¿Cómo sé si mi cambio cumple con el CIS Benchmark?**  
R: Consulta los archivos `.md` de documentación CIS en cada sección (`CIS_Benchmark_V1_Seccion_*.md`) y asegúrate de que tu implementación siga exactamente los controles descritos.

**P: ¿Puedo agregar soporte para otra distribución?**  
R: ¡Sí! Usa condicionales basados en `ansible_facts.distribution` y documenta claramente las diferencias. Abre un issue primero para discutir la arquitectura.

**P: ¿Cómo reporto un falso positivo en la auditoría?**  
R: Crea un issue con: el control CIS afectado, el output del playbook, el estado esperado vs real, y tu entorno (OS, versión Ansible).

---

## 📞 Contacto

- 💬 [GitHub Discussions](https://github.com/tu-usuario/ansible-cis-benchmark/discussions)
- 🐛 [GitHub Issues](https://github.com/tu-usuario/ansible-cis-benchmark/issues)
- 📧 tu-email@ejemplo.com

---

> **Nota**: Este proyecto sigue el [Semantic Versioning](https://semver.org/). Los cambios que rompan compatibilidad requerirán un incremento de versión mayor.
