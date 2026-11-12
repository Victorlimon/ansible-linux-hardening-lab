# Hardening CIS con Ansible — Ubuntu 24.04 y Debian 12

Automatización de hardening inspirada en CIS para servidores Linux, con un ciclo
de vida completo: **auditoría** (observar), **remediación** (aplicar) y
**verificación** (validar), separadas por plataforma y con gates de seguridad.

La autoridad normativa de soporte, evidencia y límites de afirmación es
[docs/SUPPORT.md](docs/SUPPORT.md). Si otro documento la contradice, vale
SUPPORT.md.

## Estado de soporte (resumen)

| Plataforma | Arquitectura | Estado |
|---|---|---|
| Ubuntu 24.04 Server | `x86_64` | Lanzado para el subset calificado |
| Debian 12 Server | `x86_64` | Canary (remediación requiere doble gate) |

El detalle exacto del alcance, las dimensiones de evidencia y las exclusiones
está en [docs/SUPPORT.md](docs/SUPPORT.md). "Lanzado" nunca significa "todo el
perfil" ni certificación de terceros.

## Qué implementa este proyecto

- **Puntos de entrada canónicos** por plataforma y modo en
  `ansible/playbooks/`:

  | Modo | Ubuntu 24.04 | Debian 12 |
  |---|---|---|
  | Auditoría | `audit/cis_ubuntu_2404.yml` | `audit/cis_debian_12.yml` |
  | Remediación | `hardening/cis_ubuntu_2404.yml` | `hardening/cis_debian_12.yml` |
  | Verificación | `verify/cis_ubuntu_2404.yml` | `verify/cis_debian_12.yml` |
  | Preflight | (incluido en cada play) | `cis_debian_12_preflight.yml` |

- **Adaptadores**: `cis_ubuntu_2404` y `cis_debian_12`.
- **Biblioteca de mecanismos compartida**: `cis_linux_common`.
- **Preflight**: valida distribución, release, arquitectura y estado de release
  antes de tocar el objetivo.
- **Spine de metadatos body-free** (sin texto licenciado del benchmark) en
  `ansible/cis/` (catálogo, ledger, semantic-review y esquemas de calificación).

## Requisitos

- **Ansible Core 2.21.2** en el nodo de control para el laboratorio y la
  implantación prevista. Verificá el ejecutable efectivo con
  `ansible-playbook --version`.
- Python 3 en los objetivos remotos.
- Acceso SSH y `sudo` sin contraseña para el usuario remoto `ansible` (laboratorio).
- Colecciones fijadas en `ansible/requirements.yml`:
  `ansible.posix 1.5.4` y `community.general 8.6.0`.

Instalación de colecciones desde `ansible/`:

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

## Documentación

| Documento | Contenido |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Manual de uso: modos, tags reales, gates y variables |
| [docs/ROLLOUT.md](docs/ROLLOUT.md) | Procedimiento de hardening por secciones gated |
| [docs/LAB.md](docs/LAB.md) | Cómo se trabaja en el laboratorio Vagrant |
| [docs/WAZUH.md](docs/WAZUH.md) | Integración con Wazuh y almacenamiento de logs |
| [docs/PREPRODUCCION_WAZUH.md](docs/PREPRODUCCION_WAZUH.md) | Selección desde Wazuh y puerta de entrada a preproducción |
| [docs/INTEGRACION_WAZUH_ANSIBLE.md](docs/INTEGRACION_WAZUH_ANSIBLE.md) | Evidencia comprobada en el laboratorio Wazuh 4.12.0 |
| [docs/IMPROVING.md](docs/IMPROVING.md) | Cómo mejorar: calificación, mecanismos y nuevos controles |
| [docs/SUPPORT.md](docs/SUPPORT.md) | Autoridad normativa de soporte y evidencia |

## Ejecución segura rápida

```bash
ansible-playbook ansible/playbooks/hardening/cis_ubuntu_2404.yml --syntax-check
ansible-playbook ansible/playbooks/hardening/cis_ubuntu_2404.yml --list-tags --limit ubuntu24
ansible-playbook ansible/playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags sysctl --check --diff \
  -e cis_ubuntu_2404_remediation_enabled=true
```

Antes de cualquier remediación real, leé [docs/ROLLOUT.md](docs/ROLLOUT.md).
