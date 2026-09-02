# Hardening CIS con Ansible para Ubuntu 24.04 y Debian 12

Automatización incremental de hardening inspirada en CIS. **Ubuntu 24.04** es la
implementación liberada; **Debian 12** dispone de auditoría y controles canario
con gates explícitos. El proyecto no declara cobertura CIS completa ni genera
por sí solo una certificación de cumplimiento.

## Alcance real

- Ubuntu canónico: `ansible/playbooks/cis_ubuntu_2404_hardening.yml`.
- Compatibilidad Ubuntu: `ansible/playbooks/cis_hardening.yml`.
- Debian: `cis_debian_12_preflight.yml`, `cis_debian_12_audit.yml` y
  `cis_debian_12_hardening.yml`.
- Adaptadores: `cis_ubuntu_2404` y `cis_debian_12`.
- Implementación Ubuntu histórica: `ansible/roles/cis_benchmark/`.
- Destino del play: grupo de inventario `ubuntu`.
- Validación en tiempo de ejecución: distribución `Ubuntu`, versión `24.04`.
- Perfil: servidor. GDM y otros controles de estación de trabajo no se activan
  por defecto.
- Inventario utilizable actualmente: `ansible/inventories/local/hosts.yml`.
  Los inventarios `staging` y `production` están vacíos y son plantillas, no
  entornos listos para ejecutar.
- Los plays Ubuntu y Debian están aislados por grupos de versión exacta y nunca
  comparten un play de remediación.

La existencia de archivos para las secciones 1 a 7 no significa que todos sus
controles estén habilitados, automatizados o validados. Consulte la
[matriz de controles](docs/CIS_CONTROL_MATRIX.md).

## Requisitos

- Ansible Core 2.16 o posterior en el nodo de control.
- Python 3 en Ubuntu 24.04 remoto.
- Acceso SSH y `sudo` sin contraseña para el usuario remoto `ansible` en el
  laboratorio.
- Vagrant y VirtualBox para el laboratorio local. El `Makefile` usa
  `vagrant.exe`, por lo que ese flujo está orientado al host Windows del
  proyecto.
- Colecciones reproducibles fijadas en `ansible/requirements.yml`:
  `ansible.posix 1.5.4` y `community.general 8.6.0`.

Instale las colecciones desde el directorio `ansible/`:

```bash
ansible-galaxy collection install -r requirements.yml
```

`ansible.builtin` forma parte de Ansible Core y no se instala como colección
separada.

## Flujo obligatorio del laboratorio

Desde la raíz del repositorio en el host:

```bash
make up
make provision-lab       # necesario en la creación inicial del laboratorio
make status
make ansible-control
```

No continúe si `make status` no muestra `ansible-control` y el objetivo elegido en
ejecución. `make ansible-control` entra como usuario de Vagrant, `vagrant`, que
ejecuta Ansible con la toolchain aislada. La identidad remota `ansible` y su
clave fueron preparadas por `make provision-lab`:

```bash
cd /home/vagrant/ansible/ansible
export PATH=/home/vagrant/.venvs/ansible-cis/bin:$PATH
ansible --version
ansible-galaxy collection install -r requirements.yml
ansible-inventory --graph
ansible ubuntu24 --limit ubuntu24 -m ansible.builtin.ping
```

La separación es intencionada: `vagrant` controla la VM y ejecuta Ansible; la
identidad remota no privilegiada `ansible` se conecta a los objetivos. La configuración
`ansible/ansible.cfg` selecciona el inventario local, el rol y `become`.
La verificación de host keys está activa globalmente; solo el inventario local
efímero contiene una excepción SSH y esta no debe copiarse a producción.

## Ejecución segura

Mantenga `--limit ubuntu24` o `--limit debian12` incluso con el inventario local y ejecute primero
una sección. El modo check es una simulación y algunas tareas de consulta se
ejecutan expresamente con `check_mode: false`; revise siempre la salida.

```bash
# Validaciones sin cambios
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml --syntax-check
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml --list-hosts --limit ubuntu24
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml --list-tags --limit ubuntu24

# Vista previa de una sección
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml \
  --limit ubuntu24 --tags cis_sec1 --check --diff

# Aplicación de la sección y segunda aplicación real para idempotencia
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --tags cis_sec1
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml --limit ubuntu24 --tags cis_sec1
ansible-playbook playbooks/cis_ubuntu_2404_hardening.yml \
  --limit ubuntu24 --tags cis_sec1 --check --diff
```

Las etiquetas estables de sección son `cis_sec1` a `cis_sec7` (también existen
`cis_1` a `cis_7`). Los tags de subsección y control no tienen una notación
uniforme histórica: por ejemplo, SSH usa `cis_5.1.4`, UFW usa `cis_4_2_6` y
auditd usa `cis_6_2_3_1`. Antes de ejecutar un control, obtenga el nombre real:

```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec5 --list-tasks
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags 'cis_5.1.4' --check --diff
```

## Valores seguros y opt-in

Los defaults se dividen en
`ansible/roles/cis_benchmark/defaults/main/00-global.yml` hasta
`07-system-maintenance.yml`.

- Activas por defecto: secciones 1, 2, 3 y 5, con excepciones internas.
- Desactivadas por defecto: firewall (4), logging/auditd/AIDE (6) y mantenimiento
  del sistema (7).
- También son opt-in: PAM, GDM, retiradas de servicios y clientes, módulos de
  red potencialmente usados, contraseña GRUB, AppArmor global en enforcing,
  creación/inicialización de AIDE y varias remediaciones de cuentas.
- Los controles de particiones no crean ni migran particiones. Informan si no
  existe un montaje separado y solo añaden opciones al montaje existente.
- `nftables` e `iptables` aparecen como selecciones, pero sus rutas detienen la
  ejecución porque no están implementadas de forma segura. Para Ubuntu 24.04,
  use UFW.

Antes de activar una sección o control opt-in, defina el cambio en variables de
inventario, sométalo a `--check --diff`, mantenga consola/snapshot y apruebe una
ventana de mantenimiento. No active toda la cobertura con variables globales
sin revisar dependencias y riesgo de bloqueo.

## Variables críticas

- UFW: `cis_section4_firewall`, `cis_firewall_engine`,
  `cis_ufw_ssh_port`, `cis_ufw_ssh_allowed_sources`,
  `cis_ufw_allowed_in_rules`, `cis_ufw_allowed_out_ports`.
- SSH: `cis_section5_1_ssh_server`, `cis_ssh_remote_user` y
  `cis_ssh_config`, en especial `use_allow_list`, `access_control_type` y
  `allowed_users_groups`.
- PAM: `cis_section5_3_pam`, límites `cis_pam_faillock_*` y política
  `cis_pam_pwquality_*`.
- auditd: `cis_section6_logging_audit`, `section6_logging` y
  `cis_audit_allow_disruptive_actions`.
- AIDE: `section6_logging['6_3_1_aide_installed'].enabled` y
  `section6_logging['6_3_1_aide_init'].enabled`.
- Particiones: `cis_1_1_2_*_partition` habilita la comprobación de cada punto y
  `cis_1_1_2_*_{nodev,nosuid,noexec}` controla opciones de montaje.

El inventario local habilita UFW solo para el grupo `ubuntu` y permite SSH desde
`192.168.56.0/24`, además de HTTP/HTTPS. Es una política de laboratorio, no una
política de producción.

## Documentación

- [Guía técnica](docs/README.md)
- [Operación en Ubuntu 24.04](docs/PRODUCTION_UBUNTU24.md)
- [Matriz de controles 1-7](docs/CIS_CONTROL_MATRIX.md)
- [Arquitectura escalable](docs/SCALABILITY.md)
- [Baseline DevSecOps](docs/DEVSECOPS.md)
- [Matriz Debian 12](docs/CIS_DEBIAN12_CONTROL_MATRIX.md)
- [Índice](docs/INDEX.md)

## Recuperación

Mantenga abierta una consola de Vagrant o hipervisor y tome un snapshot antes
de UFW, SSH, PAM, auditd, AIDE o montajes. Si se pierde SSH, recupere por
consola, restaure la allowlist/configuración y valide con `sshd -t`,
`ufw status verbose` y una nueva conexión antes de cerrar la sesión de respaldo.
La guía de producción contiene el procedimiento completo.
