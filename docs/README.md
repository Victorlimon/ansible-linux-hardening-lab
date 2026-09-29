# Documentación técnica

Esta documentación describe el árbol actual del proyecto. For normative status,
evidence dimensions, and exclusions, use the sole authority:
[Support and evidence policy](SUPPORT.md). Ubuntu 24.04 x86_64 is released for
the qualified subset and Debian 12 x86_64 remains canary-only.

## Componentes reales

```text
ansible/
├── ansible.cfg
├── requirements.yml
├── playbooks/
│   ├── cis_debian_12_preflight.yml
│   ├── audit/cis_ubuntu_2404.yml
│   ├── audit/cis_debian_12.yml
│   ├── hardening/cis_ubuntu_2404.yml
│   ├── hardening/cis_debian_12.yml
│   ├── verify/cis_ubuntu_2404.yml
│   └── verify/cis_debian_12.yml
├── inventories/
│   ├── local/
│   │   ├── hosts.yml
│   │   └── group_vars/{all,ubuntu_2404,debian_12}.yml
│   ├── staging/hosts.yml       # vacío
│   └── production/hosts.yml    # vacío
└── roles/
    ├── cis_platform_preflight/
    ├── cis_linux_common/                 # mecanismos equivalentes probados
    ├── cis_ubuntu_2404/
    ├── cis_debian_12/
    └── cis_benchmark/                    # biblioteca interna/compatibilidad
```

Los puntos de entrada canónicos por plataforma viven bajo
`playbooks/{audit,hardening,verify}/cis_<plataforma>.yml`. El adaptador
`cis_ubuntu_2404` orquesta setup y siete entradas de sección acotadas de la
biblioteca histórica, sin importar su `tasks/main.yml`. Debian utiliza
interfaces canónicas separadas para auditoría, remediación y verificación. El
catálogo interno del preflight aplica identidad y arquitectura en runtime; it is
not a public support authority.

`cis_linux_common` contiene verticales probadas para `/etc/passwd`,
`/etc/crontab`, estado IPv6 y TCP SYN cookies. Los adaptadores conservan IDs,
benchmark, habilitación y gates; el rol común solo recibe contratos técnicos
parametrizados.

## Inventario y usuarios

`ansible.cfg` apunta por defecto a `inventories/local/hosts.yml`. Los hosts son
`ubuntu24` (`192.168.56.12`) y `debian12` (`192.168.56.11`). Cada entry point
selecciona exclusivamente su grupo de plataforma.

- Usuario de control de Vagrant: `vagrant`.
- Usuario que debe lanzar Ansible en `ansible-control`: `vagrant`.
- Usuario SSH remoto configurado por inventario: `ansible`.
- Elevación remota: `sudo`, `become_user=root`, sin solicitud de contraseña en
  el laboratorio.

El script `create-ansible-user.sh` crea `ansible` en las VMs, instala su clave y
solo copia la clave privada a `/home/vagrant/.ssh/id_rsa` en
`ansible-control`. El repositorio completo se monta en
`/home/vagrant/ansible`; el proyecto Ansible está en su subdirectorio
`ansible/`.
`ansible.cfg` mantiene `host_key_checking` activo. La excepción
`StrictHostKeyChecking=no` existe únicamente en el inventario local efímero;
producción debe gestionar `known_hosts` y verificar la huella de cada nodo.

## Dependencias

El mínimo declarado por el rol es Ansible Core 2.16. Verifique la versión en el
nodo de control antes de operar. Las colecciones requeridas son las fijadas en
`ansible/requirements.yml`:

```bash
cd /home/vagrant/ansible/ansible
export PATH=/home/vagrant/.venvs/ansible-cis/bin:$PATH
ansible --version
ansible-galaxy collection install -r requirements.yml
```

`ansible.posix` aporta, entre otros, `sysctl` y `mount`;
`community.general` aporta `ufw` y `modprobe`. Las versiones exactas son
`ansible.posix 1.5.4` y `community.general 8.6.0`.

## Flujo de ejecución

En el host, desde la raíz del proyecto:

```bash
make up
make provision-lab       # una vez o al reconstruir las VMs
make status
make ansible-control
```

En el nodo de control:

```bash
cd /home/vagrant/ansible/ansible
export PATH=/home/vagrant/.venvs/ansible-cis/bin:$PATH
ansible-inventory --graph
ansible ubuntu24 --limit ubuntu24 -m ansible.builtin.ping
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --syntax-check
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --list-hosts --limit ubuntu24
```

El límite explícito es una barrera operacional y debe conservarse incluso
cuando solo exista una VM Ubuntu en el laboratorio.

## Tags

Los tags de sección soportados por el entry point son:

| Sección | Tags de entrada |
|---|---|
| 1 | `cis_1`, `cis_sec1` |
| 2 | `cis_2`, `cis_sec2` |
| 3 | `cis_3`, `cis_sec3` |
| 4 | `cis_4`, `cis_sec4` |
| 5 | `cis_5`, `cis_sec5` |
| 6 | `cis_6`, `cis_sec6` |
| 7 | `cis_7`, `cis_sec7`, `system_maintenance` |

La notación histórica de tags inferiores mezcla puntos y guiones bajos. No
derive un tag desde el número CIS. Descúbralo y previsualice las tareas:

```bash
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --limit ubuntu24 --list-tags
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags cis_sec6 --list-tasks
```

Ejecución por sección y por control:

```bash
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags cis_sec3 --check --diff \
  -e cis_ubuntu_2404_remediation_enabled=true
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags cis_3_3_1 --check --diff \
  -e cis_ubuntu_2404_remediation_enabled=true
```

Los tags `always` hacen que facts y validaciones necesarias puedan ejecutarse
aunque se seleccione un control.

## Modelo de seguridad de defaults

Los defaults del rol tienen la menor precedencia y deben sobreescribirse desde
el inventario aprobado. "Activo" significa que la tarea se considera en una
ejecución sin tags; no significa que el control sea aplicable, que siempre
remedie ni que haya pasado una auditoría externa.

- Secciones 1, 2, 3 y 5: activas con decisiones disruptivas desactivadas.
- Sección 4: desactivada. UFW requiere una fuente SSH explícita no vacía antes
  de aplicar default deny de entrada, salida y tráfico routed.
- Sección 5.3 PAM: desactivada aunque la sección 5 esté activa.
- Sección 6: desactivada. auditd y logging se habilitan al optar por la sección;
  AIDE sigue necesitando opt-in separado para instalación e inicialización.
- Sección 7 y sus dos subsecciones: desactivadas.
- Controles `Manual` o `Audit`: pueden consultar y mostrar hallazgos sin
  remediarlos. No producen un informe consolidado.

Consulte [CIS_CONTROL_MATRIX.md](CIS_CONTROL_MATRIX.md) para el detalle por
sección y [PRODUCTION_UBUNTU24.md](PRODUCTION_UBUNTU24.md) para las variables y
salvaguardas operativas.

El rol es una base de hardening y no debe etiquetarse como perfil CIS Level 1
completo hasta cerrar los bloqueos de la matriz, ejecutar pruebas post-reboot y
adjuntar una evaluación independiente por control.

## Pruebas e idempotencia

Secuencia mínima por sección:

```bash
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --syntax-check
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags cis_sec5 --check --diff \
  -e cis_ubuntu_2404_remediation_enabled=true
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags cis_sec5 \
  -e cis_ubuntu_2404_remediation_enabled=true
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags cis_sec5 \
  -e cis_ubuntu_2404_remediation_enabled=true
```

En la segunda aplicación real, investigue cualquier `changed` recurrente. Una
segunda ejecución con `--check` es útil, pero no sustituye la segunda aplicación
real ni las comprobaciones del servicio. Check mode no es transaccional, no
simula todos los módulos y las tareas con datos registrados pueden comportarse
de modo distinto. `--diff` puede revelar configuración sensible: proteja logs y
salidas de CI.

Compruebe fuera de la sesión SSH que va a conservar:

```bash
sudo sshd -t
sudo sshd -T | grep -E 'permitrootlogin|usepam|maxauthtries'
sudo ufw status verbose
sudo auditctl -s
systemctl is-active ssh auditd
```

## Recuperación

No hay rollback automático. Antes de cambios críticos, tome snapshot, asegure
consola y mantenga una segunda sesión root/sudo. La recuperación puede requerir
restaurar archivos creados por módulos con `backup`, corregir UFW desde consola,
rehabilitar paquetes/servicios o restaurar el snapshot. No asuma que todas las
tareas generan backup.
