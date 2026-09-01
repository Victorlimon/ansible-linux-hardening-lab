# Documentación técnica

Esta documentación describe el árbol actual del proyecto. Ubuntu 24.04 es la
plataforma liberada y Debian 12 permanece en estado canario. No existe todavía
generación consolidada de evidencia, Molecule ni una prueba que permita afirmar
cumplimiento CIS completo.

## Componentes reales

```text
ansible/
├── ansible.cfg
├── requirements.yml
├── playbooks/
│   ├── cis_hardening.yml                 # compatibilidad Ubuntu
│   ├── cis_ubuntu_2404_hardening.yml     # canónico Ubuntu
│   ├── cis_debian_12_preflight.yml
│   ├── cis_debian_12_audit.yml
│   └── cis_debian_12_hardening.yml
├── inventories/
│   ├── local/
│   │   ├── hosts.yml
│   │   └── group_vars/{all,ubuntu_2404,debian_12}.yml
│   ├── staging/hosts.yml       # vacío
│   └── production/hosts.yml    # vacío
└── roles/
    ├── cis_platform_preflight/
    ├── cis_ubuntu_2404/
    ├── cis_debian_12/
    └── cis_benchmark/                    # implementación Ubuntu histórica
```

`cis_hardening.yml` importa el entry point canónico Ubuntu. El adaptador
`cis_ubuntu_2404` compone temporalmente `cis_benchmark`. Debian utiliza un
adaptador y plays separados con gates canario. El catálogo interno del preflight
es la única fuente de identidad, arquitectura y estado de plataforma.

## Inventario y usuarios

`ansible.cfg` apunta por defecto a `inventories/local/hosts.yml`. Los hosts son
`ubuntu24` (`192.168.56.12`) y `debian12` (`192.168.56.11`). Cada entry point
selecciona exclusivamente su grupo de plataforma.

- Usuario de control de Vagrant: `vagrant`.
- Usuario que debe lanzar Ansible en `ansible-control`: `ansible`.
- Usuario SSH remoto configurado por inventario: `ansible`.
- Elevación remota: `sudo`, `become_user=root`, sin solicitud de contraseña en
  el laboratorio.

El script `create-ansible-user.sh` crea `ansible` en las VMs, instala su clave y
solo copia la clave privada a `/home/ansible/.ssh/id_rsa` en `ansible-control`.
El repositorio Ansible se monta en `/home/vagrant/ansible`.
`ansible.cfg` mantiene `host_key_checking` activo. La excepción
`StrictHostKeyChecking=no` existe únicamente en el inventario local efímero;
producción debe gestionar `known_hosts` y verificar la huella de cada nodo.

## Dependencias

El mínimo declarado por el rol es Ansible Core 2.16. Verifique la versión en el
nodo de control antes de operar. Las colecciones requeridas son las fijadas en
`ansible/requirements.yml`:

```bash
cd /home/vagrant/ansible
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
sudo -iu ansible
cd /home/vagrant/ansible
ansible-inventory --graph
ansible ubuntu24 --limit ubuntu24 -m ansible.builtin.ping
ansible-playbook playbooks/cis_hardening.yml --syntax-check
ansible-playbook playbooks/cis_hardening.yml --list-hosts --limit ubuntu24
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
ansible-playbook playbooks/cis_hardening.yml --limit ubuntu24 --list-tags
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec6 --list-tasks
```

Ejecución por sección y por control:

```bash
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec3 --check --diff
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_3_3_1 --check --diff
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
ansible-playbook playbooks/cis_hardening.yml --syntax-check
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec5 --check --diff
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec5
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec5
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
