# Laboratorio (lab)

Cómo levantar y usar el laboratorio Vagrant para probar los playbooks sin tocar
producción.

## Topología

Tres VMs VirtualBox conectadas por red privada (`private_network`, host-only):

| VM | Box (versión) | IP | Rol |
|---|---|---|---|
| `ansible-control` | `bento/ubuntu-24.04` `202510.26.0` | `192.168.56.10` | Nodo de control (Ansible) |
| `debian12` | `bento/debian-12` `202510.26.0` | `192.168.56.11` | Objetivo Debian |
| `ubuntu24` | `bento/ubuntu-24.04` `202510.26.0` | `192.168.56.12` | Objetivo Ubuntu |

- El repositorio completo se monta **solo** en `ansible-control`, en
  `/home/vagrant/ansible` (el proyecto Ansible está en su subdirectorio
  `ansible/`).
- Las VMs se comunican entre sí por la red `192.168.56.0/24`. No hay `forwarded_port`
  explícito; el acceso interactivo es por `vagrant ssh` (que auto-asigna puertos
  SSH locales 2222/2200/2201 para control/debian/ubuntu).
- No hay carpeta `/vagrant` sincronizada en los nodos objetivo.

## Requisitos

- Vagrant + VirtualBox en el host.
- El `Makefile` usa `vagrant.exe` y los scripts de provisión asumen WSL, por lo
  que el flujo del host está pensado para **Windows + WSL**.

## Puesta en marcha inicial

```bash
make check-host     # verifica prerequisitos del host
make up             # genera claves SSH (setup-ssh) y levanta las VMs
make provision-lab  # crea usuario ansible + instala toolchain de Ansible
make status         # confirmá que las 3 VMs están running
```

`make provision-lab` ejecuta en orden:

1. `lab/vagrant/scripts/create-ansible-user.sh` — crea el usuario `ansible` en
   las 3 VMs, instala `authorized_keys` y un drop-in sudoers
   (`ansible ALL=(ALL) NOPASSWD:ALL`). La **clave privada** se copia **solo** a
   `/home/vagrant/.ssh/id_rsa` de `ansible-control`.
2. `lab/vagrant/scripts/setup-postprovision.sh` — chequeo de `os-release`.
3. `lab/vagrant/scripts/install-ansible.sh` — paquetes pinned, venv
   `/home/vagrant/.venvs/ansible-cis`, `pip-compile --generate-hashes` y
   `ansible-galaxy install`.

## Trabajo diario

```bash
make start           # encender VMs sin provisionar
make status          # estado
make ansible-control # entrar al nodo de control
```

Dentro de `ansible-control`:

```bash
cd /home/vagrant/ansible/ansible
export PATH=/home/vagrant/.venvs/ansible-cis/bin:$PATH
ansible --version
ansible-inventory --graph
ansible ubuntu24 --limit ubuntu24 -m ansible.builtin.ping
```

## Usuarios y claves

- **`vagrant`**: controla la VM y ejecuta Ansible en `ansible-control`.
- **`ansible`**: identidad remota no privilegiada que Ansible usa para conectarse
  a los objetivos (por `ansible.cfg` + inventario). Eleva con `sudo`
  (`become`), sin password en el lab.
- Claves ed25519 en `lab/vagrant/ssh/` (generadas por `setup-ssh.sh`; están en
  `.gitignore`).

## Acceso SSH directo (sin `make`)

Si preferís SSH en vez de `vagrant ssh`, el patrón (desde WSL, ajustá la ruta de
la clave y el puerto):

```bash
ssh -i "lab/vagrant/.vagrant/machines/ansible-control/virtualbox/private_key" \
    -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o BatchMode=yes \
    -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa \
    vagrant@127.0.0.1
```

Los puertos `2222`/`2200`/`2201` son los que Vagrant auto-asigna al SSH de
`ansible-control`/`debian12`/`ubuntu24`. Para conocer el puerto exacto:

```bash
cd lab/vagrant && vagrant ssh-config <vm>
```

## Inventario del laboratorio

El inventario local está en `ansible/inventories/local/`:

- `hosts.yml`: `ubuntu24` (192.168.56.12) y `debian12` (192.168.56.11), con
  grupos `ubuntu → ubuntu_2404` y `debian → debian_12`.
- `group_vars/all.yml`: `cis_execution_environment: lab`.
- `all.vars`: `ansible_user: ansible`, clave `~/.ssh/id_rsa`, `become` sudo, y
  excepción SSH (`StrictHostKeyChecking=no`) **solo para el lab**.

La verificación de host keys está activa globalmente en `ansible.cfg`; la
excepción SSH existe únicamente en el inventario local efímero y **no debe
copiarse a producción**.

## Notas y gotchas

- Un `ansible-control` recién arrancado puede colgar el SSH en el "banner
  exchange"; `make start` + reintentar, o `vagrant reload ansible-control`, lo
  resuelve.
- Para reconstruir el lab desde cero: `make destroy` y repetir la puesta en
  marcha inicial.
- Los scripts se invocan con su intérprete; no fuerces el bit ejecutable sobre
  archivos del repositorio (el montaje usa `fmode=644` a propósito).
