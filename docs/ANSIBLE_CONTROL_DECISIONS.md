# Inventario de decisiones para el hardening completo de ansible-control

Este documento reúne las decisiones que deben tomarse **antes** de aplicar el
perfil CIS completo (SSH, PAM, sudo y firewall) sobre el nodo de control. Esas
familias quedaron fuera del perfil actual
([ANSIBLE_CONTROL_HARDENING.md](ANSIBLE_CONTROL_HARDENING.md)) precisamente
porque dependen de estos datos. Ningún valor se debe suponer: si una fila queda
vacía, el control asociado permanece desactivado.

- **Columna "Laboratorio":** valor observado en el repositorio o en el
  laboratorio Vagrant. Sirve como referencia y para las pruebas, no como valor
  de producción.
- **Columna "Producción":** la completa el responsable institucional. Los
  valores reales se guardan **fuera del repositorio**.

## 1. Por qué el nodo de control requiere este inventario

ansible-control concentra las credenciales SSH con privilegios sobre todos los
nodos. Un error de acceso lo deja inaccesible; un compromiso expone la
infraestructura completa. Cada decisión de este documento corresponde a uno de
esos dos riesgos: **perder el acceso** o **ampliar la superficie de ataque**.

## 2. Acceso administrativo (SSH)

| # | Decisión | Qué se rompe si es incorrecta | Laboratorio | Producción | Controles CIS Ubuntu 24.04 |
|---|---|---|---|---|---|
| A1 | Usuarios administradores que inician sesión por SSH | Un usuario fuera de la lista queda sin acceso | `vagrant` (sesión de administración) | | 5.1.4 |
| A2 | Grupo de administradores (alternativa a A1) | Igual que A1 | No definido | | 5.1.4 |
| A3 | Puerto SSH | Firewall y `sshd` deben coincidir | `22` | | 4.2.x / 4.3.x |
| A4 | Red de origen de administración (CIDR) | Sin ella, el firewall no abre SSH (`cis_ufw_ssh_allowed_sources: []`) | `192.168.56.0/24` (red privada Vagrant) | | 4.2.6 / 4.3.x |
| A5 | Método de autenticación | Desactivar contraseñas sin llaves instaladas bloquea el acceso | Llaves + contraseña de Vagrant | | 5.1.x |
| A6 | Algoritmos (Ciphers, MACs, KEX) aceptados por los clientes de administración | Clientes antiguos no podrán conectarse | Cliente OpenSSH reciente | | 5.1.6, 5.1.12, 5.1.15 |
| A7 | Texto del banner legal | Requisito legal institucional | Sin banner | | 1.6.x / 5.1.5 |
| A8 | Acceso de rescate fuera de banda | Sin él, un error de SSH o firewall es irrecuperable | Consola de VirtualBox | | Precondición |

## 3. Privilegios (sudo y PAM)

| # | Decisión | Qué se rompe si es incorrecta | Laboratorio | Producción | Controles CIS |
|---|---|---|---|---|---|
| P1 | ¿sudo exige contraseña? (quitar `NOPASSWD`) | Las ejecuciones desatendidas fallan si no hay contraseña disponible | `NOPASSWD` | | 5.2.4 |
| P2 | Tiempo de validez de sudo | Sesiones largas piden la contraseña de nuevo | Predeterminado | | 5.2.6 |
| P3 | Grupo para `su` (debe quedar vacío) | Ninguno si el grupo es correcto | `sugroup` (valor del rol) | | 5.2.7 |
| P4 | Intentos fallidos antes del bloqueo y tiempo de desbloqueo | Un administrador puede bloquearse a sí mismo | No aplicado | | 5.3.3.1.1–5.3.3.1.3 |
| P5 | ¿El bloqueo se aplica también a root? | Bloqueo de root sin acceso de rescate | No aplicado | | 5.3.3.1.3 |
| P6 | Política de contraseñas (longitud, complejidad, historial) | Ninguno inmediato; afecta el próximo cambio de contraseña | No aplicado | | 5.3.3.2.x / 5.3.3.3.x |
| P7 | Caducidad: ¿solo para cuentas nuevas o también para las existentes? | Una contraseña de administrador vencida bloquea sudo | No aplicado | | 5.4.1.x |
| P8 | Cuenta de servicio del gateway Wazuh | El gateway deja de ejecutar los playbooks | `ansible-wazuh` (pruebas de integración) | | 5.4.2.x |

## 4. Firewall: tráfico permitido

El perfil aplica política de **denegación por defecto** en entrada y salida.
Cada flujo necesario debe declararse explícitamente.

| # | Flujo | Dirección | Laboratorio | Producción | Motivo |
|---|---|---|---|---|---|
| F1 | SSH de administración | Entrada | `192.168.56.0/24` → TCP 22 | | Acceso administrativo |
| F2 | SSH hacia los nodos gestionados | Salida | → `192.168.56.11`, `192.168.56.12` TCP 22 | | Ejecución de Ansible |
| F3 | Agente Wazuh hacia el manager | Salida | → `192.168.56.1` TCP 1514 y 1515 | | Eventos, SCA y Active Response |
| F4 | DNS | Salida | Resolvedor de la VM | | Resolución de nombres |
| F5 | NTP | Salida | `systemd-timesyncd` predeterminado | | Sincronización de hora (2.3.x) |
| F6 | Repositorios de paquetes | Salida | Espejos de Ubuntu (HTTP/HTTPS) | | Actualizaciones |
| F7 | Motor de firewall | — | `ufw` (`cis_firewall`) | | Un solo motor (4.1.1) |

## 5. Credenciales y archivos sensibles

| # | Decisión | Laboratorio | Producción |
|---|---|---|---|
| C1 | Ruta y propietario de la llave SSH hacia los nodos | `~/.ssh/id_rsa` del usuario de ejecución | |
| C2 | ¿La llave tiene passphrase / se usa `ssh-agent`? | No | |
| C3 | ¿Se usa Ansible Vault? ¿Dónde se guarda su contraseña? | No | |
| C4 | Verificación de host keys (`known_hosts`) | Desactivada (excepción solo de laboratorio) | |
| C5 | Ruta del repositorio y modo del directorio | `/home/vagrant/ansible`, modo por definir (0700 / 0750) | |
| C6 | Ruta del entorno virtual de Ansible Core 2.21.2 | `/home/vagrant/.venvs/ansible-cis` | |
| C7 | Estado del gateway | `/var/lib/ansible-wazuh/` | |

## 6. Monitoreo del propio controlador

| # | Decisión | Laboratorio | Producción |
|---|---|---|---|
| M1 | Rutas vigiladas por Wazuh FIM (llaves, repositorio, inventarios, configuración del gateway) | Sin configurar | |
| M2 | Reglas de auditd sobre llaves y sudoers | Solo reglas CIS de nodos | |
| M3 | Retención de journal y de `ansible.log` | 1 GiB / 12 rotaciones semanales | |

## 7. Orden de aplicación propuesto

Cada etapa se aplica solo si sus filas están completas. Antes de cada etapa
se mantiene una sesión SSH abierta de respaldo y se prueba una sesión nueva al
terminar.

1. **Llaves y credenciales** (C1–C4): no cambian el acceso; reducen exposición.
2. **SSH sin firewall** (A1–A7): validar con `sshd -t` y una sesión nueva.
3. **Firewall** (F1–F7): validar acceso administrativo, SSH a nodos y agente
   Wazuh activo en el manager.
4. **sudo y PAM** (P1–P8): validar `sudo -v` y una ejecución del gateway.
5. **Monitoreo** (M1–M3).
6. **Evidencia final:** primera ejecución con `failed=0`, segunda con
   `changed=0`, playbook de verificación con `failed=0` y score SCA del agente.

## 8. Fuera de alcance

- Contenerizar ansible-control (decisión registrada: servidor dedicado
  endurecido).
- Particionado del disco (1.1.2.x): no se puede aplicar en caliente.
- Contraseña de GRUB (1.4.1): requiere una decisión separada sobre el acceso
  por consola.
