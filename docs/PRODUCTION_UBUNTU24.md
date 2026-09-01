# Operación segura en Ubuntu 24.04 Server

Esta guía prepara una ejecución controlada del rol `cis_benchmark`. No certifica
cumplimiento, no reemplaza una evaluación CIS independiente y no ofrece rollback
automático.

## Objetivo y responsabilidades

El rol acepta exclusivamente Ubuntu 24.04 Server. El playbook selecciona el
grupo `ubuntu` y usa privilegios root. Para un servidor real, cree un inventario
aprobado que defina ese grupo; `inventories/production/hosts.yml` está vacío y
no debe usarse hasta completarlo y revisarlo.

En el laboratorio, el host Windows administra Vagrant, `vagrant` entra al nodo
de control y `ansible` ejecuta Ansible y accede al remoto. En producción, preserve
la separación funcional: una identidad de control sin trabajo interactivo
innecesario y una identidad remota `ansible` con clave protegida, `sudo`
controlado y trazabilidad.

## Preparación obligatoria

1. Confirme consola fuera de banda y una ventana de mantenimiento.
2. Tome snapshot o backup recuperable y pruebe su restauración.
3. Mantenga una segunda sesión privilegiada abierta durante UFW, SSH y PAM.
4. Confirme Ubuntu 24.04 Server, espacio libre, sincronización horaria y estado
   de paquetes/servicios.
5. Revise excepciones de aplicaciones, puertos, redes de gestión, montajes,
   cuentas locales, autenticación y retención de logs.
6. Instale Ansible Core 2.16 o posterior y las colecciones fijadas.
7. Limite primero a un host canario y a una sola sección.
8. Active `cis_production_mode: true` y complete el identificador de cambio,
   confirmaciones de backup recuperable y acceso fuera de banda. El rol aborta
   si faltan esos gates, espacio mínimo, arquitectura soportada o usuario remoto
   no-root.
9. Defina `cis_execution_environment: production`. El valor por defecto
   `unconfigured` falla deliberadamente, y el inventario local usa `lab`.

Laboratorio desde el host:

```bash
make up
make provision-lab
make status
make ansible-control
```

Laboratorio desde `ansible-control`:

```bash
cd /home/vagrant/ansible
ansible --version
ansible-inventory --graph
ansible ubuntu24 --limit ubuntu24 -m ansible.builtin.ping
```

El nodo `ansible-control` se opera como `vagrant`; el usuario `ansible` existe
en los nodos gestionados. Las colecciones se preparan mediante
`make provision-lab`, no instalándolas manualmente durante una prueba.

## Inventario

El inventario local ya define `ubuntu24`, pero su política UFW solo sirve para
la red privada Vagrant. Para un inventario real, la forma mínima es:

```yaml
all:
  children:
    ubuntu:
      hosts:
        servidor-canario:
          ansible_host: 203.0.113.10
  vars:
    ansible_user: ansible
    ansible_python_interpreter: /usr/bin/python3
    ansible_become: true
    ansible_become_method: sudo
```

No almacene claves privadas ni secretos en el inventario. Use una ubicación de
clave protegida y Ansible Vault para valores sensibles. Antes de aplicar:
Mantenga la verificación SSH de host keys activa, cargue las huellas aprobadas
en `known_hosts` y no copie `ansible_ssh_common_args` del inventario local.

```bash
ansible-inventory -i inventories/production/hosts.yml --graph
ansible-playbook -i inventories/production/hosts.yml \
  playbooks/cis_hardening.yml --limit servidor-canario --list-hosts
```

En el laboratorio, mantenga siempre `--limit ubuntu24`.

## Variables críticas

### UFW

`cis_section4_firewall` es `false` por defecto. Antes de ponerlo a `true`:

- Mantenga `cis_firewall_engine: ufw`. Las rutas nftables/iptables finalizan
  deliberadamente porque no están implementadas de forma segura.
- Defina `cis_ufw_ssh_port` con el puerto real.
- Defina al menos una red confiable en `cis_ufw_ssh_allowed_sources`; una lista
  vacía hace fallar la validación.
- Inventaríe todos los servicios en `cis_ufw_allowed_in_rules`.
- Revise `cis_ufw_allowed_out_ports`: el rol aplica deny por defecto también a
  salida, por lo que DNS, repositorios, NTP, proxies, monitorización y APIs deben
  estar contemplados.
- La política es autoritativa: en la primera aplicación, cuando cambia su huella
  o cuando los archivos de reglas derivan del estado registrado, el rol ejecuta
  un reset de UFW antes de reconstruir las reglas. Las reglas no declaradas se
  eliminan. Mantenga una sesión de recuperación abierta. Una interrupción entre
  el reset y el enable puede dejar UFW desactivado y requiere recuperación.
- El reset se bloquea en ejecución real salvo que se apruebe expresamente con
  `cis_ufw_authoritative_reset_confirmed: true`; vuelva a `false` después de la
  ventana. `--check --diff` no necesita esa confirmación.
- Las redes de documentación RFC 5737 son rechazadas y el ejemplo permanece con
  la sección desactivada hasta que se definan CIDR reales.
- El rol valida los CIDR antes del reset y exige coherencia entre la política
  IPv6 declarada, el estado efectivo del kernel y `IPV6=` en `/etc/default/ufw`.

Riesgo principal: pérdida inmediata de SSH o conectividad de aplicaciones.

### SSH

`cis_section5_1_ssh_server` está activo. Revise todo `cis_ssh_config`, en
particular algoritmos, forwarding, `PermitRootLogin`, tiempos y máximos. La
allowlist está desactivada con `use_allow_list: false`; si se activa:

- Asegure que `cis_ssh_remote_user`/`ansible` pertenezca al grupo permitido.
- Alinee `access_control_type` y `allowed_users_groups`.
- Valide `sshd -t` y abra una conexión nueva antes de cerrar la existente.

Riesgo principal: bloquear al usuario de automatización o clientes con
algoritmos incompatibles.

### PAM y cuentas

`cis_section5_3_pam` es `false`. Activarlo reconstruye perfiles PAM y puede
bloquear todos los accesos. Revise `cis_pam_faillock_deny`, tiempos de desbloqueo,
`cis_pam_pwquality_*` y el historial de contraseñas. Pruebe consola, SSH, sudo y
cuentas de servicio.

Los cambios masivos sobre cuentas existentes, shells y bloqueos tienen flags
opt-in en `05-access-control.yml`. No los active sin un mapa de cuentas y dueños.

### auditd

`cis_section6_logging_audit` es `false`. Al activarlo se configuran logging y
auditd, parámetros de arranque y reglas. Revise capacidad de `/var/log/audit`,
retención y volumen de eventos. `cis_audit_allow_disruptive_actions: false`
degrada acciones de disco críticas a `syslog`; cambiarlo puede detener o poner
el sistema en modo de emergencia según la política elegida. La regla de comandos
privilegiados de alto volumen y el modo immutable permanecen opt-in.

Riesgos: consumo de disco/CPU, reglas inválidas, necesidad de reinicio para
parámetros de arranque e imposibilidad de modificar reglas immutable sin reboot.
Las reglas audit b32/b64 actuales están validadas únicamente para `x86_64`; el
rol falla explícitamente en otras arquitecturas.

### AIDE

Activar la sección 6 no instala ni inicializa AIDE por sí solo. Revise y habilite
por separado:

```yaml
section6_logging:
  '6_3_1_aide_installed':
    enabled: true
  '6_3_1_aide_init':
    enabled: true
```

Al sobreescribir el diccionario completo conserve las demás claves necesarias
de `section6_logging`; una sustitución parcial mal planteada puede eliminar
defaults anidados. La inicialización recorre el filesystem y puede tardar y
consumir I/O. Dimensione y excluya datos volátiles según política. El timer
diario solo se habilita después de comprobar que existe una base inicializada.

Una base AIDE existente nunca se actualiza ni se promociona automáticamente al
cambiar reglas. La actualización y promoción son aprobaciones separadas:

```yaml
section6_logging:
  # Copiar primero el diccionario completo desde defaults.
  '6_3_3_aide_database_update':
    enabled: true              # genera aide.db.new
    promote_candidate: false   # revisar hallazgos/checksum antes de cambiarlo
```

El repositorio ya no contiene una clave SSH del laboratorio. Si una versión
anterior fue compartida, considere esa clave comprometida, rótela y elimínela
también del historial Git mediante un procedimiento aprobado.

### rsyslog

La política local es específica del entorno y está desactivada por defecto. Si
se habilita, el rol escribe únicamente `/etc/rsyslog.d/70-cis-local.conf`; no
reemplaza `/etc/rsyslog.d/50-default.conf`. Los listeners TCP/UDP inesperados
provocan un fallo para revisión, en lugar de ser eliminados silenciosamente.
Cada drop-in se valida antes de reemplazarse; si la validación de la
configuración completa falla, el rol restaura los backups y aborta.
El forwarding rsyslog disponible sigue siendo TCP sin TLS; para transporte
autenticado seleccione `systemd-journal-upload` con certificados o implemente
una política rsyslog TLS revisada antes de producción.

### Particiones y montajes

Los flags `cis_1_1_2_*_partition` no crean particiones. Si `/tmp`, `/home`,
`/var`, `/var/tmp`, `/var/log` o `/var/log/audit` no son montajes separados, el
rol informa una acción manual. Si ya existen, las variables `nodev`, `nosuid` y
`noexec` pueden persistir opciones y remontar.

Riesgos: una opción incompatible puede impedir ejecución, instalación o inicio
de aplicaciones. Crear/migrar particiones requiere planificación de capacidad,
backup y ventana independiente.

## Ejecución por etapas

Descubra tags y tareas; no presuponga la notación del tag de control:

```bash
ansible-playbook playbooks/cis_hardening.yml --limit ubuntu24 --list-tags
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec1 --list-tasks
```

Para cada sección:

```bash
# 1. Vista previa
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec1 --check --diff

# 2. Aplicación controlada
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec1

# 3. Segunda aplicación real para idempotencia
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec1

# 4. Comprobación final sin cambios
ansible-playbook playbooks/cis_hardening.yml \
  --limit ubuntu24 --tags cis_sec1 --check --diff
```

Cambie `cis_sec1` por la sección siguiente solo tras validar servicios y
aplicación. Para un control, use el tag exacto mostrado por `--list-tasks`, por
ejemplo `cis_5.1.4`, `cis_4_2_6` o `cis_6_2_3_1`.

Check mode no garantiza una aplicación exitosa: módulos sin soporte pueden
omitir acciones y los resultados registrados pueden no existir. Algunas
consultas del rol usan `check_mode: false` para observar el estado real. Diff
puede exponer datos sensibles.

## Validación posterior

Adapte estas comprobaciones a la sección aplicada:

```bash
sudo sshd -t
sudo sshd -T | grep -E 'permitrootlogin|usepam|maxauthtries|maxsessions'
sudo ufw status verbose
sudo sysctl net.ipv4.ip_forward
systemctl is-active ssh cron rsyslog auditd
sudo auditctl -s
sudo augenrules --check
findmnt /tmp /home /var /var/tmp /var/log /var/log/audit
```

Revise el recap. En la segunda aplicación real, `changed=0` es el objetivo para
el alcance seleccionado; cualquier cambio recurrente debe investigarse, no
ocultarse. Valide además acceso nuevo por SSH, sudo, resolución DNS, NTP,
telemetría y salud de la aplicación.

## Recuperación

Si se pierde conectividad o autenticación:

1. No cierre la consola ni la sesión privilegiada de respaldo.
2. Entre por consola del hipervisor/Vagrant.
3. Para UFW, inspeccione `ufw status numbered`; desactive temporalmente UFW solo
   si es necesario para recuperar gestión y reinstale una allowlist correcta.
4. Para SSH, ejecute `sshd -t`, corrija la configuración o restaure un backup y
   recargue `ssh`; no reinicie a ciegas con sintaxis inválida.
5. Para PAM, restaure los perfiles/configuración conocidos y pruebe consola,
   sudo y una conexión nueva.
6. Para montajes, corrija `/etc/fstab` desde consola y valide con `findmnt` y
   `mount -a` antes de reiniciar.
7. Para auditd/AIDE, detenga la expansión del consumo, corrija reglas/retención
   y considere el reinicio si se activó modo immutable.
8. Si no puede demostrar un estado seguro, restaure el snapshot/backup y
   documente la causa antes de reintentar.

Desactivar una variable después de aplicar no revierte necesariamente el cambio:
normalmente solo evita que la tarea vuelva a ejecutarse.
