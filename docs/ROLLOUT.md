# Procedimiento de rollout (hardening por secciones gated)

Guía operativa para aplicar el hardening completo de forma segura, sección por
sección, respetando los gates del proyecto. Leela entera antes de tocar un
objetivo real.

## Principio rector

El proyecto aplica remediaciones **solo cuando el operador lo habilita
explícitamente**, en dos capas:

1. **Master gate**: `cis_<plataforma>_remediation_enabled: true` + `--tags`
   explícito (sin `--tags` se rechaza la corrida global).
2. **Gates por control**: las remediaciones disruptivas están en `false` por
   defecto (`<selector>_remediate: false`); hay que encenderlas una por una.
3. **Canario Debian**: además exige `cis_debian_12_canary_confirmed: true`.

La auditoría y la verificación **nunca** cambian el objetivo. Son siempre la
primera y la última etapa de cada sección.

## Orden recomendado (menos → más disruptivo)

| Paso | Familia | Tag(s) de selección | Riesgo |
|---|---|---|---|
| 1 | Parámetros de kernel (sysctl) | `sysctl` | Bajo |
| 2 | Configuración de red e IPv6 | `network`, `ipv6`, `ipv6_status` | Bajo |
| 3 | Setup inicial (banners, sudo, montajes) | `config_line`, `banners`, `issue`, `sudo` | Bajo-Medio |
| 4 | Logging y auditoría (auditd) | `package_installed`, `service_enabled`, `gated_unsafe` | Medio |
| 5 | Servicios (deshabilitar no usados) | `package_absent`, `service_disabled` | Medio |
| 6 | Permisos de archivos y mantenimiento | `fixed_file_permissions`, `world_writable_files` | Medio |
| 7 | **Firewall (UFW / nftables)** | `cis_4_2_*` / `cis_4_3_*`, `ufw_rule`, `ufw_policy` | **Alto** |
| 8 | **SSH, PAM y cuentas** | `cis_5_*`, `sshd`, `sudo`, `config_line` | **Crítico** |

Los pasos 7 y 8 son los que pueden dejarte afuera. Nunca arranques por ellos.

## Preparación previa (obligatoria)

1. **Consola de respaldo abierta** (hipervisor/Vagrant) y una **segunda sesión
   SSH/root** activa, que se mantiene hasta validar el acceso.
2. **Snapshot** de la VM antes de cada sección crítica.
3. **Confirmar acceso SSH actual** con la identidad que usás (`ansible`) y
   localizar el mecanismo de recuperación (consola o `vagrant ssh`).
4. **Preflight** limpio:

   ```bash
   ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml --list-hosts --limit ubuntu24
   ansible-playbook playbooks/audit/cis_ubuntu_2404.yml --limit ubuntu24
   ```

   La auditoría inicial te da el baseline (`failed` debería ser 0; los desvíos
   aparecen como tareas `failed` solo en `verify`, no en `audit`).

## Procedimiento por sección (repetir en cada paso)

Reemplazá `<tag>` por el tag de la fila correspondiente.

```bash
# A. Vista previa sin cambios
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags <tag> --check --diff \
  -e cis_ubuntu_2404_remediation_enabled=true

# B. Aplicación real
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags <tag> \
  -e cis_ubuntu_2404_remediation_enabled=true

# C. Segunda aplicación real (idempotencia: changed=0 esperado)
ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
  --limit ubuntu24 --tags <tag> \
  -e cis_ubuntu_2404_remediation_enabled=true

# D. Verificación independiente
ansible-playbook playbooks/verify/cis_ubuntu_2404.yml --limit ubuntu24 --tags <tag>

# E. Chequeos de servicio fuera de la sesión
sudo sshd -t
sudo sshd -T | grep -E 'permitrootlogin|usepam|maxauthtries'
sudo ufw status verbose      # solo si usás UFW
sudo auditctl -s             # solo si habilitaste auditd
systemctl is-active ssh auditd
```

Si en **C** aparece cualquier `changed` recurrente, investigalo: puede ser una
tarea no idempotente. En **D**, `failed=0` significa que el estado quedó conforme.

### Habilitar una remediación disruptiva

Las remediaciones opt-in (particiones, retiro de servicios, AIDE, faillock,
etc.) no corren aunque selecciones su tag. Encendelas una por una en el
inventario, nunca con variables globales:

```yaml
# inventories/<entorno>/group_vars/<plataforma>.yml
cis_ubuntu_2404_6_3_1_aide_installed_remediate: true
cis_ubuntu_2404_6_3_1_aide_init_remediate: true
```

Revisá `--list-tasks` y el `defaults/main.yml` del adaptador para el nombre
exacto de cada selector antes de habilitarlo.

## Paso 7 — Firewall (riesgo alto)

1. Definí el motor: `cis_firewall` (`ufw` en Ubuntu por defecto, `nftables` en
   Debian por defecto). El código condiciona la sección 4 a este valor.
2. Verificá `cis_ufw_ssh_port` (default `22`).
3. Antes de `default deny`, asegurá una regla que permita tu SSH entrante. Si
   tu motor es UFW, la allowlist de fuentes debe existir antes de aplicar.

   ```bash
   ansible-playbook playbooks/hardening/cis_ubuntu_2404.yml \
     --limit ubuntu24 --tags ufw_rule --check --diff \
     -e cis_ubuntu_2404_remediation_enabled=true
   ```

4. Aplicá primero las reglas de permit, **después** el default deny, y validá
   `sudo ufw status verbose` desde una segunda sesión antes de cerrar nada.
5. Si perdés acceso: consola → `ufw disable` (o restaurar reglas) y revisar.

## Paso 8 — SSH, PAM y cuentas (crítico)

1. Aplicá **primero** los controles de SSH que preservan tu acceso (allowlist de
   usuarios, `PermitRootLogin no` solo si tenés un usuario sudo no-root
   confirmado).
2. PAM (faillock, pwquality, etc.) es opt-in: habilitá un control a la vez.
3. Después de cada subgrupo, validá **sin cerrar la sesión de respaldo**:

   ```bash
   sudo sshd -t
   sudo sshd -T | grep -E 'permitrootlogin|usepam|maxauthtries|passwordauthentication'
   ```

4. Abrí una **conexión SSH nueva** y confirmá login antes de cerrar la sesión
   vieja. Si falla, recuperás desde consola o la sesión de respaldo.

## Debian 12 — doble gate canario

Debian usa los mismos playbooks pero exige el gate canario además del master:

```bash
ansible-playbook playbooks/hardening/cis_debian_12.yml \
  --limit debian12 --tags sysctl --check --diff \
  -e cis_debian_12_remediation_enabled=true \
  -e cis_debian_12_canary_confirmed=true
```

`cis_debian_12_canary_confirmed` también aparece en los `when:` de remediación
por control: sin él, la remediación no se ejecuta.

## Rollback y recuperación

No hay rollback automático. Las opciones son:

1. **Snapshot**: restaurar la VM al estado previo a la sección.
2. **Backups de módulos**: las tareas con `backup: true` dejan copias con
   timestamp junto al archivo original; restaurá y reiniciá el servicio.
3. **Consola**: rehabilita el servicio/paquete o corrige el archivo.

Prioridad de recuperación si se pierde SSH: consola → restaurar
allowlist/config → `sshd -t` → reconectar → `ufw status verbose` → recién
entonces cerrar la sesión de respaldo.

## Receipts (evidencia)

Registrá por cada sección: playbook + tag + entorno, resultado de cada corrida
(recap de `ok/changed/failed`), `changed` de la segunda corrida, y los chequeos
de servicio. Guardalos en `ansible/evidence/cis/<fecha>/`. La calificación
formal y los límites de afirmación siguen el proceso de
[IMPROVING.md](IMPROVING.md) y [SUPPORT.md](SUPPORT.md).
