# Baseline DevSecOps

## Límite de ejecución

El host edita el repositorio y administra Vagrant. Todos los comandos Ansible se
ejecutan dentro de `ansible-control`, desde `/home/vagrant/ansible`. Las VMs de
destino permitidas son `ubuntu24` y `debian12`, siempre con inventario local y
`--limit` explícito.

## Capas de validación

### Host, sin Ansible

```bash
./scripts/check_host.sh
```

Comprueba whitespace, sintaxis Bash de scripts versionados y claves de
laboratorio rastreadas. Ejecuta Gitleaks si está instalado. Actualmente la clave
histórica eliminada sigue en el índice/historial y debe considerarse un bloqueo
de seguridad hasta su rotación y limpieza aprobada.

### Nodo de control, sin remediar destinos

```bash
make ansible-control
cd /home/vagrant/ansible
./scripts/check_control.sh
./scripts/test_contracts.sh
```

`check_control.sh` valida inventario y sintaxis de todos los entry points. Si se
define `CIS_STRICT_QUALITY_TOOLS=true`, la ausencia de `ansible-lint` o
`yamllint` es un error. `test_contracts.sh` verifica que Ubuntu y Debian no se
seleccionen mutuamente.

### Integración en laboratorio

La integración requiere, por control: ping inicial, `--check --diff`, primera
aplicación real, segunda aplicación con `changed=0`, verificación funcional y
ping final. Reboot solo se incorpora cuando el dominio lo requiere.

## Dependencias

Las colecciones de runtime están fijadas en `ansible/requirements.yml`.
`ansible/requirements-dev.in` declara herramientas de desarrollo, pero aún se
debe generar y probar un lock reproducible desde `ansible-control`; no se deben
inventar versiones no verificadas ni instalarlas en el host.

## CI futura

Un runner hospedado podrá ejecutar únicamente checks estáticos y secret scan.
La convergencia necesita un runner efímero Windows/VirtualBox que administre el
laboratorio y ejecute Ansible exclusivamente dentro de `ansible-control`.
Hasta disponer de ese runner, no se presentarán syntax checks como pruebas de
integración ni como evidencia de cumplimiento CIS.
