# Baseline DevSecOps

## Límite de ejecución

El host edita el repositorio y administra Vagrant. Todos los comandos Ansible se
ejecutan dentro de `ansible-control`, desde `/home/vagrant/ansible/ansible`. El
repositorio completo se monta en `/home/vagrant/ansible` para que los checks
usen la configuración versionada. Las VMs de
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
cd /home/vagrant/ansible/ansible
bash ./scripts/check_control.sh
bash ./scripts/test_contracts.sh
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
`ansible/requirements-dev.in` declara las herramientas de desarrollo y
`ansible/requirements-dev.lock` fija sus versiones y hashes. El lock se genera
y valida desde `ansible-control`; estas herramientas no se instalan en el host.

## Baseline de ansible-lint

`.ansible-lint-ignore` registra deuda histórica por pareja archivo/regla. El
baseline aceptado contiene 96 parejas que representan 578 warnings con el
perfil `basic`; ansible-lint debe terminar con cero fallos. No se debe regenerar
el archivo automáticamente en cambios ordinarios: cada corrección elimina su
entrada cuando ya no quedan infracciones de esa regla en el archivo.

La granularidad del formato de ignore es archivo/regla, no línea. Por ello una
revisión debe rechazar instancias nuevas de una regla ya exceptuada dentro del
mismo archivo, aunque ansible-lint las muestre como warning. Las reglas o los
archivos que no figuran en el baseline siguen siendo fallos y evitan ampliar la
deuda silenciosamente.

## CI futura

Un runner hospedado podrá ejecutar únicamente checks estáticos y secret scan.
La convergencia necesita un runner efímero Windows/VirtualBox que administre el
laboratorio y ejecute Ansible exclusivamente dentro de `ansible-control`.
Hasta disponer de ese runner, no se presentarán syntax checks como pruebas de
integración ni como evidencia de cumplimiento CIS.
