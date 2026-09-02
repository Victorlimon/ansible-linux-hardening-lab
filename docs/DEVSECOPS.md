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
laboratorio rastreadas. Ejecuta Gitleaks si está instalado. La historia remota
fue reemplazada tras retirar la clave efímera comprometida; los clones anteriores
deben descartarse o restablecerse contra la historia saneada.

### Nodo de control, sin remediar destinos

```bash
make ansible-control
cd /home/vagrant/ansible/ansible
bash ./scripts/check_control.sh
bash ./scripts/test_contracts.sh
bash ./scripts/test_p3_pilot.sh
bash ./scripts/test_p4_common.sh
```

`check_control.sh` valida inventario y sintaxis de todos los entry points. Si se
define `CIS_STRICT_QUALITY_TOOLS=true`, la ausencia de `ansible-lint` o
`yamllint` es un error. `test_contracts.sh` verifica que Ubuntu y Debian no se
seleccionen mutuamente.

`test_p3_pilot.sh` ejecuta únicamente la auditoría y verificación independientes
de Debian 12 CIS 7.1.1. Exige `changed=0` en el recap de auditoría y comprueba la
conectividad final; no induce deriva ni remedia el objetivo.

`test_p4_common.sh` exige auditoría `PASS` con `changed=0`, verificación
independiente y ping para CIS 7.1.1 en Ubuntu 24.04 y Debian 12. Es un gate
read-only; la inducción de deriva y las convergencias permanecen como prueba de
integración explícita.

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
