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
laboratorio rastreadas. Ejecuta Gitleaks si está instalado y detecta las
interfaces `git` actual o `detect` histórica. La historia remota
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
bash ./scripts/test_p4_banners.sh
bash ./scripts/test_p4_cron.sh
bash ./scripts/test_p4_network.sh
bash ./scripts/test_p4_sysctl.sh
bash ./scripts/test_p4_shadow.sh
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

`test_p4_banners.sh` comprueba que Debian 12 CIS 1.6.2 audita con contenido
redactado y `changed=0`, que remediation deshabilitada no predice cambios, que
remediation habilitada no acepta texto vacío sin aprobación, que verification
no puede declarar `PASS` en ese estado y que la conectividad permanece
disponible.

`test_p4_cron.sh` exige auditoría `PASS` con `changed=0`, verificación
independiente y ping para CIS 2.4.1.2 en Ubuntu 24.04 y Debian 12. La
aplicabilidad se obtiene con package facts; el mecanismo no instala `cron` ni
crea `/etc/crontab` cuando el paquete no está instalado. El gate también prueba
la clasificación `NOT_APPLICABLE` mediante un nombre de paquete deliberadamente
ausente.

`test_p4_network.sh` ejecuta CIS 3.1.1 en modo audit y verification para las
dos plataformas. Exige clasificación manual, evidencia del parámetro del
módulo y de ambos sysctl, `changed=0` y ping posterior. Esta vertical no ofrece
remediation: la política IPv6 se decide fuera del mecanismo de observación. El
gate también rechaza valores distintos de `enabled`, `disabled` o `undecided`.

`test_p4_sysctl.sh` exige que CIS 3.3.10 observe
`net.ipv4.tcp_syncookies=1` tanto en runtime como en la configuración
persistente efectiva de Ubuntu 24.04 y Debian 12. Incluye la ruta sysctl
seleccionada por UFW, ejecuta verification independiente, exige `changed=0` y
comprueba conectividad. Es un gate read-only posterior a la convergencia.

`test_p4_shadow.sh` valida las interfaces independientes de Debian CIS 7.1.5.
Exige evidencia audit sanitizada y `changed=0`, comprueba que la remediation
deshabilitada no cambie nada y que falte la confirmación canary produzca rechazo;
después ejecuta check mode, dos convergencias con gates explícitos, verification
independiente e inspección de conectividad. Nunca lee contenido ni checksum de
`/etc/shadow`.

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
baseline aceptado contiene 96 parejas que representan 575 warnings con el
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
