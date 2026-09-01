#!/bin/bash
set -euo pipefail

# lab/vagrant/scripts/setup-postprovision.sh
# Verificación mínima de las VMs. Las actualizaciones del sistema pertenecen a
# un flujo explícito y versionado; este provisioner no ejecuta upgrades.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

VMS=("ansible-control" "debian12" "ubuntu24")

for VM in "${VMS[@]}"; do
    echo "  Verificando plataforma en $VM..."
    vagrant.exe ssh "$VM" -c "test -r /etc/os-release && . /etc/os-release && printf '%s %s\\n' \"\$ID\" \"\$VERSION_ID\""
done

echo "  Verificación de plataforma completada sin actualizar paquetes."
