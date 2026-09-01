#!/bin/bash
set -euo pipefail

# lab/vagrant/scripts/setup-postprovision.sh
# Tareas adicionales: actualizar paquetes en todas las VMs

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

VMS=("ansible-control" "debian12" "ubuntu24")

for VM in "${VMS[@]}"; do
    echo "  Actualizando paquetes en $VM..."
    vagrant.exe ssh "$VM" -c "sudo apt update && sudo apt upgrade -y"
done

echo "  Post-provisión completada."
