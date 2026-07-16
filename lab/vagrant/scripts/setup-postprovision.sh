#!/bin/bash
# lab/vagrant/scripts/setup-postprovision.sh
# Tareas adicionales: actualizar paquetes en todas las VMs

VMS=("ansible-control" "debian12" "ubuntu24")

for VM in "${VMS[@]}"; do
    echo "  Actualizando paquetes en $VM..."
    vagrant.exe ssh "$VM" -c "sudo apt update && sudo apt upgrade -y"
done

echo "  Post-provisión completada."