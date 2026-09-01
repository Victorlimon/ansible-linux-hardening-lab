#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

USER="ansible"
VMS=("ansible-control" "debian12" "ubuntu24")
PUB_KEY="$SCRIPT_DIR/../ssh/id_rsa.pub"
PRIV_KEY="$SCRIPT_DIR/../ssh/id_rsa"

if [ ! -f "$PUB_KEY" ] || [ ! -f "$PRIV_KEY" ]; then
    echo "  No se encuentran las llaves. Ejecuta setup-ssh.sh primero."
    exit 1
fi

for VM in "${VMS[@]}"; do
    echo "👤 Creando usuario $USER en $VM..."
    vagrant.exe ssh "$VM" -c "id -u $USER >/dev/null 2>&1 || sudo useradd -m -s /bin/bash $USER"
    vagrant.exe ssh "$VM" -c "printf '%s\n' '$USER ALL=(ALL) NOPASSWD:ALL' > /tmp/$USER-sudoers && sudo visudo -cf /tmp/$USER-sudoers && sudo install -o root -g root -m 0440 /tmp/$USER-sudoers /etc/sudoers.d/$USER && rm -f /tmp/$USER-sudoers"
    vagrant.exe ssh "$VM" -c "sudo mkdir -p /home/$USER/.ssh && sudo chmod 700 /home/$USER/.ssh"
    vagrant.exe upload "$PUB_KEY" "/tmp/$USER-authorized-key" "$VM"
    vagrant.exe ssh "$VM" -c "sudo install -o $USER -g $USER -m 0600 /tmp/$USER-authorized-key /home/$USER/.ssh/authorized_keys && rm -f /tmp/$USER-authorized-key"
    vagrant.exe ssh "$VM" -c "sudo chown -R $USER:$USER /home/$USER/.ssh"
done

# Copiar la llave privada **solo al nodo control**
echo "  Copiando llave privada al nodo control..."
vagrant.exe upload "$PRIV_KEY" "/tmp/$USER-private-key" "ansible-control"
vagrant.exe ssh "ansible-control" -c "sudo install -o $USER -g $USER -m 0600 /tmp/$USER-private-key /home/$USER/.ssh/id_rsa && rm -f /tmp/$USER-private-key"

echo "  Usuario $USER creado y listo para SSH en todas las VMs. Llave privada disponible solo en ansible-control."
