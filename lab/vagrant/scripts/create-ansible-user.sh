#!/bin/bash

USER="ansible"
VMS=("ansible-control" "debian12" "ubuntu24")
PUB_KEY="$(dirname "$0")/../ssh/id_rsa.pub"
PRIV_KEY="$(dirname "$0")/../ssh/id_rsa"

if [ ! -f "$PUB_KEY" ] || [ ! -f "$PRIV_KEY" ]; then
    echo "  No se encuentran las llaves. Ejecuta setup-ssh.sh primero."
    exit 1
fi

for VM in "${VMS[@]}"; do
    echo "👤 Creando usuario $USER en $VM..."
    vagrant.exe ssh "$VM" -c "sudo useradd -m -s /bin/bash $USER || echo '$USER ya existe'"
    vagrant.exe ssh "$VM" -c "echo '$USER ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/$USER"
    vagrant.exe ssh "$VM" -c "sudo chmod 440 /etc/sudoers.d/$USER"
    vagrant.exe ssh "$VM" -c "sudo mkdir -p /home/$USER/.ssh && sudo chmod 700 /home/$USER/.ssh"
    vagrant.exe ssh "$VM" -c "echo '$(cat $PUB_KEY)' | sudo tee /home/$USER/.ssh/authorized_keys > /dev/null"
    vagrant.exe ssh "$VM" -c "sudo chown -R $USER:$USER /home/$USER/.ssh"
    vagrant.exe ssh "$VM" -c "sudo chmod 600 /home/$USER/.ssh/authorized_keys"
done

# Copiar la llave privada **solo al nodo control**
echo "  Copiando llave privada al nodo control..."
vagrant.exe ssh "ansible-control" -c "echo '$(cat $PRIV_KEY)' | sudo tee /home/$USER/.ssh/id_rsa > /dev/null"
vagrant.exe ssh "ansible-control" -c "sudo chown $USER:$USER /home/$USER/.ssh/id_rsa"
vagrant.exe ssh "ansible-control" -c "sudo chmod 600 /home/$USER/.ssh/id_rsa"

echo "  Usuario $USER creado y listo para SSH en todas las VMs. Llave privada disponible solo en ansible-control."