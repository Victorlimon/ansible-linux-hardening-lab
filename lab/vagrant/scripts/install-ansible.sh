#!/bin/bash
set -euo pipefail

# lab/vagrant/scripts/install-ansible.sh
# Instala Ansible en ansible-control

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

NODE="ansible-control"

echo "  Instalando Ansible en $NODE..."
vagrant.exe ssh "$NODE" -c "\
    sudo apt update -y && \
    sudo apt install -y software-properties-common && \
    sudo add-apt-repository --yes --update ppa:ansible/ansible && \
    sudo apt install -y ansible && \
    ansible-galaxy collection install -r /home/vagrant/ansible/requirements.yml \
"
echo "  Ansible instalado en $NODE"
