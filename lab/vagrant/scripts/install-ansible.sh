#!/bin/bash
# lab/vagrant/scripts/install-ansible.sh
# Instala Ansible en ansible-control

NODE="ansible-control"

echo "  Instalando Ansible en $NODE..."
vagrant.exe ssh "$NODE" -c "\
    sudo apt update -y && \
    sudo apt install -y software-properties-common && \
    sudo add-apt-repository --yes --update ppa:ansible/ansible && \
    sudo apt install -y ansible \
"
echo "  Ansible instalado en $NODE"