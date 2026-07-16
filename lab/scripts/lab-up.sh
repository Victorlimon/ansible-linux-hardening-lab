#!/bin/bash
cd "$(dirname "$0")/.." || exit 1

# Ir al directorio vagrant y levantar las máquinas
cd vagrant || exit 1
vagrant.exe up

echo "  Laboratorio Vagrant levantado."

#echo "Para ejecutar Ansible  el nodo control de Vagrant:"
#echo "  vagrant ssh control -c 'cd /vagrant/ansible && ansible-playbook -i inventories/local/hosts.yml playbooks/hardening.yml'"S