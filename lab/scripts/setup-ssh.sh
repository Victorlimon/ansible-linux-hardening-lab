#!/bin/bash
# Genera claves SSH si no existen
mkdir -p ../vagrant/ssh
if [ ! -f ../vagrant/ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 2048 -f ../vagrant/ssh/id_rsa -N ""
    echo "  Claves SSH generadas en ../vagrant/ssh/"
else
    echo "   Las claves ya existen."
fi