#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_DIR="$SCRIPT_DIR/../vagrant/ssh"

# La clave es un artefacto efímero del laboratorio y nunca pertenece al repo.
umask 077
mkdir -p "$SSH_DIR"
if [ ! -f "$SSH_DIR/id_rsa" ]; then
    ssh-keygen -q -t ed25519 -f "$SSH_DIR/id_rsa" -N "" -C "ansible-vagrant-lab"
    chmod 0600 "$SSH_DIR/id_rsa"
    chmod 0644 "$SSH_DIR/id_rsa.pub"
    echo "  Claves SSH efímeras generadas en $SSH_DIR"
else
    chmod 0600 "$SSH_DIR/id_rsa"
    chmod 0644 "$SSH_DIR/id_rsa.pub"
    echo "  Las claves efímeras del laboratorio ya existen."
fi
