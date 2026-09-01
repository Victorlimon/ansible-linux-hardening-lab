#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

# Ir al directorio vagrant y levantar las máquinas
cd vagrant || exit 1
vagrant.exe up

echo "  Laboratorio Vagrant levantado."
