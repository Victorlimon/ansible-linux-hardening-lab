#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../vagrant" || exit 1
vagrant.exe halt
echo "✅ Laboratorio Vagrant detenido."
