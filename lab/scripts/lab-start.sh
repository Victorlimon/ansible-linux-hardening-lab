#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../vagrant" || exit 1
vagrant.exe up
echo "✅ Laboratorio Vagrant iniciado."
