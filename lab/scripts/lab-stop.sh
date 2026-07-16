#!/bin/bash
cd "$(dirname "$0")/../vagrant" || exit 1
vagrant.exe halt
echo "✅ Laboratorio Vagrant detenido."