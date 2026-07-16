#!/bin/bash
cd "$(dirname "$0")/../vagrant" || exit 1
vagrant.exe destroy -f
echo "✅ Laboratorio Vagrant destruido."