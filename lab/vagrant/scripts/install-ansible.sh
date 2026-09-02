#!/bin/bash
set -euo pipefail

# lab/vagrant/scripts/install-ansible.sh
# Instala una toolchain reproducible dentro de ansible-control.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

NODE="ansible-control"
REPOSITORY_ROOT="/home/vagrant/ansible"
PROJECT_ROOT="$REPOSITORY_ROOT/ansible"
VENV="/home/vagrant/.venvs/ansible-cis"
LOCK_FILE="$PROJECT_ROOT/requirements-dev.lock"

PYTHON_VENV_VERSION="3.12.3-0ubuntu2.1"
PYTHON_PIP_VERSION="24.0+dfsg-1ubuntu1.3"
SHELLCHECK_VERSION="0.9.0-1"
GITLEAKS_VERSION="8.16.0-1ubuntu0.24.04.3"
GIT_FILTER_REPO_VERSION="2.38.0-2"

echo "  Instalando prerrequisitos fijados en $NODE..."
vagrant.exe ssh "$NODE" -c "\
    sudo apt-get update && \
    sudo apt-get install -y \
      python3-venv=$PYTHON_VENV_VERSION \
      python3-pip=$PYTHON_PIP_VERSION \
      shellcheck=$SHELLCHECK_VERSION \
      gitleaks=$GITLEAKS_VERSION \
      git-filter-repo=$GIT_FILTER_REPO_VERSION && \
    mkdir -p /home/vagrant/.venvs && \
    python3 -m venv $VENV \
"

if [ ! -f "../../ansible/requirements-dev.lock" ]; then
    echo "  Generando lock inicial con hashes dentro de ansible-control..."
    vagrant.exe ssh "$NODE" -c "\
        $VENV/bin/python -m pip install pip-tools && \
        cd $PROJECT_ROOT && \
        $VENV/bin/pip-compile --generate-hashes \
          --allow-unsafe \
          --output-file requirements-dev.lock requirements-dev.in \
    "
fi

echo "  Instalando toolchain Python desde el lock..."
vagrant.exe ssh "$NODE" -c "\
    cd $PROJECT_ROOT && \
    $VENV/bin/python -m pip install --require-hashes -r $LOCK_FILE && \
    $VENV/bin/ansible-galaxy collection install -r $PROJECT_ROOT/requirements.yml --force && \
    $VENV/bin/ansible --version && \
    $VENV/bin/ansible-lint --version && \
    $VENV/bin/yamllint --version && \
    shellcheck --version && \
    gitleaks version && \
    git-filter-repo --version \
"

echo "  Toolchain fijada instalada en $VENV"
