# Rutas
SCRIPTS_DIR := ./lab/scripts
SCRIPTS_DIR_VAGRANT := ./lab/vagrant/scripts


.PHONY: all help check-host up destroy setup-ssh provision-lab stop start status ansible-control ubuntu24-ssh debian12-ssh

all: up

help:
	@echo "Objetivos seguros en el host: check-host, status, start y stop"
	@echo "Ansible se valida dentro de ansible-control con los playbooks audit/hardening/verify y los calificadores Python"

check-host:
	@./scripts/check_host.sh

# --- Generar claves SSH ---
setup-ssh:
	@echo "🔑 Ejecutando setup-ssh.sh..."
	@cd $(SCRIPTS_DIR) && ./setup-ssh.sh

# --- Levantar laboratorio Vagrant ---
up: setup-ssh
	@echo "  Ejecutando lab-up.sh..."
	@cd $(SCRIPTS_DIR) && ./lab-up.sh

# --- Provisionar laboratorio completo ---
provision-lab:
	@echo "  Provisionando laboratorio..."
	@cd $(SCRIPTS_DIR_VAGRANT) && ./create-ansible-user.sh
	@cd $(SCRIPTS_DIR_VAGRANT) && ./setup-postprovision.sh
	@cd $(SCRIPTS_DIR_VAGRANT) && ./install-ansible.sh
	@echo "  Laboratorio provisionado y listo para Ansible."

# --- Destruir laboratorio Vagrant ---
destroy:
	@echo "  Ejecutando lab-destroy.sh..."
	@cd $(SCRIPTS_DIR) && ./lab-destroy.sh

# --- Detener laboratorio Vagrant ---
stop:
	@echo "  Ejecutando lab-stop.sh..."
	@cd $(SCRIPTS_DIR) && ./lab-stop.sh

# --- Encender laboratorio Vagrant sin provisionar ---
start:
	@echo "  Ejecutando lab-start.sh..."
	@cd $(SCRIPTS_DIR) && ./lab-start.sh

# --- Consultar estado del laboratorio ---
status:
	@cd ./lab/vagrant && vagrant.exe status

# --- Conectarse a ansible-control ---
ansible-control:
	@echo "🔗 Conectando a ansible-control..."
	cd ./lab/vagrant && vagrant.exe ssh ansible-control

# --- Conectarse a ubuntu24 ---
ubuntu24-ssh:
	@echo "🔗 Conectando a ubuntu24..."
	cd ./lab/vagrant && vagrant.exe ssh ubuntu24

# --- Conectarse a Debian 12 ---
debian12-ssh:
	@echo "🔗 Conectando a debian12..."
	cd ./lab/vagrant && vagrant.exe ssh debian12



