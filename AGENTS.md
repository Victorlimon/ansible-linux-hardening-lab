# Referencia local de Ansible

Antes de crear o modificar playbooks, roles, inventarios o configuracion de
Ansible, consulta `docs/ansible-documentation/`. Es una copia local, de solo
lectura, del repositorio oficial `ansible/ansible-documentation`.

- Usa `docs/ansible-documentation/docs/docsite/rst/` para sintaxis YAML,
  inventarios, playbooks, variables, vault, colecciones y buenas practicas.
- Usa `ansible-doc <modulo>` para confirmar los parametros, valores admitidos y
  el comportamiento de modulos/plugins instalados: su documentacion fuente
  pertenece al repositorio `ansible/ansible`, no a esta copia.
- El proyecto requiere Ansible Core 2.16 o posterior. No adoptes funciones de
  versiones mas recientes sin comprobar la version con `ansible --version`.
- No modifiques ni incluyas `docs/ansible-documentation/` en los commits del
  proyecto. Actualizala solo con `git -C docs/ansible-documentation pull --ff-only`.
