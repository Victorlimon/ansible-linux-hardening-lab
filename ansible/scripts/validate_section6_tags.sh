#!/bin/bash
# =============================================================================
# validate_section6_tags.sh
# Script para validar que todos los archivos de Section 6 tienen tags jerárquicos
# =============================================================================

set -e

PROJECT_ROOT="C:/Users/Victor/Desktop/ansible_prod_ia/ansible"
SECTION6_PATH="${PROJECT_ROOT}/roles/cis_benchmark/tasks/section6_logging"

echo "🔍 Validando tags en Section 6: Logging & Auditing..."
echo ""

# Función para verificar tags en un archivo
check_tags() {
    local file="$1"
    local expected_parent="$2"
    
    # Buscar líneas con "tags:" y verificar que contengan el tag padre
    if grep -q "tags:" "$file"; then
        if grep -A 10 "tags:" "$file" | grep -q "${expected_parent}"; then
            echo "✅ $(basename "$file"): Contiene tag '${expected_parent}'"
            return 0
        else
            echo "❌ $(basename "$file"): FALTA tag '${expected_parent}'"
            return 1
        fi
    else
        echo "⚠️  $(basename "$file"): No tiene sección de tags"
        return 2
    fi
}

# Validar main.yml de section6_logging
echo "📁 Validando: section6_logging/main.yml"
check_tags "${SECTION6_PATH}/main.yml" "cis_6" || true
echo ""

# Validar 6.1-system_logging
echo "📁 Validando: 6.1-system_logging/"
check_tags "${SECTION6_PATH}/6.1-system_logging/main.yml" "cis_6_1" || true
for file in "${SECTION6_PATH}/6.1-system_logging"/*.yml; do
    if [[ "$file" != *"main.yml" ]]; then
        base=$(basename "$file")
        case "$base" in
            *6.1.1*) check_tags "$file" "cis_6_1_1" || true ;;
            *6.1.2*) check_tags "$file" "cis_6_1_2" || true ;;
            *6.1.3*) check_tags "$file" "cis_6_1_3" || true ;;
            *6.1.4*) check_tags "$file" "cis_6_1_4" || true ;;
        esac
    fi
done
echo ""

# Validar 6.2-system_auditing
echo "📁 Validando: 6.2-system_auditing/"
check_tags "${SECTION6_PATH}/6.2-system_auditing/main.yml" "cis_6_2" || true
for file in "${SECTION6_PATH}/6.2-system_auditing"/*.yml; do
    if [[ "$file" != *"main.yml" ]]; then
        base=$(basename "$file")
        case "$base" in
            *6.2.1*) check_tags "$file" "cis_6_2_1" || true ;;
            *6.2.2*) check_tags "$file" "cis_6_2_2" || true ;;
            *6.2.3*) check_tags "$file" "cis_6_2_3" || true ;;
            *6.2.4*) check_tags "$file" "cis_6_2_4" || true ;;
        esac
    fi
done
echo ""

# Validar 6.3
echo "📁 Validando: 6.3-configure_integrity_checking.yml"
check_tags "${SECTION6_PATH}/6.3-configure_integrity_checking.yml" "cis_6_3" || true
echo ""

# Validación con ansible-playbook
echo "🧪 Validación con Ansible CLI..."
echo ""

cd "$PROJECT_ROOT"

echo "📋 Listando tags disponibles para Section 6:"
ansible-playbook playbooks/cis_hardening.yml --list-tags 2>/dev/null | grep -E "cis_6" | head -20 || echo "⚠️  No se pudo ejecutar ansible-playbook (verificar instalación)"

echo ""
echo "✅ Validación completada."
echo ""
echo "📚 Para más información, consulta: docs/section6_tags_reference.md"
