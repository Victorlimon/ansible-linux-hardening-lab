#!/bin/bash
# =================================================================
# Validate CIS Benchmark Section 6.3 (AIDE) Implementation
# Usage: bash scripts/validate_section6_3.sh <target_host> [cis_tag]
# Example: bash scripts/validate_section6_3.sh ubuntu-server cis_6_3
# =================================================================

set -e

TARGET_HOST="${1:-ubuntu-server}"
CIS_TAG="${2:-cis_6_3}"
PLAYBOOK="playbooks/cis_hardening.yml"

echo "=========================================="
echo "CIS 6.3 AIDE Validation Script"
echo "=========================================="
echo "Target: $TARGET_HOST"
echo "Tag: $CIS_TAG"
echo "Playbook: $PLAYBOOK"
echo ""

# 1. List tasks that would run
echo "[1/5] Listing tasks for tag: $CIS_TAG"
ansible-playbook "$PLAYBOOK" --tags "$CIS_TAG" --list-tasks --limit "$TARGET_HOST" 2>/dev/null | grep -E "(6\.3\.[0-9]|TASK)" || echo "  No tasks found for tag"
echo ""

# 2. Check syntax
echo "[2/5] Validating playbook syntax..."
ansible-playbook "$PLAYBOOK" --syntax-check 2>&1 | grep -E "(ERROR|WARNING|playbook:)" || echo "  Syntax OK"
echo ""

# 3. Run in check mode
echo "[3/5] Running in --check mode (no changes applied)..."
ansible-playbook "$PLAYBOOK" --tags "$CIS_TAG" --check --diff --limit "$TARGET_HOST" -vvv 2>&1 | tail -20
echo ""

# 4. Verify idempotency (run twice)
echo "[4/5] Testing idempotency (first run)..."
FIRST_RUN=$(ansible-playbook "$PLAYBOOK" --tags "$CIS_TAG" --limit "$TARGET_HOST" 2>&1 | grep "changed=" | tail -1)
echo "  First run: $FIRST_RUN"

echo "[4/5] Testing idempotency (second run)..."
SECOND_RUN=$(ansible-playbook "$PLAYBOOK" --tags "$CIS_TAG" --limit "$TARGET_HOST" 2>&1 | grep "changed=" | tail -1)
echo "  Second run: $SECOND_RUN"

if [[ "$SECOND_RUN" == *"changed=0"* ]]; then
    echo "  ✅ Idempotency verified: No changes on second run"
else
    echo "  ⚠️  Warning: Changes detected on second run - review tasks"
fi
echo ""

# 5. Post-check validation (if AIDE is installed)
echo "[5/5] Post-check validation on target host..."
ssh "$TARGET_HOST" "sudo aide --config-check 2>&1" 2>/dev/null && echo "  ✅ AIDE config syntax: VALID" || echo "  ⚠️  AIDE not installed or config check failed"
ssh "$TARGET_HOST" "systemctl is-active dailyaidecheck.timer 2>&1" 2>/dev/null && echo "  ✅ AIDE timer: ACTIVE" || echo "  ⚠️  AIDE timer: NOT ACTIVE"
ssh "$TARGET_HOST" "ls -la /var/lib/aide/aide.db 2>&1" 2>/dev/null && echo "  ✅ AIDE database: EXISTS" || echo "  ⚠️  AIDE database: NOT FOUND"

echo ""
echo "=========================================="
echo "Validation Complete"
echo "=========================================="
