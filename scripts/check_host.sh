#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

git diff --check

while IFS= read -r script; do
  [[ -z "$script" ]] && continue
  bash -n "$script"
done < <(git ls-files --cached --others --exclude-standard '*.sh')

tracked_lab_keys="$(git ls-files 'lab/vagrant/ssh/id_rsa' 'lab/vagrant/ssh/id_rsa.pub')"
if [[ -n "$tracked_lab_keys" ]]; then
  printf '%s\n' "ERROR: laboratory SSH key paths remain tracked by Git:" >&2
  printf '%s\n' "$tracked_lab_keys" >&2
  exit 1
fi

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks git --config .gitleaks.toml --redact
else
  printf '%s\n' "WARN: gitleaks is not installed; secret scanning was skipped." >&2
fi

printf '%s\n' "Host-safe checks completed. No Ansible command was executed."
