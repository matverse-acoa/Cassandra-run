#!/usr/bin/env bash
set -euo pipefail

ROLE="${MATVERSE_ROLE:-unknown}"
echo "Architectural enforcement for role: ${ROLE}"

required_paths=(
  deployer
  infra
  k8s
  monitoring
  scripts
  docker-compose.production.yml
  stack.yml
  Ω-NODE-REGISTER.json
  README.md
)

required_files=(
  deployer/__init__.py
  deployer/acoa_metrics_adapter.py
  deployer/main.py
  deployer/pbse_integration.py
  deployer/requirements.txt
  deployer/review.py
  infra/main.tf
  infra/variables.tf
  k8s/Chart.yaml
  k8s/values-production.yaml
  monitoring/prometheus.yml
)

missing=0

if [[ "${ROLE}" == "foundation" ]]; then
  forbidden_patterns=(
    "cosign"
    "sign_and_anchor.py"
    "docker"
    "kubectl"
    "terraform"
  )
elif [[ "${ROLE}" == "runtime" ]]; then
  forbidden_patterns=(
    "terraform apply"
    "kubectl apply"
  )
else
  forbidden_patterns=()
fi

for path in "${required_paths[@]}"; do
  if [[ ! -e "${path}" ]]; then
    echo "Missing required path: ${path}" >&2
    missing=1
  fi
done

for path in "${required_files[@]}"; do
  if [[ ! -f "${path}" ]]; then
    echo "Missing required file: ${path}" >&2
    missing=1
  fi
done

for pattern in "${forbidden_patterns[@]}"; do
  if grep -R "${pattern}" . >/dev/null; then
    echo "ERROR: Forbidden pattern for role ${ROLE}: ${pattern}" >&2
    missing=1
  fi
done

if [[ "${ROLE}" == "foundation" ]]; then
  if ! grep -q "Arquitetura" README.md; then
    echo "README.md is missing the 'Arquitetura' section header." >&2
    missing=1
  fi
fi

if [[ ${missing} -ne 0 ]]; then
  echo "Architectural enforcement failed." >&2
  exit 1
fi

echo "Architectural enforcement passed."
