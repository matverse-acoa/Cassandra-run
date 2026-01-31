#!/usr/bin/env bash
set -euo pipefail

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

if ! rg -q "^## Arquitetura$" README.md; then
  echo "README.md is missing the 'Arquitetura' section header." >&2
  missing=1
fi

if [[ ${missing} -ne 0 ]]; then
  echo "Architectural enforcement failed." >&2
  exit 1
fi

echo "Architectural enforcement passed."
