#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deploy_script="${repo_root}/deploy-production.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
mock_bin="${tmp_dir}/bin"
mkdir -p "${mock_bin}"
export TEST_LOG="${tmp_dir}/commands.log"
: > "${TEST_LOG}"

write_mock() {
    local target="$1"
    shift
    printf '%s\n' "$@" > "${target}"
    chmod +x "${target}"
}

write_mock "${mock_bin}/systemctl" \
    '#!/usr/bin/env bash' \
    'exit 0'
write_mock "${mock_bin}/curl" \
    '#!/usr/bin/env bash' \
    'printf "healthy\\n"'
write_mock "${mock_bin}/journalctl" \
    '#!/usr/bin/env bash' \
    'exit 0'
write_mock "${mock_bin}/docker" \
    '#!/usr/bin/env bash' \
    'printf "%s\\n" "$*" >> "${TEST_LOG}"' \
    'exit 0'
write_mock "${mock_bin}/kubectl" \
    '#!/usr/bin/env bash' \
    'printf "%s\\n" "$*" >> "${TEST_LOG}"' \
    'if [[ "${1:-}" == "create" ]]; then printf "apiVersion: v1\\nkind: Secret\\n"; fi' \
    'if [[ "${1:-}" == "apply" && "${2:-}" == "-f" && "${3:-}" == "-" ]]; then while IFS= read -r _; do :; done; fi' \
    'exit 0'

export PATH="${mock_bin}:${PATH}"
source "${deploy_script}"

DEPLOY_MODE=systemd
validate_deployment > /dev/null

DEPLOY_MODE=docker
check_requirements > /dev/null

work_dir="${tmp_dir}/docker"
mkdir -p "${work_dir}"
pushd "${work_dir}" > /dev/null
deploy_docker > /dev/null
[[ ! -e docker-compose.yml ]]
popd > /dev/null

deploy_kubernetes > /dev/null
grep -q -- '--dry-run=client -o yaml' "${TEST_LOG}"
grep -q -- 'apply -f -' "${TEST_LOG}"
grep -Fxq '.secrets/' "${repo_root}/.gitignore"
grep -Fxq 'docker-compose.yml' "${repo_root}/.gitignore"

printf 'deploy-production.sh checks passed\n'
