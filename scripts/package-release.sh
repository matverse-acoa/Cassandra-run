#!/bin/bash
# package-release.sh
# Empacota release do Cassandra-run com manifesto e hash

set -euo pipefail

VERSION="${1:-v1.0.0}"
RELEASE_NAME="${RELEASE_NAME:-cassandra-run-pbse-${VERSION}}"
OUTPUT_ZIP="${OUTPUT_ZIP:-${RELEASE_NAME}.zip}"
MANIFEST_FILE="${MANIFEST_FILE:-MANIFEST.sha3}"
RELEASE_FILE="${RELEASE_FILE:-RELEASE.txt}"
RELEASE_ITEMS="${RELEASE_ITEMS:-runtime docker systemd etc}"

log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

ensure_tools() {
    local tools=(zip sha3sum)
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Ferramenta ausente: $tool"
            exit 1
        fi
    done
}

ensure_items_exist() {
    local missing=()
    for item in ${RELEASE_ITEMS}; do
        if [[ ! -e "$item" ]]; then
            missing+=("$item")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Itens ausentes para empacotamento: ${missing[*]}"
        log_error "Defina RELEASE_ITEMS para ajustar a lista."
        exit 1
    fi
}

package_release() {
    log_info "Empacotando release ${RELEASE_NAME}"
    zip -r "${OUTPUT_ZIP}" ${RELEASE_ITEMS}
    sha3sum "${OUTPUT_ZIP}" > "${MANIFEST_FILE}"
    echo "MatVerse Cassandra-Run PBSE Runtime ${VERSION} — $(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        > "${RELEASE_FILE}"
    log_info "Artefato gerado: ${OUTPUT_ZIP}"
    log_info "Manifesto gerado: ${MANIFEST_FILE}"
    log_info "Release notes geradas: ${RELEASE_FILE}"
}

main() {
    ensure_tools
    ensure_items_exist
    package_release
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
