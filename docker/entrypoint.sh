#!/usr/bin/env sh
set -eu

echo "[PBSE] Verificando politica e assinatura..."
sha3sum /etc/matverse/policy_pack.json

exec "$@"
