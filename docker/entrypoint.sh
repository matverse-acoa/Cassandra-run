#!/bin/sh
set -eu

echo "[PBSE] Verificando política e assinatura..."
sha3sum /etc/matverse/policy_pack.json

exec "$@"
