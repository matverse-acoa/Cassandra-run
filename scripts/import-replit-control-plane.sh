#!/usr/bin/env bash
# Imports a Replit pnpm workspace into a reviewable Cassandra staging directory.
# Usage: bash scripts/import-replit-control-plane.sh /path/to/Asset-Management-System [--check]
set -euo pipefail

SOURCE_ROOT="${1:-}"
MODE="${2:-}"
DESTINATION="imports/replit-asset-management-system"

if [[ -z "$SOURCE_ROOT" ]]; then
  echo "Usage: bash scripts/import-replit-control-plane.sh /path/to/Asset-Management-System [--check]" >&2
  exit 64
fi

if [[ ! -f "$SOURCE_ROOT/package.json" || ! -f "$SOURCE_ROOT/pnpm-workspace.yaml" ]]; then
  echo "Source does not look like the expected Replit pnpm workspace." >&2
  exit 65
fi

if [[ "$MODE" == "--check" ]]; then
  echo "Source: $SOURCE_ROOT"
  echo "Destination: $DESTINATION"
  echo "Included roots: artifacts/api-server artifacts/cassandra-dashboard lib/api-client-react lib/api-spec lib/api-zod lib/db scripts"
  echo "Excluded: .git .local node_modules dist .tsbuildinfo attached_assets mockup-sandbox .replit-artifact"
  exit 0
fi

rm -rf "$DESTINATION"
mkdir -p "$DESTINATION"

copy_path() {
  local path="$1"
  if [[ -e "$SOURCE_ROOT/$path" ]]; then
    mkdir -p "$DESTINATION/$(dirname "$path")"
    rsync -a \
      --exclude='.git' \
      --exclude='.local' \
      --exclude='node_modules' \
      --exclude='dist' \
      --exclude='*.tsbuildinfo' \
      --exclude='attached_assets' \
      --exclude='mockup-sandbox' \
      --exclude='.replit-artifact' \
      "$SOURCE_ROOT/$path" "$DESTINATION/$(dirname "$path")/"
  fi
}

for path in \
  artifacts/api-server \
  artifacts/cassandra-dashboard \
  lib/api-client-react \
  lib/api-spec \
  lib/api-zod \
  lib/db \
  scripts \
  package.json \
  pnpm-lock.yaml \
  pnpm-workspace.yaml \
  tsconfig.json \
  tsconfig.base.json \
  .npmrc \
  .replit \
  replit.md; do
  copy_path "$path"
done

find "$DESTINATION" -type f -print0 | sort -z | xargs -0 sha256sum > "$DESTINATION/SOURCE_MANIFEST.sha256"

cat > "$DESTINATION/IMPORT_METADATA.json" <<'JSON'
{
  "migration_id": "cassandra-control-plane-v0.1",
  "source_kind": "replit-pnpm-workspace",
  "strategy": "preserve-first-refactor-later",
  "next_step": "Run pnpm install --frozen-lockfile, pnpm run typecheck, and pnpm run build from the staging root."
}
JSON

echo "Imported into $DESTINATION"
echo "Review changes, then commit them on import/cassandra-control-plane-v0.1."
