# Cassandra Control Plane v0.1 — Migration Gate

This branch stages the migration of the Replit Asset Management System into the Cassandra repository without modifying `main`.

## Objective

Preserve the original Replit pnpm workspace first, validate it, and only then refactor it into the canonical Cassandra topology.

```text
Replit source workspace
  -> imports/replit-asset-management-system
  -> CI: install, typecheck, build
  -> reviewable pull request
  -> canonical extraction

Canonical extraction
  artifacts/api-server          -> services/replit-api
  artifacts/cassandra-dashboard -> apps/replit-dashboard
  lib/api-spec                  -> packages/api-spec
  lib/api-client-react          -> packages/api-client-react
  lib/api-zod                   -> packages/api-zod
  lib/db                        -> packages/db
```

## Safety boundaries

- Do not import `.git`, `.local`, `node_modules`, `dist`, `.tsbuildinfo`, `attached_assets`, or `.replit-artifact`.
- Preserve `pnpm-lock.yaml` and source configuration so the staged source can be reproduced.
- Treat build success as implementation evidence only; it does not establish scientific truth, production readiness, or replay completeness.
- Any remote LLM adapter remains optional and must not authorize external execution.

## Local command

```bash
bash scripts/import-replit-control-plane.sh /path/to/Asset-Management-System --check
bash scripts/import-replit-control-plane.sh /path/to/Asset-Management-System
```

The import generates `SOURCE_MANIFEST.sha256` and `IMPORT_METADATA.json` inside the staging root. CI then runs `pnpm install --frozen-lockfile`, `pnpm run typecheck`, and `pnpm run build`.

## Merge gate

Before merging into `main`, verify:

1. The staging CI is green.
2. The source manifest has no unexpected files.
3. No secrets, conversation attachments, local runtime caches, or generated distributions are present.
4. The control-plane contracts identify OG1, OG2, OG3 and the states `PASS`, `HOLD`, `BLOCK`, and `ESCALATE`.
5. The resulting API exposes evidence and receipts as integrity records, not claims of truth.
