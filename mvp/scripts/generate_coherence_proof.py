#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime, timezone

def _run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def main() -> None:
    git_sha = os.getenv("GITHUB_SHA") or _run(["git", "rev-parse", "HEAD"])
    git_ref = os.getenv("GITHUB_REF", "")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    tree_hash = _run(["git", "rev-parse", f"{git_sha}^{{tree}}"])

    payload = {
        "schema": "cassandra-run.coherence-proof.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git": {
            "ref": git_ref,
            "sha": git_sha,
            "tree": tree_hash,
        },
        "repo": repo,
        "ci": {
            "run_id": run_id,
        },
    }

    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
