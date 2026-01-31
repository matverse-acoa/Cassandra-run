#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser(description="Sign and anchor a coherence proof via cosign.")
    parser.add_argument("proof_path", help="Path to coherence proof JSON")
    args = parser.parse_args()

    proof = Path(args.proof_path)
    if not proof.exists():
        raise SystemExit(f"Proof not found: {proof}")

    signature = proof.with_suffix(proof.suffix + ".sig")
    certificate = proof.with_suffix(proof.suffix + ".crt")

    subprocess.run(
        [
            "cosign",
            "sign-blob",
            "--yes",
            "--output-signature",
            str(signature),
            "--output-certificate",
            str(certificate),
            str(proof),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
