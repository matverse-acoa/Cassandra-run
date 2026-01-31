import argparse
import json
import os

import requests

from config import STATIC_TOKEN

BASE_URL = os.getenv("CAS_RUN_API_URL", "http://localhost:8080")


def main() -> None:
    parser = argparse.ArgumentParser(prog="matverse", description="Cassandra-run CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    submit_parser = subparsers.add_parser("submit", help="Submit a new event")
    submit_parser.add_argument("--payload", required=True, help="JSON payload")

    subparsers.add_parser("ledger", help="List all events in the ledger")

    proof_parser = subparsers.add_parser("proof", help="Get proofs for an event")
    proof_parser.add_argument("--event-id", type=int, required=True, help="Event ID")

    subparsers.add_parser("replay", help="Replay all events")

    args = parser.parse_args()

    headers = {"Authorization": f"Bearer {STATIC_TOKEN}"}

    if args.command == "submit":
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print("Invalid JSON payload")
            return
        response = requests.post(f"{BASE_URL}/submit", json=payload, headers=headers)
        print(json.dumps(response.json(), indent=2))

    elif args.command == "ledger":
        response = requests.get(f"{BASE_URL}/ledger", headers=headers)
        print(json.dumps(response.json(), indent=2))

    elif args.command == "proof":
        response = requests.get(f"{BASE_URL}/proof/{args.event_id}", headers=headers)
        print(json.dumps(response.json(), indent=2))

    elif args.command == "replay":
        response = requests.post(f"{BASE_URL}/replay", headers=headers)
        print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
