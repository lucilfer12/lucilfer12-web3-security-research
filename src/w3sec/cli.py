from __future__ import annotations
import argparse
from pathlib import Path
from .validator import validate_repo
def main() -> int:
    parser = argparse.ArgumentParser(prog="w3sec", description="Web3 security research utilities")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="validate structured research records")
    v.add_argument("path", nargs="?", default=".")
    args = parser.parse_args()
    if args.command == "validate":
        errors = validate_repo(Path(args.path))
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
            return 1
        print("Research validation: OK")
        return 0
    return 2