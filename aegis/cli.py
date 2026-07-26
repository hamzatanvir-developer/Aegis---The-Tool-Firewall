"""Command line interface for Aegis."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from aegis.db import DB_FILE
from aegis.dashboard import run_dashboard

DEFAULT_POLICY_YAML = """version: "1.0"
policies:
  - name: block_destructive_sql
    enabled: true
  - name: block_destructive_shell
    enabled: true
  - name: redact_pii
    enabled: true
"""


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _validate_policy_document(document: Any) -> list[str]:
    errors: list[str] = []

    if not isinstance(document, dict):
        return ["guardrails.yaml must contain a top-level mapping"]

    if not isinstance(document.get("version"), str):
        errors.append("Missing or invalid 'version' field")

    policies = document.get("policies")
    if not isinstance(policies, list) or not policies:
        errors.append("Missing or invalid 'policies' list")
        return errors

    for index, policy in enumerate(policies):
        if not isinstance(policy, dict):
            errors.append(f"Policy #{index + 1} must be a mapping")
            continue

        if not isinstance(policy.get("name"), str) or not policy["name"].strip():
            errors.append(f"Policy #{index + 1} is missing a valid 'name'")

        if not isinstance(policy.get("enabled"), bool):
            errors.append(f"Policy #{index + 1} is missing a valid 'enabled' boolean")

    return errors


def _print_errors(errors: Iterable[str]) -> None:
    for error in errors:
        print(f"ERROR: {error}")


def init_command(config_path: Path) -> int:
    if config_path.exists():
        print(f"{config_path.name} already exists")
        return 0

    config_path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    print(f"Created {config_path.name}")
    return 0


def check_command(config_path: Path) -> int:
    try:
        document = _load_yaml(config_path)
    except FileNotFoundError:
        print(f"ERROR: {config_path} not found")
        return 2
    except yaml.YAMLError as exc:
        print(f"ERROR: Invalid YAML: {exc}")
        return 2

    errors = _validate_policy_document(document)
    if errors:
        _print_errors(errors)
        return 1

    print(f"{config_path.name} is valid")
    return 0


def status_command(db_path: Path = Path(DB_FILE)) -> int:
    try:
        with sqlite3.connect(db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total = int(cursor.fetchone()[0])
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE verdict = 'ALLOW'")
            allow_count = int(cursor.fetchone()[0])
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE verdict = 'BLOCK'")
            block_count = int(cursor.fetchone()[0])
    except sqlite3.Error as exc:
        print(f"ERROR: Unable to read audit metrics: {exc}")
        return 1

    print("Aegis Status")
    print(f"Total tool invocations: {total}")
    print(f"ALLOW count: {allow_count}")
    print(f"BLOCK count: {block_count}")
    return 0


def dashboard_command(port: int, db_path: Path) -> int:
    run_dashboard(port=port, db_path=str(db_path))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis security firewall CLI")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser("init", help="Create a default guardrails.yaml")
    init_parser.add_argument("path", nargs="?", default="guardrails.yaml")

    check_parser = subcommands.add_parser("check", help="Validate a guardrails.yaml file")
    check_parser.add_argument("path", nargs="?", default="guardrails.yaml")

    status_parser = subcommands.add_parser("status", help="Show audit log metrics")
    status_parser.add_argument("--db", default=DB_FILE, help="Path to the local audit database")

    dashboard_parser = subcommands.add_parser("dashboard", help="Launch the inspection dashboard")
    dashboard_parser.add_argument("--port", type=int, default=8000, help="Port to bind the dashboard to")
    dashboard_parser.add_argument("--db", default=DB_FILE, help="Path to the local audit database")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return init_command(Path(args.path))
    if args.command == "check":
        return check_command(Path(args.path))
    if args.command == "status":
        return status_command(Path(args.db))
    if args.command == "dashboard":
        return dashboard_command(args.port, Path(args.db))

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())