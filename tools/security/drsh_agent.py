#!/usr/bin/env python3
"""One independent agent that logs into a live DuetOS guest through DRSH.

This is intentionally separate from the protocol and OS attack suites.  The
agent owns a real authenticated DRSH shell session and runs an operator-
supplied command plan inside the guest.  The host campaign starts one process
per agent so the login/control boundary is exercised end to end.

DRSH v0 has one synchronous authenticated session, so callers must not run
multiple agents against the same guest concurrently.  drsh_host.py enforces
that rule for campaign runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from drsh_wire import DrshDisconnected, DrshProtocolError, DrshSession


PROFILES: dict[str, tuple[str, ...]] = {
    "recon": (
        "id",
        "ps",
        "netinfo",
        "firewall status",
        "drshd status",
    ),
    "operator": (
        "id",
        "policy show",
        "netinfo",
        "drshd status",
    ),
    "control": (
        "id",
        "echo DRSH_AGENT_CONTROLLED > /tmp/drsh-agent-marker",
        "cat /tmp/drsh-agent-marker",
        "firewall status",
        "drshd status",
    ),
}
CONTROL_PROFILES = frozenset({"control"})


def emit(jsonl: bool, event: str, **fields: object) -> None:
    record = {"event": event, **fields}
    if jsonl:
        print(json.dumps(record, sort_keys=True), flush=True)
        return

    if event == "command":
        status = "PASS" if fields.get("ok") else "FAIL"
        print(f"[{status}] {fields.get('command', '')}")
        output = str(fields.get("output", "")).rstrip()
        if output:
            print(output)
        error = fields.get("error")
        if error:
            print(f"error: {error}", file=sys.stderr)
        return

    if event == "login":
        print(f"[{('PASS' if fields.get('ok') else 'FAIL')}] login agent={fields.get('agent', '')}")
        if fields.get("error"):
            print(f"error: {fields['error']}", file=sys.stderr)
        return

    if event == "logout":
        print(f"[INFO] logout agent={fields.get('agent', '')}")
        return

    print(json.dumps(record, sort_keys=True))


def command_plan(args: argparse.Namespace) -> list[str]:
    commands: list[str] = []
    for command in args.command:
        if not command.strip():
            raise ValueError("--command cannot be empty")
        commands.append(command)

    if args.commands_file is not None:
        for raw_line in args.commands_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                commands.append(line)

    if args.profile:
        try:
            commands.extend(PROFILES[args.profile])
        except KeyError as error:
            raise ValueError(f"unknown profile {args.profile!r}; choose from {', '.join(sorted(PROFILES))}") from error

    if not commands and not sys.stdin.isatty():
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if line and not line.startswith("#"):
                commands.append(line)

    if not commands:
        raise ValueError("no commands supplied; use --profile, --command, --commands-file, or stdin")
    return commands


def connect(host: str, port: int, password: bytes, retries: int, retry_delay: float) -> DrshSession:
    last_error: BaseException | None = None
    for attempt in range(retries):
        try:
            session = DrshSession.connect(host, port, password, timeout=5.0)
            session.open_shell()
            return session
        except DrshProtocolError:
            # A protocol/authentication failure is deterministic; retrying it
            # only adds noise and can trip the guest's lockout policy.
            raise
        except (DrshDisconnected, OSError) as error:
            last_error = error
            if attempt + 1 < retries:
                time.sleep(retry_delay)
    assert last_error is not None
    raise last_error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one real authenticated DRSH agent session")
    parser.add_argument("--agent", default=os.environ.get("DRSH_AGENT", "agent"), help="stable agent name for logs")
    parser.add_argument("--host", default=os.environ.get("DRSH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRSH_PORT", "4322")))
    parser.add_argument("--password", default=os.environ.get("DRSH_PASSWORD", "test"), help=argparse.SUPPRESS)
    parser.add_argument("--profile", choices=sorted(PROFILES), help="built-in non-destructive command plan")
    parser.add_argument("--command", action="append", default=[], help="guest shell command; may be repeated")
    parser.add_argument("--commands-file", type=Path, help="UTF-8 file containing one guest command per line")
    parser.add_argument("--connect-retries", type=int, default=8)
    parser.add_argument("--retry-delay", type=float, default=1.0)
    parser.add_argument("--command-timeout", type=float, default=10.0)
    parser.add_argument("--max-output", type=int, default=16_384, help="cap captured output per command")
    parser.add_argument("--jsonl", action="store_true", help="emit machine-readable event records")
    parser.add_argument("--allow-guest-control", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help="validate and print the plan without logging in")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.connect_retries < 1 or args.retry_delay < 0 or args.command_timeout <= 0 or args.max_output < 1:
        print("invalid retry, timeout, or output limits", file=sys.stderr)
        return 2
    custom_input = bool(args.command or args.commands_file or (args.profile is None and not sys.stdin.isatty()))
    if (custom_input or args.profile in CONTROL_PROFILES) and not args.allow_guest_control:
        print(
            "custom or control DRSH commands require --allow-guest-control; use a safe built-in profile by default",
            file=sys.stderr,
        )
        return 2

    try:
        commands = command_plan(args)
    except (OSError, ValueError) as error:
        print(f"plan error: {error}", file=sys.stderr)
        return 2

    if args.dry_run:
        for index, command in enumerate(commands, start=1):
            emit(args.jsonl, "planned_command", agent=args.agent, index=index, command=command)
        return 0

    session: DrshSession | None = None
    try:
        session = connect(args.host, args.port, args.password.encode("utf-8"), args.connect_retries, args.retry_delay)
        emit(args.jsonl, "login", agent=args.agent, host=args.host, port=args.port, ok=True)
        for command in commands:
            try:
                output = session.run_shell_command(command, timeout=args.command_timeout)
                if len(output) > args.max_output:
                    output = output[: args.max_output] + "\n[agent output truncated]"
                emit(args.jsonl, "command", agent=args.agent, command=command, ok=True, output=output)
            except (DrshDisconnected, DrshProtocolError, OSError) as error:
                emit(args.jsonl, "command", agent=args.agent, command=command, ok=False, output="", error=str(error))
                return 1
    except (DrshDisconnected, DrshProtocolError, OSError, RuntimeError) as error:
        emit(args.jsonl, "login", agent=args.agent, host=args.host, port=args.port, ok=False, error=str(error))
        return 1
    finally:
        if session is not None:
            session.close()
        emit(args.jsonl, "logout", agent=args.agent)

    return 0


if __name__ == "__main__":
    sys.exit(main())
