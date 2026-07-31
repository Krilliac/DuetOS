#!/usr/bin/env python3
"""Host a throwaway DuetOS guest and run real DRSH agent workers.

The existing drsh_attack.py and drsh_os_attack.py exercise protocol and
shell-vector assertions.  This launcher tests a different boundary: it boots
an isolated QEMU guest with the test-only DRSH listener enabled, then starts
independent drsh_agent.py processes that authenticate and control the guest
through the forwarded TCP service.

DRSH admits a bounded set of independent authenticated sessions. Agents are
therefore launched as separate concurrent processes; each performs its own
login, command execution, and logout. The host forward is loopback-only by
default and the guest is torn down by default when the campaign ends.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = REPO_ROOT / "tools" / "qemu" / "run.sh"
AGENT_SCRIPT = REPO_ROOT / "tools" / "security" / "drsh_agent.py"
DRSH_HOST = "127.0.0.1"


DEFAULT_PLAN = (
    {"name": "recon-agent", "profile": "recon"},
    {"name": "operator-agent", "profile": "operator"},
)
BUILTIN_PROFILES = frozenset({"recon", "operator", "control"})
CONTROL_PROFILES = frozenset({"control"})


@dataclass(frozen=True)
class AgentSpec:
    name: str
    profile: str | None = None
    commands: tuple[str, ...] = ()


class CampaignError(RuntimeError):
    """The guest campaign could not be started or completed."""


def choose_port(requested: int) -> int:
    if requested:
        if not 1 <= requested <= 65_535:
            raise CampaignError("--host-port must be between 1 and 65535")
        return requested
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((DRSH_HOST, 0))
        return int(probe.getsockname()[1])


def git_bash() -> str:
    override = os.environ.get("DUETOS_GIT_BASH")
    if override:
        return override
    if os.name == "nt":
        candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
        if candidate.exists():
            return str(candidate)
        raise CampaignError(
            "Git Bash is required to launch tools/qemu/run.sh on Windows; "
            "set DUETOS_GIT_BASH to its bash.exe path"
        )
    return shutil.which("bash") or "/bin/bash"


def load_plan(path: Path | None) -> tuple[AgentSpec, ...]:
    if path is None:
        raw_plan = list(DEFAULT_PLAN)
    else:
        try:
            raw_plan = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CampaignError(f"cannot read agent plan {path}: {error}") from error
    if not isinstance(raw_plan, list) or not raw_plan:
        raise CampaignError("agent plan must be a non-empty JSON array")

    specs: list[AgentSpec] = []
    for index, item in enumerate(raw_plan):
        if not isinstance(item, dict):
            raise CampaignError(f"agent plan entry {index} must be an object")
        name = item.get("name")
        profile = item.get("profile")
        commands = item.get("commands", [])
        if not isinstance(name, str) or not name.strip():
            raise CampaignError(f"agent plan entry {index} has no non-empty name")
        if profile is not None and (not isinstance(profile, str) or not profile.strip()):
            raise CampaignError(f"agent {name!r} has an invalid profile")
        if profile is not None and profile not in BUILTIN_PROFILES:
            raise CampaignError(f"agent {name!r} has unknown profile {profile!r}")
        if not isinstance(commands, list) or any(
            not isinstance(command, str) or not command.strip() for command in commands
        ):
            raise CampaignError(f"agent {name!r} commands must be non-empty strings")
        if profile is None and not commands:
            raise CampaignError(f"agent {name!r} has neither profile nor commands")
        specs.append(AgentSpec(name.strip(), profile, tuple(commands)))
    return tuple(specs)


def validate_plan(specs: tuple[AgentSpec, ...], guest_control: bool) -> None:
    unknown_profiles = [
        spec.profile for spec in specs if spec.profile is not None and spec.profile not in BUILTIN_PROFILES
    ]
    if unknown_profiles:
        raise CampaignError(f"unknown built-in profile(s): {', '.join(sorted(set(unknown_profiles)))}")
    if not guest_control:
        control_profiles = [spec.name for spec in specs if spec.profile in CONTROL_PROFILES]
        if control_profiles:
            joined = ", ".join(control_profiles)
            raise CampaignError(f"control profile for {joined} requires --i-understand-guest-control")
    custom = [spec.name for spec in specs if spec.commands]
    if custom and not guest_control:
        joined = ", ".join(custom)
        raise CampaignError(
            f"custom guest commands for {joined} require --i-understand-guest-control; "
            "built-in profiles remain available without that flag"
        )


def build_agent_command(spec: AgentSpec, host: str, port: int, jsonl: bool, allow_control: bool) -> list[str]:
    command = [
        sys.executable,
        str(AGENT_SCRIPT),
        "--agent",
        spec.name,
        "--host",
        host,
        "--port",
        str(port),
    ]
    if spec.profile:
        command.extend(["--profile", spec.profile])
    for guest_command in spec.commands:
        command.extend(["--command", guest_command])
    if jsonl:
        command.append("--jsonl")
    if allow_control:
        # Forward the explicit authorization to the child. The password stays
        # in the environment and is never placed in argv or in a log line.
        command.append("--allow-guest-control")
    return command


def drsh_autostart_enabled(cache: Path) -> bool:
    if not cache.exists():
        return False
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("DUETOS_DRSH_AUTOSTART:BOOL="):
            return line.rsplit("=", 1)[-1] == "ON"
    return False


def wait_for_drsh_ready(process: subprocess.Popen[bytes], serial_log: Path, timeout: float) -> None:
    marker = "listening on TCP port"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CampaignError(f"QEMU exited before DRSH became reachable (exit={process.returncode})")
        if serial_log.exists():
            try:
                # COM1 is configured as an unbuffered QEMU file sink. Read a
                # bounded tail so a long boot log cannot make readiness polling
                # grow without limit.
                with serial_log.open("rb") as stream:
                    stream.seek(max(0, serial_log.stat().st_size - 131_072))
                    if marker in stream.read().decode("utf-8", errors="replace"):
                        return
            except OSError:
                pass
        time.sleep(0.25)
    raise CampaignError(f"timed out waiting for the guest DRSH readiness marker in {serial_log}")


def terminate_guest(process: subprocess.Popen[bytes], grace_seconds: float) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=grace_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Boot DuetOS and run real authenticated DRSH agents")
    parser.add_argument("--preset", default=os.environ.get("DUETOS_PRESET", "x86_64-debug"))
    parser.add_argument("--host-port", type=int, default=0, help="loopback DRSH port; 0 chooses a free port")
    parser.add_argument("--password", default=os.environ.get("DRSH_PASSWORD", "test"), help=argparse.SUPPRESS)
    parser.add_argument("--plan", type=Path, help="JSON array of {name, profile?, commands?} agent specs")
    parser.add_argument(
        "--agent",
        action="append",
        dest="agent_names",
        metavar="NAME[:PROFILE]",
        help="run one built-in agent; profile defaults to recon; repeatable",
    )
    parser.add_argument(
        "--i-understand-guest-control",
        action="store_true",
        help="allow custom commands that can mutate or stop the guest",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        help="bind the QEMU host forward on all host interfaces (high risk; default is loopback)",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="configure/build with DUETOS_DRSH_AUTOSTART=ON before booting",
    )
    parser.add_argument("--connect-only", action="store_true", help="use an already-running loopback DRSH guest")
    parser.add_argument("--boot-timeout", type=float, default=120.0)
    parser.add_argument("--guest-timeout", type=float, default=900.0)
    parser.add_argument("--keep-guest", action="store_true", help="leave QEMU running after agents finish")
    parser.add_argument("--log-dir", type=Path, help="directory for serial, QEMU, and agent logs")
    parser.add_argument("--jsonl", action="store_true", help="request JSONL agent logs")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the plan and print the campaign without starting QEMU",
    )
    return parser.parse_args()


def make_plan(args: argparse.Namespace) -> tuple[AgentSpec, ...]:
    specs = load_plan(args.plan)
    if args.agent_names:
        parsed: list[AgentSpec] = []
        for raw in args.agent_names:
            name, separator, profile = raw.partition(":")
            if not name.strip() or (separator and not profile.strip()):
                raise CampaignError(f"invalid --agent {raw!r}; expected NAME[:PROFILE]")
            parsed.append(AgentSpec(name.strip(), profile.strip() if separator else "recon"))
        specs = tuple(parsed)
    validate_plan(specs, args.i_understand_guest_control)
    return specs


def main() -> int:
    args = parse_args()
    try:
        if args.boot_timeout <= 0 or args.guest_timeout <= 0:
            raise CampaignError("timeouts must be positive")
        if args.build and not args.connect_only and not args.dry_run and os.name == "nt":
            raise CampaignError(
                "--build must run inside a WSL-native DuetOS checkout; sync this Windows tree with "
                "tools/build/sync-to-wsl-scratch.sh, then invoke drsh_host.py from WSL"
            )
        specs = make_plan(args)
        port = choose_port(args.host_port)
        if args.dry_run:
            print(f"DRSH endpoint: {DRSH_HOST}:{port}")
            for index, spec in enumerate(specs, start=1):
                target = spec.profile or f"{len(spec.commands)} custom command(s)"
                print(f"agent {index}: {spec.name} -> {target}")
            return 0
        build_dir = REPO_ROOT / "build" / args.preset
        cache = build_dir / "CMakeCache.txt"
        iso = build_dir / "duetos.iso"
        if not args.connect_only:
            if not RUN_SCRIPT.exists():
                raise CampaignError(f"missing QEMU launcher: {RUN_SCRIPT}")
            if not args.build and (not cache.exists() or not iso.exists()):
                raise CampaignError(
                    f"{build_dir} is not bootable; configure/build first, or pass --build"
                )
            if cache.exists() and not args.build:
                if not drsh_autostart_enabled(cache):
                    raise CampaignError(
                        "the selected build has DUETOS_DRSH_AUTOSTART=OFF; rerun with --build "
                        "or configure that option explicitly"
                    )
        log_dir = args.log_dir or Path(tempfile.mkdtemp(prefix="duetos-drsh-campaign-"))
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"campaign logs: {log_dir}")
        print(f"DRSH endpoint: {DRSH_HOST}:{port}")
        print(f"agents: {', '.join(spec.name for spec in specs)}")

        if args.build and not args.connect_only:
            print("[host] configuring DUETOS_DRSH_AUTOSTART=ON")
            subprocess.run(
                ["cmake", "--preset", args.preset, "-DDUETOS_DRSH_AUTOSTART=ON"],
                cwd=REPO_ROOT,
                check=True,
            )
            subprocess.run(["cmake", "--build", str(build_dir)], cwd=REPO_ROOT, check=True)
            if not drsh_autostart_enabled(cache) or not iso.exists():
                raise CampaignError(f"DRSH build completed without a bootable ISO in {build_dir}")

        guest: subprocess.Popen[bytes] | None = None
        guest_log = log_dir / "guest.log"
        guest_log_handle = None
        try:
            if not args.connect_only:
                env = os.environ.copy()
                env.update(
                    {
                        "DUETOS_PRESET": args.preset,
                        "DUETOS_DRSH_HOST_PORT": str(port),
                        "DUETOS_DRSH_ALLOW_EXTERNAL": "1" if args.allow_external else "0",
                        "DUETOS_DISPLAY": "none",
                        "DUETOS_GDB_TRANSPORT": "pty",
                        "DUETOS_QMP": "0",
                        "DUETOS_TIMEOUT": str(args.guest_timeout),
                        "DUETOS_SERIAL_FILE": str((log_dir / "serial.log").resolve()),
                    }
                )
                guest_log_handle = guest_log.open("wb")
                print("[host] starting QEMU")
                guest = subprocess.Popen(
                    [git_bash(), "tools/qemu/run.sh"],
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=guest_log_handle,
                    stderr=subprocess.STDOUT,
                )
                wait_for_drsh_ready(guest, log_dir / "serial.log", args.boot_timeout)
                time.sleep(0.5)

            failures = 0
            child_env = os.environ.copy()
            child_env["DRSH_PASSWORD"] = args.password
            children = []
            for index, spec in enumerate(specs, start=1):
                agent_log = log_dir / f"agent-{index:02d}-{spec.name}.log"
                print(f"[host] starting {spec.name} ({index}/{len(specs)})")
                output = agent_log.open("wb")
                try:
                    child = subprocess.Popen(
                        build_agent_command(
                            spec,
                            DRSH_HOST,
                            port,
                            args.jsonl,
                            args.i_understand_guest_control,
                        ),
                        cwd=REPO_ROOT,
                        env=child_env,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                    )
                except Exception:
                    output.close()
                    raise
                children.append((index, spec, child, output, agent_log))

            # Keep every agent as an independent process, but wait only after
            # all have been published so the guest exercises real concurrent
            # DRSH sessions rather than a serialized worker queue.
            for index, spec, child, output, agent_log in children:
                returncode = child.wait()
                output.close()
                print(f"[host] {spec.name} exit={returncode} log={agent_log}")
                if returncode != 0:
                    failures += 1

            print(f"CAMPAIGN SUMMARY agents={len(specs)} failures={failures} endpoint={DRSH_HOST}:{port}")
            return 1 if failures else 0
        finally:
            if guest_log_handle is not None:
                guest_log_handle.close()
            if guest is not None and not args.keep_guest:
                print("[host] stopping QEMU")
                terminate_guest(guest, grace_seconds=5.0)
            elif guest is not None:
                print(f"[host] keeping QEMU alive at {DRSH_HOST}:{port} (pid={guest.pid})")
    except (CampaignError, OSError, subprocess.CalledProcessError) as error:
        print(f"CAMPAIGN FAILED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
