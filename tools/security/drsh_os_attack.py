#!/usr/bin/env python3
"""DRSH authenticated OS probe harness.

This script intentionally reuses drsh_wire.py for the protocol and crypto
contract.  Its default vector is non-destructive network/status probing.  Any
vector that can mutate guest state, expose sensitive data, exhaust resources,
or reboot/panic the guest requires --i-understand-destructive.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from drsh_wire import DrshDisconnected, DrshProtocolError, DrshSession


@dataclass(frozen=True)
class Probe:
    command: str
    title: str
    destructive: bool = False
    sensitive: bool = False
    timeout: float = 10.0


@dataclass
class Finding:
    vector: str
    severity: str
    title: str
    detail: str = ""


class Shell:
    def __init__(self, host: str, port: int, password: bytes) -> None:
        self.session = DrshSession.connect(host, port, password, timeout=5.0)
        self.session.open_shell()

    def run(self, command: str, timeout: float = 3.0) -> str:
        return self.session.run_shell_command(command, timeout=timeout)

    def close(self) -> None:
        self.session.close()


def add(findings: list[Finding], vector: str, severity: str, title: str, detail: str = "") -> None:
    findings.append(Finding(vector, severity, title, detail))
    print(f"  {severity}: {title}")
    if detail:
        for line in detail.strip().splitlines()[:3]:
            print(f"    {line[:180]}")


BLOCKED_MARKERS = (
    "denied",
    "error",
    "failed",
    "force  to proceed",
    "command not found",
    "no such",
    "only /tmp",
    "outside 1 gib direct map",
    "protected",
    "refused",
    "unknown",
    "usage",
)


def response_indicates_blocked(response: str) -> bool:
    lower = response.lower()
    return any(marker in lower for marker in BLOCKED_MARKERS)


def run_probe_vector(shell: Shell, vector: str, probes: list[Probe], findings: list[Finding]) -> bool:
    print(f"\n[OS-PROBE] {vector}")
    for probe in probes:
        try:
            response = shell.run(probe.command, timeout=probe.timeout)
        except (DrshDisconnected, DrshProtocolError, OSError) as error:
            if probe.destructive:
                add(
                    findings,
                    vector,
                    "HIGH",
                    f"destructive command disrupted DRSH session: {probe.command}",
                    str(error),
                )
                return False
            raise
        blocked = response_indicates_blocked(response)
        if vector == "escape" and probe.destructive and response.strip():
            # Command-injection probes that return a normal shell error, a
            # literal echo, or a directory listing did not execute the embedded
            # reboot/halt/panic payload. If one of those payloads actually
            # fires, the probe normally ends as a timeout/disconnect and is
            # classified by the exception path above.
            snippet = response.strip().replace("\n", " ")[:160]
            add(findings, vector, "INFO", f"{probe.command}: {snippet}")
        elif probe.destructive and response.strip() and not blocked:
            add(findings, vector, "HIGH", f"destructive command may have succeeded: {probe.command}", response)
        elif probe.sensitive and response.strip() and not blocked:
            add(findings, vector, "MEDIUM", f"sensitive probe returned data: {probe.command}", response)
        else:
            snippet = response.strip().replace("\n", " ")[:160]
            add(findings, vector, "INFO", f"{probe.command}: {snippet}")
    return True


SAFE_VECTORS: dict[str, list[Probe]] = {
    "network": [
        Probe("ifconfig", "interface listing"),
        Probe("arp", "ARP table"),
        Probe("netinfo", "network status"),
        Probe("firewall status", "firewall status"),
        Probe("ping 127.0.0.1", "loopback ping"),
        Probe("drshd status", "DRSH daemon status"),
    ],
}


DESTRUCTIVE_VECTORS: dict[str, list[Probe]] = {
    "memory": [
        Probe("peek 0xffffffff80200000", "kernel text read", sensitive=True),
        Probe("peek 0x0", "null page read", sensitive=True),
        Probe("memdump 0xffffffff80200000 64", "kernel memory dump", sensitive=True),
        Probe("vtop 0xffffffff80200000", "kernel VA to physical mapping", sensitive=True),
        Probe("poke 0xffffffff80200000 0x90", "kernel text write", destructive=True),
        Probe("poke 0x0 0x41414141", "null write", destructive=True),
    ],
    "registers": [
        Probe("cr", "control register dump", sensitive=True),
        Probe("rflags", "RFLAGS dump", sensitive=True),
        Probe("msr 0x1B", "APIC_BASE MSR read", sensitive=True),
        Probe("msr 0xC0000080", "EFER MSR read", sensitive=True),
        Probe("wrmsr 0xC0000080 0", "clear EFER", destructive=True),
        Probe("wrmsr 0x1B 0", "clear APIC base", destructive=True),
    ],
    "filesystem": [
        Probe("ls /", "root listing", sensitive=True),
        Probe("cat /etc/passwd", "password file read", sensitive=True),
        Probe("cat /../../../etc/shadow", "path traversal read", sensitive=True),
        Probe("touch /test_attack_file", "root file create", destructive=True),
        Probe("echo PWNED > /test_attack_file", "root file write", destructive=True),
        Probe("rm /boot/kernel", "boot artifact removal", destructive=True),
        Probe("dd if=/dev/zero of=/dev/sda bs=512 count=1", "block device overwrite", destructive=True),
    ],
    "process": [
        Probe("ps", "process listing", sensitive=True),
        Probe("kill 1", "kill init", destructive=True),
        Probe("kill 0", "kill current group", destructive=True),
        Probe("spawn /bin/sh", "spawn shell", destructive=True),
    ],
    "auth": [
        Probe("whoami", "identity", sensitive=True),
        Probe("id", "identity detail", sensitive=True),
        Probe("groups", "group detail", sensitive=True),
        Probe("passwd root newpassword", "password mutation", destructive=True),
        Probe("useradd attacker", "user creation", destructive=True),
        Probe("su root", "privilege escalation", destructive=True),
    ],
    "hardware": [
        Probe("lspci", "PCI listing", sensitive=True),
        Probe("lapic", "LAPIC status", sensitive=True),
        Probe("io inb 0x3F8", "I/O port read", sensitive=True),
        Probe("io outb 0x3F8 0x41", "serial port write", destructive=True),
        Probe("io outb 0x64 0xFE", "keyboard controller reset", destructive=True),
    ],
    "debug": [
        Probe("kdbg status", "kernel debugger status", sensitive=True),
        Probe("bp list", "breakpoint listing", sensitive=True),
        Probe("fault-inject list", "fault injection listing", sensitive=True),
        Probe("fault-inject enable slab-oom", "enable slab OOM injection", destructive=True),
        Probe("fault-inject enable page-fault", "enable page fault injection", destructive=True),
    ],
    "stress": [
        Probe("stress cpu 100", "CPU stress", destructive=True, timeout=5.0),
        Probe("loadtest alloc 1000000", "allocation stress", destructive=True, timeout=5.0),
        Probe("bench mem", "memory benchmark", destructive=True, timeout=5.0),
    ],
    "power": [
        Probe("power status", "power status", sensitive=True),
        Probe("suspend", "suspend", destructive=True),
        Probe("shutdown", "shutdown", destructive=True),
        Probe("reboot", "reboot", destructive=True),
        Probe("halt", "halt", destructive=True),
        Probe("panic-test", "panic trigger", destructive=True),
    ],
    "escape": [
        Probe("help; reboot", "command separator reboot", destructive=True),
        Probe("echo $(reboot)", "subshell reboot", destructive=True),
        Probe("echo `halt`", "backtick halt", destructive=True),
        Probe("ls && panic-test", "AND panic", destructive=True),
        Probe("help\nreboot\n", "newline command injection", destructive=True),
        Probe("ls\x00reboot", "NUL command injection", destructive=True),
    ],
}


def vector_names(include_destructive: bool) -> list[str]:
    names = sorted(SAFE_VECTORS)
    if include_destructive:
        destructive = sorted(DESTRUCTIVE_VECTORS)
        # Keep explicit guest-power vectors at the end for --vector all. Those
        # commands are allowed to halt/reboot/panic the throwaway QEMU guest, so
        # running them early masks useful findings from the other categories.
        names.extend(name for name in destructive if name != "power")
        if "power" in DESTRUCTIVE_VECTORS:
            names.append("power")
    return names


def run_vectors(shell: Shell, names: list[str], findings: list[Finding]) -> None:
    for name in names:
        probes = SAFE_VECTORS.get(name) or DESTRUCTIVE_VECTORS.get(name)
        if probes is None:
            raise ValueError(f"unknown vector: {name}")
        if not run_probe_vector(shell, name, probes, findings):
            print(f"\n[OS-PROBE] stopping after terminal destructive effect in {name}")
            break


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DRSH authenticated OS probe harness")
    parser.add_argument("--host", default=os.environ.get("DRSH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRSH_PORT", "4322")))
    parser.add_argument("--password", default=os.environ.get("DRSH_PASSWORD", "test"))
    parser.add_argument("--vector", default="network")
    parser.add_argument(
        "--i-understand-destructive",
        action="store_true",
        help="allow vectors that can mutate guest state, expose sensitive data, reboot, halt, or panic the guest",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = vector_names(args.i_understand_destructive) if args.vector == "all" else [args.vector]
    destructive_requested = any(name in DESTRUCTIVE_VECTORS for name in requested)
    if destructive_requested and not args.i_understand_destructive:
        print(
            "Refusing destructive or sensitive DRSH OS vector without --i-understand-destructive. "
            "Use drsh_attack.py for the default non-destructive wire suite."
        )
        return 2

    findings: list[Finding] = []
    print(f"DRSH OS probe harness target {args.host}:{args.port}")
    shell = Shell(args.host, args.port, args.password.encode("utf-8"))
    try:
        run_vectors(shell, requested, findings)
    except (DrshDisconnected, DrshProtocolError, OSError, ValueError) as error:
        print(f"FATAL: {error}")
        return 2
    finally:
        shell.close()

    critical_or_high = [f for f in findings if f.severity in {"CRITICAL", "HIGH"}]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    print("\nOS PROBE SUMMARY")
    print(f"Total: {len(critical_or_high)} high-impact, {len(medium)} medium, {len(findings)} findings")
    return 1 if critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
