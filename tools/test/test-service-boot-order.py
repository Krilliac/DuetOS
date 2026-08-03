#!/usr/bin/env python3
"""Guard the scheduler-before-user-service boot dependency."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAIN_CPP = ROOT / "kernel/core/main.cpp"
BRINGUP_CPP = ROOT / "kernel/core/boot_bringup.cpp"


def function_body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\([^)]*\)\s*\{", source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = source.find("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated function: {signature}")


def unique_position(source: str, label: str, pattern: str) -> int:
    matches = list(re.finditer(pattern, source))
    if len(matches) != 1:
        raise AssertionError(f"expected one {label}, found {len(matches)}")
    return matches[0].start()


class ServiceBootOrderTests(unittest.TestCase):
    def test_user_services_start_after_userland_phase(self) -> None:
        main = function_body(MAIN_CPP.read_text(encoding="utf-8"), r'extern\s+"C"\s+void\s+kernel_main')
        bringup = BRINGUP_CPP.read_text(encoding="utf-8")
        kernel_services = function_body(bringup, r"void\s+BootBringupKernelServices")
        devices = function_body(bringup, r"void\s+BootBringupDevices")
        desktop = function_body(bringup, r"void\s+BootBringupDesktop")

        desktop_call = unique_position(main, "desktop bring-up call", r"\bBootBringupDesktop\s*\(")
        scheduler_call = unique_position(main, "kernel-services bring-up call", r"\bBootBringupKernelServices\s*\(")
        devices_call = unique_position(main, "device bring-up call", r"\bBootBringupDevices\s*\(")
        self.assertLess(desktop_call, scheduler_call)
        self.assertLess(scheduler_call, devices_call)

        sched_init = unique_position(kernel_services, "scheduler initialization", r"\bSchedInit\s*\(")
        sched_phase = unique_position(
            kernel_services,
            "scheduler phase completion",
            r"\bRunPhase\s*\(\s*duetos::core::Phase::Sched\s*\)",
        )
        self.assertLess(sched_init, sched_phase)

        self.assertNotRegex(desktop, r"\bServiceManagerStartAll\s*\(")
        self.assertNotRegex(devices, r"\bServiceManagerStartAll\s*\(")
        service_init = unique_position(devices, "service manager initialization", r"\bServiceManagerInit\s*\(")
        service_test = unique_position(devices, "service manager self-test", r"\bServiceManagerSelfTest\s*\(")
        self.assertLess(service_init, service_test)

        userland_phase = unique_position(
            main,
            "Userland phase completion",
            r"\bRunPhase\s*\(\s*duetos::core::Phase::Userland\s*\)",
        )
        service_start = unique_position(main, "user service launch", r"\bServiceManagerStartAll\s*\(")
        heartbeat_start = unique_position(main, "heartbeat launch", r"\bStartHeartbeatThread\s*\(")
        self.assertLess(userland_phase, service_start)
        self.assertLess(service_start, heartbeat_start)

        all_boot_sources = main + bringup
        self.assertEqual(len(re.findall(r"\bServiceManagerStartAll\s*\(", all_boot_sources)), 1)


if __name__ == "__main__":
    unittest.main()
