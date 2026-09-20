#!/usr/bin/env python3
"""Guard the iphlpapi kSockOpGetLease register contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root = args.root.resolve()

    iphlpapi = (root / "userland/libs/iphlpapi/iphlpapi.c").read_text(encoding="utf-8")
    syscall_h = (root / "kernel/syscall/syscall.h").read_text(encoding="utf-8")
    syscall_cpp = (root / "kernel/syscall/syscall.cpp").read_text(encoding="utf-8")

    wrapper = re.search(
        r"static long long iphlp_sock_op\(.*?^}",
        iphlpapi,
        flags=re.DOTALL | re.MULTILINE,
    )
    require(wrapper is not None, "iphlpapi socket trampoline missing")
    wrapper_text = wrapper.group(0)
    for token in ('"S"(a1)', '"d"(a2)', '[a3] "r"(a3)', '"mov %[a3], %%r10'):
        require(token in wrapper_text, f"iphlpapi trampoline register mapping missing {token}")

    lease_call = re.search(
        r"iphlp_sock_op\(\s*13\s*/\*\s*kSockOpGetLease\s*\*/\s*,"
        r"\s*\(long long\)out\s*,\s*\(long long\)sizeof\(\*out\)\s*,\s*0\s*\)",
        iphlpapi,
    )
    require(
        lease_call is not None,
        "kSockOpGetLease must pass output in rsi/a1 and capacity in rdx/a2",
    )
    require(
        re.search(
            r"kSockOpGetLease:.*?rsi\s*=\s*user SocketLeaseInfo\* out\."
            r".*?rdx\s*=\s*user-supplied buffer size",
            syscall_h,
            flags=re.DOTALL,
        )
        is not None,
        "kernel kSockOpGetLease register contract missing",
    )
    require(
        'CopyToUser(reinterpret_cast<void*>(frame->rsi), &info, sizeof(info))' in syscall_cpp,
        "kernel kSockOpGetLease no longer writes through rsi",
    )
    require(
        "const u64 cap = frame->rdx;" in syscall_cpp,
        "kernel kSockOpGetLease no longer reads capacity from rdx",
    )
    require(
        "ActiveIpv4ConfigRead" in syscall_cpp and "config_source" in syscall_cpp,
        "kernel network-info ABI must expose active DHCP/static source state",
    )
    require(
        "config_source" in syscall_h and "config_source" in iphlpapi,
        "kernel and iphlpapi disagree on the byte-31 configuration source",
    )
    require(
        "lease->config_source == 2" in iphlpapi,
        "GetAdaptersInfo must set DhcpEnabled only for config_source=Dhcp",
    )
    require(
        "DuetOS Ethernet (e1000)" not in iphlpapi and '"DuetOS Ethernet"' in iphlpapi,
        "GetAdaptersInfo must not identify every physical NIC as e1000",
    )
    require(
        "0x00FFFFFFu" not in syscall_cpp,
        "network-info ABI must derive the netmask from the configured prefix",
    )

    print("[iphlpapi-socket-abi] PASS (GetLease rsi=out, rdx=capacity, source-aware)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError) as exc:
        print(f"[iphlpapi-socket-abi] FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
