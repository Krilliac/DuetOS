#!/usr/bin/env python3
"""Contract: cryptographic RNG facades use the kernel CSPRNG or fail.

WHY
    SystemFunction036 (RtlGenRandom), CryptGenRandom and BCryptGenRandom are
    documented as cryptographically secure. Applications use them for session
    tokens, password-reset values, nonces, key material, cookie secrets and
    authentication challenges.

    The PE32 facades returned success while filling the buffer from

        ctr = ctr * 1103515245u + 12345u

    which is the textbook glibc LCG — recoverable from a single output. That
    is strictly worse than failing: a caller that receives an error takes its
    failure path, whereas a caller handed LCG bytes ships a broken secret and
    never learns.

    The kernel CSPRNG already existed (SYS_RANDOM_BYTES = 212, RDSEED/RDRAND
    seeded) and the 64-bit bcrypt already used it; the 32-bit facades carried
    a stale comment claiming a real RNG "needs the 32-bit syscall trampoline",
    which by then existed at userland/libs/common/duet32_syscall.h and was
    already used by every other _32 DLL.

    Pins two invariants: no RNG facade contains a live LCG, and each one
    routes through SYS_RANDOM_BYTES and fails closed on a short fill.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIBS = ROOT / "userland/libs"

RNG_EXPORTS = ("SystemFunction036", "CryptGenRandom", "BCryptGenRandom", "RtlGenRandom")
# An ASSIGNMENT using the LCG constant — comments mentioning it are fine.
LIVE_LCG = re.compile(r"^\s*\w+\s*=\s*\w+\s*\*\s*1103515245", re.M)


def rng_sources() -> list[Path]:
    out = []
    for p in sorted(LIBS.rglob("*.c")):
        t = p.read_text(encoding="utf-8", errors="replace")
        if any(f"__stdcall {e}(" in t for e in RNG_EXPORTS):
            out.append(p)
    return out


class NoPredictableGenerator(unittest.TestCase):
    def test_rng_facades_were_found(self) -> None:
        # Guards against the scan silently passing because nothing matched.
        self.assertGreaterEqual(len(rng_sources()), 2,
                                "expected several DLLs exporting RNG entry points")

    def test_no_live_lcg_in_any_rng_facade(self) -> None:
        offenders = []
        for p in rng_sources():
            body = p.read_text(encoding="utf-8", errors="replace")
            for m in LIVE_LCG.finditer(body):
                line = body[: m.start()].count("\n") + 1
                offenders.append(f"{p.relative_to(ROOT).as_posix()}:{line}")
        self.assertEqual(offenders, [],
                         "a cryptographic RNG facade is filling from an LCG: "
                         + ", ".join(offenders))


class RoutesThroughTheKernelCsprng(unittest.TestCase):
    def test_pe32_facades_call_sys_random_bytes(self) -> None:
        for name in ("advapi32_32/advapi32_32.c", "bcrypt_32/bcrypt_32.c"):
            t = (LIBS / name).read_text(encoding="utf-8")
            self.assertIn("SYS_RANDOM_BYTES", t, f"{name} must use the kernel CSPRNG")
            self.assertIn("duet_syscall2", t, f"{name} must issue the syscall")

    def test_short_fill_is_reported_as_failure(self) -> None:
        # A partial fill must never be reported as success — the tail of the
        # buffer would be uninitialised or stale.
        adv = (LIBS / "advapi32_32/advapi32_32.c").read_text(encoding="utf-8")
        helper = adv[adv.index("static BOOL duet32_csprng_fill("):]
        helper = helper[: helper.index("\n}") + 2]
        self.assertRegex(helper, r"==\s*len",
                         "must require a full-length fill before returning success")

        bc = (LIBS / "bcrypt_32/bcrypt_32.c").read_text(encoding="utf-8")
        fn = bc[bc.index("__stdcall BCryptGenRandom("):]
        fn = fn[: fn.index("\n}") + 2]
        self.assertIn("!=", fn)
        self.assertIn("0xC0000001", fn, "must return STATUS_UNSUCCESSFUL, not success")

    def test_syscall_number_matches_the_kernel(self) -> None:
        hdr = (ROOT / "kernel/syscall/syscall.h").read_text(encoding="utf-8")
        m = re.search(r"SYS_RANDOM_BYTES\s*=\s*(\d+)", hdr)
        self.assertIsNotNone(m, "kernel must still define SYS_RANDOM_BYTES")
        kernel_nr = int(m.group(1))
        for name in ("advapi32_32/advapi32_32.c", "bcrypt_32/bcrypt_32.c"):
            t = (LIBS / name).read_text(encoding="utf-8")
            d = re.search(r"#define\s+SYS_RANDOM_BYTES\s+(\d+)", t)
            self.assertIsNotNone(d, f"{name} must define the syscall number")
            self.assertEqual(int(d.group(1)), kernel_nr,
                             f"{name} disagrees with the kernel syscall number")


if __name__ == "__main__":
    unittest.main(verbosity=2)
