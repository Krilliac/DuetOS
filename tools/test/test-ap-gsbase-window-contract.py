#!/usr/bin/env python3
"""Contract: an AP never enters shared kernel machinery with stale GSBASE.

WHY
    LoadGdtForCurrent's `mov %ax, %gs` reloads GS's hidden base from the
    kernel-data descriptor (base 0), so it ZEROES IA32_GS_BASE as a side
    effect. Loading the GDT and re-establishing GSBASE are therefore
    inseparable: between them the CPU has no valid per-CPU pointer.

    Splitting them across two CPUHP states (StartingGdt then StartingGsBase)
    opened a window, because CpuhpBringUp logs `startup OK state` after EVERY
    state and klog tags each line via CurrentCpuIdOrBsp() -> CurrentCpu().
    That log ran with GSBASE == 0, so CurrentCpu() took its LAPIC-ID recovery
    path and bumped the non-BSP fallback counter.

    That counter's own comment says "a clean boot must stay at zero now the
    AP-bring-up GS ordering + AP lidt are fixed; a non-zero value is a
    regression" — so every boot reported a regression that was really just
    this gap. Observed count: 69 per boot.

    The GDT-load step now re-establishes GSBASE itself, closing that window.
    A second gap remained before CPUHP: ApEntryFromTrampoline called
    CpuhpBringUp while GSBASE was still unset, and its first spinlock's
    lockdep bookkeeping called CurrentCpu four times. Pin both boundaries:
    install GSBASE from the already-validated PerCpu before CPUHP, then
    restore it again immediately after the GDT load clears the hidden base.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMP = (ROOT / "kernel/arch/x86_64/smp.cpp").read_text(encoding="utf-8")
CPUHP = (ROOT / "kernel/cpu/cpuhp.cpp").read_text(encoding="utf-8")
PERCPU = (ROOT / "kernel/cpu/percpu.cpp").read_text(encoding="utf-8")
PROFILE = (ROOT / "tools/test/profile-boot-smoke.sh").read_text(encoding="utf-8")
BOCHS = (ROOT / "tools/test/bochs-smoke.sh").read_text(encoding="utf-8")
CTEST = (ROOT / "tools/test/ctest-boot-smoke.sh").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")


def fn_body(src: str, signature: str) -> str:
    start = src.index(signature)
    return src[start : src.index("\n}", start) + 2]


class GdtStepRestoresGsBase(unittest.TestCase):
    def test_gdt_step_writes_gsbase_itself(self) -> None:
        body = fn_body(SMP, "::duetos::core::Result<void> CpuhpStartGdt(")
        self.assertIn("LoadGdtForCurrent", body)
        self.assertIn("WriteMsrGsBase", body,
                      "the GDT load zeroes GSBASE; the same step must restore it")

    def test_gsbase_write_follows_the_gdt_load(self) -> None:
        body = fn_body(SMP, "::duetos::core::Result<void> CpuhpStartGdt(")
        self.assertLess(body.index("LoadGdtForCurrent"), body.index("WriteMsrGsBase"),
                        "writing GSBASE before the GDT load is dead — it gets clobbered")

    def test_kernel_gs_base_shadow_is_written_too(self) -> None:
        body = fn_body(SMP, "::duetos::core::Result<void> CpuhpStartGdt(")
        self.assertIn("WriteMsrKernelGsBase", body,
                      "the swapgs shadow must be established alongside GSBASE")

    def test_dedicated_gsbase_step_still_exists(self) -> None:
        # Kept so CPUHP state numbering (pinned by the AP handshake contract)
        # does not shift. Its write is idempotent.
        self.assertIn("CpuhpStartGsBase", SMP)
        self.assertIn("CpuhpState::StartingGsBase", SMP)


class EntryInstallsGsBaseBeforeCpuhp(unittest.TestCase):
    def test_validated_percpu_is_installed_before_cpuhp_locking(self) -> None:
        body = fn_body(SMP, 'extern "C" [[noreturn]] void ApEntryFromTrampoline(')
        pcpu = body.index("cpu::PerCpu* const pcpu")
        gs = body.index("WriteMsrGsBase", pcpu)
        kgs = body.index("WriteMsrKernelGsBase", pcpu)
        bringup = body.index("CpuhpBringUp", pcpu)
        self.assertLess(pcpu, gs)
        self.assertLess(gs, bringup)
        self.assertLess(kgs, bringup)
        self.assertIn("WriteMsrGsBase(reinterpret_cast<u64>(pcpu))", body)
        self.assertIn("WriteMsrKernelGsBase(reinterpret_cast<u64>(pcpu))", body)

    def test_bsp_asserts_ap_bringup_needed_no_fallback(self) -> None:
        body = fn_body(SMP, "u64 SmpStartAps()")
        self.assertIn("CurrentCpuGsbaseFallbackCount", body)
        self.assertIn("AP bring-up required stale GSBASE fallback", body)

    def test_boot_gates_reject_any_future_fallback_warning(self) -> None:
        marker = "CurrentCpu LAPIC-resolved a non-kernel GSBASE"
        for source in (PROFILE, BOCHS, CTEST):
            self.assertIn(marker, source)

    def test_contract_is_wired_into_hosted_structural_ci(self) -> None:
        self.assertIn("python3 tools/test/test-ap-gsbase-window-contract.py", WORKFLOW)


class TheHazardStillExists(unittest.TestCase):
    """If these stop being true the rationale changes and this contract
    should be revisited rather than silently kept."""

    def test_cpuhp_logs_after_every_state(self) -> None:
        self.assertRegex(CPUHP, r'KLOG_\w+\("cpuhp",\s*"startup OK state"')

    def test_currentcpu_still_counts_nonbsp_fallbacks(self) -> None:
        self.assertIn("g_gsbase_fallback_nonbsp", PERCPU)

    def test_the_zero_claim_is_still_asserted_somewhere(self) -> None:
        # The counter is only meaningful if something still claims it must be
        # zero on a clean boot.
        self.assertIn("must stay at zero", PERCPU)


if __name__ == "__main__":
    unittest.main(verbosity=2)
