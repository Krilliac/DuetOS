#pragma once

#include "util/types.h"

/*
 * DuetOS — FPU / SSE / AVX state management.
 *
 * The kernel is built with -mno-sse -mno-mmx -mno-80387, so kernel
 * code itself never touches the FPU. Userland may. The four pieces
 * here:
 *
 *   1. CPUID probe — what state components does the CPU support, and
 *      how big is the XSAVE area for the components we plan to use?
 *   2. CR4 / XCR0 enable — turn on OSFXSR + OSXMMEXCPT, plus OSXSAVE
 *      and the relevant XCR0 bits if XSAVE is supported.
 *   3. Per-task save area — owned by the scheduler, sized to
 *      `FpuSaveAreaSize()`, alignment 64.
 *   4. Save / restore primitives — implemented in fpu_context.S.
 *
 * The save and restore symbols are issued from the scheduler's
 * context-switch path. The init function planes a freshly-prepared
 * area for a new task so the first restore lands on architectural
 * init state instead of garbage MXCSR.
 *
 * Context: kernel. Safe at any IRQ level — the asm primitives
 * neither read nor write IRQ-affected state.
 */

namespace duetos::arch
{

/// One-shot. Probes CPUID for SSE / XSAVE / AVX support, sets
/// CR4.OSFXSR + CR4.OSXMMEXCPT, and (if XSAVE is supported) sets
/// CR4.OSXSAVE plus writes XCR0 with the components the kernel will
/// allow user-mode to use. Logs a one-line boot summary
/// `[cpu] fpu: fxsr=<y/n> xsave=<y/n> avx=<y/n> area=<bytes>`.
void FpuInit();

/// Bytes required for the per-task save area, aligned to 64.
/// Returns 512 (legacy FXSAVE) when XSAVE is unavailable. Stable
/// once `FpuInit` has run.
u32 FpuSaveAreaSize();

/// Mask handed to xsave64 / xrstor64. Zero when XSAVE is
/// unavailable, in which case the asm primitives fall back to
/// FXSAVE / FXRSTOR. Stable once `FpuInit` has run.
u64 FpuXFeatureMask();

/// True iff the CPU advertises XSAVE and the kernel enabled it.
bool FpuHasXsave();

/// Touch the assembly-entry anchor table so `--gc-sections` keeps
/// every .S symbol this slice introduces. Logs a one-line boot
/// summary `[asm] entry stubs registered: <n> symbols`. Implemented
/// in arch/x86_64/asm_entry_table.cpp.
void AsmEntryAnchorReport();

} // namespace duetos::arch

extern "C"
{

    /// Save FPU / SSE / AVX state to `save_area`. Pass the value
    /// returned by `FpuXFeatureMask()` as `mask`. Caller must ensure
    /// `save_area` is 64-byte aligned and at least `FpuSaveAreaSize()`
    /// bytes.
    void FpuSaveXState(void* save_area, duetos::u64 mask);

    /// Mirror of `FpuSaveXState`.
    void FpuRestoreXState(const void* save_area, duetos::u64 mask);

    /// Initialise `save_area` so the first restore lands on
    /// architectural init state. Required once per fresh task.
    void FpuInitState(void* save_area);

} // extern "C"
