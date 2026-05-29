/*
 * DuetOS — Intel iGPU forcewake + GT-init. See intel_forcewake.h.
 *
 * The masked-bit encoders are verified at COMPILE time by the
 * static_asserts below (the bug-prone part — a wrong shift would fail
 * the build). The MMIO handshake is gated behind a live Intel BAR0 and
 * is unverified on silicon (no Intel model in QEMU).
 */

#include "drivers/gpu/intel_forcewake.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/gpu/intel_gpu.h"
#include "log/klog.h"
#include "time/timekeeper.h"

namespace duetos::drivers::gpu::intel
{

// Compile-time proof of the masked-bit encoding. If any of these
// trip, the build fails — the encoder can never ship wrong.
static_assert(MaskedBitEnable(kFwKernelBit) == 0x00010001u, "fw kernel enable");
static_assert(MaskedBitDisable(kFwKernelBit) == 0x00010000u, "fw kernel disable");
static_assert(MaskedBitEnable(kFwFallbackBit) == 0x80008000u, "fw fallback enable");
static_assert(MaskedBitDisable(kFwFallbackBit) == 0x80000000u, "fw fallback disable");
static_assert(MaskedBitEnable(kIntelStopRing) == 0x01000100u, "stop_ring enable");
static_assert(MaskedBitDisable(kIntelStopRing) == 0x01000000u, "stop_ring disable");

namespace
{

// Poll an ack register's `bit` until it matches `want_set`, or the
// 50 ms forcewake timeout elapses. Mirrors Bringup's poll: the iter
// cap is the backstop when Timekeeper hasn't selected a source yet
// (MonotonicNs() == 0).
bool PollAck(const GpuInfo& g, u64 ack, u32 bit, bool want_set)
{
    constexpr u64 kTimeoutNs = 50ull * 1000ull * 1000ull;
    constexpr u32 kIterCap = 1u << 20;
    const u64 start_ns = ::duetos::time::MonotonicNs();
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        if (((IntelReg32(g, ack) & bit) != 0) == want_set)
            return true;
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now = ::duetos::time::MonotonicNs();
            if (now > start_ns && (now - start_ns) > kTimeoutNs)
                break;
        }
    }
    return false;
}

} // namespace

bool ForcewakeGet(const GpuInfo& g, const ForcewakeDomain& d)
{
    // Standard get: wait the ack clear, request KERNEL, wait the ack
    // set. (We don't hard-fail if the initial clear-wait times out —
    // i915 only warns; the request below is what matters.)
    (void)PollAck(g, d.ack, kFwKernelBit, /*want_set=*/false);
    IntelReg32Write(g, d.set, MaskedBitEnable(kFwKernelBit));
    if (PollAck(g, d.ack, kFwKernelBit, /*want_set=*/true))
        return true;

    // Gen9–11 erratum (WaRsForcewakeAddDelayForAck): the primary ack
    // can be missed. Coax it via the FALLBACK bit, re-sample the real
    // KERNEL ack, then drop the fallback request.
    (void)PollAck(g, d.ack, kFwFallbackBit, /*want_set=*/false);
    IntelReg32Write(g, d.set, MaskedBitEnable(kFwFallbackBit));
    (void)PollAck(g, d.ack, kFwFallbackBit, /*want_set=*/true);
    const bool acked = (IntelReg32(g, d.ack) & kFwKernelBit) != 0;
    IntelReg32Write(g, d.set, MaskedBitDisable(kFwFallbackBit));
    return acked;
}

void ForcewakePut(const GpuInfo& g, const ForcewakeDomain& d)
{
    IntelReg32Write(g, d.set, MaskedBitDisable(kFwKernelBit));
}

bool ForcewakeGetForRing(const GpuInfo& g)
{
    const bool render = ForcewakeGet(g, kFwRender);
    const bool gt = ForcewakeGet(g, kFwGt);
    if (render && gt)
    {
        arch::SerialWrite("[gpu/intel/fw] render+gt forcewake held\n");
        return true;
    }
    KLOG_WARN_2V("drivers/gpu/intel", "forcewake ack missing (ring may not execute)", "render",
                 static_cast<u64>(render), "gt", static_cast<u64>(gt));
    return false;
}

void IntelRingUnstop(const GpuInfo& g)
{
    IntelReg32Write(g, kIntelRcsMiMode, MaskedBitDisable(kIntelStopRing));
    constexpr u32 kIterCap = 1u << 16;
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        if ((IntelReg32(g, kIntelRcsMiMode) & kIntelModeIdle) == 0)
            return;
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/gpu/intel", "RING_MI_MODE still parked after STOP_RING clear");
}

void IntelForcewakeSelfTest()
{
    // The encoders are already proven by the static_asserts above; this
    // emits the grep-able boot sentinel and re-checks the domain table
    // (which static_assert can't fully express — distinctness).
    const bool table_ok = kFwRender.set != 0 && kFwRender.ack != 0 && kFwGt.set != kFwRender.set &&
                          kFwGt.ack != kFwRender.ack && kFwMedia.set != 0 && kFwMedia.ack != 0;
    if (table_ok)
    {
        arch::SerialWrite("[gpu/intel/fw] selftest PASS (masked-bit encoders compile-verified + domain table)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x4657u /* 'FW' */);
    arch::SerialWrite("[gpu/intel/fw] selftest FAIL (domain table)\n");
}

} // namespace duetos::drivers::gpu::intel
