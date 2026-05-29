#pragma once

#include "drivers/gpu/gpu.h"
#include "util/types.h"

/*
 * DuetOS — Intel iGPU forcewake + GT-init preconditions (Gen9–Gen12).
 *
 * On real Intel silicon the GT register block (the ring registers at
 * MMIO 0x2000, the engines, etc.) is power-gated: reads return garbage
 * and writes are dropped unless software holds a *forcewake* on the
 * domain that owns the register. QEMU has no Intel-iGPU model, so the
 * existing RCS scaffold's register pokes were never exercised against
 * a part that enforces this — `intel::Bringup` programming the ring
 * without forcewake would silently no-op on metal.
 *
 * The RCS 0x2000 register block straddles two domains
 * (`__gen9_fw_ranges`): 0x2000–0x26FF is RENDER, 0x2700–0x2FFF is GT.
 * So the ring bring-up must hold BOTH before touching RING_CTL/HEAD/
 * TAIL/START. v0 acquires them at bring-up and holds them for the boot
 * (no release) — the simplest posture that also defeats RC6 sleeping
 * the GT mid-submission.
 *
 * Verification ceiling: the masked-bit encoders below are pinned by a
 * pure boot self-test (runs + PASSes under QEMU with no device). The
 * MMIO handshake itself is real-hardware-only — there is nothing on a
 * QEMU box to ACK it. See wiki/reference/GPU-Implementation-Notes.md.
 *
 * Context: kernel. Called from `intel::Bringup` (gated on a live Intel
 * BAR0) and from the boot self-test.
 */

namespace duetos::drivers::gpu::intel
{

// A forcewake domain is a (request, ack) MMIO register pair. Writing
// the request with FORCEWAKE_KERNEL set wakes the domain; the matching
// ack bit reflecting back confirms the GT is awake.
struct ForcewakeDomain
{
    u64 set; // request register offset (BAR0)
    u64 ack; // ack register offset (BAR0)
    const char* name;
};

// Request bits. KERNEL is the normal wake bit; FALLBACK is the
// recovery bit the Gen9–11 erratum (WaRsForcewakeAddDelayForAck) uses
// when the primary ack is missed.
inline constexpr u32 kFwKernelBit = 1u << 0;
inline constexpr u32 kFwFallbackBit = 1u << 15;

// Gen9 canonical offsets; stable Gen9..Gen12. Gen11+ adds per-instance
// media domains we don't need for an RCS/BCS bring-up.
inline constexpr ForcewakeDomain kFwRender = {0xA278, 0x0D84, "render"};
inline constexpr ForcewakeDomain kFwGt = {0xA188, 0x130044, "gt"};
inline constexpr ForcewakeDomain kFwMedia = {0xA270, 0x0D88, "media"};

// Masked-bit MMIO value helpers. Intel forcewake / ring-mode registers
// reserve the upper 16 bits as a write-enable mask: a low bit is only
// modified if its mask bit (low bit << 16) is also set. ENABLE sets
// the target bit; DISABLE clears it. Pure — self-tested.
constexpr u32 MaskedBitEnable(u32 bit)
{
    return (bit << 16) | bit;
}
constexpr u32 MaskedBitDisable(u32 bit)
{
    return bit << 16;
}

// Acquire one forcewake domain on `g`. Polls the ack clear, requests
// KERNEL, polls the ack set; on a missed ack runs the Gen9–11 FALLBACK
// recovery. Returns true iff the domain acked awake. MMIO — only
// meaningful on a live Intel device.
bool ForcewakeGet(const GpuInfo& g, const ForcewakeDomain& d);

// Release a forcewake domain (clears KERNEL). v0 ring bring-up never
// calls this — forcewake is held for the boot — but it completes the
// API for a future suspend/idle path.
void ForcewakePut(const GpuInfo& g, const ForcewakeDomain& d);

// Acquire RENDER + GT (the two domains the RCS 0x2000 block spans).
// Returns true iff both acked. Logs the outcome.
bool ForcewakeGetForRing(const GpuInfo& g);

// Un-stop the RCS via RING_MI_MODE (masked-clear STOP_RING), then
// bounded-poll until MODE_IDLE de-asserts. MMIO. Required before the
// ring will execute on real silicon.
void IntelRingUnstop(const GpuInfo& g);

// Pure boot self-test: asserts the masked-bit encoders and the domain
// table. Device-independent — runs and PASSes under QEMU. Emits
// `[gpu/intel/fw] selftest PASS (...)`; fires kBootSelftestFail on a
// mismatch.
void IntelForcewakeSelfTest();

} // namespace duetos::drivers::gpu::intel
