/*
 * DuetOS — Intel iGPU GGTT manager. See intel_ggtt.h.
 *
 * EncodeGgttPte is proven at COMPILE time (static_asserts below). The
 * GgttInit / GgttMapPage BAR-alias writes are gated on a live Intel
 * device and unverified on silicon (no Intel model in QEMU).
 */

#include "drivers/gpu/intel_ggtt.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/gpu/intel_gpu.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/zone.h"

namespace duetos::drivers::gpu::intel
{

// Compile-time proof of the PTE encoder.
static_assert(EncodeGgttPte(0x12345000ull) == 0x12345001ull, "ggtt pte present + addr");
static_assert(EncodeGgttPte(0) == 0x1ull, "ggtt pte present on null");
static_assert(EncodeGgttPte(0x12345ABCull) == 0x12345001ull, "ggtt pte page-aligns the address");
static_assert((EncodeGgttPte(0x1000ull) & (1ull << 1)) == 0, "ggtt pte LM bit stays clear for iGPU");

namespace
{

bool g_ready = false;
u64 g_gtt_offset = 0; // byte offset of the PTE table within BAR0
u64 g_va_lo_idx = 0;  // first slot of our high window
u64 g_va_hi_idx = 0;  // one past the last slot
u64 g_next_idx = 0;   // next free slot
mm::DmaBuffer g_scratch = {};

} // namespace

u64 GgttInit(const GpuInfo& g)
{
    if (g_ready)
        return g_va_hi_idx - g_va_lo_idx;
    if (g.mmio_virt == nullptr || g.mmio_size < 0x400000)
    {
        KLOG_WARN("drivers/gpu/intel", "GGTT: BAR0 unmapped or < 4 MiB — init skipped");
        return 0;
    }

    // PTEs occupy the upper half of BAR0 (GTTMMADR). One 8-byte PTE
    // per 4 KiB of GPU VA.
    g_gtt_offset = g.mmio_size / 2;
    const u64 total_slots = (g.mmio_size - g_gtt_offset) / 8;

    // Allocate + scratch-fill ONLY the top 1/8 of the GVA space. The
    // firmware framebuffer + stolen memory live in the low aperture
    // slots; clobbering them would kill the display. Allocating high
    // keeps the screen alive.
    g_va_lo_idx = (total_slots * 7) / 8;
    g_va_hi_idx = total_slots;
    g_next_idx = g_va_lo_idx;

    auto sr = mm::AllocDmaCoherent(0x1000u, mm::Zone::Normal);
    if (!sr.has_value())
    {
        KLOG_WARN("drivers/gpu/intel", "GGTT: scratch page alloc failed");
        return 0;
    }
    g_scratch = sr.value();
    const u64 scratch_pte = EncodeGgttPte(g_scratch.phys);
    for (u64 i = g_va_lo_idx; i < g_va_hi_idx; ++i)
        IntelReg64Write(g, g_gtt_offset + i * 8, scratch_pte);
    (void)IntelReg64(g, g_gtt_offset + g_va_lo_idx * 8); // posting read flushes the WC writes

    g_ready = true;
    arch::SerialWrite("[gpu/intel/ggtt] init pte_table_off=");
    arch::SerialWriteHex(g_gtt_offset);
    arch::SerialWrite(" window_slots=");
    arch::SerialWriteHex(g_va_hi_idx - g_va_lo_idx);
    arch::SerialWrite(" base_gva=");
    arch::SerialWriteHex(g_va_lo_idx * 0x1000ull);
    arch::SerialWrite("\n");
    return g_va_hi_idx - g_va_lo_idx;
}

u64 GgttMapPage(const GpuInfo& g, u64 host_phys)
{
    if (!g_ready)
        return 0;
    if ((host_phys & 0xFFFull) != 0)
    {
        KLOG_WARN_V("drivers/gpu/intel", "GGTT map: phys not page-aligned", host_phys);
        return 0;
    }
    if (g_next_idx >= g_va_hi_idx)
    {
        KLOG_WARN("drivers/gpu/intel", "GGTT map: high window exhausted");
        return 0;
    }
    const u64 idx = g_next_idx++;
    IntelReg64Write(g, g_gtt_offset + idx * 8, EncodeGgttPte(host_phys));
    (void)IntelReg64(g, g_gtt_offset + idx * 8); // posting read
    return idx * 0x1000ull;
}

bool GgttReady()
{
    return g_ready;
}

void IntelGgttSelfTest()
{
    // Encoder already compile-proven above; this emits the grep-able
    // sentinel and re-checks at runtime for completeness.
    const bool ok = EncodeGgttPte(0x12345000ull) == 0x12345001ull && EncodeGgttPte(0) == 0x1ull &&
                    EncodeGgttPte(0x12345ABCull) == 0x12345001ull && (EncodeGgttPte(0x1000ull) & (1ull << 1)) == 0;
    if (ok)
    {
        arch::SerialWrite("[gpu/intel/ggtt] selftest PASS (PTE encode compile-verified)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x6754u /* 'gt' */);
    arch::SerialWrite("[gpu/intel/ggtt] selftest FAIL (PTE encode)\n");
}

} // namespace duetos::drivers::gpu::intel
