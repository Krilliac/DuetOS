#include "drivers/gpu/gpu_telemetry.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/intel_gpu.h"

namespace duetos::drivers::gpu
{

namespace
{
constexpr u16 kIntelVid = 0x8086;
constexpr u64 kRegGen6Rpstat1 = 0xA01C; // GEN6_RPSTAT1
} // namespace

u32 GpuIntelCagfToMhz(u32 rpstat1)
{
    // GEN9_CAGF: bits 31:23 (9-bit current actual graphics frequency).
    const u32 cagf = (rpstat1 >> 23) & 0x1FFu;
    // Gen9 GT frequency step is 50/3 MHz per CAGF unit.
    return (cagf * 50u) / 3u;
}

GpuTelemetryReading GpuTelemetryRead(u64 index)
{
    GpuTelemetryReading r = {};
    if (index >= GpuCount())
        return r;
    const GpuInfo& g = Gpu(index);
    r.valid = true;
    r.vendor_id = g.vendor_id;
    r.device_id = g.device_id;
    r.vendor = g.vendor;
    r.family = g.family;
    r.mmio_live = g.mmio_live;
    r.is_intel = (g.vendor_id == kIntelVid);

    if (r.is_intel && g.mmio_live)
    {
        const u32 rpstat = intel::IntelReg32(g, kRegGen6Rpstat1);
        if (rpstat != 0xFFFFFFFFu)
        {
            r.rpstat_valid = true;
            r.rpstat_raw = rpstat;
            r.freq_mhz_est = GpuIntelCagfToMhz(rpstat); // GAP: gen-specific
        }
    }
    // GAP: temperature not read on any vendor in v0.
    return r;
}

void GpuTelemetryProbe()
{
    using arch::SerialWrite;
    const u64 n = GpuCount();
    if (n == 0)
    {
        SerialWrite("[gpu-telem] no display controllers discovered\n");
        return;
    }
    for (u64 i = 0; i < n; ++i)
    {
        const GpuTelemetryReading r = GpuTelemetryRead(i);
        SerialWrite("[gpu-telem] ");
        SerialWrite(r.vendor != nullptr ? r.vendor : "unknown");
        SerialWrite(" ");
        SerialWrite(r.family != nullptr ? r.family : "(no family)");
        if (r.rpstat_valid)
        {
            SerialWrite(" rpstat1=");
            arch::SerialWriteHex(r.rpstat_raw);
            SerialWrite(" freq_mhz~");
            arch::SerialWriteHex(r.freq_mhz_est);
        }
        else
        {
            SerialWrite(" freq=unavailable");
        }
        SerialWrite(" temp=unavailable\n"); // GAP
    }
}

void GpuTelemetrySelfTest()
{
    using core::PanicWithValue;

    // CAGF field is bits 31:23. rpstat with CAGF=0x1B (27) => 27*50/3 = 450 MHz.
    const u32 rp = 0x1Bu << 23;
    if (GpuIntelCagfToMhz(rp) != 450u)
        PanicWithValue("drivers/gpu", "CAGF 0x1B != 450 MHz", GpuIntelCagfToMhz(rp));

    // CAGF=0 => 0 MHz; low bits below the field must not contribute.
    if (GpuIntelCagfToMhz(0x007FFFFFu) != 0u)
        PanicWithValue("drivers/gpu", "sub-CAGF bits leaked", GpuIntelCagfToMhz(0x007FFFFFu));

    // CAGF=0x48 (72) => 72*50/3 = 1200 MHz.
    if (GpuIntelCagfToMhz(0x48u << 23) != 1200u)
        PanicWithValue("drivers/gpu", "CAGF 0x48 != 1200 MHz", GpuIntelCagfToMhz(0x48u << 23));

    arch::SerialWrite("[gpu-telemetry-selftest] PASS (Gen9 CAGF->MHz extraction)\n");
}

} // namespace duetos::drivers::gpu
