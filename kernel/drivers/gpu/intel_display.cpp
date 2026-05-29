/*
 * DuetOS — Intel iGPU display detect. See intel_display.h.
 *
 * EncodeGmbus1Read is proven at COMPILE time (static_assert). The GMBUS
 * read sequence (GmbusReadEdid / IntelDisplayProbe) is gated on a live
 * Intel device and unverified on silicon (no Intel model in QEMU).
 */

#include "drivers/gpu/intel_display.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/gpu/intel_gpu.h"
#include "time/timekeeper.h"

namespace duetos::drivers::gpu::intel
{

static_assert(kGmbusSwRdy == 0x40000000u, "GMBUS_SW_RDY");
static_assert(kGmbusCycleWait == 0x02000000u, "GMBUS_CYCLE_WAIT");
static_assert(kGmbusCycleStop == 0x08000000u, "GMBUS_CYCLE_STOP");
static_assert(EncodeGmbus1Read(0x50u, 128u) == 0x428000A1u, "GMBUS1 read cmd (slave 0x50, 128 bytes)");

namespace
{

// Poll GMBUS2: +1 = HW_RDY (a word is available), -1 = SATOER (NAK /
// no device on this pin), 0 = timeout. 50 ms cap (the GMBUS timeout).
int PollGmbusReady(const GpuInfo& g)
{
    constexpr u64 kTimeoutNs = 50ull * 1000ull * 1000ull;
    constexpr u32 kIterCap = 1u << 20;
    const u64 start_ns = ::duetos::time::MonotonicNs();
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        const u32 s = IntelReg32(g, kGmbus2);
        if (s & kGmbusSatoer)
            return -1;
        if (s & kGmbusHwRdy)
            return 1;
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now = ::duetos::time::MonotonicNs();
            if (now > start_ns && (now - start_ns) > kTimeoutNs)
                break;
        }
    }
    return 0;
}

} // namespace

u32 GmbusReadEdid(const GpuInfo& g, u32 pin, u8* buf, u32 len)
{
    if (g.mmio_virt == nullptr || buf == nullptr || len == 0)
        return 0;
    IntelReg32Write(g, kGmbus0, pin & 0x7u); // rate = 100 KHz (0), port = pin
    IntelReg32Write(g, kGmbus1, EncodeGmbus1Read(kEdidDdcSlave, len));

    u32 got = 0;
    while (got < len)
    {
        if (PollGmbusReady(g) != 1)
            break; // NAK or timeout — no panel on this pin
        const u32 word = IntelReg32(g, kGmbus3);
        for (u32 b = 0; b < 4 && got < len; ++b)
            buf[got++] = static_cast<u8>((word >> (b * 8)) & 0xFFu);
    }

    IntelReg32Write(g, kGmbus1, kGmbusCycleStop | kGmbusSwRdy);
    IntelReg32Write(g, kGmbus0, 0);
    return got;
}

void IntelDisplayProbe(const GpuInfo& g)
{
    if (g.mmio_virt == nullptr || !g.mmio_live)
        return;
    static const u8 kEdidMagic[8] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};
    u8 edid[128];
    bool any = false;
    for (u32 pin = 1; pin <= 6; ++pin)
    {
        for (u32 i = 0; i < 128; ++i)
            edid[i] = 0;
        const u32 n = GmbusReadEdid(g, pin, edid, 128);
        if (n < 8)
            continue;
        bool magic = true;
        for (u32 i = 0; i < 8; ++i)
            magic &= (edid[i] == kEdidMagic[i]);
        if (magic)
        {
            any = true;
            arch::SerialWrite("[gpu/intel/disp] EDID detected on GMBUS pin=");
            arch::SerialWriteHex(pin);
            arch::SerialWrite("\n");
        }
    }
    if (!any)
        arch::SerialWrite("[gpu/intel/disp] no EDID on GMBUS pins 1..6\n");
}

void IntelDisplaySelfTest()
{
    if (EncodeGmbus1Read(0x50u, 128u) == 0x428000A1u && kGmbusSatoer == 0x400u && kGmbusHwRdy == 0x800u)
    {
        arch::SerialWrite("[gpu/intel/disp] selftest PASS (GMBUS read-cmd encoder compile-verified)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x4453u /* 'DS' */);
    arch::SerialWrite("[gpu/intel/disp] selftest FAIL (GMBUS encoder)\n");
}

} // namespace duetos::drivers::gpu::intel
