#include "drivers/net/nic_telemetry.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/net/net.h"

namespace duetos::drivers::net
{

void NicMacFromRalRah(u32 ral, u32 rah, u8 out[6])
{
    out[0] = static_cast<u8>(ral & 0xFF);
    out[1] = static_cast<u8>((ral >> 8) & 0xFF);
    out[2] = static_cast<u8>((ral >> 16) & 0xFF);
    out[3] = static_cast<u8>((ral >> 24) & 0xFF);
    out[4] = static_cast<u8>(rah & 0xFF);
    out[5] = static_cast<u8>((rah >> 8) & 0xFF);
}

void NicTelemetryProbe()
{
    using arch::SerialWrite;
    const u64 n = NicCount();
    if (n == 0)
    {
        SerialWrite("[nic] no network controllers discovered\n");
        return;
    }
    for (u64 i = 0; i < n; ++i)
    {
        const NicInfo& nic = Nic(i);
        SerialWrite("[nic] ");
        SerialWrite(nic.family != nullptr ? nic.family : "unknown");
        if (nic.mac_valid)
        {
            SerialWrite(" mac=");
            for (u32 b = 0; b < 6; ++b)
            {
                if (b != 0)
                    SerialWrite(":");
                arch::SerialWriteHex(nic.mac[b]);
            }
        }
        else
        {
            SerialWrite(" mac=(not read)");
        }
        SerialWrite(" link=");
        SerialWrite(nic.link_up ? "up" : "down");
        SerialWrite(nic.driver_online ? " driver=online" : " driver=offline");
        SerialWrite("\n");
    }
}

void NicTelemetrySelfTest()
{
    using core::PanicWithValue;

    // RAL = 0x04030201 (bytes 01 02 03 04), RAH = 0x00000605 (bytes 05 06)
    // => MAC 01:02:03:04:05:06.
    u8 mac[6] = {};
    NicMacFromRalRah(0x04030201u, 0x00000605u, mac);
    for (u32 i = 0; i < 6; ++i)
    {
        const u8 expect = static_cast<u8>(i + 1);
        if (mac[i] != expect)
            PanicWithValue("drivers/nic", "MAC byte decode mismatch", (static_cast<u64>(i) << 8) | mac[i]);
    }
    // RAH high bytes (the valid bit + reserved at bits 16+) must not
    // bleed into byte 5.
    NicMacFromRalRah(0x0u, 0x8000FFEEu, mac);
    if (mac[4] != 0xEE || mac[5] != 0xFF)
        PanicWithValue("drivers/nic", "RAH masking wrong", (static_cast<u64>(mac[5]) << 8) | mac[4]);

    arch::SerialWrite("[nic-telemetry-selftest] PASS (RAL/RAH MAC decode + masking)\n");
}

} // namespace duetos::drivers::net
