#include "arch/x86_64/rtc.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "arch/x86_64/cpu.h"

namespace duetos::arch
{

namespace
{

constexpr u16 kCmosIndex = 0x70;
constexpr u16 kCmosData = 0x71;

// CMOS index values we care about. The upper bit of the index
// byte is the "NMI disable" flag — we leave whatever the firmware
// had; don't want to accidentally re-enable or disable NMIs just
// to read a time register.
constexpr u8 kRegSeconds = 0x00;
constexpr u8 kRegMinutes = 0x02;
constexpr u8 kRegHours = 0x04;
constexpr u8 kRegDay = 0x07;
constexpr u8 kRegMonth = 0x08;
constexpr u8 kRegYear = 0x09;
constexpr u8 kRegStatusA = 0x0A;
constexpr u8 kRegStatusB = 0x0B;

constexpr u8 kStatusAUpdateInProgress = 0x80;
constexpr u8 kStatusBBinaryMode = 0x04;
constexpr u8 kStatusB24HourMode = 0x02;

u8 ReadRaw(u8 reg)
{
    Outb(kCmosIndex, reg);
    return Inb(kCmosData);
}

bool UpdateInProgress()
{
    return (ReadRaw(kRegStatusA) & kStatusAUpdateInProgress) != 0;
}

u8 BcdToBinary(u8 v)
{
    return static_cast<u8>((v & 0x0F) + ((v >> 4) * 10));
}

} // namespace

void RtcRead(RtcTime* out)
{
    if (out == nullptr)
    {
        return;
    }

    // Wait for any in-progress update to finish. Per the 146818
    // spec the update cycle completes within ~2 ms, so a bounded
    // spin is fine. Without this the reads racing a firmware
    // update can mix half-new / half-old fields.
    for (u32 i = 0; i < 1'000'000; ++i)
    {
        if (!UpdateInProgress())
        {
            break;
        }
    }

    // Double-read pattern: read every field, then re-read and
    // compare. If they differ, an update snuck in; try again.
    // Bounded to a handful of attempts — unbounded retry on a
    // wedged chip would freeze the caller.
    u8 s1, m1, h1, d1, mo1, y1;
    u8 s2, m2, h2, d2, mo2, y2;
    u8 status_b = 0;
    bool stable = false;
    for (u32 attempt = 0; attempt < 8; ++attempt)
    {
        s1 = ReadRaw(kRegSeconds);
        m1 = ReadRaw(kRegMinutes);
        h1 = ReadRaw(kRegHours);
        d1 = ReadRaw(kRegDay);
        mo1 = ReadRaw(kRegMonth);
        y1 = ReadRaw(kRegYear);
        status_b = ReadRaw(kRegStatusB);

        s2 = ReadRaw(kRegSeconds);
        m2 = ReadRaw(kRegMinutes);
        h2 = ReadRaw(kRegHours);
        d2 = ReadRaw(kRegDay);
        mo2 = ReadRaw(kRegMonth);
        y2 = ReadRaw(kRegYear);

        if (s1 == s2 && m1 == m2 && h1 == h2 && d1 == d2 && mo1 == mo2 && y1 == y2)
        {
            stable = true;
            break;
        }
    }
    if (!stable)
    {
        // RTC kept changing under us across all retries. Hardware
        // is wedged or QEMU's CMOS emulation is racing. Caller gets
        // whatever the last attempt produced; flag it once so an
        // operator notices.
        KLOG_ONCE_WARN("arch/rtc", "RtcRead: 8 retries failed to converge; returning last sample");
    }

    const bool binary_mode = (status_b & kStatusBBinaryMode) != 0;
    const bool hour_24 = (status_b & kStatusB24HourMode) != 0;

    // For 12-hour mode the high bit of the hours register is the
    // PM flag. Strip it BEFORE the BCD convert — 1 p.m. in BCD
    // looks like 0x81, which as raw BCD decodes to 81 decimal.
    bool pm = false;
    if (!hour_24 && (h1 & 0x80) != 0)
    {
        pm = true;
        h1 &= 0x7F;
    }

    if (!binary_mode)
    {
        s1 = BcdToBinary(s1);
        m1 = BcdToBinary(m1);
        h1 = BcdToBinary(h1);
        d1 = BcdToBinary(d1);
        mo1 = BcdToBinary(mo1);
        y1 = BcdToBinary(y1);
    }

    // 12-hour → 24-hour conversion. Midnight in 12-hour mode is
    // stored as 12 AM; noon is 12 PM. Other hours PM = +12.
    if (!hour_24)
    {
        if (h1 == 12)
        {
            h1 = pm ? 12 : 0; // 12 PM stays 12; 12 AM becomes 0
        }
        else if (pm)
        {
            h1 = static_cast<u8>(h1 + 12);
        }
    }

    out->second = s1;
    out->minute = m1;
    out->hour = h1;
    out->day = d1;
    out->month = mo1;
    // Assume 2000s — century register is FADT-dependent and v0
    // doesn't consume it. Good through 2099.
    out->year = static_cast<u16>(2000 + y1);
}

u8 CmosReadByte(u8 index)
{
    // Mask to 7 bits so we never set the NMI-disable bit.
    return ReadRaw(index & 0x7F);
}

void CmosDump()
{
    SerialWrite("[cmos] 128-byte RAM dump\n");
    for (u32 row = 0; row < 8; ++row)
    {
        SerialWrite("[cmos] ");
        SerialWriteHex(u8(row * 16));
        SerialWrite(":");
        for (u32 col = 0; col < 16; ++col)
        {
            SerialWrite(" ");
            SerialWriteHex(CmosReadByte(u8(row * 16 + col)));
        }
        SerialWrite("\n");
    }
}

} // namespace duetos::arch
