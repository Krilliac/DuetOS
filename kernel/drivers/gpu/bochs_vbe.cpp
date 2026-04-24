#include "bochs_vbe.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"

namespace duetos::drivers::gpu
{

namespace
{

// Legacy BGA (Bochs Graphics Adapter) port pair — same I/O port
// addresses every BGA-compatible device has used since Bochs
// originally shipped VBE support in 2002. QEMU's stdvga /
// bochs-display / qxl-vga all honour these even when they
// expose MMIO bars for the same registers.
constexpr u16 kVbeIndexPort = 0x01CE;
constexpr u16 kVbeDataPort = 0x01CF;

// Register indices that go through the port pair above.
constexpr u16 kVbeIdxId = 0x0;                    // {0xB0C0 | version_nibble} when queryable
constexpr u16 kVbeIdxXres = 0x1;                  // pixels
constexpr u16 kVbeIdxYres = 0x2;                  // pixels
constexpr u16 kVbeIdxBpp = 0x3;                   // 8 / 15 / 16 / 24 / 32
constexpr u16 kVbeIdxEnable = 0x4;                // bitfield, see kVbeEn* below
[[maybe_unused]] constexpr u16 kVbeIdxBank = 0x5; // bank number (pre-LFB)
[[maybe_unused]] constexpr u16 kVbeIdxVirtWidth = 0x6;
[[maybe_unused]] constexpr u16 kVbeIdxVirtHeight = 0x7;
[[maybe_unused]] constexpr u16 kVbeIdxXOffset = 0x8;
[[maybe_unused]] constexpr u16 kVbeIdxYOffset = 0x9;

// ENABLE register bits.
constexpr u16 kVbeEnEnabled = 0x01;                  // the controller is generating output
constexpr u16 kVbeEnGetCaps = 0x02;                  // reads of xres/yres/bpp return MAX not current
[[maybe_unused]] constexpr u16 kVbeEn8BitDac = 0x20; // 6-to-8 bit DAC (colour expansion)
constexpr u16 kVbeEnLfb = 0x40;                      // LFB aperture enabled (we always want this)
constexpr u16 kVbeEnNoClearMem = 0x80;               // don't clear VRAM during mode-set

u16 Read(u16 index)
{
    // The index latches per-socket — must write it every time we
    // want to read a different register. No atomicity guarantee
    // across CPUs; we're single-CPU at the kernel-driver layer
    // so the write-then-read sequence is race-free here.
    ::duetos::arch::Outw(kVbeIndexPort, index);
    return ::duetos::arch::Inw(kVbeDataPort);
}

void Write(u16 index, u16 value)
{
    ::duetos::arch::Outw(kVbeIndexPort, index);
    ::duetos::arch::Outw(kVbeDataPort, value);
}

bool IdIsBochs(u16 id)
{
    // Known IDs: 0xB0C0 / 0xB0C1 / 0xB0C2 / 0xB0C3 / 0xB0C4 /
    // 0xB0C5. Every version after 0xB0C0 supports strictly more
    // features, so any 0xB0Cx is acceptable for v0.
    return (id & 0xFFF0) == 0xB0C0;
}

} // namespace

VbeCaps VbeQuery()
{
    VbeCaps c = {};
    const u16 id = Read(kVbeIdxId);
    if (!IdIsBochs(id))
    {
        c.present = false;
        return c;
    }
    c.present = true;
    c.version = u16(id & 0x000F);

    // Capture current mode before toggling GETCAPS.
    c.cur_xres = Read(kVbeIdxXres);
    c.cur_yres = Read(kVbeIdxYres);
    c.cur_bpp = Read(kVbeIdxBpp);
    c.enabled = (Read(kVbeIdxEnable) & kVbeEnEnabled) != 0;

    // Query maxes: set ENABLE.GETCAPS=1, read xres/yres/bpp
    // (those registers now return maxima), then clear the bit.
    const u16 saved_enable = Read(kVbeIdxEnable);
    Write(kVbeIdxEnable, kVbeEnGetCaps);
    c.max_xres = Read(kVbeIdxXres);
    c.max_yres = Read(kVbeIdxYres);
    c.max_bpp = Read(kVbeIdxBpp);
    Write(kVbeIdxEnable, saved_enable);

    return c;
}

bool VbeSetMode(u16 width, u16 height, u16 bpp)
{
    const u16 id = Read(kVbeIdxId);
    if (!IdIsBochs(id))
        return false;
    // Disable → program → enable with LFB. The NOCLEARMEM bit
    // preserves the existing framebuffer content across the
    // mode change; without it every pixel goes black during
    // the switch, which is visible as a flash.
    Write(kVbeIdxEnable, 0);
    Write(kVbeIdxXres, width);
    Write(kVbeIdxYres, height);
    Write(kVbeIdxBpp, bpp);
    Write(kVbeIdxEnable, kVbeEnEnabled | kVbeEnLfb | kVbeEnNoClearMem);

    // Confirm the controller accepted the request. Bochs VBE
    // clips silently to its maximums rather than returning an
    // error code, so a mismatched readback = unsupported mode.
    const u16 got_x = Read(kVbeIdxXres);
    const u16 got_y = Read(kVbeIdxYres);
    const u16 got_bpp = Read(kVbeIdxBpp);

    arch::SerialWrite("[bochs-vbe] set-mode requested=");
    arch::SerialWriteHex(width);
    arch::SerialWrite("x");
    arch::SerialWriteHex(height);
    arch::SerialWrite("x");
    arch::SerialWriteHex(bpp);
    arch::SerialWrite(" got=");
    arch::SerialWriteHex(got_x);
    arch::SerialWrite("x");
    arch::SerialWriteHex(got_y);
    arch::SerialWrite("x");
    arch::SerialWriteHex(got_bpp);
    arch::SerialWrite("\n");

    return got_x == width && got_y == height && got_bpp == bpp;
}

void VbeSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/gpu/bochs-vbe", "VbeSelfTest");
    const VbeCaps c = VbeQuery();
    if (!c.present)
    {
        arch::SerialWrite("[bochs-vbe] not present (register pair reads non-BGA value)\n");
        return;
    }
    arch::SerialWrite("[bochs-vbe] present id=0xB0C");
    arch::SerialWriteHex(c.version);
    arch::SerialWrite(" cur=");
    arch::SerialWriteHex(c.cur_xres);
    arch::SerialWrite("x");
    arch::SerialWriteHex(c.cur_yres);
    arch::SerialWrite("x");
    arch::SerialWriteHex(c.cur_bpp);
    arch::SerialWrite(c.enabled ? " (live)" : " (disabled)");
    arch::SerialWrite(" max=");
    arch::SerialWriteHex(c.max_xres);
    arch::SerialWrite("x");
    arch::SerialWriteHex(c.max_yres);
    arch::SerialWrite("x");
    arch::SerialWriteHex(c.max_bpp);
    arch::SerialWrite("\n");
}

} // namespace duetos::drivers::gpu
