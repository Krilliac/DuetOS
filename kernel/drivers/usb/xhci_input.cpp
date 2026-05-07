/*
 * DuetOS — xHCI driver: HID input translation.
 *
 * Sibling TU to xhci.cpp / xhci_complete.cpp. Houses the boot-
 * protocol HID translation layer that lifts USB HID Keyboard/Keypad
 * page usages and boot-mouse reports into the kernel's PS/2-shaped
 * input queues so the shell + window manager don't care whether
 * the device behind a key event is on the USB bus or the legacy
 * 8042 controller.
 *
 * No xHCI controller / TRB / Runtime state is touched here — the
 * functions take already-decoded report bytes from HidPollEntry
 * over in xhci.cpp. Cross-TU surface lives in xhci_internal.h.
 */

#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/usb/hid_descriptor.h"
#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

using namespace duetos::drivers::input;

// HID usage → PS/2 set-1 scancode mapping for the printable
// keys. The mapping is physical-key based (the same physical
// position on every layout); we then run the scancode through
// the active PS/2 keymap (g_keymap_lower / upper) to honour
// the layout chosen via Settings → Keyboard. 0 = no mapping;
// caller falls back to the per-usage switch below.
constexpr u8 kHidUsageToScancode[256] = {
    /* 0x00 */ 0,    0,    0,    0,    0x1E, 0x30, 0x2E, 0x20,
    /* 0x08 */ 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26,
    /* 0x10 */ 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14,
    /* 0x18 */ 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, 0x02, 0x03,
    /* 0x20 */ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    /* 0x28 */ 0,    0,    0,    0,    0,    0x0C, 0x0D, 0x1A,
    /* 0x30 */ 0x1B, 0x2B, 0,    0x27, 0x28, 0x29, 0x33, 0x34,
    /* 0x38 */ 0x35, 0,    0,    0,    0,    0,    0,    0,
    /* 0x40 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x48 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x50 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x58 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x60 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x68 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x70 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x78 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x80 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x88 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x90 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0x98 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xA0 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xA8 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xB0 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xB8 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xC0 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xC8 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xD0 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xD8 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xE0 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xE8 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xF0 */ 0,    0,    0,    0,    0,    0,    0,    0,
    /* 0xF8 */ 0,    0,    0,    0,    0,    0,    0,    0,
};

// Active layout keymaps via the ps2kbd accessor. Both
// arrays are 128 entries; the pointer is whichever layout
// the user picked via Settings.

// Translate a USB HID Keyboard/Keypad page usage ID (§10 of HUT
// 1.4) to the KeyEvent `code` field the shell expects. Routes
// printable keys through kHidUsageToScancode + the active PS/2
// keymap so a runtime layout change (US/UK/Dvorak/DE/FR/Colemak)
// applies to USB HID keyboards too. Falls back to the original
// per-usage US punctuation table when there's no scancode map.
u16 TranslateHidUsage(u8 usage, bool shift)
{
    using namespace duetos::drivers::input;
    const u8 scan = kHidUsageToScancode[usage];
    if (scan != 0)
    {
        const char* table = shift ? Ps2KeyboardActiveUpperMap() : Ps2KeyboardActiveLowerMap();
        const char ch = table[scan];
        if (ch != 0)
            return u16(static_cast<u8>(ch));
        // Active layout has no glyph for this scancode (e.g. DE
        // layout's umlaut positions). Keep US fallback so the
        // user still sees something printable.
    }
    switch (usage)
    {
    case 0x28:
        return u16(kKeyEnter);
    case 0x29:
        return u16(kKeyEsc);
    case 0x2A:
        return u16(kKeyBackspace);
    case 0x2B:
        return u16(kKeyTab);
    case 0x2C:
        return u16(' ');
    case 0x2D:
        return shift ? u16('_') : u16('-');
    case 0x2E:
        return shift ? u16('+') : u16('=');
    case 0x2F:
        return shift ? u16('{') : u16('[');
    case 0x30:
        return shift ? u16('}') : u16(']');
    case 0x31:
        return shift ? u16('|') : u16('\\');
    case 0x33:
        return shift ? u16(':') : u16(';');
    case 0x34:
        return shift ? u16('"') : u16('\'');
    case 0x35:
        return shift ? u16('~') : u16('`');
    case 0x36:
        return shift ? u16('<') : u16(',');
    case 0x37:
        return shift ? u16('>') : u16('.');
    case 0x38:
        return shift ? u16('?') : u16('/');
    case 0x3A:
        return u16(kKeyF1);
    case 0x3B:
        return u16(kKeyF2);
    case 0x3C:
        return u16(kKeyF3);
    case 0x3D:
        return u16(kKeyF4);
    case 0x3E:
        return u16(kKeyF5);
    case 0x3F:
        return u16(kKeyF6);
    case 0x40:
        return u16(kKeyF7);
    case 0x41:
        return u16(kKeyF8);
    case 0x42:
        return u16(kKeyF9);
    case 0x43:
        return u16(kKeyF10);
    case 0x44:
        return u16(kKeyF11);
    case 0x45:
        return u16(kKeyF12);
    case 0x4F:
        return u16(kKeyArrowRight);
    case 0x50:
        return u16(kKeyArrowLeft);
    case 0x51:
        return u16(kKeyArrowDown);
    case 0x52:
        return u16(kKeyArrowUp);
    default:
        return u16(duetos::drivers::input::kKeyNone);
    }
}

u8 TranslateHidModifiers(u8 hid_mod)
{
    using namespace duetos::drivers::input;
    u8 m = 0;
    if (hid_mod & 0x11u) // LCtrl | RCtrl
        m |= kKeyModCtrl;
    if (hid_mod & 0x22u) // LShift | RShift
        m |= kKeyModShift;
    if (hid_mod & 0x44u) // LAlt | RAlt
        m |= kKeyModAlt;
    if (hid_mod & 0x88u) // LMeta | RMeta
        m |= kKeyModMeta;
    return m;
}

bool UsageInReport(u8 usage, const u8 report[8])
{
    for (u32 i = 2; i < 8; ++i)
    {
        if (report[i] == usage)
            return true;
    }
    return false;
}

// Decode a HID mouse report and inject one MousePacket. Reports
// come in every poll even when nothing moves; we do NOT filter
// zero-motion reports so a driver looking for button edges still
// sees the right stream.
//
// Layouts handled (the common forms a USB-HID mouse uses without
// negotiating SetProtocol — the host gets whichever the device
// powers up in):
//   - 3 bytes (boot protocol):
//       byte 0 = buttons (bit 0 = left, 1 = right, 2 = middle)
//       byte 1 = signed dx
//       byte 2 = signed dy
//   - 4 bytes (extended boot, the most common wheel-mouse layout):
//       same as 3-byte + byte 3 = signed wheel ticks
//   - 5+ bytes (extended boot + side buttons / tilt):
//       byte 0 also exposes bits 3 = button4, 4 = button5
//       byte 3 = wheel, byte 4 ignored (horizontal tilt — no
//       MousePacket field for it yet)
//
// Reports of zero length or smaller than 3 bytes are dropped.
// Reports longer than 8 bytes are clamped to 8 (typical interrupt
// IN endpoint max for a HID mouse — anything bigger is a
// non-standard layout we won't decode without the report descriptor
// parser landing field-level offsets).
void HidMouseInjectN(const u8* report, u32 len)
{
    using namespace duetos::drivers::input;
    if (report == nullptr || len < 3)
        return;
    if (len > 8)
        len = 8;
    MousePacket p{};
    p.buttons = 0;
    if (report[0] & 0x01)
        p.buttons |= kMouseButtonLeft;
    if (report[0] & 0x02)
        p.buttons |= kMouseButtonRight;
    if (report[0] & 0x04)
        p.buttons |= kMouseButtonMiddle;
    if (len >= 5)
    {
        if (report[0] & 0x08)
            p.buttons |= kMouseButton4;
        if (report[0] & 0x10)
            p.buttons |= kMouseButton5;
    }
    p.dx = static_cast<i32>(static_cast<i8>(report[1]));
    p.dy = static_cast<i32>(static_cast<i8>(report[2]));
    if (len >= 4)
        p.dz = static_cast<i32>(static_cast<i8>(report[3]));
    MouseInjectPacket(p);
}

void HidMouseInject(const u8 report[3])
{
    HidMouseInjectN(report, 3);
}

namespace
{

// Pull `bits` bits starting at `bit_off` out of `report[0..len)`.
// HID packs fields in little-endian bit order; bit 0 of byte 0 is
// the lowest-significance bit of the report stream. Returns 0 for
// any out-of-range read so a malformed report can't run off the
// end. `bits` must be ≤ 32.
u32 ExtractBitsLE(const u8* report, u32 len, u32 bit_off, u32 bits)
{
    if (report == nullptr || bits == 0 || bits > 32)
        return 0;
    u32 acc = 0;
    for (u32 i = 0; i < bits; ++i)
    {
        const u32 src_bit = bit_off + i;
        const u32 byte_off = src_bit >> 3;
        const u32 in_byte = src_bit & 7;
        if (byte_off >= len)
            break; // truncate-on-short-report
        const u32 b = (report[byte_off] >> in_byte) & 1u;
        acc |= b << i;
    }
    return acc;
}

// Sign-extend a `bits`-wide unsigned value to a 32-bit signed
// integer. `bits` must be in [1..32]. Used to lift HID's variable-
// width relative axes into i32 deltas.
i32 SignExtend(u32 value, u32 bits)
{
    if (bits == 0 || bits >= 32)
        return static_cast<i32>(value);
    const u32 mask = (1u << bits) - 1u;
    value &= mask;
    const u32 sign_bit = 1u << (bits - 1);
    if (value & sign_bit)
        return static_cast<i32>(value | ~mask);
    return static_cast<i32>(value);
}

i32 ExtractField(const u8* report, u32 len, const hid::HidMouseField& f)
{
    if (!f.present || f.bit_size == 0)
        return 0;
    const u32 raw = ExtractBitsLE(report, len, f.bit_offset, f.bit_size);
    return f.is_signed ? SignExtend(raw, f.bit_size) : static_cast<i32>(raw);
}

} // namespace

void HidMouseInjectWithLayout(const u8* report, u32 len, const void* layout_opaque)
{
    using namespace duetos::drivers::input;
    if (report == nullptr || layout_opaque == nullptr || len == 0)
        return;
    const auto* layout = static_cast<const hid::HidMouseLayout*>(layout_opaque);
    if (!layout->valid)
        return;

    // Skip the optional Report ID prefix byte. The layout's
    // bit offsets are relative to the start of the *payload*,
    // so a report with an ID prefix slides the report pointer
    // forward and reduces `len` by one.
    if (layout->report_id != 0)
    {
        if (len < 1 || report[0] != layout->report_id)
            return;
        ++report;
        --len;
    }

    MousePacket p{};
    p.buttons = 0;
    if (layout->buttons.present)
    {
        const u32 mask = ExtractBitsLE(report, len, layout->buttons.bit_offset, layout->buttons.bit_size);
        if (mask & 0x01u)
            p.buttons |= kMouseButtonLeft;
        if (mask & 0x02u)
            p.buttons |= kMouseButtonRight;
        if (mask & 0x04u)
            p.buttons |= kMouseButtonMiddle;
        if (mask & 0x08u)
            p.buttons |= kMouseButton4;
        if (mask & 0x10u)
            p.buttons |= kMouseButton5;
    }
    p.dx = ExtractField(report, len, layout->x);
    p.dy = ExtractField(report, len, layout->y);
    p.dz = ExtractField(report, len, layout->wheel);
    // Horizontal tilt has no MousePacket field today — the
    // existing PS/2 surface only carries a single Z (vertical
    // wheel). Discarded for now; revisit when a UI consumer
    // legitimately wants horizontal scroll.
    MouseInjectPacket(p);
}

// for every usage in curr-not-in-prev. Modifier edges emit
// modifier-only events (code=kKeyNone) so downstream can refresh
// any "Ctrl held" UI cues without polling.
void HidDiffAndInject(const u8 prev[8], const u8 curr[8])
{
    using namespace duetos::drivers::input;
    const u8 prev_mod = prev[0];
    const u8 curr_mod = curr[0];
    const bool shift = (curr_mod & 0x22u) != 0;
    const u8 kernel_mods = TranslateHidModifiers(curr_mod);

    // Modifier-only event on any modifier-byte change — mirrors
    // what the PS/2 decoder emits on Shift / Ctrl / Alt / Meta
    // edges so downstream "modifier held" cues update.
    if (prev_mod != curr_mod)
    {
        KeyEvent ev{};
        ev.code = kKeyNone;
        ev.modifiers = kernel_mods;
        ev.is_release = false;
        KeyboardInjectEvent(ev);
    }

    // Release edges — usages in prev that aren't in curr.
    for (u32 i = 2; i < 8; ++i)
    {
        const u8 u = prev[i];
        if (u == 0 || u == 0x01 /* ErrorRollOver */)
            continue;
        if (UsageInReport(u, curr))
            continue;
        KeyEvent ev{};
        ev.code = TranslateHidUsage(u, shift);
        ev.modifiers = kernel_mods;
        ev.is_release = true;
        KeyboardInjectEvent(ev);
    }
    // Press edges — usages in curr that weren't in prev.
    for (u32 i = 2; i < 8; ++i)
    {
        const u8 u = curr[i];
        if (u == 0 || u == 0x01)
            continue;
        if (UsageInReport(u, prev))
            continue;
        KeyEvent ev{};
        ev.code = TranslateHidUsage(u, shift);
        ev.modifiers = kernel_mods;
        ev.is_release = false;
        KeyboardInjectEvent(ev);
    }
}

} // namespace duetos::drivers::usb::xhci::internal
