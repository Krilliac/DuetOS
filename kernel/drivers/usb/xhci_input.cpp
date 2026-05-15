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

#include "drivers/input/hid_keyboard.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/usb/hid_descriptor.h"
#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

using namespace duetos::drivers::input;
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

// Boot-protocol keyboard report diffing now lives in the
// transport-neutral input layer (drivers/input/hid_keyboard) so the
// USB and Bluetooth HID paths share one usage→KeyEvent table. This
// is a thin forwarder; HidPollEntry in xhci_init.cpp is the caller.
void HidDiffAndInject(const u8 prev[8], const u8 curr[8])
{
    duetos::drivers::input::HidKeyboardDiffAndInject(prev, curr);
}

} // namespace duetos::drivers::usb::xhci::internal
