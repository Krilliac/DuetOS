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
#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

using namespace duetos::drivers::input;

// Translate a USB HID Keyboard/Keypad page usage ID (§10 of HUT
// 1.4) to the KeyEvent `code` field the shell expects. Returns
// ASCII when there's a direct printable mapping (letters, digits,
// common punctuation) pre-shifted by the HID modifier byte; the
// KeyCode enum for non-printable keys (arrows, F-keys, Esc /
// Tab / Backspace / Enter). Unmapped usage → kKeyNone.
u16 TranslateHidUsage(u8 usage, bool shift)
{
    if (usage >= 0x04 && usage <= 0x1D)
    {
        // A..Z
        return shift ? u16('A' + (usage - 0x04)) : u16('a' + (usage - 0x04));
    }
    if (usage >= 0x1E && usage <= 0x27)
    {
        // 1..0 (0x27 is zero, not after nine)
        static constexpr char kDigitsLower[] = "1234567890";
        static constexpr char kDigitsUpper[] = "!@#$%^&*()";
        const u32 i = (usage - 0x1E);
        return shift ? u16(kDigitsUpper[i]) : u16(kDigitsLower[i]);
    }
    using namespace duetos::drivers::input;
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

// Diff previous vs current HID boot keyboard report. Emit a
// release KeyEvent for every usage in prev-not-in-curr, a press
// Parse a 3-byte HID Boot Mouse report. Layout:
//   byte 0 = buttons (bit 0 = left, 1 = right, 2 = middle, rest
//            reserved)
//   byte 1 = signed dx in mickeys (device-defined units; QEMU
//            treats them as pixels on the host display)
//   byte 2 = signed dy (positive = down; matches our
//            Ps2KeyboardReadPacket convention)
// Inject one MousePacket per report. Boot mouse reports come
// in every tick even when nothing moves; we do NOT filter
// zero-motion reports so a driver looking for button edges
// still sees the right stream.
void HidMouseInject(const u8 report[3])
{
    using namespace duetos::drivers::input;
    MousePacket p{};
    p.buttons = 0;
    if (report[0] & 0x01)
        p.buttons |= kMouseButtonLeft;
    if (report[0] & 0x02)
        p.buttons |= kMouseButtonRight;
    if (report[0] & 0x04)
        p.buttons |= kMouseButtonMiddle;
    // Sign-extend the int8 deltas into our int32 fields.
    p.dx = static_cast<i32>(static_cast<i8>(report[1]));
    p.dy = static_cast<i32>(static_cast<i8>(report[2]));
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
