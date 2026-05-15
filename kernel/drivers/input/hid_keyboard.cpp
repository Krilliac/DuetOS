/*
 * DuetOS — transport-neutral USB-HID boot-protocol keyboard decoder.
 *
 * See hid_keyboard.h. This is the single owner of the HID-usage →
 * KeyEvent mapping; the xHCI HID poll task and the Bluetooth HID
 * (HOGP / classic HIDP) path both call HidKeyboardDiffAndInject.
 */

#include "drivers/input/hid_keyboard.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::input
{

// HID usage → PS/2 set-1 scancode for the printable keys. Physical-
// key based: the same physical position on every layout, then run
// through the active PS/2 keymap so a runtime layout change applies
// to HID keyboards too. 0 = no scancode; fall through to the
// per-usage switch below.
namespace
{

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

bool UsageInReport(u8 usage, const u8 report[8])
{
    for (u32 i = 2; i < 8; ++i)
    {
        if (report[i] == usage)
            return true;
    }
    return false;
}

} // namespace

u16 HidKeyboardTranslateUsage(u8 usage, bool shift)
{
    const u8 scan = kHidUsageToScancode[usage];
    if (scan != 0)
    {
        const char* table = shift ? Ps2KeyboardActiveUpperMap() : Ps2KeyboardActiveLowerMap();
        const char ch = table[scan];
        if (ch != 0)
            return u16(static_cast<u8>(ch));
        // Active layout has no glyph for this scancode (e.g. DE
        // layout umlaut positions). Fall through to the US table
        // so the user still sees something printable.
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
        return u16(kKeyNone);
    }
}

u8 HidKeyboardTranslateModifiers(u8 hid_mod)
{
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

u32 HidKeyboardDiffEvents(const u8 prev[8], const u8 curr[8], KeyEvent* out, u32 max)
{
    if (prev == nullptr || curr == nullptr || out == nullptr || max == 0)
        return 0;

    const u8 prev_mod = prev[0];
    const u8 curr_mod = curr[0];
    const bool shift = (curr_mod & 0x22u) != 0;
    const u8 kernel_mods = HidKeyboardTranslateModifiers(curr_mod);
    u32 n = 0;

    // Modifier-only event on any modifier-byte change — mirrors the
    // PS/2 decoder so downstream "modifier held" cues update without
    // polling.
    if (prev_mod != curr_mod && n < max)
    {
        KeyEvent ev{};
        ev.code = kKeyNone;
        ev.modifiers = kernel_mods;
        ev.is_release = false;
        out[n++] = ev;
    }

    // Release edges — usages in prev that aren't in curr.
    for (u32 i = 2; i < 8 && n < max; ++i)
    {
        const u8 u = prev[i];
        if (u == 0 || u == 0x01 /* ErrorRollOver */)
            continue;
        if (UsageInReport(u, curr))
            continue;
        KeyEvent ev{};
        ev.code = HidKeyboardTranslateUsage(u, shift);
        ev.modifiers = kernel_mods;
        ev.is_release = true;
        out[n++] = ev;
    }
    // Press edges — usages in curr that weren't in prev.
    for (u32 i = 2; i < 8 && n < max; ++i)
    {
        const u8 u = curr[i];
        if (u == 0 || u == 0x01)
            continue;
        if (UsageInReport(u, prev))
            continue;
        KeyEvent ev{};
        ev.code = HidKeyboardTranslateUsage(u, shift);
        ev.modifiers = kernel_mods;
        ev.is_release = false;
        out[n++] = ev;
    }
    return n;
}

void HidKeyboardDiffAndInject(const u8 prev[8], const u8 curr[8])
{
    KeyEvent evs[kHidKbMaxEventsPerDiff];
    const u32 n = HidKeyboardDiffEvents(prev, curr, evs, kHidKbMaxEventsPerDiff);
    for (u32 i = 0; i < n; ++i)
        KeyboardInjectEvent(evs[i]);
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[hid-kbd] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    core::Panic("drivers/input/hid_keyboard", "HID keyboard self-test mismatch");
}

} // namespace

void HidKeyboardSelfTest()
{
    // Press 'a' (usage 0x04) with no modifiers from an all-zero
    // report. US layout → lower 'a'.
    {
        const u8 prev[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        const u8 curr[8] = {0, 0, 0x04, 0, 0, 0, 0, 0};
        KeyEvent ev[kHidKbMaxEventsPerDiff];
        const u32 n = HidKeyboardDiffEvents(prev, curr, ev, kHidKbMaxEventsPerDiff);
        Expect(n == 1, "press 'a' yields 1 event");
        Expect(ev[0].code == u16('a'), "press 'a' code");
        Expect(!ev[0].is_release, "press 'a' is press");
        Expect(ev[0].modifiers == 0, "press 'a' no mods");
    }

    // Hold LShift then press 'a' → modifier edge + press 'A'.
    {
        const u8 prev[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        const u8 curr[8] = {0x02, 0, 0x04, 0, 0, 0, 0, 0};
        KeyEvent ev[kHidKbMaxEventsPerDiff];
        const u32 n = HidKeyboardDiffEvents(prev, curr, ev, kHidKbMaxEventsPerDiff);
        Expect(n == 2, "shift+a yields modifier edge + press");
        Expect(ev[0].code == kKeyNone, "shift edge is modifier-only");
        Expect((ev[0].modifiers & kKeyModShift) != 0, "shift edge sets shift");
        Expect(ev[1].code == u16('A'), "shifted 'a' is 'A'");
        Expect((ev[1].modifiers & kKeyModShift) != 0, "press carries shift");
    }

    // Release 'a' (curr clears the slot).
    {
        const u8 prev[8] = {0, 0, 0x04, 0, 0, 0, 0, 0};
        const u8 curr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        KeyEvent ev[kHidKbMaxEventsPerDiff];
        const u32 n = HidKeyboardDiffEvents(prev, curr, ev, kHidKbMaxEventsPerDiff);
        Expect(n == 1, "release 'a' yields 1 event");
        Expect(ev[0].code == u16('a'), "release 'a' code");
        Expect(ev[0].is_release, "release 'a' is release");
    }

    // n-key rollover: every slot 0x01 (ErrorRollOver) is ignored —
    // no spurious presses, no key left stuck.
    {
        const u8 prev[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        const u8 curr[8] = {0, 0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        KeyEvent ev[kHidKbMaxEventsPerDiff];
        const u32 n = HidKeyboardDiffEvents(prev, curr, ev, kHidKbMaxEventsPerDiff);
        Expect(n == 0, "rollover report yields no events");
    }

    // Special key: Enter (usage 0x28) → kKeyEnter.
    {
        const u8 prev[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        const u8 curr[8] = {0, 0, 0x28, 0, 0, 0, 0, 0};
        KeyEvent ev[kHidKbMaxEventsPerDiff];
        const u32 n = HidKeyboardDiffEvents(prev, curr, ev, kHidKbMaxEventsPerDiff);
        Expect(n == 1 && ev[0].code == u16(kKeyEnter), "Enter usage maps to kKeyEnter");
    }

    // Null-arg guard.
    {
        KeyEvent ev[1];
        Expect(HidKeyboardDiffEvents(nullptr, nullptr, ev, 1) == 0, "null args yield 0");
    }

    arch::SerialWrite("[hid-kbd] selftest pass\n");
}

} // namespace duetos::drivers::input
