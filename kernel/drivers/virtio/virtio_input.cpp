#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/input/ps2kbd.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "sched/sched.h"

/*
 * virtio-input — paravirtualised keyboard (virtio 1.0 §5.8).
 *
 * Two virtqueues: eventq (0, device → driver: input events) and
 * statusq (1, driver → device: LED / force-feedback). v0 wires the
 * eventq keyboard path only — statusq is not installed (no LED /
 * FF consumer in tree) and pointer events are GAPped (see below).
 *
 * The eventq carries a stream of `virtio_input_event` records, one
 * per used-ring buffer (§5.8.6.2). Each is the exact Linux evdev
 * shape: {type, code, value}. For a keyboard the device emits
 * EV_KEY records (type 1) whose `code` is a Linux keycode and
 * whose `value` is 1 (press) / 0 (release) / 2 (autorepeat), each
 * followed by an EV_SYN (type 0) frame terminator we ignore.
 *
 * Linux keycodes for the AT 101/104 block (1..0x58) are
 * numerically identical to PS/2 set-1 scancodes by historical
 * design, so the printable path reuses the SAME active PS/2 keymap
 * the PS/2 and USB-HID keyboard decoders use — one source of truth
 * for layout (CLAUDE.md rule 6). Decoded `KeyEvent`s go through
 * `KeyboardInjectEvent`, the same kernel input queue PS/2 / xHCI
 * HID / Bluetooth HID feed.
 *
 * GAP: pointer devices (EV_REL / EV_ABS — virtio-mouse /
 * virtio-tablet) decode to nothing here; the mouse injection path
 * is a separate slice. GAP: single device — a second virtio-input
 * function is rejected (matches virtio-console's v0 stance).
 *
 * Context: kernel. Probe runs at boot (no IRQ); a dedicated poll
 * task drains the eventq on the same 10 ms cadence virtio-net's
 * RX task uses. IRQ-driven completion is the next layer.
 */

namespace duetos::drivers::virtio
{

namespace
{

using duetos::drivers::input::KeyboardInjectEvent;
using duetos::drivers::input::KeyEvent;
namespace input = duetos::drivers::input;

// evdev event types (linux/input-event-codes.h).
inline constexpr u16 kEvSyn = 0x00;
inline constexpr u16 kEvKey = 0x01;

// evdev modifier keycodes.
inline constexpr u16 kKeyLeftCtrl = 29;
inline constexpr u16 kKeyRightCtrl = 97;
inline constexpr u16 kKeyLeftShift = 42;
inline constexpr u16 kKeyRightShift = 54;
inline constexpr u16 kKeyLeftAlt = 56;
inline constexpr u16 kKeyRightAlt = 100;
inline constexpr u16 kKeyLeftMeta = 125;
inline constexpr u16 kKeyRightMeta = 126;
inline constexpr u16 kKeyCapsLock = 58;

// virtio-input config-space selects (§5.8.5) — we only read NAME
// for an honest boot-log sentinel.
inline constexpr u8 kCfgIdName = 0x01;

struct virtio_input_event
{
    u16 type;
    u16 code;
    u32 value;
};

struct InputState
{
    bool up;
    bool shift;
    bool ctrl;
    bool alt;
    bool meta;
    bool caps;
    VirtioPciLayout layout;
    VirtioQueue evtq;
    mm::PhysAddr evt_buf_phys;
    u8* evt_buf_virt;
    u64 events_seen;
};

constinit InputState g_input = {};
inline constexpr u16 kNumEvtSlots = 16;
inline constexpr u32 kEvtRecBytes = sizeof(virtio_input_event); // 8
inline constexpr u32 kEvtPollSleepTicks = 1;                    // ~10 ms at 100 Hz
inline constexpr u32 kEvtPollBudget = 32;

// Self-test capture seam — when armed, decoded KeyEvents land in
// g_cap_buf instead of the live input queue so the boot self-test
// proves the evdev→KeyEvent chain without phantom keystrokes.
constinit bool g_cap_active = false;
constinit KeyEvent g_cap_buf[16] = {};
constinit u32 g_cap_count = 0;

void EmitEvent(const KeyEvent& ev)
{
    if (g_cap_active)
    {
        const u32 cap = sizeof(g_cap_buf) / sizeof(g_cap_buf[0]);
        if (g_cap_count < cap)
            g_cap_buf[g_cap_count++] = ev;
        return;
    }
    KeyboardInjectEvent(ev);
}

u8 ModMask()
{
    u8 m = 0;
    if (g_input.shift)
        m |= input::kKeyModShift;
    if (g_input.ctrl)
        m |= input::kKeyModCtrl;
    if (g_input.alt)
        m |= input::kKeyModAlt;
    if (g_input.meta)
        m |= input::kKeyModMeta;
    if (g_input.caps)
        m |= input::kKeyModCapsLock;
    return m;
}

// Returns true and updates modifier state if `code` is a modifier
// key. Caps Lock toggles on press only; the rest track held state.
bool HandleModifier(u16 code, bool pressed)
{
    switch (code)
    {
    case kKeyLeftCtrl:
    case kKeyRightCtrl:
        g_input.ctrl = pressed;
        return true;
    case kKeyLeftShift:
    case kKeyRightShift:
        g_input.shift = pressed;
        return true;
    case kKeyLeftAlt:
    case kKeyRightAlt:
        g_input.alt = pressed;
        return true;
    case kKeyLeftMeta:
    case kKeyRightMeta:
        g_input.meta = pressed;
        return true;
    case kKeyCapsLock:
        if (pressed)
            g_input.caps = !g_input.caps;
        return true;
    default:
        return false;
    }
}

// Translate one evdev keycode to a KeyEvent.code. Printable keys
// (code in the AT block) index the active PS/2 keymap directly —
// the evdev code IS the set-1 scancode there. Returns kKeyNone for
// a code this v0 does not map (caller drops it).
u16 EvdevToKeyCode(u16 code)
{
    switch (code)
    {
    case 1:
        return u16(input::kKeyEsc);
    case 103:
        return u16(input::kKeyArrowUp);
    case 108:
        return u16(input::kKeyArrowDown);
    case 105:
        return u16(input::kKeyArrowLeft);
    case 106:
        return u16(input::kKeyArrowRight);
    case 102:
        return u16(input::kKeyHome);
    case 107:
        return u16(input::kKeyEnd);
    case 104:
        return u16(input::kKeyPageUp);
    case 109:
        return u16(input::kKeyPageDown);
    case 110:
        return u16(input::kKeyInsert);
    case 111:
        return u16(input::kKeyDelete);
    case 59:
    case 60:
    case 61:
    case 62:
    case 63:
    case 64:
    case 65:
    case 66:
    case 67:
    case 68: // F1..F10
        return u16(input::kKeyF1 + (code - 59));
    case 87:
        return u16(input::kKeyF11);
    case 88:
        return u16(input::kKeyF12);
    default:
        break;
    }
    // AT 101/104 printable block: evdev code == set-1 scancode.
    // The active PS/2 map already encodes Enter '\n' / Backspace
    // '\b' / Tab '\t' / Space ' ' at the right slots, which equal
    // kKeyEnter / kKeyBackspace / kKeyTab respectively.
    if (code < 0x59)
    {
        const char* tbl = g_input.shift ? input::Ps2KeyboardActiveUpperMap() : input::Ps2KeyboardActiveLowerMap();
        const char ch = tbl[code];
        if (ch != 0)
            return u16(static_cast<u8>(ch));
    }
    return u16(input::kKeyNone);
}

// Process one fully-decoded evdev record. EV_KEY drives the
// keyboard path; EV_SYN and everything else (EV_REL/EV_ABS — see
// the pointer GAP) are ignored.
void TranslateRecord(const virtio_input_event& e)
{
    if (e.type == kEvSyn)
        return;
    if (e.type != kEvKey)
        return; // GAP: EV_REL / EV_ABS pointer events not wired.

    const bool pressed = (e.value != 0);    // 1 press, 2 autorepeat
    const bool is_release = (e.value == 0); // 0 release

    if (HandleModifier(e.code, pressed))
    {
        // Mirror the PS/2 / HID decoders: a modifier transition
        // surfaces as a code-less event so "Ctrl held" UI cues
        // update without polling.
        KeyEvent ev{};
        ev.code = u16(input::kKeyNone);
        ev.modifiers = ModMask();
        ev.is_release = is_release;
        EmitEvent(ev);
        return;
    }

    const u16 kc = EvdevToKeyCode(e.code);
    if (kc == u16(input::kKeyNone))
        return;
    KeyEvent ev{};
    ev.code = kc;
    ev.modifiers = ModMask();
    ev.is_release = is_release;
    EmitEvent(ev);
}

void EvtPostDesc(u16 idx)
{
    VirtqDesc* d = const_cast<VirtqDesc*>(g_input.evtq.desc);
    d[idx].addr = g_input.evt_buf_phys + u64(idx) * kEvtRecBytes;
    d[idx].len = kEvtRecBytes;
    d[idx].flags = kVirtqDescWrite; // device writes the event
    d[idx].next = 0;
    VirtioQueuePublish(&g_input.layout, &g_input.evtq, idx);
}

u32 DrainEvents(u32 budget)
{
    if (!g_input.up)
        return 0;
    u32 drained = 0;
    while (drained < budget)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (!VirtioQueueTryPop(&g_input.evtq, &head, &used_len))
            break;
        if (head < kNumEvtSlots && used_len >= kEvtRecBytes)
        {
            virtio_input_event e{};
            const u8* src = g_input.evt_buf_virt + head * kEvtRecBytes;
            for (u32 i = 0; i < kEvtRecBytes; ++i)
                reinterpret_cast<u8*>(&e)[i] = src[i];
            ++g_input.events_seen;
            TranslateRecord(e);
        }
        if (head < kNumEvtSlots)
            EvtPostDesc(static_cast<u16>(head));
        ++drained;
    }
    return drained;
}

void VirtioInputPollEntry(void*)
{
    for (;;)
    {
        const u32 drained = DrainEvents(kEvtPollBudget);
        if (drained == kEvtPollBudget)
            continue; // burst — keep draining before we sleep.
        duetos::sched::SchedSleepTicks(kEvtPollSleepTicks);
    }
}

} // namespace

bool VirtioInputProbe(const VirtioPciLayout& L)
{
    if (g_input.up)
    {
        KLOG_WARN("drivers/virtio/input", "second device detected; v0 supports only one");
        return false;
    }

    VirtioPciLayout layout = L;
    if (!VirtioNegotiate(&layout, kFeatureVersion1))
    {
        KLOG_WARN("drivers/virtio/input", "feature negotiation failed");
        return false;
    }
    if (layout.num_queues < 1)
    {
        KLOG_WARN_V("drivers/virtio/input", "device exposes no queues", static_cast<u64>(layout.num_queues));
        return false;
    }

    // queue_index 0 is the eventq (device → driver).
    if (!VirtioQueueSetup(&layout, &g_input.evtq, /*queue_index=*/0, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/input", "eventq setup failed");
        return false;
    }

    const mm::PhysAddr phys = mm::AllocateFrame();
    if (phys == mm::kNullFrame)
    {
        KLOG_WARN("drivers/virtio/input", "event buffer alloc failed");
        return false;
    }
    g_input.evt_buf_phys = phys;
    g_input.evt_buf_virt = static_cast<u8*>(mm::PhysToVirt(phys));
    for (u32 i = 0; i < mm::kPageSize; ++i)
        g_input.evt_buf_virt[i] = 0;

    // Optional: pull the device name for a grep-able boot sentinel
    // (select=ID_NAME, subsel=0; size at off 2, string at off 8).
    char name[64];
    name[0] = 0;
    if (layout.device_cfg != nullptr)
    {
        volatile u8* cfg = layout.device_cfg;
        cfg[0] = kCfgIdName; // select
        cfg[1] = 0;          // subsel
        const u8 sz = cfg[2];
        const u32 n = (sz < sizeof(name) - 1) ? sz : u32(sizeof(name) - 1);
        for (u32 i = 0; i < n; ++i)
            name[i] = static_cast<char>(cfg[8 + i]);
        name[n] = 0;
    }

    g_input.layout = layout;
    g_input.up = true;

    // Pre-post every eventq descriptor; from here the device can
    // write input events into our buffers.
    for (u16 i = 0; i < kNumEvtSlots; ++i)
        EvtPostDesc(i);

    duetos::sched::SchedCreate(VirtioInputPollEntry, nullptr, "virtio-input-evt-poll");

    if (name[0] != 0)
        KLOG_INFO_S("drivers/virtio/input", "attached (keyboard, eventq)", "name", name);
    else
        KLOG_INFO("drivers/virtio/input", "attached (keyboard, eventq)");
    return true;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[virtio-input] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    core::Panic("drivers/virtio/input", "virtio-input self-test mismatch");
}

virtio_input_event MkKey(u16 code, u32 value)
{
    virtio_input_event e{};
    e.type = kEvKey;
    e.code = code;
    e.value = value;
    return e;
}

} // namespace

void VirtioInputSelfTest()
{
    g_cap_active = true;
    g_input.shift = g_input.ctrl = g_input.alt = g_input.meta = g_input.caps = false;

    // Press 'a' (evdev KEY_A = 30) → lower 'a', no mods.
    g_cap_count = 0;
    TranslateRecord(MkKey(30, 1));
    Expect(g_cap_count == 1, "press 'a' yields 1 event");
    Expect(g_cap_buf[0].code == u16('a') && !g_cap_buf[0].is_release, "press 'a' decoded");
    Expect(g_cap_buf[0].modifiers == 0, "press 'a' no mods");

    // Release 'a' (value 0).
    g_cap_count = 0;
    TranslateRecord(MkKey(30, 0));
    Expect(g_cap_count == 1 && g_cap_buf[0].code == u16('a') && g_cap_buf[0].is_release, "release 'a' decoded");

    // LeftShift press (modifier-only edge) then 'a' → 'A'.
    g_cap_count = 0;
    TranslateRecord(MkKey(kKeyLeftShift, 1));
    Expect(g_cap_count == 1 && g_cap_buf[0].code == u16(input::kKeyNone), "shift edge is modifier-only");
    Expect((g_cap_buf[0].modifiers & input::kKeyModShift) != 0, "shift edge sets shift bit");
    g_cap_count = 0;
    TranslateRecord(MkKey(30, 1));
    Expect(g_cap_count == 1 && g_cap_buf[0].code == u16('A'), "shifted 'a' is 'A'");
    Expect((g_cap_buf[0].modifiers & input::kKeyModShift) != 0, "press carries shift");
    TranslateRecord(MkKey(kKeyLeftShift, 0)); // release shift, clear state

    // Enter (evdev KEY_ENTER = 28) → kKeyEnter via the PS/2 map.
    g_cap_count = 0;
    TranslateRecord(MkKey(28, 1));
    Expect(g_cap_count == 1 && g_cap_buf[0].code == u16(input::kKeyEnter), "Enter maps to kKeyEnter");

    // Esc (evdev KEY_ESC = 1) → kKeyEsc (special-cased).
    g_cap_count = 0;
    TranslateRecord(MkKey(1, 1));
    Expect(g_cap_count == 1 && g_cap_buf[0].code == u16(input::kKeyEsc), "Esc maps to kKeyEsc");

    // ArrowUp (evdev KEY_UP = 103) → kKeyArrowUp.
    g_cap_count = 0;
    TranslateRecord(MkKey(103, 1));
    Expect(g_cap_count == 1 && g_cap_buf[0].code == u16(input::kKeyArrowUp), "Up maps to kKeyArrowUp");

    // EV_SYN frame terminator and an unmapped EV_REL produce nothing.
    g_cap_count = 0;
    virtio_input_event syn{};
    syn.type = kEvSyn;
    TranslateRecord(syn);
    virtio_input_event rel{};
    rel.type = 0x02; // EV_REL
    rel.code = 0;
    rel.value = 1;
    TranslateRecord(rel);
    Expect(g_cap_count == 0, "EV_SYN + EV_REL yield no events");

    // Teardown: leave decoder state pristine for production.
    g_input.shift = g_input.ctrl = g_input.alt = g_input.meta = g_input.caps = false;
    g_cap_active = false;
    g_cap_count = 0;
    arch::SerialWrite("[virtio-input] selftest pass\n");
}

} // namespace duetos::drivers::virtio
