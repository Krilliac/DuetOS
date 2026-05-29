#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
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
 * Pointer devices (virtio-mouse) are decoded too: EV_REL deltas
 * (REL_X / REL_Y / REL_WHEEL) and the mouse-button EV_KEY codes
 * (BTN_LEFT / RIGHT / MIDDLE / SIDE / EXTRA) accumulate across a
 * frame and flush as one `MousePacket` on the EV_SYN terminator,
 * through `MouseInjectPacket` — the same kernel pointer queue
 * PS/2 / xHCI-HID mice feed (CLAUDE.md rule 6, one source of
 * truth).
 *
 * Tablets (virtio-tablet) advertise EV_ABS axes ABS_X / ABS_Y that
 * carry absolute device coordinates rather than deltas. To keep the
 * one-source-of-truth invariant — `MousePacket` is relative-only,
 * fed by every pointer driver — the decoder converts absolute axes
 * into deltas at the driver boundary: it remembers the last raw
 * ABS_X / ABS_Y per device and the next frame's packet carries
 * `dx = curr - last`. The first frame after an EV_ABS axis appears
 * anchors the baseline and emits no movement (so a freshly attached
 * tablet doesn't fling the cursor to (0,0)). End-user behaviour
 * matches QEMU `-device virtio-tablet`: host motion drives guest
 * cursor 1:1, the host releases its pointer grab once it sees the
 * guest read EV_ABS.
 *
 * GAP: single device — a second virtio-input function is rejected
 * (matches virtio-console's v0 stance).
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
using duetos::drivers::input::MouseInjectPacket;
using duetos::drivers::input::MousePacket;
namespace input = duetos::drivers::input;

// evdev event types (linux/input-event-codes.h).
inline constexpr u16 kEvSyn = 0x00;
inline constexpr u16 kEvKey = 0x01;
inline constexpr u16 kEvRel = 0x02;
inline constexpr u16 kEvAbs = 0x03;

// evdev relative axes.
inline constexpr u16 kRelX = 0x00;
inline constexpr u16 kRelY = 0x01;
inline constexpr u16 kRelWheel = 0x08;

// evdev absolute axes. ABS_X / ABS_Y carry tablet coordinates in
// the device-supplied range (queried via virtio config-space
// ID_ABS_INFO §5.8.5 — we don't need the range to compute deltas).
inline constexpr u16 kAbsX = 0x00;
inline constexpr u16 kAbsY = 0x01;

// evdev mouse-button keycodes. BTN_* codes start at 0x100; any
// EV_KEY whose code is in this range is pointer-domain, not a
// keyboard key, and never reaches the keymap.
inline constexpr u16 kBtnFirst = 0x100;
inline constexpr u16 kBtnLeft = 0x110;
inline constexpr u16 kBtnRight = 0x111;
inline constexpr u16 kBtnMiddle = 0x112;
inline constexpr u16 kBtnSide = 0x113;
inline constexpr u16 kBtnExtra = 0x114;

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
    // Pointer accumulator. dx/dy/dz collect EV_REL deltas within a
    // frame and reset on flush; buttons hold level state (evdev
    // reports a button only on its press/release edge). EV_ABS axes
    // (virtio-tablet) are converted to deltas via last_abs_{x,y};
    // the first EV_ABS sighting anchors the baseline (abs_seen)
    // without emitting a packet, so a freshly attached tablet
    // doesn't fling the cursor.
    i32 ptr_dx;
    i32 ptr_dy;
    i32 ptr_dz;
    u8 ptr_buttons;
    bool ptr_dirty; // a pointer event arrived since the last EV_SYN
    i32 last_abs_x;
    i32 last_abs_y;
    bool abs_seen_x;
    bool abs_seen_y;
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
constinit MousePacket g_cap_mouse_buf[8] = {};
constinit u32 g_cap_mouse_count = 0;

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

void EmitMouse(const MousePacket& p)
{
    if (g_cap_active)
    {
        const u32 cap = sizeof(g_cap_mouse_buf) / sizeof(g_cap_mouse_buf[0]);
        if (g_cap_mouse_count < cap)
            g_cap_mouse_buf[g_cap_mouse_count++] = p;
        return;
    }
    MouseInjectPacket(p);
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

// Accumulate one EV_REL delta into the frame's pending packet.
// evdev sign conventions already match MousePacket: REL_Y positive
// = down (screen-space), REL_WHEEL positive = scroll up. REL_HWHEEL
// and other axes have no MousePacket field and are dropped (mirrors
// the USB-HID horizontal-tilt stance).
void HandleRel(u16 code, i32 delta)
{
    switch (code)
    {
    case kRelX:
        g_input.ptr_dx += delta;
        break;
    case kRelY:
        g_input.ptr_dy += delta;
        break;
    case kRelWheel:
        g_input.ptr_dz += delta;
        break;
    default:
        return; // unmapped axis — no frame activity
    }
    g_input.ptr_dirty = true;
}

// Convert one EV_ABS axis report into the frame's accumulator. The
// first sighting of an axis stores its raw value as the baseline
// without contributing to the packet; subsequent reports turn into
// (curr - last) deltas. evdev's ABS_Y sign convention matches
// MousePacket: positive = down. Axes other than ABS_X / ABS_Y
// (multitouch slots, tilt, pressure) have no MousePacket field
// today and are dropped here — the USB-HID stance for the same
// classes.
void HandleAbs(u16 code, i32 value)
{
    switch (code)
    {
    case kAbsX:
        if (g_input.abs_seen_x)
        {
            const i32 delta = value - g_input.last_abs_x;
            g_input.ptr_dx += delta;
            g_input.ptr_dirty = true;
        }
        else
        {
            g_input.abs_seen_x = true;
        }
        g_input.last_abs_x = value;
        break;
    case kAbsY:
        if (g_input.abs_seen_y)
        {
            const i32 delta = value - g_input.last_abs_y;
            g_input.ptr_dy += delta;
            g_input.ptr_dirty = true;
        }
        else
        {
            g_input.abs_seen_y = true;
        }
        g_input.last_abs_y = value;
        break;
    default:
        return;
    }
}

// Update level-state for a mouse button (BTN_* EV_KEY code). Unknown
// BTN_* codes (joystick / tool) are pointer-domain but unmapped, so
// they neither toggle a button nor leak into the keymap.
void HandleButton(u16 code, bool down)
{
    u8 bit = 0;
    switch (code)
    {
    case kBtnLeft:
        bit = input::kMouseButtonLeft;
        break;
    case kBtnRight:
        bit = input::kMouseButtonRight;
        break;
    case kBtnMiddle:
        bit = input::kMouseButtonMiddle;
        break;
    case kBtnSide:
        bit = input::kMouseButton4;
        break;
    case kBtnExtra:
        bit = input::kMouseButton5;
        break;
    default:
        return;
    }
    if (down)
        g_input.ptr_buttons |= bit;
    else
        g_input.ptr_buttons &= static_cast<u8>(~bit);
    g_input.ptr_dirty = true;
}

// EV_SYN terminator: emit one MousePacket if any pointer event
// arrived this frame. Deltas reset; button level-state persists.
void FlushPointer()
{
    if (!g_input.ptr_dirty)
        return;
    MousePacket p{};
    p.dx = g_input.ptr_dx;
    p.dy = g_input.ptr_dy;
    p.dz = g_input.ptr_dz;
    p.buttons = g_input.ptr_buttons;
    EmitMouse(p);
    g_input.ptr_dx = 0;
    g_input.ptr_dy = 0;
    g_input.ptr_dz = 0;
    g_input.ptr_dirty = false;
}

// Process one fully-decoded evdev record. EV_KEY (keyboard codes)
// drives the keyboard path; EV_REL, EV_ABS (virtio-tablet) and the
// BTN_* EV_KEY codes drive the pointer accumulator, flushed on
// EV_SYN.
void TranslateRecord(const virtio_input_event& e)
{
    if (e.type == kEvSyn)
    {
        FlushPointer();
        return;
    }
    if (e.type == kEvRel)
    {
        HandleRel(e.code, static_cast<i32>(e.value));
        return;
    }
    if (e.type == kEvAbs)
    {
        HandleAbs(e.code, static_cast<i32>(e.value));
        return;
    }
    if (e.type != kEvKey)
        return; // ignore unmapped event types (EV_MSC timestamp, EV_LED, ...)
    if (e.code >= kBtnFirst)
    {
        HandleButton(e.code, e.value != 0);
        return;
    }

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

    auto phys_r = mm::AllocateFrame();
    if (!phys_r)
    {
        KLOG_WARN("drivers/virtio/input", "event buffer alloc failed");
        return false;
    }
    const mm::PhysAddr phys = phys_r.value();
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

    // Spec §3.1.1 step 8 — eventq is configured; finalise the
    // device before pre-posting buffers it will write into.
    VirtioMarkDriverOk(&layout);

    // Pre-post every eventq descriptor; from here the device can
    // write input events into our buffers.
    for (u16 i = 0; i < kNumEvtSlots; ++i)
        EvtPostDesc(i);

    duetos::sched::SchedCreate(VirtioInputPollEntry, nullptr, "virtio-input-evt-poll");

    if (name[0] != 0)
        KLOG_INFO_S("drivers/virtio/input", "attached (keyboard/pointer, eventq)", "name", name);
    else
        KLOG_INFO("drivers/virtio/input", "attached (keyboard/pointer, eventq)");
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

virtio_input_event MkRel(u16 code, i32 value)
{
    virtio_input_event e{};
    e.type = kEvRel;
    e.code = code;
    e.value = static_cast<u32>(value);
    return e;
}

virtio_input_event MkAbs(u16 code, i32 value)
{
    virtio_input_event e{};
    e.type = kEvAbs;
    e.code = code;
    e.value = static_cast<u32>(value);
    return e;
}

virtio_input_event MkSyn()
{
    virtio_input_event e{};
    e.type = kEvSyn;
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

    // A bare EV_SYN with no preceding pointer activity emits nothing
    // on either queue.
    g_cap_count = 0;
    g_cap_mouse_count = 0;
    TranslateRecord(MkSyn());
    Expect(g_cap_count == 0 && g_cap_mouse_count == 0, "lone EV_SYN yields nothing");

    // Pointer: REL_X=+5, REL_Y=-3 then EV_SYN → one MousePacket.
    g_cap_mouse_count = 0;
    TranslateRecord(MkRel(kRelX, 5));
    TranslateRecord(MkRel(kRelY, -3));
    Expect(g_cap_mouse_count == 0, "REL deltas do not emit before EV_SYN");
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 1, "EV_SYN flushes one MousePacket");
    Expect(g_cap_mouse_buf[0].dx == 5 && g_cap_mouse_buf[0].dy == -3, "REL deltas decoded (dy down-positive)");
    Expect(g_cap_mouse_buf[0].buttons == 0, "no buttons held");

    // Button level-state: BTN_LEFT down persists across frames; the
    // delta resets after the previous flush.
    g_cap_mouse_count = 0;
    TranslateRecord(MkKey(kBtnLeft, 1));
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 1 && (g_cap_mouse_buf[0].buttons & input::kMouseButtonLeft) != 0,
           "BTN_LEFT press surfaces");
    Expect(g_cap_mouse_buf[0].dx == 0 && g_cap_mouse_buf[0].dy == 0, "deltas reset after prior flush");
    g_cap_mouse_count = 0;
    TranslateRecord(MkRel(kRelWheel, 1));
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 1 && g_cap_mouse_buf[0].dz == 1, "REL_WHEEL +1 decoded (up-positive)");
    Expect((g_cap_mouse_buf[0].buttons & input::kMouseButtonLeft) != 0, "held button persists across frames");
    // Release BTN_LEFT and flush its frame so the pending edge does
    // not leak into the next sub-test.
    g_cap_mouse_count = 0;
    TranslateRecord(MkKey(kBtnLeft, 0));
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 1 && g_cap_mouse_buf[0].buttons == 0, "BTN_LEFT release clears the bit");

    // An unmapped BTN_* code is pointer-domain: it neither toggles a
    // button nor reaches the keymap, so the frame stays empty.
    g_cap_count = 0;
    g_cap_mouse_count = 0;
    TranslateRecord(MkKey(0x120, 1)); // BTN_TRIGGER (joystick)
    TranslateRecord(MkSyn());
    Expect(g_cap_count == 0 && g_cap_mouse_count == 0, "unmapped BTN_* yields nothing");

    // virtio-tablet (EV_ABS) path. The first frame anchors the
    // baseline silently; the second emits the delta. ABS_Y down-
    // positive matches MousePacket dy down-positive.
    g_input.last_abs_x = 0;
    g_input.last_abs_y = 0;
    g_input.abs_seen_x = false;
    g_input.abs_seen_y = false;
    g_cap_mouse_count = 0;
    TranslateRecord(MkAbs(kAbsX, 100));
    TranslateRecord(MkAbs(kAbsY, 50));
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 0, "first EV_ABS frame anchors baseline silently");
    Expect(g_input.last_abs_x == 100 && g_input.last_abs_y == 50, "baseline recorded");
    g_cap_mouse_count = 0;
    TranslateRecord(MkAbs(kAbsX, 110));
    TranslateRecord(MkAbs(kAbsY, 45));
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 1, "second EV_ABS frame emits delta packet");
    Expect(g_cap_mouse_buf[0].dx == 10 && g_cap_mouse_buf[0].dy == -5, "EV_ABS delta decoded (dy down-positive)");

    // Tablet + button works the same as relative + button.
    g_cap_mouse_count = 0;
    TranslateRecord(MkKey(kBtnLeft, 1));
    TranslateRecord(MkAbs(kAbsX, 115));
    TranslateRecord(MkSyn());
    Expect(g_cap_mouse_count == 1 && g_cap_mouse_buf[0].dx == 5 &&
               (g_cap_mouse_buf[0].buttons & input::kMouseButtonLeft) != 0,
           "EV_ABS + BTN_LEFT compose one packet");
    // Release the held button so it doesn't leak past selftest.
    TranslateRecord(MkKey(kBtnLeft, 0));
    TranslateRecord(MkSyn());

    // Teardown: leave decoder state pristine for production.
    g_input.shift = g_input.ctrl = g_input.alt = g_input.meta = g_input.caps = false;
    g_input.ptr_dx = g_input.ptr_dy = g_input.ptr_dz = 0;
    g_input.ptr_buttons = 0;
    g_input.ptr_dirty = false;
    g_input.last_abs_x = 0;
    g_input.last_abs_y = 0;
    g_input.abs_seen_x = false;
    g_input.abs_seen_y = false;
    g_cap_active = false;
    g_cap_count = 0;
    g_cap_mouse_count = 0;
    arch::SerialWrite("[virtio-input] selftest pass\n");
}

} // namespace duetos::drivers::virtio
