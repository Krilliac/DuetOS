#include "drivers/input/ps2mouse.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "core/panic.h"
#include "security/login.h"
#include "sched/sched.h"
#include "util/saturating.h"

// Vector 0x2C = IRQ 12. Stub lives in exceptions.S alongside
// isr_33 (kbd, IRQ 1); both follow the same isr_common path.
extern "C" void isr_44();

namespace duetos::drivers::input
{

namespace
{

using arch::Inb;
using arch::Outb;
using arch::SerialWrite;
using arch::SerialWriteHex;

// 8042 controller ports. Same as keyboard — the mouse lives on the
// SAME controller, different channel.
constexpr u16 kDataPort = 0x60;
constexpr u16 kStatusPort = 0x64;

// Status register bits.
constexpr u8 kStatusOutputFull = 1U << 0;
constexpr u8 kStatusInputFull = 1U << 1;
constexpr u8 kStatusMouseData = 1U << 5; // byte is from aux channel

// Controller commands (sent to 0x64).
constexpr u8 kCmdReadConfig = 0x20;
constexpr u8 kCmdWriteConfig = 0x60;
constexpr u8 kCmdEnablePort2 = 0xA8;
constexpr u8 kCmdTestPort2 = 0xA9;
constexpr u8 kCmdWritePort2 = 0xD4; // next byte on 0x60 → aux device

// Config byte bits.
constexpr u8 kConfigPort2IrqEnable = 1U << 1;
constexpr u8 kConfigPort2ClockDisable = 1U << 5;

constexpr u8 kResponseTestPort2Pass = 0x00;

// Mouse device commands (sent through 0xD4 + 0x60).
constexpr u8 kMouseCmdSetDefaults = 0xF6;
constexpr u8 kMouseCmdEnableReporting = 0xF4;
constexpr u8 kMouseCmdSetSampleRate = 0xF3; // followed by a rate byte
constexpr u8 kMouseCmdGetDeviceId = 0xF2;   // ACK then one ID byte

constexpr u8 kMouseAck = 0xFA;

// Poll cap for the 8042 status waits. On bare metal an `Inb` is a few
// cycles, so a large cap is cheap. Under hardware virtualization (VBox,
// VMware, KVM) every `Inb` on the 8042 ports is a VM-exit (~0.5-1 us),
// so the old 1'000'000 cap meant ~1 second PER wait when the device is
// silent — and a mouse-absent VBox aux channel makes every wait spin to
// the full cap, stacking dozens of them into a ~30 s apparent boot hang
// before the "no PS/2 mouse" bail. A present mouse ACKs in microseconds
// (a handful of reads), so 50k keeps an ample margin for real hardware
// while bounding the mouse-absent path to a fraction of a second per
// wait. (Mirrors the VM-exit-cost reasoning behind the auth-pentest
// debug-skip.)
constexpr u64 kPollSpinLimit = 50'000;

// ISA IRQ 12 on the 8042 aux channel.
constexpr u8 kMouseIsaIrq = 12;
constexpr u8 kMouseVector = 0x2C;

// Ring of DECODED packets (not raw bytes). Rationale: packet-boundary
// tracking belongs in the IRQ handler where we already see the bytes
// in order; handing the task-side reader a queue of pre-decoded
// MousePackets saves it from re-implementing the 3-byte state machine.
constexpr u64 kRingSize = 32;
constexpr u64 kRingMask = kRingSize - 1;
static_assert((kRingSize & kRingMask) == 0, "ring size must be power of two");

constinit MousePacket g_ring[kRingSize] = {};
constinit u64 g_ring_head = 0;
constinit u64 g_ring_tail = 0;

// Per-packet IRQ-side state. Three bytes come in; we assemble them
// and only push a complete packet onto the ring.
constinit u8 g_packet_cursor = 0;
constinit u8 g_packet_bytes[4] = {0, 0, 0, 0};
// Packet length: 3 for the standard protocol, 4 once the IntelliMouse
// wheel extension is negotiated (byte[3] carries the signed Z/wheel
// delta). Set by EnableWheel() at bring-up.
constinit u8 g_packet_len = 3;

constinit duetos::sched::WaitQueue g_readers{};

// Lifetime stats — saturating per class BB. Ring cursors above stay
// plain u64 because they're indexed with `& kRingMask` (modular
// arithmetic that SatU64 would freeze).
constinit util::SatU64 g_irqs_seen = 0;
constinit util::SatU64 g_packets_decoded = 0;
constinit util::SatU64 g_bytes_dropped = 0;

// "Available" guard. Ps2MouseInit flips this true only after the
// mouse ACKed its enable-reporting command. If init failed softly,
// every reader just parks forever on a queue that never wakes —
// which is the correct behaviour (no spurious data), but we log
// the skip so it's visible in the boot log rather than mysterious.
constinit bool g_available = false;

// ---------------------------------------------------------------------------
// Controller bring-up helpers — shared conceptually with ps2kbd.cpp but
// duplicated here because the sequence differs enough that a generic
// "8042 helper" library would be a premature abstraction.
// ---------------------------------------------------------------------------

// Returns true if the input buffer drained within the poll budget.
// Init path callers treat false as "no 8042 / no aux channel" and
// soft-fail; anywhere else, a failure is genuinely fatal and the
// caller can decide to panic.
bool TryWaitInputClear()
{
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusInputFull) == 0)
        {
            return true;
        }
    }
    return false;
}

void WaitInputClear()
{
    if (!TryWaitInputClear())
    {
        // Debug: panic so a hardware-stall during development
        // surfaces immediately. Release: log and return — the
        // caller's next port write will go out on a stuck
        // controller and PS/2 init will quietly fail, leaving
        // USB HID as the input path.
        core::DebugPanicOrWarn("drivers/ps2mouse", "8042 input buffer never cleared");
    }
}

// Returns true and writes the read byte into *out on success;
// returns false on poll-budget exhaustion (no aux device or
// firmware-only USB-legacy machine that ignores the test command).
bool TryWaitOutputFull(u8* out)
{
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
        {
            *out = Inb(kDataPort);
            return true;
        }
    }
    return false;
}

u8 WaitOutputFull()
{
    u8 byte = 0;
    if (!TryWaitOutputFull(&byte))
    {
        // Debug: panic. Release: log and return zero — the
        // caller will see a 0 byte from the controller, which
        // is a benign value that fails any subsequent
        // ID/handshake check; PS/2 init backs out cleanly.
        core::DebugPanicOrWarn("drivers/ps2mouse", "8042 output buffer never filled");
    }
    return byte;
}

void SendCtrlCmd(u8 cmd)
{
    WaitInputClear();
    Outb(kStatusPort, cmd);
}

void SendCtrlData(u8 data)
{
    WaitInputClear();
    Outb(kDataPort, data);
}

u8 ReadConfigByte()
{
    SendCtrlCmd(kCmdReadConfig);
    return WaitOutputFull();
}

void WriteConfigByte(u8 value)
{
    SendCtrlCmd(kCmdWriteConfig);
    SendCtrlData(value);
}

// Send a byte to the MOUSE device (aux channel) and wait for ACK
// (0xFA). Returns false on timeout or non-ACK — callers decide
// whether to warn or panic. USB-legacy emulated mice sometimes
// silently ignore some commands, so soft-fail is safer here.
bool MouseSendAndAck(u8 byte)
{
    SendCtrlCmd(kCmdWritePort2);
    WaitInputClear();
    Outb(kDataPort, byte);
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
        {
            return Inb(kDataPort) == kMouseAck;
        }
    }
    return false;
}

// Send a mouse command that returns one data byte after its ACK
// (e.g. Get-Device-ID, 0xF2). Returns the byte, or 0xFF on timeout.
u8 MouseSendAndReadByte(u8 cmd)
{
    if (!MouseSendAndAck(cmd))
        return 0xFF;
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
            return Inb(kDataPort);
    }
    return 0xFF;
}

// Set the mouse sample rate (0xF3 + rate byte). Both bytes ACK.
bool MouseSetSampleRate(u8 rate)
{
    return MouseSendAndAck(kMouseCmdSetSampleRate) && MouseSendAndAck(rate);
}

// Negotiate the Microsoft IntelliMouse wheel extension via the
// documented 200/100/80 sample-rate "magic knock", then read the device
// ID: ID==3 means the mouse switched to the 4-byte wheel protocol
// (byte[3] = signed Z). Non-IntelliMouse mice ignore the knock and report
// ID 0, so we stay in safe 3-byte mode — this is purely additive. Must
// run BEFORE enable-reporting so the rate writes don't interleave with
// motion packets.
void EnableWheel()
{
    if (!MouseSetSampleRate(200) || !MouseSetSampleRate(100) || !MouseSetSampleRate(80))
        return;
    const u8 id = MouseSendAndReadByte(kMouseCmdGetDeviceId);
    if (id == 3)
    {
        g_packet_len = 4;
        core::Log(core::LogLevel::Info, "drivers/ps2mouse", "IntelliMouse wheel enabled (4-byte protocol)");
    }
    // Restore a sane reporting rate (the knock left it at 80 Hz).
    (void)MouseSetSampleRate(100);
}

// ---------------------------------------------------------------------------
// Packet decode.
// ---------------------------------------------------------------------------
MousePacket DecodePacket(const u8* b)
{
    // Byte 0 bit layout (standard 3-byte protocol):
    //   [0] Left button
    //   [1] Right button
    //   [2] Middle button
    //   [3] Always-1 sync marker
    //   [4] X sign bit (1 → byte 1 is negative)
    //   [5] Y sign bit
    //   [6] X overflow — delta exceeded ±255, byte 1 untrustworthy
    //   [7] Y overflow — same for Y
    //
    // We treat overflow as "saturate to ±255 in the reported
    // direction" rather than dropping the packet, matching the
    // behaviour of every mainstream OS. Drops would lose button
    // state updates inside the overflowing packet, which matters
    // more than a one-frame movement inaccuracy.
    const u8 flags = b[0];
    const u8 raw_x = b[1];
    const u8 raw_y = b[2];

    i32 dx = static_cast<i32>(raw_x);
    if (flags & (1U << 4))
    {
        dx -= 256;
    }
    if (flags & (1U << 6))
    {
        dx = (dx < 0) ? -255 : 255;
    }

    i32 dy = static_cast<i32>(raw_y);
    if (flags & (1U << 5))
    {
        dy -= 256;
    }
    if (flags & (1U << 7))
    {
        dy = (dy < 0) ? -255 : 255;
    }
    // Invert Y so the caller's "up = negative" convention matches
    // screen-space pixels. PS/2 reports positive-Y as UP (historical
    // mathematical convention); every GUI we care about wants
    // positive-Y as DOWN.
    dy = -dy;

    u8 buttons = 0;
    if (flags & (1U << 0))
        buttons |= kMouseButtonLeft;
    if (flags & (1U << 1))
        buttons |= kMouseButtonRight;
    if (flags & (1U << 2))
        buttons |= kMouseButtonMiddle;

    MousePacket p{};
    p.dx = dx;
    p.dy = dy;
    p.buttons = buttons;

    // IntelliMouse wheel (4-byte mode only): byte[3] is the signed Z
    // delta. Linux psmouse maps wheel-up to +REL_WHEEL via -(s8)byte[3];
    // the dz field's convention is likewise "positive = scroll up", so
    // negate the two's-complement Z. In 3-byte mode dz stays 0.
    if (g_packet_len == 4)
    {
        const i32 z = (b[3] & 0x80U) ? (static_cast<i32>(b[3]) - 256) : static_cast<i32>(b[3]);
        p.dz = -z;
    }
    return p;
}

void PushPacket(const MousePacket& p)
{
    if (g_ring_head - g_ring_tail >= kRingSize)
    {
        // Once-warn: dropping mouse packets means the consumer (the
        // window manager) is not draining fast enough.
        KLOG_ONCE_WARN("drivers/ps2mouse", "mouse packet ring full — discarding OLDEST (consumer too slow)");
        ++g_ring_tail; // drop oldest — same policy as the keyboard ring
        ++g_bytes_dropped;
    }
    g_ring[g_ring_head & kRingMask] = p;
    ++g_ring_head;
    ++g_packets_decoded;
}

void IrqHandler()
{
    ++g_irqs_seen;

    while (true)
    {
        const u8 st = Inb(kStatusPort);
        if ((st & kStatusOutputFull) == 0)
        {
            break;
        }
        // The aux bit (0x20) tells us whether this byte is from the
        // mouse or the keyboard. In theory both share the IRQ only
        // via spurious crosstalk, but some emulated controllers
        // don't even set the bit — treat "aux bit not set" as a
        // belt-and-braces filter, not a gate.
        if ((st & kStatusMouseData) == 0)
        {
            // Not our byte. Leave it in the FIFO for the keyboard
            // IRQ handler; reading it here would steal keypresses.
            break;
        }
        const u8 byte = Inb(kDataPort);

        // First byte of a packet MUST have bit 3 set (the "always 1"
        // sync marker). If it's clear, we're mid-stream out of phase:
        // resync by discarding bytes until we see a valid byte 0.
        if (g_packet_cursor == 0 && (byte & (1U << 3)) == 0)
        {
            // Out-of-phase byte 0: surfaces firmware/IRQ-routing
            // bugs, since a healthy stream never desyncs after the
            // initial reset+enable. Once-warn keeps the IRQ path
            // quiet under sustained miswire.
            KLOG_ONCE_WARN("drivers/ps2mouse", "first-packet-byte missing sync bit (3) — resyncing stream");
            ++g_bytes_dropped;
            continue;
        }

        g_packet_bytes[g_packet_cursor] = byte;
        ++g_packet_cursor;

        if (g_packet_cursor >= g_packet_len)
        {
            PushPacket(DecodePacket(g_packet_bytes));
            g_packet_cursor = 0;
        }
    }

    duetos::sched::WaitQueueWakeOne(&g_readers);
}

// Polled 8042 controller + aux-device bring-up (steps 1-5). Split
// out so Ps2MouseInit can run the WHOLE dialogue under a single
// interrupts-disabled window with one clean exit. This matters:
// Ps2MouseInit runs AFTER Ps2KeyboardInit has already unmasked
// IRQ 1, so every non-aux controller response we poll for here
// (the 0xA9 test result, ReadConfigByte's reply, device ACKs)
// also raises the keyboard IRQ — the keyboard ISR then reads
// port 0x60 first and our poll loop spins to its cap forever.
// On QEMU the race window happened not to bite; on VirtualBox
// the controller's IRQ timing makes the steal deterministic,
// which is exactly the "port-2 self-test no response" boot bail.
// Returns true iff the mouse ACKed enable-reporting.
bool Ps2MouseControllerBringup()
{
    // Step 1: enable the aux channel. The keyboard driver's
    // ControllerInit disabled it during its bring-up; re-enable
    // before anything else.
    SendCtrlCmd(kCmdEnablePort2);

    // Step 2: port-2 interface self-test. Result byte 0 = pass;
    // anything else is a bad / missing aux channel. Warn + bail —
    // many laptops have no PS/2 aux line at all (USB-only), and
    // that should be a soft failure, not a panic. Use the
    // try-variant: a controller that never fills its output buffer
    // is also a "no PS/2 mouse" signal (QEMU q35 with no -device
    // pcips2-mouse, real machines without legacy 8042 emulation).
    SendCtrlCmd(kCmdTestPort2);
    u8 port2_test = 0;
    if (!TryWaitOutputFull(&port2_test))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2mouse", "port-2 self-test no response (no PS/2 mouse?)");
        return false;
    }
    if (port2_test != kResponseTestPort2Pass)
    {
        core::LogWithValue(core::LogLevel::Warn, "drivers/ps2mouse", "port-2 self-test failed (no PS/2 mouse?)",
                           port2_test);
        return false;
    }

    // Step 3: device reset + set defaults. The mouse's "set defaults"
    // (0xF6) puts it into standard 3-byte mode at 100 Hz sample rate,
    // which is what we parse below. A reset (0xFF) would also work,
    // but adds a multi-byte self-test response we'd have to drain —
    // 0xF6 is one ACK and done.
    if (!MouseSendAndAck(kMouseCmdSetDefaults))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2mouse", "set-defaults (0xF6) not ACKed — mouse disabled");
        return false;
    }

    // Step 3b: try to negotiate the IntelliMouse wheel (4-byte) protocol.
    // Safe no-op on mice that don't support it (they stay 3-byte). Done
    // before enable-reporting so the rate-set dialogue isn't interleaved
    // with motion packets.
    EnableWheel();

    // Step 4: enable data reporting. Without this, the mouse stays
    // mute regardless of movement.
    if (!MouseSendAndAck(kMouseCmdEnableReporting))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2mouse", "enable-reporting (0xF4) not ACKed — mouse disabled");
        return false;
    }

    // Step 5: flip on the aux-channel IRQ + active clock in the
    // config byte. Keyboard init left this disabled.
    u8 config = ReadConfigByte();
    config |= kConfigPort2IrqEnable;
    config = static_cast<u8>(config & ~kConfigPort2ClockDisable);
    WriteConfigByte(config);
    return true;
}

} // namespace

void Ps2MouseInit()
{
    static constinit bool s_initialised = false;
    KASSERT(!s_initialised, "drivers/ps2mouse", "Ps2MouseInit called twice");
    s_initialised = true;

    // Run steps 1-6 with interrupts disabled. Ps2KeyboardInit has
    // already unmasked IRQ 1, so without this the live keyboard ISR
    // races every non-aux controller byte we poll for below and the
    // mouse never initialises (the VirtualBox "port-2 self-test no
    // response" bail). Save/restore IF rather than unconditionally
    // STI so a future caller that runs with interrupts already off
    // isn't surprised. The whole dialogue is bounded spin-polls +
    // register writes — no sleep / block — so a CLI window is safe.
    constexpr u64 kRflagsIf = 1ULL << 9;
    const bool irqs_were_on = (arch::ReadRflags() & kRflagsIf) != 0;
    arch::Cli();

    if (!Ps2MouseControllerBringup())
    {
        if (irqs_were_on)
        {
            arch::Sti();
        }
        return;
    }

    // Step 6: route through the IOAPIC + IDT. Identical shape to
    // the keyboard. Note that IRQ 12 may or may not have a MADT
    // override on real hardware — IsaIrqToGsi handles that. Still
    // under CLI: these are IDT / IOAPIC register writes, and the
    // mouse IRQ can't be delivered until the route below lands
    // anyway.
    arch::IdtSetGate(kMouseVector, reinterpret_cast<u64>(&isr_44));
    arch::IrqInstall(kMouseVector, &IrqHandler);
    const u32 gsi = acpi::IsaIrqToGsi(kMouseIsaIrq);
    const u8 bsp_id = static_cast<u8>(arch::LapicRead(arch::kLapicRegId) >> 24);
    arch::IoApicRoute(gsi, kMouseVector, bsp_id, kMouseIsaIrq);

    g_available = true;

    // Route is live; the polled dialogue is done. Re-enable
    // interrupts (if the caller had them on) before the logging
    // tail so the CLI window stays as tight as the bug fix needs.
    if (irqs_were_on)
    {
        arch::Sti();
    }

    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "routed isa_irq", kMouseIsaIrq);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "  gsi", gsi);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "  vector", kMouseVector);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "  lapic_id", bsp_id);
    // Kept (gated at Debug): mouse device ACKed enable-reporting? 0 here
    // means VBox presented no PS/2 aux device — visible in a debug build.
    duetos::core::LogWithValue(duetos::core::LogLevel::Debug, "drivers/ps2mouse", "  available", g_available ? 1u : 0u);
}

MousePacket Ps2MouseReadPacket()
{
    arch::Cli();
    while (g_ring_head == g_ring_tail)
    {
        duetos::sched::WaitQueueBlock(&g_readers);
    }
    const MousePacket p = g_ring[g_ring_tail & kRingMask];
    ++g_ring_tail;
    arch::Sti();
    return p;
}

bool Ps2MouseTryReadPacket(MousePacket* out)
{
    if (out == nullptr)
    {
        return false;
    }
    arch::Cli();
    if (g_ring_head == g_ring_tail)
    {
        arch::Sti();
        return false;
    }
    *out = g_ring[g_ring_tail & kRingMask];
    ++g_ring_tail;
    arch::Sti();
    return true;
}

Ps2MouseStats Ps2MouseStatsRead()
{
    return Ps2MouseStats{
        .irqs_seen = g_irqs_seen,
        .packets_decoded = g_packets_decoded,
        .bytes_dropped = g_bytes_dropped,
    };
}

void MouseInjectPacket(const MousePacket& p)
{
    // Bracket with Cli/Sti so the IRQ-time PushPacket can't
    // race us on head/tail. The internal push handles the
    // drop-oldest policy when the ring is full.
    arch::Cli();
    PushPacket(p);
    arch::Sti();
    duetos::core::InputActivityStamp();
}

} // namespace duetos::drivers::input
