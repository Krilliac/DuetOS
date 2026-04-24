#include "ps2mouse.h"

#include "../../acpi/acpi.h"
#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/idt.h"
#include "../../arch/x86_64/ioapic.h"
#include "../../arch/x86_64/lapic.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../sched/sched.h"

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

constexpr u8 kMouseAck = 0xFA;

// Same poll cap shape the keyboard driver uses — 1M reads ≈ tens of ms.
constexpr u64 kPollSpinLimit = 1'000'000;

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
constinit u8 g_packet_bytes[3] = {0, 0, 0};

constinit duetos::sched::WaitQueue g_readers{};

constinit u64 g_irqs_seen = 0;
constinit u64 g_packets_decoded = 0;
constinit u64 g_bytes_dropped = 0;

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

void WaitInputClear()
{
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusInputFull) == 0)
        {
            return;
        }
    }
    core::Panic("drivers/ps2mouse", "8042 input buffer never cleared");
}

u8 WaitOutputFull()
{
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
        {
            return Inb(kDataPort);
        }
    }
    core::Panic("drivers/ps2mouse", "8042 output buffer never filled");
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
    return p;
}

void PushPacket(const MousePacket& p)
{
    if (g_ring_head - g_ring_tail >= kRingSize)
    {
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
            ++g_bytes_dropped;
            continue;
        }

        g_packet_bytes[g_packet_cursor] = byte;
        ++g_packet_cursor;

        if (g_packet_cursor == 3)
        {
            PushPacket(DecodePacket(g_packet_bytes));
            g_packet_cursor = 0;
        }
    }

    duetos::sched::WaitQueueWakeOne(&g_readers);
}

} // namespace

void Ps2MouseInit()
{
    static constinit bool s_initialised = false;
    KASSERT(!s_initialised, "drivers/ps2mouse", "Ps2MouseInit called twice");
    s_initialised = true;

    // Step 1: enable the aux channel. The keyboard driver's
    // ControllerInit disabled it during its bring-up; re-enable
    // before anything else.
    SendCtrlCmd(kCmdEnablePort2);

    // Step 2: port-2 interface self-test. Result byte 0 = pass;
    // anything else is a bad / missing aux channel. Warn + bail —
    // many laptops have no PS/2 aux line at all (USB-only), and
    // that should be a soft failure, not a panic.
    SendCtrlCmd(kCmdTestPort2);
    const u8 port2_test = WaitOutputFull();
    if (port2_test != kResponseTestPort2Pass)
    {
        core::LogWithValue(core::LogLevel::Warn, "drivers/ps2mouse", "port-2 self-test failed (no PS/2 mouse?)",
                           port2_test);
        return;
    }

    // Step 3: device reset + set defaults. The mouse's "set defaults"
    // (0xF6) puts it into standard 3-byte mode at 100 Hz sample rate,
    // which is what we parse below. A reset (0xFF) would also work,
    // but adds a multi-byte self-test response we'd have to drain —
    // 0xF6 is one ACK and done.
    if (!MouseSendAndAck(kMouseCmdSetDefaults))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2mouse", "set-defaults (0xF6) not ACKed — mouse disabled");
        return;
    }

    // Step 4: enable data reporting. Without this, the mouse stays
    // mute regardless of movement.
    if (!MouseSendAndAck(kMouseCmdEnableReporting))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2mouse", "enable-reporting (0xF4) not ACKed — mouse disabled");
        return;
    }

    // Step 5: flip on the aux-channel IRQ + active clock in the
    // config byte. Keyboard init left this disabled.
    u8 config = ReadConfigByte();
    config |= kConfigPort2IrqEnable;
    config = static_cast<u8>(config & ~kConfigPort2ClockDisable);
    WriteConfigByte(config);

    // Step 6: route through the IOAPIC + IDT. Identical shape to
    // the keyboard. Note that IRQ 12 may or may not have a MADT
    // override on real hardware — IsaIrqToGsi handles that.
    arch::IdtSetGate(kMouseVector, reinterpret_cast<u64>(&isr_44));
    arch::IrqInstall(kMouseVector, &IrqHandler);
    const u32 gsi = acpi::IsaIrqToGsi(kMouseIsaIrq);
    const u8 bsp_id = static_cast<u8>(arch::LapicRead(arch::kLapicRegId) >> 24);
    arch::IoApicRoute(gsi, kMouseVector, bsp_id, kMouseIsaIrq);

    g_available = true;

    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "routed isa_irq", kMouseIsaIrq);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "  gsi", gsi);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "  vector", kMouseVector);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2mouse", "  lapic_id", bsp_id);
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
}

} // namespace duetos::drivers::input
