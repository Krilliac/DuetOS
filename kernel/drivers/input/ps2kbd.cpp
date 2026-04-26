/*
 * DuetOS — PS/2 keyboard driver: implementation.
 *
 * Companion to ps2kbd.h — see there for the input-event shape
 * and the consumer chain (login gate -> shell -> active task).
 *
 * WHAT
 *   First end-to-end IRQ-driven driver. Hooks IRQ1, reads
 *   scancodes from port 0x60, translates Set 1 scancodes
 *   (with E0/E1 escape handling) into kKey enums + ASCII, and
 *   drops events into the input ring the kbd-reader thread
 *   pulls from.
 *
 * HOW
 *   IRQ handler is a thin "read scancode, push to ring, EOI";
 *   all decoding (modifier tracking, dead-key handling,
 *   layout) happens in the consumer thread to keep the IRQ
 *   path short. Layout table lives at the top of the file —
 *   v0 is US ANSI; non-US layouts are an additional table
 *   away.
 */

#include "drivers/input/ps2kbd.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "core/panic.h"
#include "sched/sched.h"

// Defined in exceptions.S — the stub for vector 0x21 that pushes a zero
// error code, pushes the vector, and jumps to isr_common (which calls
// TrapDispatch). The same plumbing every hardware IRQ already uses.
extern "C" void isr_33();

namespace duetos::drivers::input
{

namespace
{

using arch::Inb;
using arch::Outb;
using arch::SerialWrite;
using arch::SerialWriteHex;

// 8042 controller ports.
constexpr u16 kDataPort = 0x60;
constexpr u16 kStatusPort = 0x64;

// Status register bits.
constexpr u8 kStatusOutputFull = 1U << 0; // data waiting in 0x60
constexpr u8 kStatusInputFull = 1U << 1;  // 0x60 / 0x64 busy — do not write
constexpr u8 kStatusMouseData = 1U << 5;  // byte in 0x60 is from aux channel

// Controller commands issued via 0x64.
constexpr u8 kCmdReadConfig = 0x20;
constexpr u8 kCmdWriteConfig = 0x60;
constexpr u8 kCmdDisablePort2 = 0xA7;
constexpr u8 kCmdTestPort1 = 0xAB;
constexpr u8 kCmdDisablePort1 = 0xAD;
constexpr u8 kCmdEnablePort1 = 0xAE;
constexpr u8 kCmdSelfTest = 0xAA;

// Response bytes.
constexpr u8 kResponseSelfTestPass = 0x55;
constexpr u8 kResponseTestPort1Pass = 0x00;

// Configuration byte bits (Wired-OR on the 8042's internal RAM[0]).
constexpr u8 kConfigPort1IrqEnable = 1U << 0;
constexpr u8 kConfigPort2IrqEnable = 1U << 1;
constexpr u8 kConfigPort1ClockDisable = 1U << 4;

// Bounded spin count for controller-response polling. 1M reads is
// ~tens of milliseconds on a modern CPU — well past any legitimate
// 8042 turnaround. Hitting it means the controller is wedged, and
// the right recovery is to panic loudly (Class A: kernel integrity
// depends on a working keyboard path).
constexpr u64 kPollSpinLimit = 1'000'000;

// ISA IRQ 1 = keyboard. The MADT may remap it to a different GSI, so
// always consult `acpi::IsaIrqToGsi(1)` rather than assuming identity.
constexpr u8 kKbdIsaIrq = 1;
constexpr u8 kKbdVector = 0x21; // LAPIC vector we route IRQ 1 to

// Power-of-two ring buffer; head moves on push (IRQ context), tail on
// pop (task context). Single producer, single reader — no locking
// needed on x86_64 because byte-aligned u16 loads/stores are atomic
// and the producer runs at higher privilege (IRQ) than the consumer,
// so the consumer can never tear a producer's update.
constexpr u64 kRingSize = 64;
constexpr u64 kRingMask = kRingSize - 1;
static_assert((kRingSize & kRingMask) == 0, "ring size must be power of two");

constinit u8 g_ring[kRingSize] = {};
constinit u64 g_ring_head = 0; // write cursor (IRQ)
constinit u64 g_ring_tail = 0; // read cursor (task)

constinit duetos::sched::WaitQueue g_readers{};

constinit u64 g_irqs_seen = 0;
constinit u64 g_bytes_buffered = 0;
constinit u64 g_bytes_dropped = 0;

// External key-event injection ring. KeyboardInjectEvent pushes
// pre-cooked events here; Ps2KeyboardReadEvent drains this ring
// before falling back to the scancode path. Kept small — the HID
// polling task emits at most 6 events per report cycle + modifier
// edges (call it ~12), and the reader consumes promptly.
constexpr u64 kInjectRingSize = 32;
static_assert((kInjectRingSize & (kInjectRingSize - 1)) == 0, "inject ring size must be power of two");
constexpr u64 kInjectRingMask = kInjectRingSize - 1;
constinit KeyEvent g_inject_ring[kInjectRingSize] = {};
constinit u64 g_inject_head = 0;
constinit u64 g_inject_tail = 0;

bool InjectRingEmpty()
{
    return g_inject_head == g_inject_tail;
}

bool InjectRingPop(KeyEvent* out)
{
    if (InjectRingEmpty())
        return false;
    *out = g_inject_ring[g_inject_tail & kInjectRingMask];
    ++g_inject_tail;
    return true;
}

// ---------------------------------------------------------------------------
// Scan code set 1 → ASCII translation.
//
// QEMU (and every real 8042 in AT-compatible mode) emits scan code
// set 1 by default: one byte per make, one byte per break with the
// top bit set (0x80 | make). Certain keys (arrows, right-side mods)
// send a 0xE0 prefix followed by the make/break byte.
//
// The translator runs in TASK context (inside Ps2KeyboardReadChar),
// NOT in IRQ context — the IRQ handler still buffers raw bytes,
// preserving the existing "lossless raw path" for any consumer that
// needs un-translated scan codes (debuggers, alt keymap consumers).
//
// v0 scope:
//   - US QWERTY, no alt layouts.
//   - Tracks LShift / RShift (press + release) and Caps Lock (toggle
//     on press, ignore release). Letters XOR shift and capslock;
//     number-row and symbols only respect shift.
//   - Ignores Ctrl, Alt, Meta, F-keys, numpad, arrows, and every
//     other 0xE0-prefixed key — returns 0 so the caller can re-poll.
//   - Returns a non-zero ASCII byte per resolved keypress; returns
//     nothing (blocks) on pure modifier transitions or releases.
// ---------------------------------------------------------------------------

constexpr u8 kScanExtendedPrefix = 0xE0;
constexpr u8 kScanBreakBit = 0x80;
constexpr u8 kScanLShift = 0x2A;
constexpr u8 kScanRShift = 0x36;
constexpr u8 kScanCapsLock = 0x3A;
constexpr u64 kKeymapSize = 128;

// NOTE: indexed by scan code (0..127); 0 means "no ASCII mapping —
// caller re-polls." Only keys in the main alphanumeric block are
// mapped; specials (Esc, F1..F12, numlock, numpad, arrows) are 0.
constinit const char kKeymapLower[kKeymapSize] = {
    /* 0x00 */ 0,   0,   '1', '2', '3', '4', '5', '6', '7',  '8', '9', '0',  '-',  '=', '\b', '\t',
    /* 0x10 */ 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o',  'p', '[', ']',  '\n', 0,   'a',  's',
    /* 0x20 */ 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0,   '\\', 'z',  'x', 'c',  'v',
    /* 0x30 */ 'b', 'n', 'm', ',', '.', '/', 0,   '*', 0,    ' ', 0,   0,    0,    0,   0,    0,
    /* 0x40 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,   0,    0,    0,   0,    0,
    /* 0x50 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,   0,    0,    0,   0,    0,
    /* 0x60 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,   0,    0,    0,   0,    0,
    /* 0x70 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,   0,    0,    0,   0,    0,
};

constinit const char kKeymapUpper[kKeymapSize] = {
    /* 0x00 */ 0,   0,   '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_',  '+', '\b', '\t',
    /* 0x10 */ 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0,   'A',  'S',
    /* 0x20 */ 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0,   '|', 'Z',  'X', 'C',  'V',
    /* 0x30 */ 'B', 'N', 'M', '<', '>', '?', 0,   '*', 0,   ' ', 0,   0,   0,    0,   0,    0,
    /* 0x40 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,    0,
    /* 0x50 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,    0,
    /* 0x60 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,    0,
    /* 0x70 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,   0,    0,
};

// Translator state is per-driver, not per-reader: any reader that
// calls Ps2KeyboardReadChar shares the same modifier view. That's
// the correct model — physical Shift / Caps Lock state is a
// property of the keyboard, not of any one consumer.
constinit bool g_shift_held = false;
constinit bool g_capslock_on = false;
constinit bool g_extended_pending = false;

// Additional modifier tracking for the KeyEvent API. Left and
// right variants of Ctrl/Alt are merged into a single "held"
// bit (matches Windows and Linux conventions); Meta covers the
// left + right Windows keys (0xE0 0x5B / 0xE0 0x5C).
constinit bool g_ctrl_held = false;
constinit bool g_alt_held = false;
constinit bool g_meta_held = false;

constexpr u8 kScanLCtrl = 0x1D; // RCtrl is 0xE0-prefixed with same byte
constexpr u8 kScanLAlt = 0x38;  // RAlt / AltGr similarly 0xE0-prefixed
constexpr u8 kScanEscape = 0x01;
constexpr u8 kScanBackspace = 0x0E;
constexpr u8 kScanTab = 0x0F;
constexpr u8 kScanEnter = 0x1C;

// F1..F12 live at 0x3B..0x44 (F1..F10) and 0x57..0x58 (F11/F12).
constexpr u8 kScanF1 = 0x3B;
constexpr u8 kScanF10 = 0x44;
constexpr u8 kScanF11 = 0x57;
constexpr u8 kScanF12 = 0x58;

// Extended-key scan codes (0xE0-prefixed). Only the subset every
// interactive consumer will want in v0. Additional extended keys
// (multimedia, print-screen, pause) are dropped — the whole point
// of a typed KeyCode enum is that unnamed keys stay invisible.
constexpr u8 kScanExtArrowUp = 0x48;
constexpr u8 kScanExtArrowDown = 0x50;
constexpr u8 kScanExtArrowLeft = 0x4B;
constexpr u8 kScanExtArrowRight = 0x4D;
constexpr u8 kScanExtHome = 0x47;
constexpr u8 kScanExtEnd = 0x4F;
constexpr u8 kScanExtPageUp = 0x49;
constexpr u8 kScanExtPageDown = 0x51;
constexpr u8 kScanExtInsert = 0x52;
constexpr u8 kScanExtDelete = 0x53;
constexpr u8 kScanExtRCtrl = 0x1D;
constexpr u8 kScanExtRAlt = 0x38;
constexpr u8 kScanExtMetaLeft = 0x5B;
constexpr u8 kScanExtMetaRight = 0x5C;

// ---------------------------------------------------------------------------
// 8042 initialization sequence.
//
// Reference: OSDev wiki "8042 PS/2 Controller" + IBM AT Technical
// Reference. Panics on any hard failure (self-test mismatch, spin
// timeout) — the keyboard is on the critical path for an interactive
// console, and silently limping forward hides firmware bugs we'd
// rather see immediately.
// ---------------------------------------------------------------------------

void WaitInputClear()
{
    // Controller is ready to accept a command/data byte when bit 1 of
    // the status register clears. Without this wait, a rapid-fire write
    // sequence can drop bytes on slow firmware.
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusInputFull) == 0)
        {
            return;
        }
    }
    core::Panic("drivers/ps2kbd", "8042 input buffer never cleared");
}

u8 WaitOutputFull()
{
    // Wait for a response byte to be available and return it. Panics
    // on timeout — a wedged 8042 during init means the PS/2 driver
    // is unusable, and Class A halt is the right posture.
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
        {
            return Inb(kDataPort);
        }
    }
    core::Panic("drivers/ps2kbd", "8042 output buffer never filled");
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

void Drain()
{
    while ((Inb(kStatusPort) & kStatusOutputFull) != 0)
    {
        (void)Inb(kDataPort);
    }
}

// Send a byte to the keyboard device (port 1 data line, accessed
// through port 0x60) and wait for the 0xFA ACK response. Returns
// false on timeout or any other byte — callers log + continue
// rather than panic, since USB-legacy emulated keyboards can
// silently drop some device commands.
bool KbdSendAndAck(u8 byte)
{
    WaitInputClear();
    Outb(kDataPort, byte);
    for (u64 i = 0; i < kPollSpinLimit; ++i)
    {
        if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
        {
            return Inb(kDataPort) == 0xFA;
        }
    }
    return false;
}

void ControllerInit()
{
    // Step 1: disable both channels so no IRQ fires mid-configuration.
    // Port 2 disable is safe even on controllers that have no aux
    // channel — the command is a no-op in that case.
    SendCtrlCmd(kCmdDisablePort1);
    SendCtrlCmd(kCmdDisablePort2);

    // Step 2: flush any stale byte the firmware / bootloader produced.
    Drain();

    // Step 3: pull the current config byte, turn OFF both IRQ enables
    // (we'll re-enable port 1 last), and leave translation whatever
    // firmware set it to — our scan-code translator expects set 1 +
    // translation on, which is the PC-AT default every BIOS honours.
    u8 config = ReadConfigByte();
    config = static_cast<u8>(config & ~(kConfigPort1IrqEnable | kConfigPort2IrqEnable));
    WriteConfigByte(config);

    // Step 4: controller self-test. Some buggy firmware resets the
    // config byte on this command, so re-write it after.
    SendCtrlCmd(kCmdSelfTest);
    const u8 self_test = WaitOutputFull();
    if (self_test != kResponseSelfTestPass)
    {
        core::PanicWithValue("drivers/ps2kbd", "8042 self-test failed", self_test);
    }
    WriteConfigByte(config);

    // Step 5: port 1 interface test. Zero = pass; anything else is a
    // clock/data line fault. Log and continue — QEMU always reports
    // pass, and on real hardware we'd rather try the keyboard anyway
    // than refuse to boot on a controller quirk.
    SendCtrlCmd(kCmdTestPort1);
    const u8 port1_test = WaitOutputFull();
    if (port1_test != kResponseTestPort1Pass)
    {
        core::LogWithValue(core::LogLevel::Warn, "drivers/ps2kbd", "port-1 self-test failed", port1_test);
    }

    // Step 6: enable port 1 (controller-side). Still CLI / IRQs
    // disabled in the config byte — device commands are polled.
    SendCtrlCmd(kCmdEnablePort1);

    // Step 7: device-level reset. 0xFF on port 1 data asks the
    // keyboard to reset and run its own self-test; response is
    // 0xFA (ACK) immediately followed by 0xAA (self-test pass)
    // after a short delay. Many USB-legacy emulated keyboards
    // don't support this — log and continue on any failure so
    // the port stays usable.
    if (!KbdSendAndAck(0xFF))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2kbd", "device RESET (0xFF) not ACKed — continuing");
    }
    else
    {
        // Wait for the post-reset self-test byte. ~500 ms on real
        // hardware, instant in QEMU. Use an extended spin cap and
        // log anything that isn't 0xAA so firmware bugs show up.
        for (u64 i = 0; i < kPollSpinLimit * 10; ++i)
        {
            if ((Inb(kStatusPort) & kStatusOutputFull) != 0)
            {
                const u8 st = Inb(kDataPort);
                if (st != 0xAA)
                {
                    core::LogWithValue(core::LogLevel::Warn, "drivers/ps2kbd", "device self-test unexpected response",
                                       st);
                }
                break;
            }
        }
    }

    // Step 8: force scan code set 1 explicitly. Firmware default is
    // usually "set 2 + translation on" (indistinguishable on 0x60
    // from "set 1 + translation off"). Making it explicit survives
    // firmware that leaves the device on set 2 with translation
    // disabled, which would otherwise wreck our keymap.
    // Sequence: 0xF0 (set scan code set command) → 0xFA, then
    // 0x01 (set 1) → 0xFA.
    if (!KbdSendAndAck(0xF0))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2kbd", "scan-code-set-select (0xF0) not ACKed");
    }
    else if (!KbdSendAndAck(0x01))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2kbd", "scan code set 1 select not ACKed");
    }

    // Step 9: enable scanning — reset above disables it on most
    // devices. 0xF4 on port 1 data tells the keyboard to start
    // producing scan codes again. Without this, keypresses land
    // in the ether.
    if (!KbdSendAndAck(0xF4))
    {
        core::Log(core::LogLevel::Warn, "drivers/ps2kbd", "enable-scanning (0xF4) not ACKed");
    }

    // Step 10: flip on port 1 IRQ + ensure clock is active in the
    // config byte. From here, IOAPIC route + unmask (in
    // Ps2KeyboardInit) delivers scan codes to our IRQ handler.
    config |= kConfigPort1IrqEnable;
    config = static_cast<u8>(config & ~kConfigPort1ClockDisable);
    WriteConfigByte(config);

    // Step 11: final drain — enabling IRQs can latch a pending byte
    // on some firmware; clear it before we unmask at the IOAPIC.
    Drain();

    core::Log(core::LogLevel::Info, "drivers/ps2kbd", "8042 controller + device initialised");
}

void IrqHandler()
{
    ++g_irqs_seen;

    // Drain every pending byte in one pass. The 8042 can latch multiple
    // scan codes (a single keypress sends 1..3 bytes, and key repeat
    // under load stacks them up) before the next IRQ arrives. Skip
    // aux-channel bytes (status bit 5) — those belong to the mouse
    // and its own IRQ-12 handler will consume them. Without this
    // filter, a mouse packet landing in 0x60 between our scan-code
    // reads would be misinterpreted as keyboard bytes.
    while (true)
    {
        const u8 st = Inb(kStatusPort);
        if ((st & kStatusOutputFull) == 0)
        {
            break;
        }
        if ((st & kStatusMouseData) != 0)
        {
            break; // leave aux byte for the mouse IRQ handler
        }
        const u8 byte = Inb(kDataPort);

        // Ring is full iff (head - tail) == size. In that case the
        // oldest byte is lost: we advance tail past the sacrificial
        // entry, then push. Alternative "drop newest" behaviour would
        // be simpler but loses key-release bytes that come AFTER the
        // press — which matters more than losing the first press in a
        // queue of many.
        if (g_ring_head - g_ring_tail >= kRingSize)
        {
            ++g_ring_tail; // discard oldest
            ++g_bytes_dropped;
        }
        g_ring[g_ring_head & kRingMask] = byte;
        ++g_ring_head;
        ++g_bytes_buffered;
    }

    // Wake any reader parked on the queue. WaitQueueWakeOne sets
    // need_resched, so the IRQ dispatcher will Schedule() after EOI.
    duetos::sched::WaitQueueWakeOne(&g_readers);
}

} // namespace

void Ps2KeyboardInit()
{
    // Double-init guard: re-routing the IOAPIC pin and re-installing
    // the handler would cause transient IRQ loss + a duplicate route
    // entry. Panic is the right outcome — silent second-init is
    // impossible to diagnose from logs later.
    static constinit bool s_initialised = false;
    KASSERT(!s_initialised, "drivers/ps2kbd", "Ps2KeyboardInit called twice");
    s_initialised = true;

    // Full 8042 bring-up: disable both channels, flush stale data,
    // self-test the controller, enable port 1 + its IRQ. Leaves the
    // controller in a known-good state regardless of what the BIOS
    // did before we ran. Any failure panics inside ControllerInit
    // with a tagged value — the keyboard path is on the critical
    // path for an interactive console, so silent degradation is
    // worse than halting.
    ControllerInit();

    // Install the handler in BOTH tables: the low-level IDT stub for
    // vector 0x21, and the IRQ dispatcher's per-vector slot. The IDT
    // entry gets us into TrapDispatch; the dispatcher routes to our
    // handler.
    arch::IdtSetGate(kKbdVector, reinterpret_cast<u64>(&isr_33));
    arch::IrqInstall(kKbdVector, &IrqHandler);

    // Route ISA IRQ 1 through the IOAPIC, honouring any MADT override.
    // Destination APIC ID is the BSP — for v0 we pin every device IRQ
    // to CPU 0.
    const u32 gsi = acpi::IsaIrqToGsi(kKbdIsaIrq);
    const u8 bsp_id = static_cast<u8>(arch::LapicRead(arch::kLapicRegId) >> 24);
    arch::IoApicRoute(gsi, kKbdVector, bsp_id, kKbdIsaIrq);

    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2kbd", "routed isa_irq", kKbdIsaIrq);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2kbd", "  gsi", gsi);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2kbd", "  vector", kKbdVector);
    duetos::core::LogWithValue(duetos::core::LogLevel::Info, "drivers/ps2kbd", "  lapic_id", bsp_id);
}

u8 Ps2KeyboardRead()
{
    arch::Cli();
    // Block until EITHER the scancode ring or the injection ring
    // has something. Scancode set 1 never encodes a make byte of
    // 0, so we can use 0 as a sentinel meaning "woke up for an
    // injected event; no scancode to return" — ReadEvent handles
    // the sentinel by looping back to the inject-ring drain.
    while (g_ring_head == g_ring_tail && InjectRingEmpty())
    {
        duetos::sched::WaitQueueBlock(&g_readers);
        // When we come back, interrupts are still disabled (we never
        // Sti'd), and a byte MAY be available. Could also have been a
        // spurious wake once we add broadcast-wake primitives, so
        // re-check the condition.
    }
    if (g_ring_head == g_ring_tail)
    {
        arch::Sti();
        return 0; // sentinel: injection pending, no scancode
    }
    const u8 byte = g_ring[g_ring_tail & kRingMask];
    ++g_ring_tail;
    arch::Sti();
    return byte;
}

char Ps2KeyboardReadChar()
{
    // Drain raw scan codes until one resolves to a printable
    // character; modifier transitions, releases, and unmapped keys
    // loop back to the next byte rather than being returned as 0.
    // This keeps the caller loop simple: a non-zero return is
    // always a real keypress.
    for (;;)
    {
        const u8 sc = Ps2KeyboardRead();

        if (sc == kScanExtendedPrefix)
        {
            g_extended_pending = true;
            continue;
        }

        const bool released = (sc & kScanBreakBit) != 0;
        const u8 code = static_cast<u8>(sc & ~kScanBreakBit);

        if (g_extended_pending)
        {
            // Extended keys (arrows, right-side modifiers, multimedia)
            // don't map into the ASCII keymap today. Consume and skip.
            g_extended_pending = false;
            continue;
        }

        // Modifier updates happen on BOTH press and release for shift,
        // but only on press for caps lock (it toggles a latch).
        if (code == kScanLShift || code == kScanRShift)
        {
            g_shift_held = !released;
            continue;
        }
        if (code == kScanCapsLock)
        {
            if (!released)
            {
                g_capslock_on = !g_capslock_on;
            }
            continue;
        }

        if (released)
        {
            continue; // only emit ASCII on press edges
        }
        if (code >= kKeymapSize)
        {
            continue; // outside our mapped range (F1..F12 etc.)
        }

        const char lower = kKeymapLower[code];
        if (lower == 0)
        {
            continue; // explicitly-unmapped slot
        }

        // Letters toggle on (shift XOR capslock); everything else
        // respects shift alone. Caps Lock on a digit or punctuation
        // key does NOT shift it — matches standard PC behaviour.
        const bool is_letter = (lower >= 'a' && lower <= 'z');
        const bool use_upper = is_letter ? (g_shift_held != g_capslock_on) : g_shift_held;
        const char resolved = use_upper ? kKeymapUpper[code] : lower;

        // Upper half of a letter keymap is always populated when the
        // lower half is; any 0 here would be a keymap table bug.
        KASSERT(resolved != 0, "drivers/ps2kbd", "keymap inconsistency");
        return resolved;
    }
}

char Ps2KeyboardTryReadChar()
{
    // Non-blocking single-step of the scan-code decoder. If the
    // ring is empty, return 0 without touching state. If a byte
    // is pending but it's a modifier / release / unmapped key,
    // consume it and still return 0 — the caller's next poll will
    // try the following byte. Only a genuine printable keypress
    // returns a non-zero char.
    if (g_ring_head == g_ring_tail)
    {
        return 0;
    }
    const u8 sc = g_ring[g_ring_tail & kRingMask];
    ++g_ring_tail;

    if (sc == kScanExtendedPrefix)
    {
        g_extended_pending = true;
        return 0;
    }
    const bool released = (sc & kScanBreakBit) != 0;
    const u8 code = static_cast<u8>(sc & ~kScanBreakBit);
    if (g_extended_pending)
    {
        g_extended_pending = false;
        return 0;
    }
    if (code == kScanLShift || code == kScanRShift)
    {
        g_shift_held = !released;
        return 0;
    }
    if (code == kScanCapsLock)
    {
        if (!released)
            g_capslock_on = !g_capslock_on;
        return 0;
    }
    if (released || code >= kKeymapSize)
    {
        return 0;
    }
    const char lower = kKeymapLower[code];
    if (lower == 0)
    {
        return 0;
    }
    const bool is_letter = (lower >= 'a' && lower <= 'z');
    const bool use_upper = is_letter ? (g_shift_held != g_capslock_on) : g_shift_held;
    const char resolved = use_upper ? kKeymapUpper[code] : lower;
    return resolved;
}

namespace
{

u8 CurrentModifiers()
{
    u8 m = 0;
    if (g_shift_held)
        m |= kKeyModShift;
    if (g_ctrl_held)
        m |= kKeyModCtrl;
    if (g_alt_held)
        m |= kKeyModAlt;
    if (g_meta_held)
        m |= kKeyModMeta;
    if (g_capslock_on)
        m |= kKeyModCapsLock;
    return m;
}

u16 TranslateExtendedScan(u8 code)
{
    switch (code)
    {
    case kScanExtArrowUp:
        return kKeyArrowUp;
    case kScanExtArrowDown:
        return kKeyArrowDown;
    case kScanExtArrowLeft:
        return kKeyArrowLeft;
    case kScanExtArrowRight:
        return kKeyArrowRight;
    case kScanExtHome:
        return kKeyHome;
    case kScanExtEnd:
        return kKeyEnd;
    case kScanExtPageUp:
        return kKeyPageUp;
    case kScanExtPageDown:
        return kKeyPageDown;
    case kScanExtInsert:
        return kKeyInsert;
    case kScanExtDelete:
        return kKeyDelete;
    default:
        return kKeyNone;
    }
}

u16 TranslateFKey(u8 code)
{
    if (code >= kScanF1 && code <= kScanF10)
    {
        return static_cast<u16>(kKeyF1 + (code - kScanF1));
    }
    if (code == kScanF11)
        return kKeyF11;
    if (code == kScanF12)
        return kKeyF12;
    return kKeyNone;
}

} // namespace

KeyEvent Ps2KeyboardReadEvent()
{
    for (;;)
    {
        // Priority 1 — injected events (HID keyboard, future
        // drivers). Check under Cli so an IRQ-time producer (were
        // we to have one) doesn't race the head/tail read.
        {
            arch::Cli();
            KeyEvent injected{};
            const bool got = InjectRingPop(&injected);
            arch::Sti();
            if (got)
                return injected;
        }

        const u8 sc = Ps2KeyboardRead();
        if (sc == 0)
        {
            // Woke up because an injected event landed after we
            // released the lock above. Loop back to drain it.
            continue;
        }

        if (sc == kScanExtendedPrefix)
        {
            g_extended_pending = true;
            continue;
        }

        const bool released = (sc & kScanBreakBit) != 0;
        const u8 code = static_cast<u8>(sc & ~kScanBreakBit);

        KeyEvent ev{};
        ev.is_release = released;

        if (g_extended_pending)
        {
            g_extended_pending = false;

            // Extended modifier variants: RCtrl / RAlt / Meta.
            if (code == kScanExtRCtrl)
            {
                g_ctrl_held = !released;
                ev.code = kKeyNone;
                ev.modifiers = CurrentModifiers();
                return ev;
            }
            if (code == kScanExtRAlt)
            {
                g_alt_held = !released;
                ev.code = kKeyNone;
                ev.modifiers = CurrentModifiers();
                return ev;
            }
            if (code == kScanExtMetaLeft || code == kScanExtMetaRight)
            {
                g_meta_held = !released;
                ev.code = kKeyNone;
                ev.modifiers = CurrentModifiers();
                return ev;
            }

            const u16 extended = TranslateExtendedScan(code);
            if (extended == kKeyNone)
            {
                continue; // unmapped extended key — drop
            }
            ev.code = extended;
            ev.modifiers = CurrentModifiers();
            return ev;
        }

        // Non-extended modifiers.
        if (code == kScanLShift || code == kScanRShift)
        {
            g_shift_held = !released;
            ev.code = kKeyNone;
            ev.modifiers = CurrentModifiers();
            return ev;
        }
        if (code == kScanLCtrl)
        {
            g_ctrl_held = !released;
            ev.code = kKeyNone;
            ev.modifiers = CurrentModifiers();
            return ev;
        }
        if (code == kScanLAlt)
        {
            g_alt_held = !released;
            ev.code = kKeyNone;
            ev.modifiers = CurrentModifiers();
            return ev;
        }
        if (code == kScanCapsLock)
        {
            if (!released)
            {
                g_capslock_on = !g_capslock_on;
            }
            ev.code = kKeyNone;
            ev.modifiers = CurrentModifiers();
            return ev;
        }

        // Named non-ASCII keys first so they don't slip past into
        // the printable-ASCII path below.
        if (code == kScanEscape)
        {
            ev.code = kKeyEsc;
            ev.modifiers = CurrentModifiers();
            return ev;
        }
        if (code == kScanBackspace)
        {
            ev.code = kKeyBackspace;
            ev.modifiers = CurrentModifiers();
            return ev;
        }
        if (code == kScanTab)
        {
            ev.code = kKeyTab;
            ev.modifiers = CurrentModifiers();
            return ev;
        }
        if (code == kScanEnter)
        {
            ev.code = kKeyEnter;
            ev.modifiers = CurrentModifiers();
            return ev;
        }

        const u16 fkey = TranslateFKey(code);
        if (fkey != kKeyNone)
        {
            ev.code = fkey;
            ev.modifiers = CurrentModifiers();
            return ev;
        }

        // Printable-ASCII fall-through via the existing US QWERTY
        // keymap. Use the same shift / caps-lock logic as
        // Ps2KeyboardReadChar so the two APIs stay consistent
        // when fed the same physical keypresses.
        if (code < kKeymapSize)
        {
            const char lower = kKeymapLower[code];
            if (lower != 0)
            {
                const bool is_letter = (lower >= 'a' && lower <= 'z');
                const bool use_upper = is_letter ? (g_shift_held != g_capslock_on) : g_shift_held;
                const char resolved = use_upper ? kKeymapUpper[code] : lower;
                ev.code = static_cast<u16>(resolved);
                ev.modifiers = CurrentModifiers();
                return ev;
            }
        }

        // Unmapped — loop for the next scan code rather than
        // surfacing a zero-code event. Keeps the stream clean
        // for callers that don't want to filter kKeyNone on
        // every edge.
        continue;
    }
}

Ps2Stats Ps2KeyboardStats()
{
    return Ps2Stats{
        .irqs_seen = g_irqs_seen,
        .bytes_buffered = g_bytes_buffered,
        .bytes_dropped = g_bytes_dropped,
    };
}

void KeyboardInjectEvent(const KeyEvent& ev)
{
    arch::Cli();
    // Full-ring policy: drop the oldest event so the newest
    // always lands. The HID keyboard's state-diff path relies on
    // every press/release edge making it through; losing the
    // freshest edge (typical "drop newest" policy) would leave a
    // key permanently stuck down from the reader's perspective.
    if (g_inject_head - g_inject_tail >= kInjectRingSize)
    {
        ++g_inject_tail;
    }
    g_inject_ring[g_inject_head & kInjectRingMask] = ev;
    ++g_inject_head;
    arch::Sti();
    duetos::sched::WaitQueueWakeOne(&g_readers);
}

} // namespace duetos::drivers::input
