#include "ps2kbd.h"

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

// Defined in exceptions.S — the stub for vector 0x21 that pushes a zero
// error code, pushes the vector, and jumps to isr_common (which calls
// TrapDispatch). The same plumbing every hardware IRQ already uses.
extern "C" void isr_33();

namespace customos::drivers::input
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

// Status register bit 0 = output buffer full (data waiting to be read).
constexpr u8 kStatusOutputFull = 1U << 0;

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

constinit customos::sched::WaitQueue g_readers{};

constinit u64 g_irqs_seen = 0;
constinit u64 g_bytes_buffered = 0;
constinit u64 g_bytes_dropped = 0;

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

void IrqHandler()
{
    ++g_irqs_seen;

    // Drain every pending byte in one pass. The 8042 can latch multiple
    // scan codes (a single keypress sends 1..3 bytes, and key repeat
    // under load stacks them up) before the next IRQ arrives.
    while ((Inb(kStatusPort) & kStatusOutputFull) != 0)
    {
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
    customos::sched::WaitQueueWakeOne(&g_readers);
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

    // Drain any leftover bytes the firmware / bootloader produced. Any
    // key presses during GRUB (arrow-key navigation in the menu!) land
    // in the 8042 output buffer and would fire a stale IRQ right after
    // we unmask. Reading them here keeps the post-init log clean.
    while ((Inb(kStatusPort) & kStatusOutputFull) != 0)
    {
        (void)Inb(kDataPort);
    }

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

    customos::core::LogWithValue(customos::core::LogLevel::Info, "drivers/ps2kbd", "routed isa_irq", kKbdIsaIrq);
    customos::core::LogWithValue(customos::core::LogLevel::Info, "drivers/ps2kbd", "  gsi", gsi);
    customos::core::LogWithValue(customos::core::LogLevel::Info, "drivers/ps2kbd", "  vector", kKbdVector);
    customos::core::LogWithValue(customos::core::LogLevel::Info, "drivers/ps2kbd", "  lapic_id", bsp_id);
}

u8 Ps2KeyboardRead()
{
    arch::Cli();
    while (g_ring_head == g_ring_tail)
    {
        customos::sched::WaitQueueBlock(&g_readers);
        // When we come back, interrupts are still disabled (we never
        // Sti'd), and a byte MAY be available. Could also have been a
        // spurious wake once we add broadcast-wake primitives, so
        // re-check the condition.
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

Ps2Stats Ps2KeyboardStats()
{
    return Ps2Stats{
        .irqs_seen = g_irqs_seen,
        .bytes_buffered = g_bytes_buffered,
        .bytes_dropped = g_bytes_dropped,
    };
}

} // namespace customos::drivers::input
