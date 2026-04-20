#include "ps2kbd.h"

#include "../../acpi/acpi.h"
#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/idt.h"
#include "../../arch/x86_64/ioapic.h"
#include "../../arch/x86_64/lapic.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
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

    SerialWrite("[ps2kbd] routed isa_irq=");
    SerialWriteHex(kKbdIsaIrq);
    SerialWrite(" gsi=");
    SerialWriteHex(gsi);
    SerialWrite(" vector=");
    SerialWriteHex(kKbdVector);
    SerialWrite(" lapic_id=");
    SerialWriteHex(bsp_id);
    SerialWrite("\n");
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

Ps2Stats Ps2KeyboardStats()
{
    return Ps2Stats{
        .irqs_seen = g_irqs_seen,
        .bytes_buffered = g_bytes_buffered,
        .bytes_dropped = g_bytes_dropped,
    };
}

} // namespace customos::drivers::input
