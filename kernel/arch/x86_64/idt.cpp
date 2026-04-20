#include "idt.h"

#include "gdt.h"

#include "../../core/panic.h"

/*
 * The exception + IRQ stubs in exceptions.S publish their addresses through
 * this 48-entry array. Slots 0..31 are CPU exceptions; slots 32..47 are the
 * remapped IRQs (8259 layout, also used by the LAPIC). The LAPIC spurious
 * vector at 0xFF is published as a separate symbol — it would be wasteful
 * to extend this table to 256 entries just to hold one extra address.
 */
extern "C" customos::u64 isr_stub_table[48];

namespace customos::arch
{

namespace
{

struct [[gnu::packed]] IdtGate
{
    u16 offset_low;
    u16 selector;
    u8 ist;       // low 3 bits = IST index, upper 5 bits = 0
    u8 type_attr; // P | DPL | 0 | type. 0x8E = P + DPL0 + interrupt gate
    u16 offset_mid;
    u32 offset_high;
    u32 reserved;
};

static_assert(sizeof(IdtGate) == 16, "IDT gate must be 16 bytes in long mode");

struct [[gnu::packed]] IdtPointer
{
    u16 limit;
    u64 base;
};

alignas(16) constinit IdtGate g_idt[256] = {};

// Not constinit — see comment in gdt.cpp. Populated by IdtInit().
IdtPointer g_idt_pointer;

constexpr u8 kGateInterruptDpl0 = 0x8E; // P=1, DPL=0, type=0xE (interrupt)

void SetGate(u8 vector, u64 handler, u8 type_attr)
{
    IdtGate& gate = g_idt[vector];
    gate.offset_low = static_cast<u16>(handler & 0xFFFF);
    gate.selector = kKernelCodeSelector;
    gate.ist = 0;
    gate.type_attr = type_attr;
    gate.offset_mid = static_cast<u16>((handler >> 16) & 0xFFFF);
    gate.offset_high = static_cast<u32>((handler >> 32) & 0xFFFFFFFF);
    gate.reserved = 0;
}

} // namespace

void IdtInit()
{
    // Install both the CPU-exception vectors (0..31) and the remapped IRQ
    // vectors (32..47). The IRQ stubs are present from boot, but until
    // PicDisable + LapicInit run no controller will actually deliver to
    // them — the slots are wired so that any spurious IRQ produced during
    // bring-up still hits a real handler instead of triple-faulting.
    for (u8 vector = 0; vector < 48; ++vector)
    {
        SetGate(vector, isr_stub_table[vector], kGateInterruptDpl0);
    }

    g_idt_pointer.limit = sizeof(g_idt) - 1;
    g_idt_pointer.base = reinterpret_cast<u64>(&g_idt[0]);

    asm volatile("lidt %0" : : "m"(g_idt_pointer) : "memory");
}

void IdtSetGate(u8 vector, u64 handler)
{
    // Reject a null handler — silently installing one would turn every
    // delivery on this vector into a #PF/triple-fault at boot with no
    // diagnostic. Require callers to pass a real ISR stub.
    KASSERT_WITH_VALUE(handler != 0, "arch/idt", "IdtSetGate null handler", static_cast<u64>(vector));

    SetGate(vector, handler, kGateInterruptDpl0);
}

void IdtSetIst(u8 vector, u8 ist)
{
    // IST index lives in the low 3 bits of the ist field; upper 5
    // bits must be zero. 0 would disable IST redirection; we
    // assert against that because IdtSetIst is always called with
    // a non-zero value — disabling would mean the caller meant to
    // SetGate instead.
    KASSERT_WITH_VALUE(ist >= 1 && ist <= 7, "arch/idt", "IdtSetIst index out of range", static_cast<u64>(ist));
    g_idt[vector].ist = static_cast<u8>(ist & 0x7);
}

} // namespace customos::arch
