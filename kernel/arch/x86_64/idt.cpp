#include "idt.h"

#include "gdt.h"

/*
 * The exception stubs in exceptions.S publish their addresses through this
 * 32-entry array. Each stub pushes a uniform trap frame and jumps to a
 * common path that calls the C++ dispatcher.
 */
extern "C" customos::u64 isr_stub_table[32];

namespace customos::arch
{

namespace
{

struct [[gnu::packed]] IdtGate
{
    u16 offset_low;
    u16 selector;
    u8  ist;            // low 3 bits = IST index, upper 5 bits = 0
    u8  type_attr;      // P | DPL | 0 | type. 0x8E = P + DPL0 + interrupt gate
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

constexpr u8 kGateInterruptDpl0 = 0x8E;   // P=1, DPL=0, type=0xE (interrupt)

void SetGate(u8 vector, u64 handler, u8 type_attr)
{
    IdtGate& gate = g_idt[vector];
    gate.offset_low  = static_cast<u16>(handler & 0xFFFF);
    gate.selector    = kKernelCodeSelector;
    gate.ist         = 0;
    gate.type_attr   = type_attr;
    gate.offset_mid  = static_cast<u16>((handler >> 16) & 0xFFFF);
    gate.offset_high = static_cast<u32>((handler >> 32) & 0xFFFFFFFF);
    gate.reserved    = 0;
}

} // namespace

void IdtInit()
{
    // Vectors 0..31 are CPU exceptions. Hardware IRQs (vectors 32+) stay
    // as non-present gates until the interrupt controller is brought up.
    for (u8 vector = 0; vector < 32; ++vector)
    {
        SetGate(vector, isr_stub_table[vector], kGateInterruptDpl0);
    }

    g_idt_pointer.limit = sizeof(g_idt) - 1;
    g_idt_pointer.base  = reinterpret_cast<u64>(&g_idt[0]);

    asm volatile("lidt %0" : : "m"(g_idt_pointer) : "memory");
}

} // namespace customos::arch
