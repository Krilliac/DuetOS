#include "idt.h"

#include "gdt.h"

#include "../../core/panic.h"

/*
 * The exception + IRQ stubs in exceptions.S publish their addresses
 * through this 256-entry array. Slots 0..31 are CPU exceptions;
 * slots 32..47 are the remapped IRQs (8259 layout, also used by
 * the LAPIC); slots 48..127 + 129..254 are spurious-vector stubs
 * that log the offending vector and iretq; slot 128 is the syscall
 * gate (re-installed DPL=3 by SyscallInit); slot 255 is the LAPIC
 * spurious vector (re-installed by LapicInit). Every IDT entry has
 * a real handler — a stray vector never cascades through #NP.
 */
extern "C" duetos::u64 isr_stub_table[256];

namespace duetos::arch
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
constexpr u8 kGateInterruptDpl3 = 0xEE; // P=1, DPL=3, type=0xE (interrupt) — user-reachable

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
    // Install every IDT vector. Slots 0..31 are CPU exceptions
    // (real handlers in TrapDispatch); 32..47 are the remapped
    // IRQs (registered handler or "[irq] unhandled vector N" log);
    // 48..127 + 129..254 are spurious-vector stubs that log the
    // offending number + iretq (no panic, no #NP cascade); slot
    // 128 is the syscall gate, re-installed DPL=3 by SyscallInit
    // shortly after this returns; slot 255 is the LAPIC spurious
    // vector, re-installed by LapicInit later.
    //
    // Loop bound is 256, terminated by `vector` wrapping back to 0
    // after 255 — written as a u32 + cast to keep `vector < 256`
    // expressible without a u8 wraparound bug.
    for (u32 vector = 0; vector < 256; ++vector)
    {
        SetGate(static_cast<u8>(vector), isr_stub_table[vector], kGateInterruptDpl0);
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

void IdtSetUserGate(u8 vector, u64 handler)
{
    KASSERT_WITH_VALUE(handler != 0, "arch/idt", "IdtSetUserGate null handler", static_cast<u64>(vector));

    SetGate(vector, handler, kGateInterruptDpl3);
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

u8* IdtRawBase()
{
    return reinterpret_cast<u8*>(g_idt);
}

u64 IdtHash()
{
    // FNV-1a over the raw IDT bytes. 4096 bytes -> ~1 µs per
    // call on modern CPUs. Not cryptographic (an attacker who
    // wants to preserve the hash could pad collisions), but
    // catches every accidental modification and every
    // non-adversarial rootkit that doesn't bother re-hashing.
    constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
    constexpr u64 kFnvPrime = 0x100000001b3ULL;
    const auto* p = reinterpret_cast<const u8*>(g_idt);
    u64 h = kFnvOffset;
    for (u64 i = 0; i < sizeof(g_idt); ++i)
    {
        h ^= p[i];
        h *= kFnvPrime;
    }
    return h;
}

} // namespace duetos::arch
