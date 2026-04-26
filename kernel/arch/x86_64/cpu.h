#pragma once

#include "util/types.h"

/*
 * Low-level x86_64 CPU helpers.
 *
 * Context: kernel. All functions are inline and trivially-NOP-on-return;
 * there is no out-of-line state. Safe to call at any interrupt level.
 */

namespace duetos::arch
{

inline void Outb(u16 port, u8 value)
{
    asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

inline u8 Inb(u16 port)
{
    u8 value;
    asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

inline void Outw(u16 port, u16 value)
{
    asm volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

inline u16 Inw(u16 port)
{
    u16 value;
    asm volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

inline void Cli()
{
    asm volatile("cli" ::: "memory");
}

inline void Sti()
{
    asm volatile("sti" ::: "memory");
}

[[noreturn]] inline void Halt()
{
    for (;;)
    {
        asm volatile("cli; hlt");
    }
}

/// Idle the CPU forever with interrupts ENABLED. Wakes on every IRQ to run
/// the dispatcher, then halts again. The kernel's "I'm done with bring-up,
/// now wait for work" sink — distinct from `Halt`, which masks interrupts
/// and is the unrecoverable-error sink.
[[noreturn]] inline void IdleLoop()
{
    for (;;)
    {
        asm volatile("sti; hlt");
    }
}

inline u64 ReadCr0()
{
    u64 value;
    asm volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

/// Load CR0 with a new value. Changing certain bits (PG, PE, CD/NW,
/// WP) has system-wide effect — callers should be deliberate about
/// what they flip. The "memory" clobber prevents the compiler from
/// reordering loads/stores across the write.
inline void WriteCr0(u64 value)
{
    asm volatile("mov %0, %%cr0" : : "r"(value) : "memory");
}

inline u64 ReadCr2()
{
    u64 value;
    asm volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

inline u64 ReadCr3()
{
    u64 value;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

/// Load CR3 with a new PML4 physical address. Implicitly flushes every
/// non-global TLB entry on the executing CPU. The "memory" clobber tells
/// the compiler not to reorder loads/stores across the switch — the
/// caller has just changed which page tables are authoritative.
///
/// Invariant: bits 0..11 of `pml4_phys` MUST be zero (4 KiB-aligned PML4
/// frame). The low 12 bits of CR3 are PCID / cache-control flags; we
/// don't use PCIDs in v0, so callers pass a clean physical address.
inline void WriteCr3(u64 pml4_phys)
{
    asm volatile("mov %0, %%cr3" : : "r"(pml4_phys) : "memory");
}

inline u64 ReadCr4()
{
    u64 value;
    asm volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

inline u64 ReadRflags()
{
    u64 value;
    asm volatile("pushfq; pop %0" : "=r"(value));
    return value;
}

inline u64 ReadRsp()
{
    u64 value;
    asm volatile("mov %%rsp, %0" : "=r"(value));
    return value;
}

inline u64 ReadRbp()
{
    u64 value;
    asm volatile("mov %%rbp, %0" : "=r"(value));
    return value;
}

inline u64 ReadEfer()
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));
    return (static_cast<u64>(hi) << 32) | lo;
}

} // namespace duetos::arch
