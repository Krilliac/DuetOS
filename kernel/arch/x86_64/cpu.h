#pragma once

#include "../../core/types.h"

/*
 * Low-level x86_64 CPU helpers.
 *
 * Context: kernel. All functions are inline and trivially-NOP-on-return;
 * there is no out-of-line state. Safe to call at any interrupt level.
 */

namespace customos::arch
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

} // namespace customos::arch
