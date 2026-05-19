#pragma once

// Host fuzz shim for kernel/arch/x86_64/cpu.h. The real header is
// all privileged inline asm (cli/sti/in/out/cr/msr) — executing
// any of it under libFuzzer SIGILLs/SEGVs the host process. tcp.cpp
// uses arch::Cli()/Sti() directly as its concurrency lock; the
// fuzz harness is single-threaded so interrupt masking is a no-op.
// Port / CR / MSR accessors return 0 (no device behind them here).

#include "util/types.h"

#include <cstdlib>

namespace duetos::arch
{
inline void Outb(u16, u8) {}
inline u8 Inb(u16)
{
    return 0;
}
inline void Outw(u16, u16) {}
inline u16 Inw(u16)
{
    return 0;
}
inline void Outl(u16, u32) {}
inline u32 Inl(u16)
{
    return 0;
}
inline void Cli() {}
inline void Sti() {}

[[noreturn]] inline void Halt()
{
    // Not reachable from the fuzzed parse path; abort makes a
    // stray call a visible libFuzzer crash rather than UB.
    abort();
}
[[noreturn]] inline void IdleLoop()
{
    abort();
}
[[noreturn]] inline void TestExit(u8)
{
    abort();
}

inline u64 ReadCr0()
{
    return 0;
}
inline void WriteCr0(u64) {}
inline u64 ReadCr2()
{
    return 0;
}
inline u64 ReadCr3()
{
    return 0;
}
inline void WriteCr3(u64) {}
inline u64 ReadCr4()
{
    return 0;
}
inline u64 ReadRflags()
{
    return 0;
}
inline u64 ReadRsp()
{
    return 0;
}
inline u64 ReadRbp()
{
    return 0;
}
inline u64 ReadEfer()
{
    return 0;
}
inline u64 ReadMsr(u32)
{
    return 0;
}
inline void WriteMsr(u32, u64) {}
} // namespace duetos::arch
