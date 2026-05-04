#include "diag/debugcon.h"

#include "arch/x86_64/cpu.h"

namespace duetos::diag::debugcon
{

namespace
{

constexpr u16 kDebugconPort = 0xE9;

} // namespace

void WriteByte(u8 byte)
{
    arch::Outb(kDebugconPort, byte);
}

void Write(const u8* buf, u64 len)
{
    if (buf == nullptr)
    {
        return;
    }
    for (u64 i = 0; i < len; ++i)
    {
        arch::Outb(kDebugconPort, buf[i]);
    }
}

} // namespace duetos::diag::debugcon
