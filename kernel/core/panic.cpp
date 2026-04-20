#include "panic.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"

namespace customos::core
{

void Panic(const char* subsystem, const char* message)
{
    // Disable interrupts before writing the banner so a pending IRQ
    // can't preempt us mid-message and scramble the output. Halt
    // itself also CLI+HLT loops, but getting the clean banner out
    // first matters for diagnosis.
    arch::Cli();

    arch::SerialWrite("\n[panic] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(": ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n[panic] CPU halted — no recovery.\n");

    arch::Halt();
}

void PanicWithValue(const char* subsystem, const char* message, u64 value)
{
    arch::Cli();

    arch::SerialWrite("\n[panic] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(": ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n  value : ");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n[panic] CPU halted — no recovery.\n");

    arch::Halt();
}

} // namespace customos::core
