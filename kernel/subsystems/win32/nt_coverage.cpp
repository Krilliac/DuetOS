#include "subsystems/win32/nt_coverage.h"

#include "arch/x86_64/serial.h"
#include "subsystems/win32/nt_syscall_table_generated.h"

namespace duetos::win32
{

void Win32LogNtCoverage()
{
    // Re-walk the generated tables at boot to print the scoreboard.
    // The compile-time `kBedrockNtSyscallsCovered` already has the
    // count, but doing one runtime sweep here also confirms the
    // tables linked correctly into the kernel binary (catches a
    // future "header included but not referenced anywhere" rot).
    using namespace ::duetos::subsystems::win32;
    u32 covered = 0;
    for (u32 i = 0; i < kBedrockNtSyscallCount; ++i)
    {
        if (kBedrockNtSyscalls[i].duetos_sys != kSysNtNotImpl)
            ++covered;
    }
    arch::SerialWrite("[win32] ntdll bedrock coverage: ");
    arch::SerialWriteHex(covered);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kBedrockNtSyscallCount);
    arch::SerialWrite(" (generated table = ");
    arch::SerialWriteHex(kBedrockNtSyscallsCovered);
    arch::SerialWrite(")\n");
    arch::SerialWrite("[win32] ntdll full-table entries: ");
    arch::SerialWriteHex(kAllNtSyscallCount);
    arch::SerialWrite(" (every NT syscall known on the target Windows version)\n");
}

} // namespace duetos::win32
