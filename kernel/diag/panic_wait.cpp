#include "diag/panic_wait.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/boot_cmdline.h"

namespace duetos::diag
{

namespace
{

// Latched once at boot. Read on every panic. No locking — the
// boot-time write happens before any other CPU is online, and
// readers only see false→true transitions (the boot value is
// false, set-from-cmdline never clears it).
constinit bool g_panic_wait_armed = false;

} // namespace

void PanicWaitInitFromCmdline(const char* cmdline)
{
    if (cmdline == nullptr)
        return;
    // CmdlineMatches looks for "panic_wait=gdb" as a whitespace-
    // delimited token. Any other value (`panic_wait=none`,
    // `panic_wait=halt`) leaves the gate disarmed.
    if (::duetos::core::CmdlineMatches(cmdline, "panic_wait", "gdb"))
        g_panic_wait_armed = true;
}

bool PanicWaitArmed()
{
    return g_panic_wait_armed;
}

[[noreturn]] void PanicWaitForDebugger()
{
    // Already in panic-mode serial by the time we get here, but
    // ensure it — if a caller routed straight to us bypassing
    // the standard Panic body, the serial port is still in its
    // normal IRQ-driven mode and we'd deadlock on the first
    // write.
    ::duetos::arch::SerialEnterPanicMode();
    ::duetos::arch::SerialWrite("[panic-wait] armed; halted for GDB stub attach (default :1234)\n");
    ::duetos::arch::SerialWrite("[panic-wait] connect: gdb -ex 'target remote :1234' build/.../duetos-kernel.elf\n");

    // INT3 once so an attached GDB sees a clean break. If no
    // debugger is attached, the kernel's own #BP handler
    // re-enters the panic path, which short-circuits via
    // PanicInProgress and lands in arch::Halt() — same outcome
    // as a default boot, just with an extra "[recursive-panic]
    // bp/int3" line in the log to advertise the failed wait.
    asm volatile("int3");

    // After GDB releases (or if no GDB ever attached), spin
    // forever with interrupts off. Equivalent to arch::Halt().
    for (;;)
    {
        asm volatile("cli; hlt");
    }
}

} // namespace duetos::diag
