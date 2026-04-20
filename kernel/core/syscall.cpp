#include "syscall.h"

#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/serial.h"
#include "../sched/sched.h"
#include "klog.h"

// Defined in exceptions.S (via `ISR_NOERR 128`) — the .global label for
// the int-0x80 stub. SyscallInit installs its address into the IDT with
// a DPL=3 gate, which is the only bit that makes the int legal from ring
// 3. The function itself has no C-callable signature; we take its
// address as an opaque u64.
extern "C" void isr_128();

namespace customos::core
{

namespace
{

constexpr u8 kSyscallVector = 0x80;

// Pretty-printer for boot diagnostics — the Warn path for an
// unrecognised syscall number should be noisy enough to catch during
// bring-up but cheap enough to leave in release builds.
void ReportUnknownSyscall(u64 num, u64 rip)
{
    arch::SerialWrite("[sys] WARN unknown syscall num=");
    arch::SerialWriteHex(num);
    arch::SerialWrite(" rip=");
    arch::SerialWriteHex(rip);
    arch::SerialWrite("\n");
}

} // namespace

void SyscallInit()
{
    arch::IdtSetUserGate(kSyscallVector, reinterpret_cast<u64>(&isr_128));
    Log(LogLevel::Info, "sys", "syscall gate online at int 0x80");
}

void SyscallDispatch(arch::TrapFrame* frame)
{
    const u64 num = frame->rax;
    switch (num)
    {
    case SYS_EXIT:
    {
        const u64 code = frame->rdi;
        LogWithValue(LogLevel::Info, "sys", "exit rc", code);
        // SchedExit is [[noreturn]] — it marks the current task Dead,
        // wakes the reaper, and Schedule()s away forever. The trap
        // frame on this task's kernel stack becomes orphaned and
        // will be KFree'd by the reaper along with the stack itself.
        sched::SchedExit();
    }
    default:
        ReportUnknownSyscall(num, frame->rip);
        // Convention: -1 back to the caller for a bad syscall number.
        // Two's-complement cast keeps the rax payload machine-visible
        // as 0xFFFFFFFFFFFFFFFF rather than relying on enum promotion.
        frame->rax = static_cast<u64>(-1);
        return;
    }
}

} // namespace customos::core
