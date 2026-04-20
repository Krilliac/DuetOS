#include "syscall.h"

#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/serial.h"
#include "../mm/paging.h"
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

// Cap on the maximum bytes a single SYS_WRITE copies out of user
// memory. v0 keeps the kernel-side bounce buffer on-stack, so this
// can't grow without bound. 256 is comfortable for the first
// consumer (a "hello" print from the ring-3 smoke task) and leaves
// plenty of headroom on a 16 KiB kernel stack. Larger writes get
// truncated to this length and the returned byte count reflects
// the truncation — standard POSIX write() semantics.
constexpr u64 kSyscallWriteMax = 256;

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

// SYS_WRITE body. Copies up to `len` bytes from the user buffer,
// truncates to kSyscallWriteMax, and spits them straight at COM1.
// Only fd=1 (stdout) is recognised today — anything else is a
// caller error and returns -1 so the pattern is immediately
// auditable. Returns the actual byte count written (possibly
// truncated) or -1 on failure.
i64 DoWrite(u64 fd, const void* user_buf, u64 len)
{
    if (fd != 1)
    {
        return -1;
    }

    const u64 to_copy = (len > kSyscallWriteMax) ? kSyscallWriteMax : len;
    if (to_copy == 0)
    {
        return 0;
    }

    // Kernel-stack bounce buffer. The CopyFromUser gate ensures the
    // user pointer is in-range + SMAP-allowed; we never touch the
    // raw user address after the copy, which closes the "TOCTOU
    // between validation and read" class of bugs on its own.
    u8 kbuf[kSyscallWriteMax];
    if (!mm::CopyFromUser(kbuf, user_buf, to_copy))
    {
        return -1;
    }

    // Drive COM1 one byte at a time. SerialWrite() is null-terminated,
    // which is wrong for an arbitrary byte stream — use the per-char
    // helper via a tiny 2-char buffer so any \0 inside the user
    // payload gets forwarded faithfully as a literal 0.
    for (u64 i = 0; i < to_copy; ++i)
    {
        const char two[2] = {static_cast<char>(kbuf[i]), '\0'};
        arch::SerialWrite(two);
    }
    return static_cast<i64>(to_copy);
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

    case SYS_GETPID:
    {
        // First syscall that actually exercises the return-value
        // half of the ABI: the dispatcher writes frame->rax and
        // isr_common's pop-all + iretq delivers it to ring 3.
        frame->rax = sched::CurrentTaskId();
        return;
    }

    case SYS_WRITE:
    {
        // rdi = fd, rsi = user buf, rdx = len. DoWrite validates
        // the pointer + length via mm::CopyFromUser, SMAP-gates
        // the actual read, and returns the (possibly truncated)
        // byte count or -1 on failure.
        const i64 rc = DoWrite(frame->rdi, reinterpret_cast<const void*>(frame->rsi), frame->rdx);
        frame->rax = static_cast<u64>(rc);
        return;
    }

    case SYS_YIELD:
    {
        // Cooperative-yield from ring 3. The kernel-side SchedYield
        // briefly cli / Schedule / sti; by the time we return here,
        // either the same task was picked (no-op from ring 3's
        // perspective) or another task ran and eventually switched
        // us back in. Returns 0 — reserved for an "I was preempted"
        // boolean later if any consumer cares.
        sched::SchedYield();
        frame->rax = 0;
        return;
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
