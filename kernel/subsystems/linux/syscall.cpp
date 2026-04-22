#include "syscall.h"

#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/klog.h"
#include "../../cpu/percpu.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"

extern "C" void linux_syscall_entry();

namespace customos::subsystems::linux
{

namespace
{

// Linux x86_64 MSR numbers.
constexpr u32 kMsrStar = 0xC0000081;  // CS selectors for syscall/sysret
constexpr u32 kMsrLstar = 0xC0000082; // entry RIP for 64-bit syscall
// MSR_CSTAR (0xC0000083) is the compat-mode entry; we don't
// plan to run 32-bit code, so leave it unprogrammed.
constexpr u32 kMsrSfmask = 0xC0000084;       // RFLAGS mask applied at entry
constexpr u32 kMsrKernelGsBase = 0xC0000102; // swapgs source for kernel GS

// Canonical Linux errno values used by the handlers we implement.
// Only the subset we actually return today; extend as needed.
constexpr i64 kENOSYS = -38;
constexpr i64 kEBADF = -9;
constexpr i64 kEFAULT = -14;

// Per-process Linux fd cap on a single write/read. A real kernel
// wouldn't impose this but musl's newline-buffered stdout rarely
// issues writes over a few KiB. Cap matches the native int-0x80
// write path so behaviour stays predictable across ABIs.
constexpr u64 kLinuxIoMax = 4096;

void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFFu);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

// Linux x86_64 syscall numbers we recognise. Spec-stable — the
// RAX number IS the ABI, so these cannot be reassigned. We
// intentionally enumerate only the ones implemented today;
// others fall through to the default -ENOSYS arm.
enum : u64
{
    kSysRead = 0,
    kSysWrite = 1,
    kSysGetPid = 39,
    kSysExit = 60,
    kSysExitGroup = 231,
};

i64 DoExitGroup(u64 status)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[linux] exit_group status=");
    SerialWriteHex(status);
    SerialWrite("\n");
    sched::SchedExit();
    // sched::SchedExit is [[noreturn]]; this line is unreachable.
    return 0;
}

// Linux: write(fd, buf, count). v0 implements fd=1 (stdout) and
// fd=2 (stderr) only — both go to COM1. Everything else returns
// -EBADF so musl's perror / write-to-pipe error paths surface
// predictably. No cap-gating here yet: a Linux process that
// reached the dispatcher is trusted to the same degree a native
// ring-3 task reaching SYS_WRITE is. Gating by Process::caps
// gets bolted on when we need per-sandbox Linux policy.
i64 DoWrite(u64 fd, u64 user_buf, u64 len)
{
    if (fd != 1 && fd != 2)
    {
        return kEBADF;
    }
    const u64 to_copy = (len > kLinuxIoMax) ? kLinuxIoMax : len;
    if (to_copy == 0)
    {
        return 0;
    }
    u8 kbuf[kLinuxIoMax];
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_buf), to_copy))
    {
        return kEFAULT;
    }
    // Per-byte feed so any \0 in the payload forwards as a literal
    // 0 rather than truncating the string. Same pattern as the
    // native SYS_WRITE.
    for (u64 i = 0; i < to_copy; ++i)
    {
        const char two[2] = {static_cast<char>(kbuf[i]), '\0'};
        arch::SerialWrite(two);
    }
    return static_cast<i64>(to_copy);
}

// Linux: read(fd, buf, count). v0 stub — returns 0 (EOF) on fd=0
// (stdin). A real implementation would block on the keyboard FIFO
// or pipe; returning 0 lets musl's CRT see "no input" and proceed
// without blocking, which is what a non-interactive smoke wants.
// Non-0 fds return -EBADF.
i64 DoRead(u64 fd, u64 user_buf, u64 len)
{
    (void)user_buf;
    (void)len;
    if (fd != 0)
    {
        return kEBADF;
    }
    return 0;
}

} // namespace

extern "C" void LinuxSyscallDispatch(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("linux/syscall", "LinuxSyscallDispatch");
    const u64 nr = frame->rax;
    i64 rv = kENOSYS;
    switch (nr)
    {
    case kSysWrite:
        rv = DoWrite(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysRead:
        rv = DoRead(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysExit:
    case kSysExitGroup:
        DoExitGroup(frame->rdi);
        // Exit paths don't return; keep the compiler happy.
        rv = 0;
        break;
    case kSysGetPid:
        rv = static_cast<i64>(sched::CurrentTaskId());
        break;
    default:
        // Log the first unknown syscall per-process so we can
        // see which musl expected but we haven't implemented
        // yet. Noisy in the worst case — trim to per-PID dedup
        // when the hello-world path starts hitting fifty.
        arch::SerialWrite("[linux] unimplemented syscall nr=");
        arch::SerialWriteHex(nr);
        arch::SerialWrite("\n");
        break;
    }
    frame->rax = static_cast<u64>(rv);
}

void SyscallInit()
{
    using arch::SerialWrite;
    KLOG_TRACE_SCOPE("linux/syscall", "SyscallInit");

    // MSR_STAR: high 32 bits control CS/SS selectors.
    //   bits 47..32: SYSCALL target — kernel CS = 0x08 (GDT entry 1).
    //                The CPU also auto-loads SS = CS+8 = 0x10.
    //   bits 63..48: SYSRET target — user CS = 0x1B (GDT entry 3
    //                with RPL=3). The CPU loads SS = CS+8 = 0x23.
    //                NB: per spec, sysret adds 16 to the high-16
    //                selector value to get the 64-bit CS. We write
    //                0x10 here so the CPU derives 0x10+16=0x1B with
    //                RPL=3 for ring-3 return; SS = 0x10+8=0x18 with
    //                RPL=3 → 0x1B|0x3... actually the spec wants
    //                the base value (user CS - 16) which is 0x10.
    // Concrete layout: STAR[63:48]=0x10 (user base), STAR[47:32]=0x08.
    const u64 star = (u64(0x10) << 48) | (u64(0x08) << 32);
    WriteMsr(kMsrStar, star);

    // LSTAR: the RIP the CPU jumps to on `syscall` from 64-bit mode.
    const u64 lstar = reinterpret_cast<u64>(&linux_syscall_entry);
    WriteMsr(kMsrLstar, lstar);

    // SFMASK: RFLAGS bits cleared at syscall entry. Clear IF (bit 9)
    // so the entry stub runs with interrupts disabled, DF (bit 10)
    // for SysV ABI "direction flag = 0", and TF (bit 8) so a stray
    // trace flag from user mode doesn't single-step the kernel.
    const u64 sfmask = (1u << 9) | (1u << 10) | (1u << 8);
    WriteMsr(kMsrSfmask, sfmask);

    // KERNEL_GS_BASE: what `swapgs` will install into GS_BASE on
    // entry. Point it at this CPU's PerCpu struct so the entry
    // stub's `gs:[kPerCpuKernelRsp]` reads the right thing.
    //
    // On SMP, every AP will write its own PerCpu address at bring-
    // up. v0 is BSP-only.
    const u64 percpu_addr = reinterpret_cast<u64>(cpu::CurrentCpu());
    WriteMsr(kMsrKernelGsBase, percpu_addr);

    SerialWrite("[linux] syscall MSRs programmed (entry@");
    arch::SerialWriteHex(lstar);
    SerialWrite(", kernel_gs@");
    arch::SerialWriteHex(percpu_addr);
    SerialWrite(")\n");
}

} // namespace customos::subsystems::linux
