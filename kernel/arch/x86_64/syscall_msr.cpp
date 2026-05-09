/*
 * DuetOS — per-ABI MSR_LSTAR retargeting.
 *
 * Two SYSCALL entry stubs exist: the Linux fast path
 * (`linux_syscall_entry`, kernel/subsystems/linux/syscall_entry.S)
 * and the native-ABI path (`native_syscall_entry`,
 * kernel/arch/x86_64/native_syscall_entry.S). Both build the same
 * `arch::TrapFrame` shape but call different C++ dispatchers.
 *
 * `MSR_LSTAR` holds the entry RIP for the SYSCALL instruction. The
 * Linux SyscallInit (subsystems/linux/syscall.cpp) primes it at boot
 * with `linux_syscall_entry`. When the scheduler switches to a
 * native-ABI task, `SyscallRetargetForAbi(false)` flips LSTAR to the
 * native stub so the next user-mode SYSCALL lands on the right
 * dispatcher. Switching back to a Linux task flips it back.
 *
 * `wrmsr` to LSTAR is ~80 cycles on contemporary silicon. Cheaper
 * than threading the ABI selection through a per-syscall conditional
 * in asm, and only paid on ABI-crossing switches (most workloads
 * are homogeneous within a runqueue burst).
 *
 * `NativeSyscallEntry` is the extern "C" forwarder the assembly
 * stub calls. Forwarding through a thin shim keeps the syscall
 * dispatcher's mangled name out of the .S file and gives the
 * linker a single, stable C symbol to resolve.
 */

#include "arch/x86_64/traps.h"
#include "syscall/syscall.h"
#include "util/types.h"

namespace duetos::arch
{

namespace
{

constexpr u32 kMsrLstar = 0xC0000082;

void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

} // namespace

extern "C" void linux_syscall_entry();
extern "C" void native_syscall_entry();

void SyscallRetargetForAbi(bool linux_abi)
{
    const u64 target =
        linux_abi ? reinterpret_cast<u64>(&linux_syscall_entry) : reinterpret_cast<u64>(&native_syscall_entry);
    WriteMsr(kMsrLstar, target);
}

} // namespace duetos::arch

extern "C" void NativeSyscallEntry(duetos::arch::TrapFrame* frame)
{
    /* Forward to the native dispatcher. The dispatcher reads
     * frame->rax for the syscall number and writes frame->rax with
     * the return value before unwinding. */
    duetos::core::SyscallDispatch(frame);
}
