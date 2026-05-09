/*
 * DuetOS — Win32 NT-style int 0x2E syscall dispatcher.
 *
 * The asm stub `nt_syscall_entry` (nt_syscall_entry.S) builds an
 * `arch::TrapFrame` and calls `NtSyscallEntryDispatch`. We translate
 * the NT syscall number in `frame->rax` to the corresponding DuetOS
 * native SYS_* number using the mapping in
 * `nt_syscall_table_generated.h`, then forward to the native
 * dispatcher.
 *
 * Unmapped numbers (the table marks them with `kSysNtNotImpl`)
 * return STATUS_NOT_IMPLEMENTED (0xC0000002), matching what real
 * ntdll callers expect when a syscall isn't backed by a kernel
 * handler.
 *
 * NB: This dispatcher is only reached when the IDT has been
 * configured to route vector 0x2E at this stub. The default IDT
 * leaves vector 0x2E routed to the generic spurious-vector stub;
 * flipping it requires a deliberate wiring step (e.g. when the
 * loader detects a binary that needs the legacy gate).
 */

#include "arch/x86_64/traps.h"
#include "subsystems/win32/nt_syscall_table_generated.h"
#include "syscall/syscall.h"
#include "util/types.h"

extern "C" void NtSyscallEntryDispatch(duetos::arch::TrapFrame* frame)
{
    using namespace duetos::subsystems::win32;

    constexpr duetos::u64 kStatusNotImplemented = 0xC0000002ull;

    if (frame == nullptr)
    {
        return;
    }

    const duetos::u16 nt_num = static_cast<duetos::u16>(frame->rax & 0xFFFFu);
    const NtSyscallMapping* mapping = NtSyscallByNumber(nt_num);

    if (mapping == nullptr || mapping->duetos_sys == kSysNtNotImpl)
    {
        frame->rax = kStatusNotImplemented;
        return;
    }

    /* Forward to the native dispatcher with the translated number
     * in rax. The native dispatcher reads frame->rax for the
     * syscall number and writes frame->rax with the return value. */
    frame->rax = mapping->duetos_sys;
    duetos::core::SyscallDispatch(frame);
}
