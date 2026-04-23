#include "heap_syscall.h"

#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"
#include "heap.h"

namespace customos::subsystems::win32
{

void DoHeapAlloc(arch::TrapFrame* frame)
{
    // rdi = size in bytes. Returns user VA or 0 on OOM. See
    // heap.cpp for the first-fit allocator. Unprivileged — every
    // Win32 process has its own heap mapped during PeLoad.
    core::Process* proc = core::CurrentProcess();
    frame->rax = (proc != nullptr) ? ::customos::win32::Win32HeapAlloc(proc, frame->rdi) : 0;
}

void DoHeapFree(arch::TrapFrame* frame)
{
    // rdi = user ptr (or 0 for no-op). Returns 0.
    core::Process* proc = core::CurrentProcess();
    if (proc != nullptr)
        ::customos::win32::Win32HeapFree(proc, frame->rdi);
    frame->rax = 0;
}

void DoHeapSize(arch::TrapFrame* frame)
{
    // rdi = user ptr. Returns payload capacity. 0 on null / oor.
    core::Process* proc = core::CurrentProcess();
    frame->rax = (proc != nullptr) ? ::customos::win32::Win32HeapSize(proc, frame->rdi) : 0;
}

void DoHeapRealloc(arch::TrapFrame* frame)
{
    // rdi = existing ptr (or 0), rsi = new size.
    core::Process* proc = core::CurrentProcess();
    frame->rax = (proc != nullptr) ? ::customos::win32::Win32HeapRealloc(proc, frame->rdi, frame->rsi) : 0;
}

} // namespace customos::subsystems::win32
