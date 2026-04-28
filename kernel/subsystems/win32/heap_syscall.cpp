#include "subsystems/win32/heap_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "proc/process.h"
#include "subsystems/win32/heap.h"

namespace duetos::subsystems::win32
{

namespace
{

// Heap syscalls are unreachable from kernel-only tasks (no trap frame
// from int 0x80), but a misrouted dispatch or a syscall issued during
// a partial process tear-down would land here with proc==null. Rather
// than silently returning 0 / -1 and leaving the caller guessing, log
// once per call so a stray dispatch is visible in the serial trace.
void LogNullProc(const char* where)
{
    arch::SerialWrite("[sys] ");
    arch::SerialWrite(where);
    arch::SerialWrite(" proc=null\n");
    KLOG_WARN_S("win32/heap", "syscall hit with proc=null", "where", where);
}

} // namespace

void DoHeapAlloc(arch::TrapFrame* frame)
{
    // rdi = size in bytes. Returns user VA or 0 on OOM. See
    // heap.cpp for the first-fit allocator. Unprivileged — every
    // Win32 process has its own heap mapped during PeLoad.
    KLOG_TRACE_V("win32/heap", "DoHeapAlloc: size", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        LogNullProc("DoHeapAlloc");
        frame->rax = 0;
        return;
    }
    frame->rax = ::duetos::win32::Win32HeapAlloc(proc, frame->rdi);
    if (frame->rax == 0)
    {
        KLOG_WARN_V("win32/heap", "DoHeapAlloc: OOM at requested size", frame->rdi);
    }
    else
    {
        KLOG_DEBUG_V("win32/heap", "DoHeapAlloc: granted user VA", frame->rax);
    }
}

void DoHeapFree(arch::TrapFrame* frame)
{
    // rdi = user ptr (or 0 for no-op). Returns 0.
    KLOG_TRACE_V("win32/heap", "DoHeapFree: ptr", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        LogNullProc("DoHeapFree");
        frame->rax = 0;
        return;
    }
    ::duetos::win32::Win32HeapFree(proc, frame->rdi);
    frame->rax = 0;
}

void DoHeapSize(arch::TrapFrame* frame)
{
    // rdi = user ptr. Returns payload capacity. 0 on null / oor.
    KLOG_TRACE_V("win32/heap", "DoHeapSize: ptr", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        LogNullProc("DoHeapSize");
        frame->rax = 0;
        return;
    }
    frame->rax = ::duetos::win32::Win32HeapSize(proc, frame->rdi);
}

void DoHeapRealloc(arch::TrapFrame* frame)
{
    // rdi = existing ptr (or 0), rsi = new size.
    KLOG_TRACE_V("win32/heap", "DoHeapRealloc: new size", frame->rsi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        LogNullProc("DoHeapRealloc");
        frame->rax = 0;
        return;
    }
    frame->rax = ::duetos::win32::Win32HeapRealloc(proc, frame->rdi, frame->rsi);
    if (frame->rax == 0)
    {
        KLOG_WARN_V("win32/heap", "DoHeapRealloc: returned 0 (OOM or invalid ptr)", frame->rdi);
    }
}

} // namespace duetos::subsystems::win32
