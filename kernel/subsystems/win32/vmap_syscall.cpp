#include "subsystems/win32/vmap_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "proc/process.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/paging.h"

namespace duetos::subsystems::win32
{

void DoVmap(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/vmap", "DoVmap: requested bytes", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/vmap", "DoVmap: no current Process");
        frame->rax = 0;
        return;
    }
    const u64 bytes = frame->rdi;
    if (bytes == 0)
    {
        KLOG_DEBUG("win32/vmap", "DoVmap: zero-byte request -> 0");
        frame->rax = 0;
        return;
    }
    const u64 pages = (bytes + mm::kPageSize - 1) / mm::kPageSize;
    if (pages == 0 || proc->vmap_pages_used + pages > core::Process::kWin32VmapCapPages)
    {
        KLOG_WARN_2V("win32/vmap", "DoVmap: arena cap exceeded", "pages", pages, "used",
                     static_cast<u64>(proc->vmap_pages_used));
        arch::SerialWrite("[sys] vmap oom pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" bytes=");
        arch::SerialWriteHex(bytes);
        arch::SerialWrite(" pages=");
        arch::SerialWriteHex(pages);
        arch::SerialWrite(" used=");
        arch::SerialWriteHex(proc->vmap_pages_used);
        arch::SerialWrite("\n");
        frame->rax = 0;
        return;
    }
    const u64 base = proc->vmap_base + proc->vmap_pages_used * mm::kPageSize;
    for (u64 i = 0; i < pages; ++i)
    {
        const mm::PhysAddr f = mm::AllocateFrame();
        if (f == mm::kNullFrame)
        {
            // OOM partway through — frames already mapped stay
            // mapped but their VA is unreachable to the caller.
            // Bump cursor anyway so stranded VAs are never reused
            // (simpler than unwinding; v0 accepts the leak).
            proc->vmap_pages_used += i;
            arch::SerialWrite("[sys] vmap partial-oom pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" mapped=");
            arch::SerialWriteHex(i);
            arch::SerialWrite("/");
            arch::SerialWriteHex(pages);
            arch::SerialWrite("\n");
            KLOG_ERROR_2V("win32/vmap", "DoVmap: partial-OOM (frames stranded)", "mapped", i, "wanted", pages);
            frame->rax = 0;
            return;
        }
        mm::AddressSpaceMapUserPage(proc->as, base + i * mm::kPageSize, f,
                                    mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
    }
    proc->vmap_pages_used += pages;
    arch::SerialWrite("[sys] vmap ok pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" va=");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" pages=");
    arch::SerialWriteHex(pages);
    arch::SerialWrite("\n");
    KLOG_INFO_2V("win32/vmap", "DoVmap: ok", "va", base, "pages", pages);
    frame->rax = base;
}

void DoVunmap(arch::TrapFrame* frame)
{
    // v0: no-op with a range-validity check. A bump-only arena
    // can't free individual regions without turning into a real
    // allocator, so VirtualFree is documented as a leak.
    KLOG_TRACE_V("win32/vmap", "DoVunmap: va", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/vmap", "DoVunmap: no current Process");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 va = frame->rdi;
    const u64 arena_end = proc->vmap_base + core::Process::kWin32VmapCapPages * mm::kPageSize;
    if (va < proc->vmap_base || va >= arena_end)
    {
        KLOG_WARN_V("win32/vmap", "DoVunmap: VA outside arena", va);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
    KLOG_ONCE_INFO("win32/vmap", "DoVunmap: v0 leaks (no per-region free)");
}

} // namespace duetos::subsystems::win32
