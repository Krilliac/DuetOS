#pragma once

/*
 * Win32 heap-syscall handlers — extracted from core/syscall.cpp
 * so the dispatcher is a thin router.
 *
 *   SYS_HEAP_ALLOC    (11) — rdi=size
 *   SYS_HEAP_FREE     (12) — rdi=ptr
 *   SYS_HEAP_SIZE     (14) — rdi=ptr
 *   SYS_HEAP_REALLOC  (15) — rdi=ptr, rsi=new_size
 *
 * Each Do* handler consumes a TrapFrame* and writes the Win32-
 * style result into frame->rax. Backed by the per-process first-
 * fit allocator in heap.cpp.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoHeapAlloc(arch::TrapFrame* frame);
void DoHeapFree(arch::TrapFrame* frame);
void DoHeapSize(arch::TrapFrame* frame);
void DoHeapRealloc(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
