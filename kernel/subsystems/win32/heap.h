#pragma once

#include "../../core/types.h"

/*
 * CustomOS Win32 process heap — v0.
 *
 * Per-process free-list allocator. Allocations are served out
 * of a fixed-size user-VA region mapped RW+NX when a PE with
 * imports is loaded. Every block has an 8-byte header with its
 * size; free blocks chain into a singly-linked free list whose
 * head is stored on the Process struct (kernel-side).
 *
 * Invoked from the SYS_HEAP_ALLOC / SYS_HEAP_FREE syscalls;
 * the user-mode kernel32 stubs (HeapAlloc, HeapFree, malloc,
 * free, calloc, ...) trampoline through those.
 *
 * The kernel manipulates the free list by reading/writing the
 * user-mapped heap pages through their backing physical frames
 * via PhysToVirt + AddressSpaceLookupUserFrame — same mechanism
 * the PE loader uses to patch IAT slots. No TLB manipulation.
 *
 * v0 scope:
 *   - First-fit allocation.
 *   - NO coalescing on free. Adjacent freed blocks stay
 *     separate; fragmentation is accepted.
 *   - NO heap growth: initial mapping is kWin32HeapPages pages
 *     (64 KiB), and if the free list can't satisfy a request
 *     the allocator returns 0 (Win32 semantics: HeapAlloc
 *     without HEAP_GENERATE_EXCEPTIONS returns NULL on OOM).
 *   - One heap per process. HeapCreate returns the same heap
 *     VA as GetProcessHeap; HeapDestroy is a no-op.
 *   - HeapFree(ptr) is idempotent iff ptr == 0 (Win32 contract).
 *     Double-free on a valid ptr is undefined (we leak /
 *     corrupt; same as a typical Win32 allocator in debug-off
 *     mode).
 *
 * Future work: coalesce, multi-heap, HEAP_ZERO_MEMORY flag
 * handling (currently calloc does the zeroing itself in the
 * stub).
 */

namespace customos::core
{
struct Process;
}

namespace customos::win32
{

// Fixed user VA for the heap region. Chosen to sit between the
// Win32 stubs page (0x60000000) and the PE's typical ImageBase
// (0x400000 / 0x140000000). Every process with imports gets
// its heap mapped here; the two never conflict because they're
// in separate address spaces.
inline constexpr u64 kWin32HeapVa = 0x50000000ULL;

// Pages mapped at process load. 16 × 4 KiB = 64 KiB total
// heap. Small but enough for everything hello_winapi and its
// kin want: a few KiB of allocations, no long-running growth.
inline constexpr u64 kWin32HeapPages = 16;

/// Stand up the per-process heap: allocate kWin32HeapPages
/// frames, map them RW+NX at kWin32HeapVa, seed the free list
/// as one giant free block covering the whole region, and
/// record the resulting state on `proc`. Called from PeLoad
/// after MapSection/MapHeaders for any PE with imports.
///
/// Returns true on success. On failure (frame alloc OOM or
/// mapping fails), leaves proc->heap_* at zero and returns
/// false — the caller (PeLoad) treats this as a fatal load
/// error and tears down the AS.
bool Win32HeapInit(customos::core::Process* proc);

/// Allocate `size` bytes from `proc`'s heap. Returns a user VA
/// or 0 on failure. The returned VA is 8-byte aligned and the
/// first 8 bytes of memory BEFORE the returned pointer hold
/// the allocated block's header (size in bytes, including the
/// header).
u64 Win32HeapAlloc(customos::core::Process* proc, u64 size);

/// Free a pointer previously returned by Win32HeapAlloc.
/// Silent on a null pointer (Win32 contract). Silent on an
/// out-of-range pointer too — v0 does no double-free
/// detection or arena-bounds checking beyond "VA is inside
/// [heap_base, heap_base + heap_pages * 4096)".
void Win32HeapFree(customos::core::Process* proc, u64 user_ptr);

/// Report the payload capacity in bytes of a block previously
/// returned by Win32HeapAlloc. Returns 0 for a null pointer
/// or a pointer outside the heap region. The capacity
/// reported is the rounded-up block size minus the 16-byte
/// header — callers observe the full space the allocator
/// reserved, not the original requested size. Backs Win32
/// HeapSize.
u64 Win32HeapSize(customos::core::Process* proc, u64 user_ptr);

/// Resize a heap block. Semantics mirror ucrt realloc:
///   * user_ptr == 0         -> equivalent to Win32HeapAlloc(new_size).
///   * new_size == 0         -> frees user_ptr, returns 0.
///   * new_size <= existing  -> returns user_ptr unchanged.
///   * otherwise             -> allocates a new block, copies
///                              the old payload across, frees
///                              the old block, returns the new
///                              user VA (or 0 on alloc failure,
///                              leaving user_ptr unchanged).
///
/// Not an in-place resizer — v0 has no coalescing and
/// therefore cannot grow a block into an adjacent free
/// region. The copy path walks the heap one page-chunk at
/// a time through the AS lookup used by PeekU64/PokeU64.
u64 Win32HeapRealloc(customos::core::Process* proc, u64 user_ptr, u64 new_size);

} // namespace customos::win32
