#pragma once

#include "util/types.h"
#include "mm/frame_allocator.h"

/*
 * DuetOS managed page-table API — v0.
 *
 * Sits on top of the boot PML4 installed by boot.S. Adds 4 KiB-granular
 * mapping for kernel virtual addresses outside the static higher-half
 * direct map, and a kernel MMIO virtual arena for device drivers that
 * need to address registers above 1 GiB of physical RAM (LAPIC at
 * 0xFEE00000, IOAPIC at 0xFEC00000, PCIe BARs, etc.).
 *
 * Memory layout (kernel virtual address space):
 *
 *   0x0000000000000000 .. 0x0000000040000000   identity map (1 GiB, boot only)
 *   ...                                          (low half — userland later)
 *   0xFFFFFFFF80000000 .. 0xFFFFFFFFC0000000   higher-half direct map (1 GiB)
 *   0xFFFFFFFFC0000000 .. 0xFFFFFFFFE0000000   kernel MMIO arena (512 MiB)
 *   0xFFFFFFFFE0000000 .. 0xFFFFFFFFFFFFFFFF   reserved for future use
 *
 * Scope limits that will be fixed in later commits:
 *   - Single global PML4 (the one boot.S installed). No per-process address
 *     spaces yet.
 *   - Cannot remap or split a 2 MiB PS-mapped region — those are the boot
 *     direct map and any attempt to MapPage inside [0..1 GiB] panics.
 *   - Not thread-safe. SMP bring-up will add a mutex. Page-table
 *     manipulation under a spinlock would be too much for v0; the heap
 *     thread-safety story will set the precedent.
 *   - Bump-allocator MMIO arena. UnmapMmio frees the page tables but does
 *     NOT reclaim the virtual range. Fragmentation is bounded by total
 *     driver lifetime, which is "forever" for the boot devices we care
 *     about — fine until proven otherwise.
 *
 * Context: kernel. Init runs once after KernelHeapInit. MapPage/UnmapPage
 * are then safe from any kernel code that is NOT in IRQ context.
 */

namespace duetos::mm
{

/// Page-table entry flags (Intel SDM Vol. 3A §4.5).
enum PageFlags : u64
{
    kPagePresent = 1ULL << 0,
    kPageWritable = 1ULL << 1,
    kPageUser = 1ULL << 2,
    kPageWriteThru = 1ULL << 3,
    kPageCacheDisable = 1ULL << 4,
    kPageAccessed = 1ULL << 5,
    kPageDirty = 1ULL << 6,
    kPageHugeOrPat = 1ULL << 7, // PS in PDE/PDPTE; PAT in PTE
    kPageGlobal = 1ULL << 8,
    kPageNoExecute = 1ULL << 63, // requires EFER.NXE (set by us in PagingInit)
};

/// Convenience flag bundles for common kernel uses.
inline constexpr u64 kKernelData = kPagePresent | kPageWritable | kPageNoExecute;
inline constexpr u64 kKernelMmio = kPagePresent | kPageWritable | kPageCacheDisable | kPageNoExecute;
inline constexpr u64 kKernelCode = kPagePresent; // RO + executable

/// Base of the kernel MMIO arena. Distinct from the direct map so that
/// MMIO mappings never collide with (or are overwritten by) direct-map
/// addresses, and so that drivers can sanity-check "this is an MMIO
/// pointer" cheaply with a range comparison.
inline constexpr uptr kMmioArenaBase = 0xFFFFFFFFC0000000ULL;
inline constexpr u64 kMmioArenaBytes = 512ULL * 1024 * 1024;

/// Adopt the boot PML4, enable EFER.NXE so PageNoExecute mappings are
/// honoured, and prime internal bookkeeping. Panics on failure.
void PagingInit();

/// Boot PML4 — installed by boot.S and adopted by PagingInit. Exposed
/// for `mm::AddressSpace` so it can copy the kernel-half PML4 entries
/// (indices 256..511) into every newly-created per-process PML4. The
/// kernel half is shared across every address space by sharing the
/// PDPT pages those entries point at, so changes deep in the kernel
/// page-table tree (new MMIO mapping, heap growth) propagate to every
/// process automatically — no shootdown needed. The constraint is
/// that nobody installs a brand-new top-level PML4 entry on the
/// kernel half AFTER the first AddressSpace has been created; today
/// nothing does (MMIO arena and direct map both live in PML4[511]).
u64* BootPml4Virt();
PhysAddr BootPml4Phys();

/// Install a 4 KiB mapping at `virt` for the given physical frame and
/// flags. `kPagePresent` is implied — callers should still pass it for
/// clarity. Allocates intermediate page tables on demand.
///
/// Panics if `virt` is already mapped, if `phys` or `virt` is not
/// 4 KiB-aligned, or if `virt` falls inside a 2 MiB-PS region (the boot
/// direct map). Returns nothing — failure is unrecoverable.
void MapPage(uptr virt, PhysAddr phys, u64 flags);

/// Remove the 4 KiB mapping at `virt`. Issues `invlpg` for the affected
/// page. Does NOT free intermediate page tables (those stay around in
/// case the next MMIO mapping wants the same PD/PT). Does NOT free the
/// physical frame — the caller owns the physical frame.
///
/// No-op (and silent) if `virt` is not currently mapped — drivers tearing
/// down on a path that may have failed mid-init shouldn't have to track
/// exactly which pages they got around to mapping.
void UnmapPage(uptr virt);

/// Map a contiguous physical region for MMIO access. Allocates a virtual
/// range out of the MMIO arena, installs `kKernelMmio` mappings for every
/// 4 KiB page, returns the base virtual address.
///
/// Returns 0 on failure (arena exhausted). `phys` is rounded down to a
/// page boundary; the returned virtual pointer is offset accordingly so
/// that `result + (phys & 0xFFF)` reaches the requested register address.
void* MapMmio(PhysAddr phys, u64 bytes);

/// Result-shaped sibling of `MapMmio`. `OutOfMemory` on arena
/// exhaustion; `InvalidArgument` if bytes is zero.
inline ::duetos::core::Result<void*> TryMapMmio(PhysAddr phys, u64 bytes)
{
    if (bytes == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    void* p = MapMmio(phys, bytes);
    if (p == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    return p;
}

/// Tear down a previous MapMmio allocation. The caller passes back the
/// virtual address MapMmio returned and the same byte count. Page tables
/// are left in place (see UnmapPage); the virtual range is not recycled.
void UnmapMmio(void* virt, u64 bytes);

/// Diagnostics counters; cheap (a couple of loads).
struct PagingStats
{
    u64 page_tables_allocated; // PML4/PDPT/PD/PT frames borrowed from the FA
    u64 mappings_installed;    // lifetime MapPage calls that succeeded
    u64 mappings_removed;      // lifetime UnmapPage calls that did anything
    u64 mmio_arena_used_bytes; // bump cursor offset from kMmioArenaBase
};
PagingStats PagingStatsRead();

/// Exercise MapMmio + write/read aliasing + UnmapMmio end-to-end. Prints
/// to COM1 and panics on inconsistency. Boot-time use only.
void PagingSelfTest();

/// Split every 2 MiB PS mapping covering the kernel image into a full
/// set of 512 4 KiB PTEs, then apply per-section W^X flags across
/// the kernel image:
///
///   .text             : R + X   (no Writable, no NoExecute)
///   .rodata           : R       (no Writable, kPageNoExecute)
///   .data / .bss      : R + W   (kPageWritable, kPageNoExecute)
///
/// This is the kernel-side W^X / DEP enforcement — the equivalent of
/// what a Windows kernel gets from PAGE_EXECUTE_READ vs. PAGE_READWRITE
/// on the kernel image. Before this runs, boot.S's 2 MiB PS direct
/// map gives every kernel byte R + W + X. After: an accidental write
/// through a kernel pointer into .text #PFs at the write site instead
/// of silently corrupting code, and a ROP chain that somehow reaches
/// a .data / .bss VA can't execute because those pages are NX.
///
/// Relies on linker-script symbols:
///   _text_start / _text_end
///   _rodata_start / _rodata_end
///   _data_start / _data_end
///   _bss_start / _bss_end
///
/// Idempotent — safe to call twice, but intended for a single call
/// at boot, after PagingInit. Panics on failure. Does NOT touch the
/// low-half identity map (.text.boot / .bss.boot) — boot.S needs
/// those identity-mapped for the bring-up code, and once kernel_main
/// has jumped to the higher half they're effectively dead code that
/// won't run again.
void ProtectKernelImage();

/// Arm the boot-stack guard page: mark the 4 KiB below `stack_bottom`
/// (boot.S `boot_stack_guard_page`) not-present so a boot-stack overflow
/// faults at the boundary instead of silently corrupting low RAM. Call once,
/// right after ProtectKernelImage, before any deep boot-time call chain.
void InstallBootStackGuard();

/// True if `fault_va` lands in the armed boot-stack guard page. The #PF
/// dispatcher uses this to turn a guard hit into a named "boot stack
/// overflow" panic. Returns false until InstallBootStackGuard has run.
bool IsBootStackGuardFault(u64 fault_va);

/// Overwrite the 4 KiB PTE flags for the page containing `virt`,
/// keeping the physical frame unchanged. Splits the parent 2 MiB
/// PS page if the range is still in the boot-time coarse mapping.
/// Always OR'd with `kPagePresent` on write; `virt` must be 4 KiB-
/// aligned and the page must already be mapped (panics otherwise).
///
/// The one legitimate caller outside of boot-time kernel-image
/// hardening is the debug subsystem: patching / unpatching 0xCC
/// int3 breakpoints into .text needs a brief W toggle. Use with
/// care — a long-lived writable .text is a W^X hole.
void SetPteFlags4K(u64 virt, u64 new_flags);

/// Read the current 4 KiB PTE flags for the page containing
/// `virt`. Walks the active PML4 down to the leaf entry. Returns
/// 0 if the address is unmapped, sits inside a 2 MiB-PS region,
/// or otherwise can't be resolved at the 4 KiB level — callers
/// that care MUST distinguish 0 from "PTE present but all flags
/// happen to be clear" by asserting `kPagePresent` in the
/// returned mask.
///
/// The runtime invariant checker uses this to baseline the
/// attribute tail of selected `.rodata` / `.text` pages at boot
/// and detect later per-page W^X flips that the global CR0.WP /
/// EFER.NXE detectors are blind to.
u64 GetPteFlags4K(u64 virt);

/// Snapshot of an x86_64 4-level page-table walk for `virt`. Filled
/// by `SnapshotPageWalk`; consumed by the crash-dump page-walk
/// emitter so a #PF dump can show *why* the access faulted (which
/// level the walk stopped at, what flags the leaf had).
///
/// Allocation-free, panic-free. Designed to be safe to call from
/// the trap dispatcher / panic path: a corrupted page-table entry
/// pointing outside the 1 GiB direct map causes `stop = OutOfDirectMap`
/// rather than a recursive fault.
enum class PageWalkStop : u8
{
    FourKiB,        // walked PML4 → PDPT → PD → PT, leaf in entry_pt
    TwoMiB,         // PD entry has PS bit, leaf in entry_pd
    OneGiB,         // PDPT entry has PS bit, leaf in entry_pdpt
    NotPresentPml4, // PML4 entry !P
    NotPresentPdpt, // PDPT entry !P
    NotPresentPd,   // PD entry !P
    NotPresentPt,   // PT entry !P
    NonCanonical,   // VA isn't canonical (bits 63..48 don't sign-extend bit 47)
    OutOfDirectMap, // intermediate-table phys addr would land outside [0..1 GiB)
};

struct PageWalkSnapshot
{
    u64 cr3;           // CR3 at the time of the walk
    u64 virt;          // queried VA
    u16 idx_pml4;      // PML4 index (bits 47..39)
    u16 idx_pdpt;      // PDPT index (bits 38..30)
    u16 idx_pd;        // PD   index (bits 29..21)
    u16 idx_pt;        // PT   index (bits 20..12)
    u64 entry_pml4;    // raw PML4E (0 if walk stopped above)
    u64 entry_pdpt;    // raw PDPTE
    u64 entry_pd;      // raw PDE
    u64 entry_pt;      // raw PTE
    u64 leaf_phys;     // resolved physical address (only meaningful when stop == FourKiB/TwoMiB/OneGiB)
    PageWalkStop stop; // where the walk stopped
};

/// Walk the active CR3's PML4 for `virt` and return a structured
/// snapshot of every level visited. NEVER allocates, NEVER panics.
/// Safe from panic / trap / IRQ context.
PageWalkSnapshot SnapshotPageWalk(u64 virt);

/*
 * User-pointer copy helpers.
 *
 * Every kernel read/write through a user-supplied pointer goes through
 * CopyFromUser / CopyToUser. They validate that the pointer lies inside
 * the canonical low half, reject overflow / boundary-crossing lengths,
 * and — when SMAP is active — gate the actual byte-by-byte copy with
 * stac / clac so the CPU's SMAP check lets through the user access
 * only inside this one helper.
 *
 * Return true on success, false if the pointer is rejected or if a
 * recoverable page fault is hit during the copy. `len == 0` is a
 * trivial no-op that returns true. Zero-byte buffers aren't an error
 * and neither is a null kernel_dst / kernel_src when len == 0.
 *
 * Fault handling contract: the helpers first validate the canonical
 * low-half range, pre-walk the caller's user PTEs, then enter the
 * assembly copy window that gates SMAP with stac/clac. Trap dispatch
 * recognises faults inside that window and rewrites RIP to the copy
 * fixup path, so syscall handlers see `false` instead of a kernel
 * panic. Partial prefixes may have been copied before a fault; callers
 * must treat the whole destination as untrusted on `false`.
 *
 * Context: kernel. Must NOT be called from interrupt context while the
 * current task isn't the one whose address space the user pointer lives
 * in (today there's only one address space, so that's trivially true;
 * the constraint lands with per-process page tables).
 */
bool CopyFromUser(void* kernel_dst, const void* user_src, u64 len);
bool CopyToUser(void* user_dst, const void* kernel_src, u64 len);

// ML-05: export the canonical user-half range predicate that CopyFromUser /
// CopyToUser already build on, so callers outside this TU (e.g. the debug
// SYS_BP_INSTALL handler) can refuse a ring-3-supplied kernel VA up front.
/// True if [addr, addr+len) lies wholly inside the canonical low (user)
/// half — strict on both ends (no overflow, no boundary crossing). A
/// `len == 0` range is trivially valid. Pointer accessibility (a present,
/// correctly-flagged PTE) is a separate check; this is the cheap bounds gate.
bool IsUserAddressRange(u64 addr, u64 len);

/// Read up to `len` bytes from `kernel_src` into `kernel_dst`,
/// surviving a #PF on the source. Returns true if all bytes
/// were copied; false if the load faulted (in which case the
/// destination buffer may contain partial data — caller must
/// not trust it).
///
/// Implemented via the same extable mechanism as CopyFromUser:
/// the load instruction is bracketed by labels and the trap
/// dispatcher redirects to a fixup that zeros rax. Cheap on
/// the happy path (one rep movsb + ret); recovery path is a
/// trap → extable scan → iretq.
///
/// Use for: peeking at an unmapped guard page during panic
/// dump, walking a pointer of unknown provenance from a debug
/// probe, reading a kernel data structure that might be in a
/// half-torn-down region. NOT for user-mode reads (those are
/// CopyFromUser — gates on SMAP + uses the current process's
/// AS view).
bool SafeReadKernel(void* kernel_dst, const void* kernel_src, u64 len);

/// Result for bounded NUL-terminated user-string copies.
enum class UserStringCopyStatus : u8
{
    Ok,
    BadArgument,
    Fault,
    NoTerminator,
};

struct UserStringCopyResult
{
    UserStringCopyStatus status;
    // Ok: characters copied before the NUL terminator.
    // NoTerminator: characters copied/probed before the bounded stop.
    // Fault: characters copied before the faulting probe.
    u64 length;

    constexpr bool ok() const { return status == UserStringCopyStatus::Ok; }
};

/// Copy a NUL-terminated 8-bit user string into `kernel_dst`.
///
/// `dst_cap` is the total destination capacity including the terminator.
/// When `kernel_dst != nullptr` and `dst_cap > 0`, the destination is
/// NUL-filled up front so it is safe to log/debug-print even on failure.
/// Unlike fixed-size
/// CopyFromUser, this probes one character at a time and stops at the
/// first NUL; a short string at the end of a mapped page therefore does
/// not require the following page to be mapped.
UserStringCopyResult CopyUserCString(char* kernel_dst, u64 dst_cap, const void* user_src);

/// Copy up to `dst_cap - 1` user characters and always append a kernel
/// terminator. NoTerminator means the user string was truncated cleanly,
/// not that the copy faulted. Intended for diagnostic surfaces whose ABI
/// is explicitly bounded/truncating.
UserStringCopyResult CopyUserCStringTruncating(char* kernel_dst, u64 dst_cap, const void* user_src);

/// UTF-16LE sibling of CopyUserCString. `dst_cap` is in u16 code units,
/// including the terminator. No UTF validation is performed here; callers
/// decide how to interpret non-ASCII or surrogate code units.
UserStringCopyResult CopyUserString16(u16* kernel_dst, u64 dst_cap, const void* user_src);

/// UTF-16LE sibling of CopyUserCStringTruncating.
UserStringCopyResult CopyUserString16Truncating(u16* kernel_dst, u64 dst_cap, const void* user_src);

/// Per-CPU kernel-protection bit setup: CR0.WP + CR4.SMEP + CR4.SMAP
/// + CET/IBT (where CPUID reports support). Called once from the BSP
/// inside PagingInit, and ONCE PER AP from ApEntryFromTrampoline.
///
/// Before this fix existed, `EnableKernelProtectionBits` ran only on
/// the BSP, leaving every AP with CR4 unchanged from the SMP-trampoline
/// state (typically just PAE | OSFXSR | OSXMMEXCPT). The release-build
/// observation on `claude/assembly-files-review-ju0dI` showed cpu#2
/// with CR4=0x620 (no SMEP, no SMAP) at fault time — confirming the
/// gap. Per-CPU CR4 bits MUST be programmed on each CPU; there is no
/// architectural broadcast.
///
/// The function reads CPUID leaf-7 each call, so a homogeneous SMP
/// system converges every CPU to the same protection posture. It is
/// idempotent: repeat calls re-OR the same bits and write CR4 only
/// when something changed.
void EnableKernelProtectionBitsForThisCpu(bool emit_log);

} // namespace duetos::mm
