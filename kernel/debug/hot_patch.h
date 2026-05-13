#pragma once

#include "util/types.h"

/*
 * DuetOS kernel hot-patch — v0.
 *
 * Atomically redirects a kernel function to a replacement by
 * overwriting the target's first 5 bytes with a JMP rel32. The
 * target must be declared patchable via the KHOTPATCH_PATCHABLE
 * attribute below — that reserves a 5-byte multi-byte NOP at the
 * function entry which the patch overlays without disturbing any
 * real instruction. Reverting writes the saved NOP back.
 *
 * Why this is a v0 primitive (vs. full Linux-style livepatch):
 *
 *   - The replacement must already live inside the kernel image.
 *     v0 does not load relocatable patch objects from disk —
 *     that needs a kernel-side ELF/COFF object loader, symbol
 *     resolution, and a relocation walker, none of which exists
 *     yet. The patch caller hands two function pointers (or two
 *     symbol names) that are both already linked in.
 *   - Single-CPU patch window. The patch path mirrors the
 *     breakpoint subsystem's `PokeByte` contract: while the
 *     target page is briefly W, any OTHER CPU that fetches
 *     instructions from that page could observe a partial JMP.
 *     The boot self-test runs before SMP bring-up, so it's
 *     trivially safe. Operator-triggered patches via
 *     `live-update kernel-patch` are admin-gated and the caller
 *     is expected to know what they're doing — this is a
 *     developer primitive, not a sandboxed surface.
 *   - No stack-walk refusal for "some task is currently in
 *     the target." A v1 enhancement would walk every Task's
 *     saved RIP and refuse the patch if any frame's RIP falls
 *     in [target, target+5). For v0 we only refuse a
 *     self-patch — the caller's OWN RBP chain landing in the
 *     target — to avoid the obvious foot-gun of patching the
 *     code that is calling us.
 *
 * Safety invariants the caller MUST hold:
 *
 *   - Target was declared `KHOTPATCH_PATCHABLE` (else
 *     `NotPatchable`). The 5-byte NOP that this attribute
 *     reserves is what we overlay.
 *   - Replacement's signature is ABI-compatible with the target.
 *     A wrong-signature replacement compiles, patches, and
 *     trashes the stack at the first call — no runtime check
 *     can catch this.
 *   - Patch / revert happens from kernel task context (not from
 *     an IRQ handler). The PTE flip uses the same
 *     `mm::SetPteFlags4K` path as software breakpoints, which
 *     is task-context only.
 *
 * Context: kernel. Thread-safe under the single-CPU contract
 * documented above; the patch-table lock serialises concurrent
 * installs from different kernel tasks on the same CPU.
 */

namespace duetos::debug
{

/// Mark a kernel function as hot-patchable. Inserts a 5-byte
/// multi-byte NOP at the function entry; HotPatchInstall overlays
/// this with a `JMP rel32` to the replacement. Without this
/// attribute the function's first instruction is whatever the
/// compiler emitted (typically `push rbp; mov rbp, rsp` which is
/// 4 bytes — overlaying 5 bytes would clip the next instruction
/// and crash any in-flight execution).
///
/// `noinline` is required: an inlined patchable target has no
/// callable entry to patch.
#define KHOTPATCH_PATCHABLE __attribute__((patchable_function_entry(5, 0), noinline))

enum class HotPatchStatus : u8
{
    Ok = 0,
    BadTarget,       // target address resolves outside the kernel symbol table
    BadReplacement,  // replacement address resolves outside the kernel symbol table
    OutOfRange,      // (replacement - (target + 5)) doesn't fit in i32
    NotPatchable,    // first 5 bytes of target don't match the patchable_function_entry NOP
    AlreadyPatched,  // target already has a live patch; revert first
    SlotTableFull,   // patch registry is full (raise kMaxLivePatches if you hit this)
    SelfReferential, // caller's own return chain runs through the target — refused
    UnknownSymbol,   // by-name variant: symbol not found
    InvalidHandle,   // revert: handle is zero or no longer in use
};

const char* HotPatchStatusName(HotPatchStatus s);

/// Stable handle for a live patch. Zero is never valid.
struct HotPatchHandle
{
    u32 id;
};

/// One row of the live-patch registry. Returned by
/// HotPatchEnumerate; held internally as the source of truth
/// for revert.
struct HotPatchRecord
{
    u32 id;                  // handle.id; 0 if slot is free
    u64 target_va;           // patched function entry VA
    u64 replacement_va;      // jump destination VA
    u8 original_bytes[5];    // saved prologue (the 5-byte NOP, for revert)
    u64 install_tick;        // scheduler tick at install — for the operator's eye
    const char* target_name; // resolved via embedded symbol table at install
    const char* replacement_name;
};

/// Maximum number of simultaneously-live patches. Sized to the
/// realistic operator workflow ceiling (one or two patches at a
/// time); raise if a workflow needs more.
inline constexpr u32 kMaxLivePatches = 16;

/// Install a JMP rel32 trampoline from `target_va` to
/// `replacement_va`. Both addresses must resolve to symbols in
/// the embedded kernel symbol table; the target must carry the
/// patchable-function-entry NOP. Returns Ok and writes a non-
/// zero handle on success.
HotPatchStatus HotPatchInstall(u64 target_va, u64 replacement_va, HotPatchHandle* out);

/// Convenience overload — look up names via the embedded symbol
/// table, then call HotPatchInstall. Names must match the
/// demangled form stored in the symbol table (typically
/// "namespace::Function").
HotPatchStatus HotPatchInstallByName(const char* target_name, const char* replacement_name, HotPatchHandle* out);

/// Revert a patch installed via HotPatchInstall. Restores the
/// saved prologue bytes byte-for-byte. After this returns Ok,
/// calls to the target resume the original implementation. The
/// handle becomes InvalidHandle thereafter.
HotPatchStatus HotPatchRevert(HotPatchHandle h);

/// Snapshot the live-patch registry into `out[]`. Returns the
/// number of records written, capped at `cap`. `out` may be
/// nullptr — pass to get the count only. Safe from any task
/// context (read-only copy).
u32 HotPatchEnumerate(HotPatchRecord* out, u32 cap);

/// Boot-time self-test. Patches an in-TU test target with an
/// in-TU replacement, verifies the replacement runs, reverts,
/// verifies the original runs again. Returns true on full
/// round-trip success. Emits `[hot-patch] PASS` / `[hot-patch]
/// FAIL <reason>` on serial — symmetric with the breakpoint /
/// watchpoint / tripwire self-tests.
///
/// Must run AFTER `mm::ProtectKernelImage()` (so .text is 4 KiB-
/// granular and SetPteFlags4K can flip the W bit) and BEFORE
/// SMP bring-up (so the single-CPU patch window contract holds
/// trivially).
bool HotPatchSelfTest();

/// One registered patch pair — a (target, replacement) pair the
/// kernel knows about as a candidate for bulk auto-apply. Emitted
/// into the `.duetos_hotpatch_pairs` section via the
/// KHOTPATCH_REGISTER_PAIR macro below. The bulk applier walks
/// [__duetos_hotpatch_pairs_start, __duetos_hotpatch_pairs_end)
/// and installs every entry that isn't already live.
struct HotPatchPair
{
    void (*target)();      // target function (cast from any function-ptr type)
    void (*replacement)(); // replacement function
    const char* name;      // operator-facing tag — defaults to a __FILE__:__LINE__ literal
};

/// Register a patch pair into the bulk-apply registry. Both args
/// must be addresses of functions in the same .text image (a
/// rel32 displacement from one to the other has to fit in i32 —
/// trivially true for any kernel-to-kernel jump). Target must
/// carry the KHOTPATCH_PATCHABLE attribute.
///
/// Usage:
///
///   KHOTPATCH_REGISTER_PAIR("compositor-fast-path",
///                            CompositorDraw,
///                            CompositorDrawFast);
///
/// Resolves at link time — no runtime constructors are needed.
/// The `attribute((used))` keeps the entry through LTO and
/// `--gc-sections`, mirroring the .init_array convention.
#define KHOTPATCH_REGISTER_PAIR(tag, target_fn, replacement_fn)                                                        \
    namespace                                                                                                          \
    {                                                                                                                  \
    [[gnu::section(".duetos_hotpatch_pairs"),                                                                          \
      gnu::used]] const ::duetos::debug::HotPatchPair _khotpatch_pair_##__LINE__ = {                                   \
        reinterpret_cast<void (*)()>(&(target_fn)),                                                                    \
        reinterpret_cast<void (*)()>(&(replacement_fn)),                                                               \
        (tag),                                                                                                         \
    };                                                                                                                 \
    }

/// Bulk apply. Walks every entry in the .duetos_hotpatch_pairs
/// section and calls HotPatchInstall on each one whose target
/// isn't already patched. `installed_out` / `failed_out` may be
/// nullptr — pass either to get a structured outcome. Returns
/// the total number of pairs the section contained.
struct HotPatchBulkResult
{
    u32 considered;      // total pairs walked
    u32 installed;       // pairs that landed a fresh patch
    u32 already_patched; // pairs whose target was already live (skipped)
    u32 failed;          // pairs that HotPatchInstall rejected
};

HotPatchBulkResult HotPatchApplyAll();

/// Bulk revert. Iterates the live-patch registry and reverts
/// every live patch. Idempotent — running it twice on an
/// already-empty registry returns reverted == 0.
struct HotPatchRevertAllResult
{
    u32 considered; // live patches at entry
    u32 reverted;   // reverts that succeeded
    u32 failed;     // reverts that errored (Status != Ok)
};

HotPatchRevertAllResult HotPatchRevertAll();

} // namespace duetos::debug
