/*
 * DuetOS kernel hot-patch — atomic redirection of kernel
 * functions via a 5-byte JMP rel32 overlay over the
 * patchable_function_entry NOP. See hot_patch.h for the
 * contract.
 *
 * Layout per patch:
 *
 *   target_va:  E9 <rel32>            ; JMP replacement
 *               <body of target...>
 *   replacement_va: <body of replacement, returns to target's caller>
 *
 * The 5-byte multi-byte NOP that the attribute reserves at
 * target_va is `0F 1F 44 00 08` (nopl 8(%rax,%rax,1)). Revert
 * writes it back byte-for-byte from the saved record.
 */

#include "debug/hot_patch.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "util/symbols.h"

extern "C"
{
    extern const duetos::core::SymbolEntry g_duetos_symtab_entries[];
    extern const duetos::u64 g_duetos_symtab_count;
    // Bulk-apply registry bounds — emitted by the linker (see
    // kernel/arch/x86_64/linker.ld:.duetos_hotpatch_pairs).
    // Empty when no TU has used KHOTPATCH_REGISTER_PAIR, in which
    // case start == end and HotPatchApplyAll is a no-op.
    extern const duetos::debug::HotPatchPair __duetos_hotpatch_pairs_start[];
    extern const duetos::debug::HotPatchPair __duetos_hotpatch_pairs_end[];
}

namespace duetos::debug
{

namespace
{

// Single global lock guarding the patch table + the W-window
// PTE flip. Held only while a single patch install / revert is
// in flight; never across a sleep. Implemented as a plain
// boolean because the v0 patch path runs in single-CPU context
// (boot self-test) or under operator control (admin shell);
// when SMP-safe hot-patching lands, this turns into a real
// spinlock.
bool g_lock_held = false;

HotPatchRecord g_patches[kMaxLivePatches];
u32 g_next_id = 1;

// The 5-byte multi-byte NOP that `patchable_function_entry(5, 0)`
// emits. Recognised as the "this function is patchable" sentinel.
// Anything else at target_va[0..5) is rejected (NotPatchable).
constexpr u8 kPatchableNop[5] = {0x0F, 0x1F, 0x44, 0x00, 0x08};

constexpr u8 kJmpOpcode = 0xE9;

// Lower / upper bounds of the kernel symbol table for the
// "address is inside known kernel text" check. Computed lazily
// on first call so we don't need a separate init pass.
struct SymBounds
{
    u64 lo;
    u64 hi;
    bool ready;
};
SymBounds g_symbounds{0, 0, false};

void EnsureSymBounds()
{
    if (g_symbounds.ready)
        return;
    if (g_duetos_symtab_count == 0)
    {
        // Stage-1 stub symbol table — accept any address; the
        // self-test running before stage-2 link wouldn't get
        // this far anyway. The operator path resolves names via
        // the symbol table, which is empty in stage 1, so the
        // by-name installer is a no-op in stage 1.
        g_symbounds.lo = 0;
        g_symbounds.hi = ~u64{0};
        g_symbounds.ready = true;
        return;
    }
    u64 lo = ~u64{0};
    u64 hi = 0;
    for (u64 i = 0; i < g_duetos_symtab_count; ++i)
    {
        const auto& e = g_duetos_symtab_entries[i];
        if (e.addr < lo)
            lo = e.addr;
        const u64 end = e.addr + (e.size == 0 ? 1 : e.size);
        if (end > hi)
            hi = end;
    }
    g_symbounds.lo = lo;
    g_symbounds.hi = hi;
    g_symbounds.ready = true;
}

bool AddressInKernelText(u64 va)
{
    EnsureSymBounds();
    return va >= g_symbounds.lo && va < g_symbounds.hi;
}

bool BytesEq(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

HotPatchRecord* FindRecordByTarget(u64 target_va)
{
    for (auto& r : g_patches)
    {
        if (r.id != 0 && r.target_va == target_va)
            return &r;
    }
    return nullptr;
}

HotPatchRecord* FindRecordById(u32 id)
{
    if (id == 0)
        return nullptr;
    for (auto& r : g_patches)
    {
        if (r.id == id)
            return &r;
    }
    return nullptr;
}

HotPatchRecord* AllocRecord()
{
    for (auto& r : g_patches)
    {
        if (r.id == 0)
            return &r;
    }
    return nullptr;
}

// Resolve `va` to a name via the embedded symbol table. Returns
// "??" when the symbol can't be resolved (stage-1 build, or VA
// outside the table). The returned pointer is owned by .rodata.
const char* ResolveName(u64 va)
{
    duetos::core::SymbolResolution res{};
    if (!duetos::core::ResolveAddress(va, &res) || res.entry == nullptr || res.entry->name == nullptr)
        return "??";
    return res.entry->name;
}

bool StrEqC(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

// Reverse lookup: name → address. Linear scan of the symbol
// table (~7500 entries, microseconds at boot). Returns 0 on
// miss.
u64 ResolveSymbolByName(const char* name)
{
    if (name == nullptr || name[0] == '\0')
        return 0;
    if (g_duetos_symtab_count == 0)
        return 0;
    for (u64 i = 0; i < g_duetos_symtab_count; ++i)
    {
        const auto& e = g_duetos_symtab_entries[i];
        if (e.name != nullptr && StrEqC(e.name, name))
            return e.addr;
    }
    return 0;
}

// Walk the caller's RBP frame chain and refuse if any saved RIP
// falls within [target, target+5). Bounded to 64 frames so a
// corrupted RBP can't loop. Returns true if the patch is safe
// to apply against the caller's own context.
bool CallerNotInTarget(u64 target_va)
{
    const u64 lo = target_va;
    const u64 hi = target_va + 5;
    u64 rbp = 0;
    asm volatile("mov %%rbp, %0" : "=r"(rbp));
    for (u32 i = 0; i < 64 && rbp != 0; ++i)
    {
        const u64 saved_rip = *reinterpret_cast<u64*>(rbp + 8);
        if (saved_rip >= lo && saved_rip < hi)
            return false;
        const u64 next_rbp = *reinterpret_cast<u64*>(rbp);
        if (next_rbp <= rbp) // sentinel / corrupt
            break;
        rbp = next_rbp;
    }
    return true;
}

// Flip the target page writable, splat the 5 bytes, mfence,
// flip back. Mirrors `debug::breakpoints::PokeByte` exactly —
// the single-CPU contract is the same.
void PokeFiveBytes(u64 va, const u8 bytes[5])
{
    const u64 page = va & ~0xFFFULL;
    const u64 saved = duetos::mm::GetPteFlags4K(page);
    duetos::mm::SetPteFlags4K(page, duetos::mm::kPagePresent | duetos::mm::kPageWritable);
    auto* dst = reinterpret_cast<volatile u8*>(va);
    for (u32 i = 0; i < 5; ++i)
        dst[i] = bytes[i];
    asm volatile("mfence" ::: "memory");
    // Restore original flags if we were able to read them
    // sensibly; otherwise fall back to plain R+X. The saved
    // value is 0 on stage-1 / 2-MiB-PS regions, but
    // ProtectKernelImage runs before this code is ever
    // reachable.
    const u64 restore_flags =
        (saved & duetos::mm::kPagePresent) ? (saved & ~duetos::mm::kPageWritable) : duetos::mm::kPagePresent;
    duetos::mm::SetPteFlags4K(page, restore_flags);
}

void BuildJmpRel32(i32 rel32, u8 out[5])
{
    out[0] = kJmpOpcode;
    out[1] = static_cast<u8>(rel32 & 0xFF);
    out[2] = static_cast<u8>((rel32 >> 8) & 0xFF);
    out[3] = static_cast<u8>((rel32 >> 16) & 0xFF);
    out[4] = static_cast<u8>((rel32 >> 24) & 0xFF);
}

// ---------------------------------------------------------------
// Self-test fixtures. Two patchable targets and one
// replacement — exercised end-to-end by HotPatchSelfTest. Public
// linkage (not in the anon namespace) so a future operator
// invocation can resolve them by name.
// ---------------------------------------------------------------
} // namespace

KHOTPATCH_PATCHABLE int HotPatchTestTargetReturns7()
{
    return 7;
}

KHOTPATCH_PATCHABLE int HotPatchTestReplacementReturns42()
{
    return 42;
}

namespace
{

// Volatile function-pointer indirection prevents the optimiser
// from constant-folding through the call after it sees the
// inlined body. Without this, clang -O2 sees that
// HotPatchTestTargetReturns7 returns 7 and replaces the call
// site with a literal 7 — which would compare equal after the
// patch even though the new bytes never ran.
using TestFn = int (*)();
volatile TestFn g_test_target_indirect = &HotPatchTestTargetReturns7;

int CallTestTargetIndirect()
{
    return g_test_target_indirect();
}

} // namespace

const char* HotPatchStatusName(HotPatchStatus s)
{
    switch (s)
    {
    case HotPatchStatus::Ok:
        return "Ok";
    case HotPatchStatus::BadTarget:
        return "BadTarget";
    case HotPatchStatus::BadReplacement:
        return "BadReplacement";
    case HotPatchStatus::OutOfRange:
        return "OutOfRange";
    case HotPatchStatus::NotPatchable:
        return "NotPatchable";
    case HotPatchStatus::AlreadyPatched:
        return "AlreadyPatched";
    case HotPatchStatus::SlotTableFull:
        return "SlotTableFull";
    case HotPatchStatus::SelfReferential:
        return "SelfReferential";
    case HotPatchStatus::UnknownSymbol:
        return "UnknownSymbol";
    case HotPatchStatus::InvalidHandle:
        return "InvalidHandle";
    }
    return "??";
}

HotPatchStatus HotPatchInstall(u64 target_va, u64 replacement_va, HotPatchHandle* out)
{
    if (out != nullptr)
        out->id = 0;

    if (!AddressInKernelText(target_va))
        return HotPatchStatus::BadTarget;
    if (!AddressInKernelText(replacement_va))
        return HotPatchStatus::BadReplacement;

    // Range check the rel32 displacement before touching anything.
    // After the JMP, RIP advances 5 bytes past target_va, so the
    // displacement is relative to (target_va + 5).
    const i64 displacement = static_cast<i64>(replacement_va) - static_cast<i64>(target_va + 5);
    constexpr i64 kI32Min = -(i64{1} << 31);
    constexpr i64 kI32Max = (i64{1} << 31) - 1;
    if (displacement < kI32Min || displacement > kI32Max)
        return HotPatchStatus::OutOfRange;

    // Refuse a double-install: revert is the documented way to
    // change targets. Without this guard a second install would
    // save the JMP-rel32 from the first install as "original
    // bytes" and revert would put the JMP back instead of the
    // real NOP.
    if (FindRecordByTarget(target_va) != nullptr)
        return HotPatchStatus::AlreadyPatched;

    // Verify the patchability sentinel — the first 5 bytes must
    // be the multi-byte NOP that KHOTPATCH_PATCHABLE emits.
    auto* target_bytes = reinterpret_cast<const u8*>(target_va);
    if (!BytesEq(target_bytes, kPatchableNop, 5))
        return HotPatchStatus::NotPatchable;

    if (!CallerNotInTarget(target_va))
        return HotPatchStatus::SelfReferential;

    HotPatchRecord* rec = AllocRecord();
    if (rec == nullptr)
        return HotPatchStatus::SlotTableFull;

    g_lock_held = true;

    // Save the original prologue BEFORE we splat the JMP so
    // revert can put it back exactly.
    for (u32 i = 0; i < 5; ++i)
        rec->original_bytes[i] = target_bytes[i];

    u8 jmp_bytes[5];
    BuildJmpRel32(static_cast<i32>(displacement), jmp_bytes);
    PokeFiveBytes(target_va, jmp_bytes);

    rec->id = g_next_id++;
    if (g_next_id == 0) // wrap — 0 is reserved
        g_next_id = 1;
    rec->target_va = target_va;
    rec->replacement_va = replacement_va;
    rec->install_tick = 0; // scheduler tick wired by the shell command; v0 keeps the field for forward-compat
    rec->target_name = ResolveName(target_va);
    rec->replacement_name = ResolveName(replacement_va);

    g_lock_held = false;

    KLOG_INFO_S("hot-patch", "installed", "target", rec->target_name);

    if (out != nullptr)
        out->id = rec->id;
    return HotPatchStatus::Ok;
}

HotPatchStatus HotPatchInstallByName(const char* target_name, const char* replacement_name, HotPatchHandle* out)
{
    const u64 target_va = ResolveSymbolByName(target_name);
    const u64 replacement_va = ResolveSymbolByName(replacement_name);
    if (target_va == 0 || replacement_va == 0)
        return HotPatchStatus::UnknownSymbol;
    return HotPatchInstall(target_va, replacement_va, out);
}

HotPatchStatus HotPatchRevert(HotPatchHandle h)
{
    HotPatchRecord* rec = FindRecordById(h.id);
    if (rec == nullptr)
        return HotPatchStatus::InvalidHandle;

    if (!CallerNotInTarget(rec->target_va))
        return HotPatchStatus::SelfReferential;

    g_lock_held = true;
    PokeFiveBytes(rec->target_va, rec->original_bytes);
    KLOG_INFO_S("hot-patch", "reverted", "target", rec->target_name);
    rec->id = 0;
    rec->target_va = 0;
    rec->replacement_va = 0;
    rec->target_name = nullptr;
    rec->replacement_name = nullptr;
    g_lock_held = false;

    return HotPatchStatus::Ok;
}

u32 HotPatchEnumerate(HotPatchRecord* out, u32 cap)
{
    u32 n = 0;
    for (const auto& r : g_patches)
    {
        if (r.id == 0)
            continue;
        if (out != nullptr && n < cap)
            out[n] = r;
        ++n;
    }
    return n;
}

bool HotPatchSelfTest()
{
    using duetos::arch::SerialWrite;

    // 1. Baseline — the indirect call routes through the
    //    pre-patch target and returns 7.
    int before = CallTestTargetIndirect();
    if (before != 7)
    {
        SerialWrite("[hot-patch] FAIL baseline (target returned wrong value)\n");
        return false;
    }

    // 2. Install the patch from target -> replacement.
    HotPatchHandle h{};
    const auto inst = HotPatchInstall(reinterpret_cast<u64>(&HotPatchTestTargetReturns7),
                                      reinterpret_cast<u64>(&HotPatchTestReplacementReturns42), &h);
    if (inst != HotPatchStatus::Ok)
    {
        SerialWrite("[hot-patch] FAIL install: ");
        SerialWrite(HotPatchStatusName(inst));
        SerialWrite("\n");
        return false;
    }
    if (h.id == 0)
    {
        SerialWrite("[hot-patch] FAIL install returned zero handle\n");
        return false;
    }

    // 3. Post-patch — the indirect call should now route through
    //    the replacement and return 42. The volatile indirection
    //    forces the call to materialise (no constant-folding).
    int after_patch = CallTestTargetIndirect();
    if (after_patch != 42)
    {
        SerialWrite("[hot-patch] FAIL post-patch (got wrong value)\n");
        (void)HotPatchRevert(h); // best-effort cleanup
        return false;
    }

    // 4. Revert and verify.
    const auto rev = HotPatchRevert(h);
    if (rev != HotPatchStatus::Ok)
    {
        SerialWrite("[hot-patch] FAIL revert: ");
        SerialWrite(HotPatchStatusName(rev));
        SerialWrite("\n");
        return false;
    }

    int after_revert = CallTestTargetIndirect();
    if (after_revert != 7)
    {
        SerialWrite("[hot-patch] FAIL post-revert (target did not return to original)\n");
        return false;
    }

    // 5. Double-revert must report InvalidHandle (slot has been
    //    cleared; the handle no longer matches anything live).
    const auto rev2 = HotPatchRevert(h);
    if (rev2 != HotPatchStatus::InvalidHandle)
    {
        SerialWrite("[hot-patch] FAIL double-revert did not return InvalidHandle\n");
        return false;
    }

    SerialWrite("[hot-patch] PASS install/replace/revert/double-revert round-trip\n");
    return true;
}

HotPatchBulkResult HotPatchApplyAll()
{
    HotPatchBulkResult r{};
    const auto* p = __duetos_hotpatch_pairs_start;
    const auto* end = __duetos_hotpatch_pairs_end;
    for (; p < end; ++p)
    {
        ++r.considered;
        const u64 target_va = reinterpret_cast<u64>(p->target);
        const u64 replacement_va = reinterpret_cast<u64>(p->replacement);
        // Already-live targets aren't an error — bulk apply is
        // idempotent. The caller may have hand-patched one of
        // these via `live-update kernel-patch` already.
        if (target_va == 0 || replacement_va == 0)
        {
            ++r.failed;
            continue;
        }
        HotPatchHandle h{};
        const auto st = HotPatchInstall(target_va, replacement_va, &h);
        if (st == HotPatchStatus::Ok)
            ++r.installed;
        else if (st == HotPatchStatus::AlreadyPatched)
            ++r.already_patched;
        else
            ++r.failed;
    }
    return r;
}

HotPatchRevertAllResult HotPatchRevertAll()
{
    HotPatchRevertAllResult r{};
    // Snapshot first so the iteration order is stable even as we
    // mutate the underlying records.
    HotPatchRecord rows[kMaxLivePatches];
    const u32 n = HotPatchEnumerate(rows, kMaxLivePatches);
    r.considered = n;
    for (u32 i = 0; i < n; ++i)
    {
        const HotPatchHandle h{rows[i].id};
        const auto st = HotPatchRevert(h);
        if (st == HotPatchStatus::Ok)
            ++r.reverted;
        else
            ++r.failed;
    }
    return r;
}

// Register the in-TU self-test pair into the bulk-apply
// registry. Gives the operator a non-empty
// `live-update kernel-auto-patch` out of the box and ensures
// the section / linker-symbol plumbing always has at least one
// entry to walk — no special-casing the empty-section path.
KHOTPATCH_REGISTER_PAIR("hot-patch-selftest", HotPatchTestTargetReturns7, HotPatchTestReplacementReturns42)

} // namespace duetos::debug
