#include "diag/fix_journal.h"

#include "debug/probes.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "time/timekeeper.h"
#include "util/result.h"
#include "util/string.h"
#include "util/symbols.h"
#include "util/types.h"

/*
 * Fix journal — implementation.
 *
 * Storage:
 *   - g_ring: fixed-stride array of FixRecord. Indexed mod-capacity.
 *   - g_used: number of slots currently occupied (<= capacity).
 *   - g_next_seq: monotonic sequence counter assigned at intern time.
 *   - g_lock: SpinLock guarding the ring + counters. Held only over
 *     the linear-scan + memcpy inside intern; never across logs or
 *     allocations. No probe / klog calls happen with the lock held.
 *
 * Dedup:
 *   - Linear scan keyed on (detector, source_pin). 1024 entries is
 *     small enough that this is dominated by the 40-byte string
 *     compare; nowhere near a hot path.
 *
 * Wrap behaviour:
 *   - First overflow drops new records (records_dropped++) rather
 *     than evicting old ones. The reviewer wants the *first* hit
 *     of a gap, not the most recent — old gaps are the high-value
 *     audit trail. Existing records can still bump repeat_count.
 *   - A future slice may switch to LRU eviction; today the bound
 *     is generous enough that wrap should be a regression signal.
 *
 * Trap path:
 *   - g_trap_pending: single per-CPU slot (single-CPU at v0 — when
 *     SMP lands this becomes a small per-CPU array). Trap context
 *     can write the slot non-atomically; the heartbeat-side drain
 *     reads, clears, and routes through the normal recorder.
 *
 * Threading note: this module does NOT depend on time::MonotonicNs
 * being live. If MonotonicNs is called pre-init it returns 0 (per
 * the time-keeper contract) and the records will all carry ts_ns=0
 * — fine, the seq is still monotonic.
 */

namespace duetos::diag
{

namespace
{

// Fixed in-RAM ring. .bss-resident; zero-initialized at boot.
::duetos::sync::SpinLock g_lock{};
FixRecord g_ring[kFixJournalCapacity] = {};
u64 g_used = 0;
u32 g_next_seq = 1; // 0 reserved for "unassigned" in test asserts
FixJournalStats g_stats = {};
bool g_inited = false;

// Trap-deferred slot. Writes are non-atomic from trap context; the
// drain reads then clears. v0 carries one slot total — extend to
// per-CPU when SMP lands.
struct TrapPending
{
    u8 valid;       // 0/1; only writer is the trap site, only reader is drain
    u8 detector;    // FixDetector cast
    u64 ctx_a;      // detector-specific (TrapCapture: (vector<<32) | err_code)
    u64 ctx_b;      // detector-specific (TrapCapture: faulting addr / CR2)
    u64 caller_rip; // for the eventual record
};
TrapPending g_trap_pending = {};

// Format an unsigned hex value into `dst` starting at `cursor`,
// without leading zeros, capped at `cap`. Returns the new cursor.
// Used to render `+0xOFF` suffixes in auto-derived source_pins.
u64 AppendHex(char* dst, u64 cursor, u64 cap, u64 value)
{
    if (cursor >= cap)
        return cursor;
    if (value == 0)
    {
        dst[cursor++] = '0';
        return cursor;
    }
    char tmp[16];
    int n = 0;
    while (value != 0 && n < 16)
    {
        const u8 nib = static_cast<u8>(value & 0xF);
        tmp[n++] = static_cast<char>(nib < 10 ? ('0' + nib) : ('a' + nib - 10));
        value >>= 4;
    }
    for (int i = n - 1; i >= 0 && cursor < cap; --i)
    {
        dst[cursor++] = tmp[i];
    }
    return cursor;
}

// Build a pin of the form `func+0xOFF` from a caller rip. Returns
// true if the rip resolved to a known symbol. Output is NUL-
// terminated within `cap`. Used as a fallback when the recorder
// site supplies no source_pin.
bool BuildAutoPin(char* dst, u64 cap, u64 caller_rip)
{
    if (dst == nullptr || cap == 0)
        return false;
    dst[0] = '\0';
    ::duetos::core::SymbolResolution res{};
    if (!::duetos::core::ResolveAddress(caller_rip, &res) || res.entry == nullptr)
        return false;
    const char* name = res.entry->name != nullptr ? res.entry->name : "?";
    u64 c = 0;
    while (c + 1 < cap && name[c] != '\0')
    {
        dst[c] = name[c];
        ++c;
    }
    if (c + 4 < cap)
    {
        dst[c++] = '+';
        dst[c++] = '0';
        dst[c++] = 'x';
        c = AppendHex(dst, c, cap - 1, res.offset);
    }
    if (c >= cap)
        c = cap - 1;
    dst[c] = '\0';
    return true;
}

// Bounded string copy with NUL termination. Always NUL-terminates
// the dest even when src is too long — the reviewer prefers a
// truncated pin over an overrun. Returns the number of bytes
// copied (excluding the NUL).
u64 CopyTruncated(char* dst, u64 dst_cap, const char* src)
{
    if (dst == nullptr || dst_cap == 0)
        return 0;
    if (src == nullptr)
    {
        dst[0] = '\0';
        return 0;
    }
    u64 i = 0;
    const u64 lim = dst_cap - 1;
    while (i < lim && src[i] != '\0')
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
    return i;
}

// Linear scan — returns the slot index of an existing record
// matching (detector, source_pin) or g_used (out-of-range) if no
// match. Caller must hold g_lock.
// Bounded string equality up to `cap` chars, treating a NUL on either
// side as end-of-string. Used by FindMatchLocked below because the
// ring stores pins after `CopyTruncated` (39 chars + NUL when the
// source pin was longer), and the caller still passes the full
// pre-truncation pointer. A plain StrEqual would stop at the ring's
// NUL but find a non-NUL byte in the caller's string and report
// mismatch — breaking dedup for any pin whose source-side length
// reaches the field cap.
bool PinEqualBounded(const char* a, const char* b, u64 cap)
{
    for (u64 i = 0; i < cap; ++i)
    {
        const char ca = a[i];
        const char cb = b[i];
        if (ca != cb)
            return false;
        if (ca == '\0')
            return true;
    }
    return true; // both reached the cap without diverging
}

u64 FindMatchLocked(FixDetector detector, const char* source_pin)
{
    constexpr u64 kPinCap = sizeof(g_ring[0].source_pin) - 1;
    for (u64 i = 0; i < g_used; ++i)
    {
        if (g_ring[i].detector != static_cast<u8>(detector))
            continue;
        if (PinEqualBounded(g_ring[i].source_pin, source_pin, kPinCap))
            return i;
    }
    return g_used; // sentinel: not found
}

// Core intern — assumes g_lock held. Returns the slot index of the
// resulting record (existing or newly allocated), or kFixJournalCapacity
// to signal "ring full and this would have been a new entry."
u64 InternLocked(FixDetector detector, const char* source_pin, const char* hint, u64 ctx_a, u64 ctx_b, u16 severity,
                 u64 caller_rip, u64 ts_ns, bool* out_is_new)
{
    *out_is_new = false;
    const u64 hit = FindMatchLocked(detector, source_pin);
    if (hit < g_used)
    {
        // Dedup. Bump count, leave first-seen ts/seq/rip intact.
        if (g_ring[hit].repeat_count != ~static_cast<u32>(0))
            ++g_ring[hit].repeat_count;
        ++g_stats.dedup_hits;
        ++g_stats.records_recorded;
        return hit;
    }

    if (g_used >= kFixJournalCapacity)
    {
        ++g_stats.records_dropped;
        return kFixJournalCapacity;
    }

    const u64 slot = g_used++;
    FixRecord& r = g_ring[slot];
    r.magic = kFixRecordMagic;
    r.seq = g_next_seq++;
    r.ts_ns = ts_ns;
    r.caller_rip = caller_rip;
    r.ctx_a = ctx_a;
    r.ctx_b = ctx_b;
    r.repeat_count = 1;
    r.severity = severity;
    r.detector = static_cast<u8>(detector);
    r.flags = 0;
    CopyTruncated(r.source_pin, sizeof(r.source_pin), source_pin);
    CopyTruncated(r.hint, sizeof(r.hint), hint);

    ++g_stats.records_unique;
    ++g_stats.records_recorded;
    *out_is_new = true;
    return slot;
}

::duetos::core::Result<void> RecordCommon(FixDetector detector, const char* source_pin, const char* hint, u64 ctx_a,
                                          u64 ctx_b, u16 severity, u64 caller_rip)
{
    // Auto-symbolize when the recorder supplies no pin: derive
    // `func+0xOFF` from caller_rip via the embedded symbol table.
    // Function-relative offsets are KASLR-stable (the whole image
    // shifts together), so the same call site dedups across boots.
    char auto_pin[40];
    if (source_pin == nullptr || source_pin[0] == '\0')
    {
        if (!BuildAutoPin(auto_pin, sizeof(auto_pin), caller_rip))
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        source_pin = auto_pin;
    }

    const u64 ts = ::duetos::time::MonotonicNs();

    bool is_new = false;
    u32 fired_seq = 0;
    {
        ::duetos::sync::SpinLockGuard guard(g_lock);
        const u64 slot = InternLocked(detector, source_pin, hint, ctx_a, ctx_b, severity, caller_rip, ts, &is_new);
        if (slot >= kFixJournalCapacity)
        {
            // Ring full, brand-new record dropped. The drop counter
            // was bumped inside InternLocked. Surface as OutOfMemory.
            return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
        }
        fired_seq = g_ring[slot].seq;
    }

    // Probe fire OUTSIDE the lock — ProbeFire may log via klog and
    // klog has its own lock that must not nest under ours. Only
    // fire on first observation so a clean boot logs the count of
    // unique gaps without a recurring-hit firehose.
    if (is_new)
    {
        const u64 packed = (static_cast<u64>(fired_seq) << 32) | static_cast<u64>(detector);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kFixJournaled, caller_rip, packed);
    }
    return {};
}

} // namespace

const char* FixDetectorName(FixDetector d)
{
    switch (d)
    {
    case FixDetector::None:
        return "none";
    case FixDetector::StubMarker:
        return "stub";
    case FixDetector::GapMarker:
        return "gap";
    case FixDetector::UnknownSyscall:
        return "unknown_syscall";
    case FixDetector::UnmappedThunk:
        return "unmapped_thunk";
    case FixDetector::SoftFaultRecov:
        return "soft_fault_recov";
    case FixDetector::LoaderReject:
        return "loader_reject";
    case FixDetector::CapDenial:
        return "cap_denial";
    case FixDetector::TrapCapture:
        return "trap_capture";
    case FixDetector::UserFault:
        return "user_fault";
    case FixDetector::KassertFail:
        return "kassert_fail";
    case FixDetector::AutonomicProposal:
        return "autonomic_proposal";
    case FixDetector::InferredGap:
        return "inferred_gap";
    }
    return "unknown";
}

void FixJournalInit()
{
    ::duetos::sync::SpinLockGuard guard(g_lock);
    for (u64 i = 0; i < kFixJournalCapacity; ++i)
        g_ring[i] = {};
    g_used = 0;
    g_next_seq = 1;
    g_stats = {};
    g_trap_pending = {};
    g_inited = true;
    KLOG_INFO_V("diag/fix_journal", "online ring", static_cast<u64>(kFixJournalCapacity));
}

::duetos::core::Result<void> FixJournalRecord(FixDetector detector, const char* source_pin, const char* hint, u64 ctx_a,
                                              u64 ctx_b)
{
    // __builtin_return_address(0) inside this function is the rip of
    // the instruction right after the call to FixJournalRecord — i.e.
    // the detector site (the caller of FIX_NOTE_GAP / FIX_NOTE_STUB
    // / the syscall dispatcher). That's exactly the pin we want in
    // the record.
    const u64 caller = reinterpret_cast<u64>(__builtin_return_address(0));
    return RecordCommon(detector, source_pin, hint, ctx_a, ctx_b, 0, caller);
}

::duetos::core::Result<void> FixJournalRecordSev(FixDetector detector, const char* source_pin, const char* hint,
                                                 u64 ctx_a, u64 ctx_b, u16 severity)
{
    const u64 caller = reinterpret_cast<u64>(__builtin_return_address(0));
    return RecordCommon(detector, source_pin, hint, ctx_a, ctx_b, severity, caller);
}

::duetos::core::Result<void> FixJournalRecordAtCaller(FixDetector detector, const char* source_pin, const char* hint,
                                                      u64 ctx_a, u64 ctx_b, u16 severity, u64 upstream_caller_rip)
{
    // Explicit-RIP variant: skip the __builtin_return_address(0)
    // capture and use the caller-supplied rip directly. Used by
    // primitives like KMalloc / AllocateFrame whose OOM-recording
    // site is INSIDE the primitive — the standard auto-capture
    // would attribute the OOM to "KMalloc+0xOFF" instead of the
    // upstream `auto* p = KMalloc(...)` call site the reviewer
    // actually wants for an auto-generated nullcheck patch.
    return RecordCommon(detector, source_pin, hint, ctx_a, ctx_b, severity, upstream_caller_rip);
}

void FixJournalRecordFromTrap(FixDetector detector, u64 ctx_a, u64 caller_rip)
{
    // Trap-context: cannot take the SpinLock (would re-disable IRQs
    // we've already disabled) and must not log. Single-slot pending;
    // overrun overwrites — first-fault-after-drain wins and the rest
    // contribute to trap_deferred only via the count.
    g_trap_pending.detector = static_cast<u8>(detector);
    g_trap_pending.ctx_a = ctx_a;
    g_trap_pending.ctx_b = 0;
    g_trap_pending.caller_rip = caller_rip;
    g_trap_pending.valid = 1;
    ++g_stats.trap_deferred;
}

void FixJournalRecordFromTrap2(FixDetector detector, u64 ctx_a, u64 ctx_b, u64 caller_rip)
{
    // Trap-context recorder variant that also carries ctx_b. Same
    // constraints as the single-ctx form (no allocation, no klog, no
    // SpinLock acquisition). Used by TrapCapture to carry the
    // faulting-address (CR2) alongside the (vector, error_code) pack.
    g_trap_pending.detector = static_cast<u8>(detector);
    g_trap_pending.ctx_a = ctx_a;
    g_trap_pending.ctx_b = ctx_b;
    g_trap_pending.caller_rip = caller_rip;
    g_trap_pending.valid = 1;
    ++g_stats.trap_deferred;
}

void FixJournalDrainTrapPending()
{
    if (g_trap_pending.valid == 0)
        return;
    const FixDetector det = static_cast<FixDetector>(g_trap_pending.detector);
    const u64 ctx_a = g_trap_pending.ctx_a;
    const u64 ctx_b = g_trap_pending.ctx_b;
    const u64 rip = g_trap_pending.caller_rip;
    g_trap_pending.valid = 0;

    // Detector-aware source pin and hint. Trap-deferred records are
    // by definition synthesized from a single u64 of context, so
    // hints are coarse — the call-site rip in the record is the
    // useful pivot. Leaving the pin nullptr / empty drives the
    // auto-pin path in RecordCommon, which resolves `caller_rip`
    // via the embedded symbol table — that's exactly the function +
    // offset we want for trap-context faults, since "where in the
    // kernel did the fault hit" is the question every reviewer asks.
    const char* pin = "trap.deferred";
    const char* hint = "trap-context fault deferred to drain";
    if (det == FixDetector::SoftFaultRecov)
    {
        pin = "trap.recov";
        hint = "extable / canary / fixup recovered in trap";
    }
    else if (det == FixDetector::TrapCapture)
    {
        // For TrapCapture the auto-pin (`func+0xOFF`) carries more
        // signal than a fixed string would — every distinct faulting
        // site dedups separately. Force the auto-pin path.
        pin = nullptr;
        // Decode vector from ctx_a's high 32 bits for the hint.
        // Format: hint = "trap #PF" / "trap #GP" / "trap #UD" /
        // "trap #DE" / "trap vec=NN".
        const u32 vector = static_cast<u32>(ctx_a >> 32);
        switch (vector)
        {
        case 0:
            hint = "trap #DE — divide by zero";
            break;
        case 6:
            hint = "trap #UD — undefined opcode";
            break;
        case 13:
            hint = "trap #GP — general protection";
            break;
        case 14:
            hint = "trap #PF — page fault";
            break;
        default:
            hint = "trap (vector encoded in ctx_a)";
            break;
        }
    }
    else if (det == FixDetector::UserFault)
    {
        // Ring-3 RIP doesn't resolve against the kernel symbol
        // table, so the auto-pin path would just emit "?+0xRIP".
        // Use a fixed `user.fault` pin instead so dedup collapses
        // every user crash into one record — the offline brief
        // can split per task / per RIP / per PE from the captured
        // ctx fields and caller_rip.
        pin = "user.fault";
        const u32 vector = static_cast<u32>(ctx_a >> 32);
        switch (vector)
        {
        case 0:
            hint = "user trap #DE";
            break;
        case 6:
            hint = "user trap #UD";
            break;
        case 13:
            hint = "user trap #GP";
            break;
        case 14:
            hint = "user trap #PF";
            break;
        default:
            hint = "user trap (vector in ctx_a)";
            break;
        }
    }
    (void)RecordCommon(det, pin, hint, ctx_a, ctx_b, 0, rip);
}

u64 FixJournalSnapshot(FixRecord* out, u64 cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    ::duetos::sync::SpinLockGuard guard(g_lock);
    const u64 lim = (cap < g_used) ? cap : g_used;
    // Most-recent-first: walk g_used-1 down to g_used-lim.
    for (u64 i = 0; i < lim; ++i)
    {
        out[i] = g_ring[g_used - 1 - i];
    }
    return lim;
}

u64 FixJournalSnapshotPanicSafe(FixRecord* out, u64 cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    // No lock acquire — a hard crash that trapped while the
    // recorder held g_lock would otherwise deadlock here.
    // Read the count word with a single load; treat as best
    // effort. Cap to capacity in case g_used was torn mid-write.
    u64 used = g_used;
    if (used > kFixJournalCapacity)
        used = kFixJournalCapacity;
    const u64 lim = (cap < used) ? cap : used;
    for (u64 i = 0; i < lim; ++i)
    {
        out[i] = g_ring[used - 1 - i];
    }
    return lim;
}

::duetos::core::Result<void> FixJournalMarkAudited(u32 seq)
{
    ::duetos::sync::SpinLockGuard guard(g_lock);
    for (u64 i = 0; i < g_used; ++i)
    {
        if (g_ring[i].seq == seq)
        {
            g_ring[i].flags |= kFixFlagAudited;
            return {};
        }
    }
    return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
}

FixJournalStats FixJournalGetStats()
{
    // Non-locking read — counters are u64 word-aligned, single-CPU
    // for now; SMP slop of one missed increment is acceptable for a
    // diagnostic counter. Take a copy so the caller can use it
    // without holding any lock.
    return g_stats;
}

void FixJournalEmitBootSummary()
{
    // Walk the ring under the lock and tally per-detector unique
    // counts + audited count. Counters are bounded by the ring
    // capacity so the loop is O(kFixJournalCapacity) — fine to call
    // at smoke completion.
    // Sized to (highest FixDetector value + 1) so a newly-appended
    // detector is tallied without editing a hardcoded bound. Bump
    // kDetectorSlots whenever FixDetector grows past it.
    constexpr u8 kDetectorSlots = static_cast<u8>(FixDetector::AutonomicProposal) + 1;
    u64 per_detector[kDetectorSlots] = {};
    u64 audited = 0;
    {
        ::duetos::sync::SpinLockGuard guard(g_lock);
        for (u64 i = 0; i < g_used; ++i)
        {
            const u8 d = static_cast<u8>(g_ring[i].detector);
            if (d < kDetectorSlots)
                ++per_detector[d];
            if ((g_ring[i].flags & 0x01) != 0)
                ++audited;
        }
    }
    const FixJournalStats s = FixJournalGetStats();

    // Emit one structured line that grep tools (CI / dfix-monitor /
    // run-fix-cycle.sh) can pick up directly. Format:
    //   [smoke] fix_journal_summary unique=<u> recorded=<r> dropped=<d>
    //                               audited=<a>
    //                               stub=<n> gap=<n> ...
    KLOG_INFO_2V("smoke", "fix_journal_summary unique/recorded", "unique", s.records_unique, "recorded",
                 s.records_recorded);
    KLOG_INFO_2V("smoke", "fix_journal_summary dropped/audited", "dropped", s.records_dropped, "audited", audited);
    // Per-detector breakdown — six lines is verbose but trivially
    // greppable. The detector names match `FixDetectorName()` and
    // the python report's keys, so a CI script can join them.
    for (u8 d = 1; d < kDetectorSlots; ++d)
    {
        KLOG_INFO_V("smoke", FixDetectorName(static_cast<FixDetector>(d)), per_detector[d]);
    }
    // Single-line sentinel for grep convenience. Numeric-only so
    // the format is stable for parsing.
    KLOG_INFO_2V("smoke", "fix_journal_summary done", "unique", s.records_unique, "audited", audited);
}

void FixJournalSelfTest()
{
    if (!g_inited)
    {
        KLOG_ERROR("diag/fix_journal", "selftest invoked before init — calling Init() implicitly");
        FixJournalInit();
    }

    const FixJournalStats before = FixJournalGetStats();

    // Inject one record per detector kind. Use distinct source_pins
    // so dedup doesn't collapse them.
    struct Inject
    {
        FixDetector det;
        const char* pin;
        const char* hint;
    };
    const Inject injects[] = {
        {FixDetector::StubMarker, "selftest/stub.cpp:1", "stub selftest"},
        {FixDetector::GapMarker, "selftest/gap.cpp:1", "gap selftest"},
        {FixDetector::UnknownSyscall, "selftest/syscall#999", "unknown syscall selftest"},
        {FixDetector::UnmappedThunk, "selftest!ThunkSelftest", "thunk selftest"},
        {FixDetector::SoftFaultRecov, "selftest/recov.cpp:1", "soft fault selftest"},
        {FixDetector::LoaderReject, "selftest/loader.cpp:1", "loader selftest"},
        {FixDetector::CapDenial, "selftest/cap.SelftestCap", "cap denial selftest"},
        {FixDetector::TrapCapture, "selftest/trap.cpp:1", "trap capture selftest"},
        {FixDetector::UserFault, "selftest/user.task#0", "user fault selftest"},
        {FixDetector::KassertFail, "selftest/assert.subsys", "kassert selftest"},
        {FixDetector::AutonomicProposal, "selftest/env.policy", "autonomic proposal selftest"},
    };
    constexpr u64 kInjects = sizeof(injects) / sizeof(injects[0]);

    for (u64 i = 0; i < kInjects; ++i)
    {
        const auto r = FixJournalRecord(injects[i].det, injects[i].pin, injects[i].hint, i, i + 100);
        if (!r.has_value())
        {
            KLOG_ERROR_V("diag/fix_journal", "selftest: record FAILED at index", i);
            ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                       reinterpret_cast<u64>(__builtin_return_address(0)), i);
            return;
        }
    }

    // Verify the unique-records counter rose by exactly kInjects.
    const FixJournalStats after_inject = FixJournalGetStats();
    if (after_inject.records_unique != before.records_unique + kInjects)
    {
        KLOG_ERROR_2V("diag/fix_journal", "selftest: unique counter mismatch", "expected",
                      before.records_unique + kInjects, "got", after_inject.records_unique);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 1);
        return;
    }

    // Fire one dedup hit — record the same StubMarker source_pin
    // again. records_unique must NOT change; dedup_hits must rise.
    const auto dup_result = FixJournalRecord(injects[0].det, injects[0].pin, injects[0].hint, 0, 0);
    const FixJournalStats after_dup = FixJournalGetStats();
    if (!dup_result.has_value() || after_dup.records_unique != after_inject.records_unique ||
        after_dup.dedup_hits != after_inject.dedup_hits + 1)
    {
        KLOG_ERROR("diag/fix_journal", "selftest: dedup did not collapse a repeat hit");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 2);
        return;
    }

    // Truncated-pin dedup: a source-side pin string at or above the
    // on-disk field cap (39 chars) gets truncated by CopyTruncated.
    // FindMatchLocked must compare against the truncated form rather
    // than diverge at the truncation boundary, otherwise a workload
    // that hits the same long-pin gap N times allocates N journal
    // slots instead of N repeat-bumps on one slot. Regression
    // 2026-05-23: the StrEqual-based match did diverge — a Linux
    // smoke generated six separate `syscall_file.cpp:DoOpe` rows
    // instead of one row with repeat=6.
    //
    // Pin chosen below is exactly 40 chars: CopyTruncated stores the
    // first 39 chars + NUL, dropping byte 39. The two pins below are
    // identical for bytes 0..38 and differ only at byte 39 — so they
    // collapse to one stored slot under correct dedup, but a naive
    // StrEqual against the caller's untruncated pointer diverges at
    // byte 39 and inserts a fresh slot for each submission.
    const char kPinCap_a[] = "selftest/trunc-dedup-cap40-pad-padpad-AY"; // 40-char source
    const char kPinCap_b[] = "selftest/trunc-dedup-cap40-pad-padpad-AZ"; // differs at index 39
    static_assert(sizeof(kPinCap_a) == sizeof(kPinCap_b), "trunc-dedup test pins must be same length");
    static_assert(sizeof(kPinCap_a) - 1 == 40, "trunc-dedup test pin must be exactly 40 chars to exercise the cap");
    const u64 trunc_unique_before = FixJournalGetStats().records_unique;
    const u64 trunc_dedup_before = FixJournalGetStats().dedup_hits;
    (void)FixJournalRecord(FixDetector::StubMarker, kPinCap_a, "trunc-dedup pin A", 0, 0);
    (void)FixJournalRecord(FixDetector::StubMarker, kPinCap_b, "trunc-dedup pin B", 0, 0);
    const FixJournalStats after_trunc = FixJournalGetStats();
    if (after_trunc.records_unique != trunc_unique_before + 1 || after_trunc.dedup_hits != trunc_dedup_before + 1)
    {
        KLOG_ERROR_2V("diag/fix_journal", "selftest: trunc-pin dedup failed", "expected_unique+1",
                      trunc_unique_before + 1, "got_unique", after_trunc.records_unique);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 7);
        return;
    }

    // Verify mark-done: pick the first injected seq from the
    // snapshot and flip its audited bit, confirm it sticks.
    // Buffer is sized to kInjects so the count grows automatically
    // when a new detector is appended above (regression 2026-05-23:
    // the buffer was a fixed 8 from when there were 8 detectors and
    // silently failed the snapshot check once the table grew to 10).
    FixRecord snap[kInjects] = {};
    const u64 n = FixJournalSnapshot(snap, kInjects);
    if (n < kInjects)
    {
        KLOG_ERROR_V("diag/fix_journal", "selftest: snapshot returned too few records, got", n);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 3);
        return;
    }
    const u32 target_seq = snap[0].seq;
    const auto mark = FixJournalMarkAudited(target_seq);
    if (!mark.has_value())
    {
        KLOG_ERROR_V("diag/fix_journal", "selftest: mark-done failed for seq", target_seq);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 4);
        return;
    }

    // Verify NotFound on a bogus seq.
    const auto miss = FixJournalMarkAudited(0); // seq 0 is reserved, never assigned
    if (miss.has_value())
    {
        KLOG_ERROR("diag/fix_journal", "selftest: mark-done returned ok on a missing seq");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 5);
        return;
    }

    // Auto-symbolize check: pass nullptr source_pin and verify the
    // record lands with a non-empty pin matching `<func>+0xOFF`
    // (or just `<func>` if offset is zero). Skips if the symbol
    // table couldn't resolve the caller (unlikely in this
    // function — it lives in well-known kernel .text).
    const u64 unique_before_auto = FixJournalGetStats().records_unique;
    const auto auto_result = FixJournalRecord(FixDetector::StubMarker, nullptr, "auto-pin selftest", 0, 0);
    const u64 unique_after_auto = FixJournalGetStats().records_unique;
    if (auto_result.has_value() && unique_after_auto == unique_before_auto + 1)
    {
        // Confirm the most-recent record carries a non-empty pin
        // — if the symbol resolver was active, BuildAutoPin filled
        // it; otherwise the record would have been rejected with
        // InvalidArgument (handled by the !has_value() branch).
        FixRecord newest[1] = {};
        if (FixJournalSnapshot(newest, 1) == 1 && newest[0].source_pin[0] == '\0')
        {
            KLOG_ERROR("diag/fix_journal", "selftest: auto-pin landed an empty source_pin");
            ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                       reinterpret_cast<u64>(__builtin_return_address(0)), 6);
            return;
        }
    }
    // If auto_result.has_value() is false, BuildAutoPin couldn't
    // resolve — that's a SKIP, not a FAIL (e.g. the symbol table
    // is the stage-1 stub that maps no addresses).

    KLOG_INFO_V("smoke", "fix_journal=ok records", FixJournalGetStats().records_unique);
}

} // namespace duetos::diag
