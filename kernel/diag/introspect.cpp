#include "diag/introspect.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "util/result.h"

namespace duetos::diag::introspect
{

namespace
{

// On-disk format constants — must match kernel/diag/fix_journal.h
// and the host-side gen-fix-{report,patches,trend}.py tools. These
// are duplicated rather than included because pulling in the
// persistence layer's internals just to share two structs would
// couple subsystems unnecessarily.
constexpr u32 kFixFileMagic = 0x4A584946; // 'FIXJ'
constexpr u32 kFixFileVersion = 1;
constexpr u32 kFixRecordStride = 128;
constexpr u64 kMaxRecords = 1024;

struct FixFileHeader
{
    u32 magic;
    u32 version;
    u32 count;
    u32 reserved;
};
static_assert(sizeof(FixFileHeader) == 16, "FixFileHeader layout pinned to on-disk ABI");

// All mutable state behind one lock — the introspector is touched
// from boot bring-up and from the dintro shell command on a single
// CPU at a time, but the lock keeps the contract honest if a future
// caller fires from a worker thread.
::duetos::sync::SpinLock g_lock;
PriorEntry g_prior[kPriorDigestCap] = {};
u32 g_prior_used = 0;
u32 g_prior_dropped = 0;
bool g_prior_loaded = false;
IntrospectStats g_stats = {};

// Bounded equality for source pins. Mirrors the same helper in
// fix_journal.cpp — comparing against a pin that was stored at the
// 39-char cap requires a length-bounded walk so the stored '\0'
// doesn't end the compare prematurely against the caller's longer
// string. Both sides are NUL-terminated; cap == 39 in practice.
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
    return true;
}

void CopyTruncated(char* dst, u64 dst_cap, const char* src)
{
    if (dst == nullptr || dst_cap == 0)
        return;
    u64 i = 0;
    const u64 lim = dst_cap - 1;
    while (i < lim && src != nullptr && src[i] != '\0')
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

// Read one full FAT32 file by streaming Fat32ReadAt in 256-byte
// chunks into a stack scratch buffer; invoke `each_chunk` per
// chunk. The callback returns false ONLY to indicate "stop early,
// the caller has all it needs" — that's a SUCCESS path, not a
// failure (the streamer can't distinguish). The caller validates
// success by inspecting the ctx state after the call.
bool ReadFileFully(const ::duetos::fs::fat32::Volume* v, const ::duetos::fs::fat32::DirEntry* e,
                   bool (*each_chunk)(const u8* data, u64 len, void* ctx), void* ctx)
{
    constexpr u64 kChunk = 256;
    u8 buf[kChunk];
    u64 off = 0;
    while (true)
    {
        const i64 got = ::duetos::fs::fat32::Fat32ReadAt(v, e, off, buf, kChunk);
        if (got <= 0)
            return off > 0; // ok if we read everything; false on first-read failure
        if (!each_chunk(buf, static_cast<u64>(got), ctx))
            return true; // callback signalled "stop early, I have what I need"
        off += static_cast<u64>(got);
        if (static_cast<u64>(got) < kChunk)
            return true; // short read = EOF
    }
}

// Parsing scratch passed through the Fat32 read callback. We need to
// accumulate enough bytes to cross record boundaries because
// Fat32ReadAt returns cluster-aligned chunks that don't necessarily
// match our 128-byte record stride.
struct ParseCtx
{
    u8 accum[kFixRecordStride];
    u32 accum_len;
    u32 saw_header;
    u32 expected;
    u32 records_seen;
    bool header_bad;
};

bool ConsumeRecord(const u8* rec, ParseCtx* p)
{
    // Layout matches FixRecord — see kernel/diag/fix_journal.h. The
    // offsets are part of the on-disk ABI; bumping FixFileVersion is
    // the only sanctioned way to move them.
    //
    //   off 0   u32 magic
    //   off 4   u32 seq
    //   off 8   u64 ts_ns
    //   off 16  u64 caller_rip
    //   off 24  u64 ctx_a
    //   off 32  u64 ctx_b
    //   off 40  u32 repeat_count
    //   off 44  u16 severity
    //   off 46  u8  detector
    //   off 47  u8  flags
    //   off 48  char source_pin[40]
    //   off 88  char hint[40]
    u32 magic;
    __builtin_memcpy(&magic, rec, 4);
    if (magic != kFixRecordMagic)
        return true; // torn row — skip, mirror gen-fix-* tools

    u32 repeat;
    __builtin_memcpy(&repeat, rec + 40, 4);
    u8 detector = rec[46];

    if (g_prior_used >= kPriorDigestCap)
    {
        ++g_prior_dropped;
        return true;
    }
    PriorEntry& slot = g_prior[g_prior_used++];
    slot.detector = detector;
    slot.repeat = repeat;
    char src_pin[40];
    __builtin_memcpy(src_pin, rec + 48, 40);
    src_pin[39] = '\0';
    CopyTruncated(slot.source_pin, sizeof(slot.source_pin), src_pin);
    ++p->records_seen;
    return true;
}

bool OnChunk(const u8* data, u64 len, void* ctx)
{
    ParseCtx* p = static_cast<ParseCtx*>(ctx);
    u64 cursor = 0;

    // First chunk: parse the file header. The first 16 bytes carry
    // the FIXJ header; refuse anything that doesn't match.
    if (!p->saw_header)
    {
        if (len < sizeof(FixFileHeader))
        {
            p->header_bad = true;
            return false;
        }
        FixFileHeader hdr;
        __builtin_memcpy(&hdr, data, sizeof(hdr));
        if (hdr.magic != kFixFileMagic || hdr.version != kFixFileVersion || hdr.reserved != 0 ||
            hdr.count > kMaxRecords)
        {
            p->header_bad = true;
            return false;
        }
        p->saw_header = 1;
        p->expected = hdr.count;
        cursor = sizeof(FixFileHeader);
    }

    while (cursor < len)
    {
        // Fill the accumulator up to one record stride.
        const u64 need = kFixRecordStride - p->accum_len;
        const u64 avail = len - cursor;
        const u64 take = (avail < need) ? avail : need;
        __builtin_memcpy(p->accum + p->accum_len, data + cursor, take);
        p->accum_len += static_cast<u32>(take);
        cursor += take;
        if (p->accum_len == kFixRecordStride)
        {
            ConsumeRecord(p->accum, p);
            p->accum_len = 0;
            if (p->records_seen >= p->expected)
                return false; // tell the streamer to stop early
        }
    }
    return true;
}

bool IsSelftestPin(const char* pin)
{
    if (pin == nullptr || pin[0] == '\0')
        return false;
    // Same predicate the offline tools use — the StubMarker auto-pin
    // selftest record carries "duetos::diag::FixJournalSelfTest()+0xNN".
    if (pin[0] == 's' && pin[1] == 'e' && pin[2] == 'l' && pin[3] == 'f' && pin[4] == 't' && pin[5] == 'e' &&
        pin[6] == 's' && pin[7] == 't')
    {
        return true;
    }
    // Substring "FixJournalSelfTest" or "FaultReactSelfTest".
    for (u64 i = 0; pin[i] != '\0'; ++i)
    {
        if (pin[i] == 'F' && pin[i + 1] == 'i' && pin[i + 2] == 'x' && pin[i + 3] == 'J' && pin[i + 4] == 'o' &&
            pin[i + 5] == 'u' && pin[i + 6] == 'r' && pin[i + 7] == 'n' && pin[i + 8] == 'a' && pin[i + 9] == 'l')
        {
            return true;
        }
        if (pin[i] == 'F' && pin[i + 1] == 'a' && pin[i + 2] == 'u' && pin[i + 3] == 'l' && pin[i + 4] == 't' &&
            pin[i + 5] == 'R' && pin[i + 6] == 'e' && pin[i + 7] == 'a' && pin[i + 8] == 'c' && pin[i + 9] == 't')
        {
            return true;
        }
    }
    return false;
}

} // namespace

void LoadPriorDigest()
{
    ::duetos::sync::SpinLockGuard guard(g_lock);
    if (g_prior_loaded)
    {
        return;
    }
    namespace fat = ::duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        g_stats.prior_present = 0;
        g_prior_loaded = true; // single-shot — don't keep probing
        return;
    }
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, "KERNEL.F0", &e))
    {
        g_stats.prior_present = 0;
        g_prior_loaded = true;
        return;
    }

    ParseCtx ctx = {};
    g_prior_used = 0;
    g_prior_dropped = 0;
    const bool ok = ReadFileFully(v, &e, &OnChunk, &ctx);
    if (!ok || ctx.header_bad)
    {
        g_prior_used = 0;
        g_prior_dropped = 0;
        g_stats.prior_present = 0;
        g_prior_loaded = true;
        return;
    }
    g_stats.prior_present = 1;
    g_stats.prior_loaded = g_prior_used;
    g_stats.prior_dropped = g_prior_dropped;
    g_prior_loaded = true;
    KLOG_INFO_V("diag/introspect", "prior boot digest loaded", g_prior_used);
}

namespace
{

// Find a current-ring record matching the given (detector, pin).
// Linear scan; cap = caller-provided.
bool CurrentRingHasMatch(const ::duetos::diag::FixRecord* current, u64 count, u8 detector, const char* pin,
                         u32* out_repeat)
{
    constexpr u64 kPinCap = sizeof(g_prior[0].source_pin) - 1;
    for (u64 i = 0; i < count; ++i)
    {
        if (current[i].detector != detector)
            continue;
        if (PinEqualBounded(current[i].source_pin, pin, kPinCap))
        {
            if (out_repeat != nullptr)
                *out_repeat = current[i].repeat_count;
            return true;
        }
    }
    return false;
}

bool PriorHasMatch(u8 detector, const char* pin, u32* out_repeat)
{
    constexpr u64 kPinCap = sizeof(g_prior[0].source_pin) - 1;
    for (u32 i = 0; i < g_prior_used; ++i)
    {
        if (g_prior[i].detector != detector)
            continue;
        if (PinEqualBounded(g_prior[i].source_pin, pin, kPinCap))
        {
            if (out_repeat != nullptr)
                *out_repeat = g_prior[i].repeat;
            return true;
        }
    }
    return false;
}

} // namespace

void IntrospectComputeAndLog()
{
    ::duetos::sync::SpinLockGuard guard(g_lock);

    // Snapshot the current ring into a stack buffer. kPriorDigestCap
    // is the right size for the comparison because the digest is the
    // same shape; we don't try to classify records the digest
    // couldn't hold.
    ::duetos::diag::FixRecord current[kPriorDigestCap];
    const u64 cur_count = ::duetos::diag::FixJournalSnapshot(current, kPriorDigestCap);

    u32 new_count = 0;
    u32 persistent = 0;
    u32 resolved = 0;

    for (u64 i = 0; i < cur_count; ++i)
    {
        if (IsSelftestPin(current[i].source_pin))
            continue;
        if (PriorHasMatch(current[i].detector, current[i].source_pin, nullptr))
            ++persistent;
        else
            ++new_count;
    }
    for (u32 i = 0; i < g_prior_used; ++i)
    {
        if (IsSelftestPin(g_prior[i].source_pin))
            continue;
        if (!CurrentRingHasMatch(current, cur_count, g_prior[i].detector, g_prior[i].source_pin, nullptr))
            ++resolved;
    }

    g_stats.current_total = static_cast<u32>(cur_count);
    g_stats.new_count = new_count;
    g_stats.persistent = persistent;
    g_stats.resolved = resolved;
    g_stats.last_computed += 1;

    // Structured line for log-grep + boot-log-analyze.sh — same shape
    // as `[smoke] fix_journal=ok ...` lines elsewhere. Stays at INFO.
    KLOG_INFO_2V("introspect", "delta", "new", static_cast<u64>(new_count), "persistent", static_cast<u64>(persistent));
    KLOG_INFO_V("introspect", "resolved", static_cast<u64>(resolved));
}

IntrospectStats GetStats()
{
    ::duetos::sync::SpinLockGuard guard(g_lock);
    return g_stats;
}

u64 Snapshot(DeltaEntry* out, u64 cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    ::duetos::sync::SpinLockGuard guard(g_lock);

    ::duetos::diag::FixRecord current[kPriorDigestCap];
    const u64 cur_count = ::duetos::diag::FixJournalSnapshot(current, kPriorDigestCap);

    u64 written = 0;

    // Emit NEW rows first.
    for (u64 i = 0; i < cur_count && written < cap; ++i)
    {
        if (IsSelftestPin(current[i].source_pin))
            continue;
        if (PriorHasMatch(current[i].detector, current[i].source_pin, nullptr))
            continue;
        DeltaEntry& slot = out[written++];
        slot = {};
        slot.kind = DeltaKind::New;
        slot.detector = current[i].detector;
        slot.cur_repeat = current[i].repeat_count;
        slot.prev_repeat = 0;
        CopyTruncated(slot.source_pin, sizeof(slot.source_pin), current[i].source_pin);
    }

    // Then PERSISTENT.
    for (u64 i = 0; i < cur_count && written < cap; ++i)
    {
        if (IsSelftestPin(current[i].source_pin))
            continue;
        u32 prev_repeat = 0;
        if (!PriorHasMatch(current[i].detector, current[i].source_pin, &prev_repeat))
            continue;
        DeltaEntry& slot = out[written++];
        slot = {};
        slot.kind = DeltaKind::Persistent;
        slot.detector = current[i].detector;
        slot.cur_repeat = current[i].repeat_count;
        slot.prev_repeat = prev_repeat;
        CopyTruncated(slot.source_pin, sizeof(slot.source_pin), current[i].source_pin);
    }

    // Then RESOLVED.
    for (u32 i = 0; i < g_prior_used && written < cap; ++i)
    {
        if (IsSelftestPin(g_prior[i].source_pin))
            continue;
        if (CurrentRingHasMatch(current, cur_count, g_prior[i].detector, g_prior[i].source_pin, nullptr))
            continue;
        DeltaEntry& slot = out[written++];
        slot = {};
        slot.kind = DeltaKind::Resolved;
        slot.detector = g_prior[i].detector;
        slot.cur_repeat = 0;
        slot.prev_repeat = g_prior[i].repeat;
        CopyTruncated(slot.source_pin, sizeof(slot.source_pin), g_prior[i].source_pin);
    }

    return written;
}

void IntrospectSelfTest()
{
    // Run the diff with the prior digest as it currently stands —
    // could be loaded-empty (first boot, no KERNEL.F0) or populated.
    // Either is fine for the smoke; we just assert the API answers
    // without panicking and the counters look internally consistent.
    IntrospectComputeAndLog();
    const auto s = GetStats();
    if (s.new_count + s.persistent > kPriorDigestCap)
    {
        KLOG_ERROR_V("diag/introspect", "selftest: counters exceed digest cap", s.new_count + s.persistent);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 1);
        return;
    }

    DeltaEntry rows[16] = {};
    const u64 n = Snapshot(rows, 16);
    if (n > 16)
    {
        KLOG_ERROR_V("diag/introspect", "selftest: snapshot wrote past cap, n=", n);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(__builtin_return_address(0)), 2);
        return;
    }
    // The classification is ordered: New, Persistent, Resolved.
    // Verify no row sits in the wrong slot.
    DeltaKind seen_max = DeltaKind::Unknown;
    for (u64 i = 0; i < n; ++i)
    {
        const u8 k = static_cast<u8>(rows[i].kind);
        if (k < static_cast<u8>(seen_max))
        {
            KLOG_ERROR_V("diag/introspect", "selftest: snapshot ordering violated at row", i);
            ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                       reinterpret_cast<u64>(__builtin_return_address(0)), 3);
            return;
        }
        seen_max = rows[i].kind;
    }

    ::duetos::arch::SerialWrite("[smoke] introspect=ok prior_present=");
    ::duetos::arch::SerialWriteHex(s.prior_present);
    ::duetos::arch::SerialWrite(" new=");
    ::duetos::arch::SerialWriteHex(s.new_count);
    ::duetos::arch::SerialWrite(" persistent=");
    ::duetos::arch::SerialWriteHex(s.persistent);
    ::duetos::arch::SerialWrite(" resolved=");
    ::duetos::arch::SerialWriteHex(s.resolved);
    ::duetos::arch::SerialWrite("\n");
}

} // namespace duetos::diag::introspect
