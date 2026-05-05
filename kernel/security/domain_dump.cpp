#include "security/domain_dump.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "core/panic.h"
#include "log/klog.h"
#include "security/module.h"
#include "sync/spinlock.h"
#include "util/symbols.h"

namespace duetos::security
{

namespace
{

inline constexpr u32 kRecordCapBytes = 2048;
inline constexpr u32 kKlogTailEntries = 32;
inline constexpr u32 kSchemaVersion = 1;

struct DumpRecord
{
    bool used;
    ::duetos::core::FaultDomainId domain_id;
    u32 length; // bytes used in `body`
    char body[kRecordCapBytes];
};

constinit DumpRecord g_recent[kRecentDumpRingCapacity] = {};
constinit u32 g_recent_next = 0; // monotonic write cursor (slot = next % cap)

constinit ::duetos::sync::SpinLock g_dump_lock = {};
constinit DumpRecord* g_active = nullptr; // record being written between Begin/End
constinit bool g_active_truncated = false;

// Held flags for the lock acquired in BeginDomainDump and
// released in EndDomainDump. Kept at file scope (not a local
// to Begin) because the End call is a separate function. The
// access pattern is single-Begin-then-single-End under the
// same g_dump_lock, so this is safe — concurrent callers
// serialise on the lock acquire.
::duetos::sync::IrqFlags g_dump_held_flags{};

void RecordAppend(const char* s)
{
    if (g_active == nullptr || s == nullptr)
        return;
    while (*s)
    {
        if (g_active->length + 1 >= kRecordCapBytes)
        {
            // Capacity-cap: serial output continues to flow,
            // but the in-kernel record stops growing. We mark
            // truncation so the closing footer can flag it.
            g_active_truncated = true;
            return;
        }
        g_active->body[g_active->length++] = *s++;
    }
}

void DumpEmit(const char* s)
{
    if (s == nullptr)
        return;
    ::duetos::arch::SerialWrite(s);
    RecordAppend(s);
}

void DumpEmitHex(u64 v)
{
    char buf[19] = "0x";
    constexpr const char* hex = "0123456789abcdef";
    for (u32 i = 0; i < 16; ++i)
    {
        buf[2 + i] = hex[(v >> (60 - (i * 4))) & 0xF];
    }
    buf[18] = '\0';
    DumpEmit(buf);
}

void DumpEmitDec(u64 v)
{
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        DumpEmit("0");
        return;
    }
    while (v != 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    char out[25];
    for (u32 i = 0; i < n; ++i)
    {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = '\0';
    DumpEmit(out);
}

const char* StateNameOf(::duetos::core::FaultDomainId id)
{
    return ModuleStateName(ModuleStateOf(id));
}

void EmitTrapFrame(const ::duetos::arch::TrapFrame* f)
{
    if (f == nullptr)
    {
        DumpEmit("  trap_frame   : (none)\n");
        return;
    }
    DumpEmit("  --- trap frame ---\n");
    DumpEmit("  vector       : ");
    DumpEmitHex(f->vector);
    DumpEmit("\n  error_code   : ");
    DumpEmitHex(f->error_code);
    DumpEmit("\n  rip          : ");
    DumpEmitHex(f->rip);
    DumpEmit("\n  rsp          : ");
    DumpEmitHex(f->rsp);
    DumpEmit("\n  rbp          : ");
    DumpEmitHex(f->rbp);
    DumpEmit("\n  cs           : ");
    DumpEmitHex(f->cs);
    DumpEmit("\n  ss           : ");
    DumpEmitHex(f->ss);
    DumpEmit("\n  rflags       : ");
    DumpEmitHex(f->rflags);
    DumpEmit("\n");
}

::duetos::core::LogArea AreaForDomain(const ::duetos::core::FaultDomain* d)
{
    if (d == nullptr || d->name == nullptr)
        return ::duetos::core::LogArea::General;
    return ::duetos::core::AreaFromSubsystem(d->name);
}

} // namespace

void BeginDomainDump(::duetos::core::FaultDomainId id, const DomainDumpEvidence& ev)
{
    const auto* d = ::duetos::core::FaultDomainGet(id);
    if (d == nullptr)
        return;

    // Single-writer lock so concurrent Begin/End pairs (one from
    // a heartbeat-side fault drain, one from a shell `module
    // dump`) don't interleave on serial or fight over the same
    // accumulator slot.
    auto flags = ::duetos::sync::SpinLockAcquire(g_dump_lock);

    // Pick the next ring slot (FIFO eviction). The slot is
    // reused — old contents are overwritten. We initialise the
    // record metadata before the first body byte so a shell
    // walker that races with the End sees consistent fields.
    const u32 slot = g_recent_next % kRecentDumpRingCapacity;
    DumpRecord& rec = g_recent[slot];
    rec.used = true;
    rec.domain_id = id;
    rec.length = 0;
    g_active = &rec;
    g_active_truncated = false;

    DumpEmit("\n=== DUETOS DOMAIN DUMP BEGIN ===\n");
    DumpEmit("  version       : ");
    DumpEmitHex(kSchemaVersion);
    DumpEmit("\n  domain        : ");
    DumpEmit(d->name);
    DumpEmit("\n  state         : ");
    DumpEmit(StateNameOf(id));
    DumpEmit("\n  restart_count : ");
    DumpEmitHex(d->restart_count);
    DumpEmit(" (");
    DumpEmitDec(d->restart_count);
    DumpEmit(")\n  alive         : ");
    DumpEmit(d->alive ? "true" : "false");
    DumpEmit("\n  fault_kind    : ");
    DumpEmit(::duetos::diag::FaultKindName(ev.kind));
    if (ev.faulting_rip != 0)
    {
        DumpEmit("\n  faulting_rip  : ");
        DumpEmitHex(ev.faulting_rip);
        // Resolve into "func+offset" for the immediate signal — the
        // host-side resolver still gets the raw hex for full
        // address resolution.
        ::duetos::core::SymbolResolution sres = {};
        if (::duetos::core::ResolveAddress(ev.faulting_rip, &sres) && sres.entry != nullptr)
        {
            DumpEmit(" ");
            DumpEmit(sres.entry->name);
            DumpEmit("+");
            DumpEmitHex(sres.offset);
        }
    }
    if (ev.aux != 0)
    {
        DumpEmit("\n  aux           : ");
        DumpEmitHex(ev.aux);
    }
    DumpEmit("\n");

    EmitTrapFrame(ev.frame);

    // klog tail — last ~32 entries whose subsystem prefix maps
    // to this domain's LogArea. Skipped silently if the domain
    // doesn't have a recognisable area mapping (LogArea::General
    // matches everything; we filter to only the specific area
    // when one exists).
    const auto area = AreaForDomain(d);
    if (area != ::duetos::core::LogArea::None && area != ::duetos::core::LogArea::General)
    {
        DumpEmit("  --- klog tail (filtered by area) ---\n");
        ::duetos::core::DumpLogRingFilteredAreaTo(&DumpEmit, static_cast<u32>(area), kKlogTailEntries);
    }

    // The lock stays held through End — Begin/End are paired by
    // contract. Stash the RFLAGS bag so End can release.
    g_dump_held_flags = flags;
}

void EndDomainDump()
{
    if (g_active == nullptr)
        return;

    if (g_active_truncated)
    {
        DumpEmit("  (record-buffer truncated — full dump above on serial)\n");
    }
    DumpEmit("=== DUETOS DOMAIN DUMP END ===\n\n");

    // Bump the ring cursor before clearing g_active so a shell
    // walker that races with us either sees the prior set of
    // records or the new one — never a half-finalised record.
    g_active = nullptr;
    g_active_truncated = false;
    ++g_recent_next;

    ::duetos::sync::SpinLockRelease(g_dump_lock, g_dump_held_flags);
}

void DumpRecentDumps(::duetos::core::FaultDomainId id)
{
    const auto* d = ::duetos::core::FaultDomainGet(id);
    if (d == nullptr)
    {
        ::duetos::arch::SerialWrite("[domain-dump] not found id=");
        ::duetos::arch::SerialWriteHex(id);
        ::duetos::arch::SerialWrite("\n");
        return;
    }

    // Walk oldest-first across the ring. Slot count is small
    // (8) so a lock isn't necessary for reads — the worst race
    // is "we see a record being overwritten by an in-flight
    // Begin" which surfaces as truncated text, not corruption.
    auto flags = ::duetos::sync::SpinLockAcquire(g_dump_lock);
    u32 emitted = 0;
    const u32 base = g_recent_next;
    for (u32 i = 0; i < kRecentDumpRingCapacity; ++i)
    {
        const u32 slot_idx = (base + i) % kRecentDumpRingCapacity;
        const DumpRecord& rec = g_recent[slot_idx];
        if (!rec.used || rec.domain_id != id)
            continue;
        ::duetos::arch::SerialWrite(rec.body);
        ++emitted;
    }
    ::duetos::sync::SpinLockRelease(g_dump_lock, flags);

    if (emitted == 0)
    {
        ::duetos::arch::SerialWrite("[domain-dump] no records for ");
        ::duetos::arch::SerialWrite(d->name);
        ::duetos::arch::SerialWrite("\n");
    }
}

u32 RecentDumpCount(::duetos::core::FaultDomainId id)
{
    auto flags = ::duetos::sync::SpinLockAcquire(g_dump_lock);
    u32 n = 0;
    for (u32 i = 0; i < kRecentDumpRingCapacity; ++i)
    {
        if (g_recent[i].used && g_recent[i].domain_id == id)
            ++n;
    }
    ::duetos::sync::SpinLockRelease(g_dump_lock, flags);
    return n;
}

u64 FormatAllDumps(u8* buf, u64 cap)
{
    if (buf == nullptr && cap != 0)
        return 0;
    auto flags = ::duetos::sync::SpinLockAcquire(g_dump_lock);
    u64 written = 0;
    const u32 base = g_recent_next;
    for (u32 i = 0; i < kRecentDumpRingCapacity; ++i)
    {
        const u32 slot_idx = (base + i) % kRecentDumpRingCapacity;
        const DumpRecord& rec = g_recent[slot_idx];
        if (!rec.used || rec.length == 0)
            continue;
        const u64 take = (rec.length < (cap - written)) ? rec.length : (cap - written);
        for (u64 b = 0; b < take; ++b)
        {
            buf[written + b] = static_cast<u8>(rec.body[b]);
        }
        written += take;
        if (written >= cap)
            break;
    }
    ::duetos::sync::SpinLockRelease(g_dump_lock, flags);
    return written;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    ::duetos::core::PanicWithValue("security/domain-dump", "self-test mismatch", 0);
    (void)what;
}

::duetos::core::Result<void> DdSelfInit()
{
    return {};
}
::duetos::core::Result<void> DdSelfTeardown()
{
    return {};
}

} // namespace

void DomainDumpSelfTest()
{
    KLOG_TRACE_SCOPE("security/domain-dump", "SelfTest");

    const auto id = ::duetos::core::FaultDomainRegister("selftest.domain-dump", DdSelfInit, DdSelfTeardown);
    Expect(id != ::duetos::core::kFaultDomainInvalid, "register dump test domain");

    const u32 before = RecentDumpCount(id);

    DomainDumpEvidence ev = {};
    ev.kind = ::duetos::diag::FaultKind::InternalInvariant;
    ev.faulting_rip = 0xCAFEBABE;
    ev.aux = 0x1234;
    BeginDomainDump(id, ev);
    EndDomainDump();

    const u32 after = RecentDumpCount(id);
    Expect(after == before + 1, "ring captured one record");

    // Replay must not panic; output goes to serial.
    DumpRecentDumps(id);

    // ModuleDump path also drives Begin/End under the hood.
    Expect(bool(ModuleDump(id)), "ModuleDump on registered id");
    Expect(RecentDumpCount(id) == after + 1, "ring captured second record");

    // Out-of-range id is silent for Begin/End and returns NotFound for ModuleDump.
    BeginDomainDump(::duetos::core::kFaultDomainInvalid, ev);
    EndDomainDump(); // matches the no-op Begin (no lock held)

    KLOG_INFO("security/domain-dump", "self-test PASS (begin/end/ring/replay verified)");
}

} // namespace duetos::security
