/*
 * DuetOS — security event ring: implementation.
 *
 * See event_ring.h for the design. This TU owns the ring storage,
 * the spinlock, the publish path, and the snapshot iterators.
 *
 * Storage is a `constinit` static array — no KMalloc, no init-
 * order surprises. Ready to accept publishes from the very first
 * subsystem that calls in, even before EventRingInit runs.
 */

#include "security/event_ring.h"

#include "arch/x86_64/serial.h"
#include "sync/spinlock.h"
#include "time/timekeeper.h"

namespace duetos::security
{

namespace
{

constexpr u64 kRingCapacity = 256;

struct RingState
{
    Event slots[kRingCapacity];
    u64 head;            // next slot to write into
    u64 published_total; // total successful publishes since boot
    u64 dropped_oldest;  // overwrites that erased an unread event
    bool wrapped;        // once true, every slot is valid
};

constinit RingState g_ring{};
constinit sync::SpinLock g_lock{};

// Copy at most `kEventTagLen - 1` bytes of `src` into `dst` and
// NUL-terminate. `dst` must be at least kEventTagLen bytes. `src`
// may be null (copies an empty string).
void CopyTag(char (&dst)[kEventTagLen], const char* src)
{
    if (src == nullptr)
    {
        dst[0] = '\0';
        return;
    }
    u32 i = 0;
    while (i < kEventTagLen - 1 && src[i] != '\0')
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

const char* const kEventKindNames[] = {
    "None",
    "CanaryTouch",
    "PersistenceDrop",
    "FsWriteRateBurst",
    "FsWriteRateSustained",
    "FsWriteRateLong",
    "SandboxDenialKill",
    "TickBudgetKill",
    "IdtModified",
    "GdtModified",
    "KernelTextModified",
    "SyscallMsrHijacked",
    "BootSectorModified",
    "Cr0WpCleared",
    "Cr4SmepCleared",
    "Cr4SmapCleared",
    "EferNxeCleared",
    "StackCanaryZero",
    "FeatureControlUnlocked",
    "ImageRejected",
    "ImageWarned",
    "PolicyChanged",
    "GuardModeChanged",
    "PersistenceModeChanged",
    "BlockguardModeChanged",
    "AttackSimRun",
    "IrRunbookEmitted",
    "AuthLoginSuccess",
    "AuthLoginFailure",
    "AuthAccountLocked",
    "AuthAccountUnlocked",
    "AuthAccountCreated",
    "AuthAccountDeleted",
    "AuthPasswordChanged",
};

static_assert(sizeof(kEventKindNames) / sizeof(kEventKindNames[0]) == static_cast<u32>(EventKind::Count),
              "EventKind name table out of sync with enum");

} // namespace

const char* EventKindName(EventKind k)
{
    const u32 i = static_cast<u32>(k);
    if (i >= static_cast<u32>(EventKind::Count))
    {
        return "<bad-kind>";
    }
    return kEventKindNames[i];
}

void EventRingInit()
{
    sync::SpinLockGuard guard{g_lock};
    g_ring.head = 0;
    g_ring.published_total = 0;
    g_ring.dropped_oldest = 0;
    g_ring.wrapped = false;
    for (u64 i = 0; i < kRingCapacity; ++i)
    {
        g_ring.slots[i] = Event{};
    }
}

void EventRingPublishKind(EventKind kind, u32 actor_pid, u64 aux1, u64 aux2, const char* tag)
{
    const u64 now = time::MonotonicNs();

    sync::SpinLockGuard guard{g_lock};

    const u64 slot = g_ring.head % kRingCapacity;
    if (g_ring.wrapped)
    {
        ++g_ring.dropped_oldest;
    }

    Event& e = g_ring.slots[slot];
    e.seq = g_ring.published_total + 1;
    e.uptime_ns = now;
    e.kind = kind;
    e._pad = 0;
    e.actor_pid = actor_pid;
    e.aux1 = aux1;
    e.aux2 = aux2;
    CopyTag(e.tag, tag);

    ++g_ring.head;
    if (g_ring.head >= kRingCapacity)
    {
        g_ring.wrapped = true;
    }
    ++g_ring.published_total;
}

EventRingStats EventRingStatsRead()
{
    sync::SpinLockGuard guard{g_lock};
    EventRingStats s{};
    s.published_total = g_ring.published_total;
    s.dropped_oldest = g_ring.dropped_oldest;
    s.head = g_ring.head;
    s.tail = g_ring.wrapped ? g_ring.head : 0;
    s.capacity = kRingCapacity;
    return s;
}

void EventRingForEach(EventVisitor visitor, void* cookie)
{
    if (visitor == nullptr)
    {
        return;
    }
    sync::SpinLockGuard guard{g_lock};

    if (!g_ring.wrapped)
    {
        // Slots [0, head) are valid in chronological order.
        for (u64 i = 0; i < g_ring.head; ++i)
        {
            visitor(g_ring.slots[i], cookie);
        }
        return;
    }

    // Wrapped: oldest is at slot (head % cap), then walk forward
    // capacity entries.
    const u64 start = g_ring.head % kRingCapacity;
    for (u64 step = 0; step < kRingCapacity; ++step)
    {
        const u64 idx = (start + step) % kRingCapacity;
        visitor(g_ring.slots[idx], cookie);
    }
}

void EventRingForEachKind(EventKind kind, EventVisitor visitor, void* cookie)
{
    struct Filter
    {
        EventKind kind;
        EventVisitor inner;
        void* inner_cookie;
    } filter{kind, visitor, cookie};

    auto trampoline = [](const Event& e, void* c)
    {
        auto* f = static_cast<Filter*>(c);
        if (e.kind == f->kind && f->inner != nullptr)
        {
            f->inner(e, f->inner_cookie);
        }
    };
    EventRingForEach(static_cast<EventVisitor>(trampoline), &filter);
}

namespace
{

struct DumpCookie
{
    u64 want;       // remaining lines to print
    u64 total_seen; // events visited so far
    u64 valid;      // events that exist (head or capacity)
};

void DumpVisitor(const Event& e, void* cookie)
{
    auto* d = static_cast<DumpCookie*>(cookie);
    ++d->total_seen;
    // Skip until we reach the tail of the "last want" window.
    if (d->total_seen + d->want <= d->valid)
    {
        return;
    }
    arch::SerialWrite("[secevents]   seq=");
    arch::SerialWriteHex(e.seq);
    arch::SerialWrite(" t=");
    arch::SerialWriteHex(e.uptime_ns);
    arch::SerialWrite("ns pid=");
    arch::SerialWriteHex(static_cast<u64>(e.actor_pid));
    arch::SerialWrite(" kind=");
    arch::SerialWrite(EventKindName(e.kind));
    arch::SerialWrite(" tag=\"");
    arch::SerialWrite(e.tag[0] == '\0' ? "-" : e.tag);
    arch::SerialWrite("\" aux1=");
    arch::SerialWriteHex(e.aux1);
    arch::SerialWrite(" aux2=");
    arch::SerialWriteHex(e.aux2);
    arch::SerialWrite("\n");
}

} // namespace

void EventRingDumpRecent(u64 n)
{
    EventRingStats s = EventRingStatsRead();
    const u64 valid = (s.tail == 0 && s.dropped_oldest == 0) ? s.head : s.capacity;
    const u64 want = (n == 0 || n > valid) ? valid : n;

    arch::SerialWrite("[secevents] ring: published=");
    arch::SerialWriteHex(s.published_total);
    arch::SerialWrite(" dropped_oldest=");
    arch::SerialWriteHex(s.dropped_oldest);
    arch::SerialWrite(" capacity=");
    arch::SerialWriteHex(s.capacity);
    arch::SerialWrite(" -- showing last ");
    arch::SerialWriteHex(want);
    arch::SerialWrite("\n");

    DumpCookie c{want, 0, valid};
    EventRingForEach(DumpVisitor, &c);
}

void EventRingSelfTest()
{
    const EventRingStats before = EventRingStatsRead();

    // Publish three synthetic events with distinguishable tags.
    EventRingPublishKind(EventKind::CanaryTouch, 1, 0xAA, 0xBB, "self-test-1");
    EventRingPublishKind(EventKind::PersistenceDrop, 2, 0xCC, 0xDD, "self-test-2");
    EventRingPublishKind(EventKind::ImageWarned, 3, 0xEE, 0xFF, "self-test-3");

    const EventRingStats after = EventRingStatsRead();
    if (after.published_total != before.published_total + 3)
    {
        arch::SerialWrite("[secevents] self-test FAIL: published_total delta != 3\n");
        return;
    }

    // Walk the last three; assert they appear in the right order
    // with monotonically increasing seq.
    struct Walker
    {
        u64 seen;
        u64 last_seq;
        bool ordered;
        EventKind last_three[3];
    } w{0, 0, true, {EventKind::None, EventKind::None, EventKind::None}};

    EventRingForEach(
        [](const Event& e, void* cookie)
        {
            auto* wp = static_cast<Walker*>(cookie);
            if (wp->last_seq != 0 && e.seq <= wp->last_seq)
            {
                wp->ordered = false;
            }
            wp->last_seq = e.seq;
            // Roll a 3-deep window of last-seen kinds.
            wp->last_three[0] = wp->last_three[1];
            wp->last_three[1] = wp->last_three[2];
            wp->last_three[2] = e.kind;
            ++wp->seen;
        },
        &w);

    const bool kinds_ok = w.last_three[0] == EventKind::CanaryTouch && w.last_three[1] == EventKind::PersistenceDrop &&
                          w.last_three[2] == EventKind::ImageWarned;

    if (w.ordered && kinds_ok)
    {
        arch::SerialWrite("[secevents] self-test PASS (events walked=");
        arch::SerialWriteHex(w.seen);
        arch::SerialWrite(")\n");
    }
    else
    {
        arch::SerialWrite("[secevents] self-test FAIL: ordered=");
        arch::SerialWrite(w.ordered ? "yes" : "no");
        arch::SerialWrite(" kinds_ok=");
        arch::SerialWrite(kinds_ok ? "yes" : "no");
        arch::SerialWrite("\n");
    }
}

} // namespace duetos::security
