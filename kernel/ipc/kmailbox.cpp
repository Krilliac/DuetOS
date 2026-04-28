/*
 * DuetOS — concrete KMailbox implementation, v0 (plan A3-followup).
 *
 * See `kmailbox.h` for the public contract. This TU owns:
 *   - kheap-backed allocation of both the mailbox struct AND the
 *     slot buffer; KObjectInit on Create,
 *   - the circular-buffer state machine (head / tail / count),
 *   - the destroy callback that runs on last refcount release —
 *     frees the slot buffer first, then the mailbox itself,
 *   - a self-test that exercises Post / Receive / fill / drain
 *     plus a HandleTable round-trip.
 */

#include "ipc/kmailbox.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "mm/kheap.h"
#include "sched/sched.h"

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KMailbox, base) == 0, "KObject must be the first member of KMailbox");

namespace
{

void KMailboxDestroy(KObject* obj)
{
    auto* mb = reinterpret_cast<KMailbox*>(obj);
    // Free the slot buffer FIRST (separate allocation), then the
    // mailbox itself. Order matters: after KFree(mb) the `slots`
    // field is no longer reachable.
    if (mb->slots != nullptr)
    {
        duetos::mm::KFree(mb->slots);
    }
    duetos::mm::KFree(mb);
}

} // namespace

::duetos::core::Result<KMailbox*> KMailboxCreate(u32 capacity)
{
    if (capacity == 0)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    auto* mb = static_cast<KMailbox*>(duetos::mm::KMalloc(sizeof(KMailbox)));
    if (mb == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *mb = KMailbox{};
    mb->slots = static_cast<KMailboxMessage*>(duetos::mm::KMalloc(sizeof(KMailboxMessage) * capacity));
    if (mb->slots == nullptr)
    {
        // Slot buffer allocation failed; release the half-built
        // mailbox before returning. KObjectInit hasn't run yet
        // so we can KFree directly without going through Release.
        duetos::mm::KFree(mb);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    KObjectInit(&mb->base, KObjectType::Mailbox, &KMailboxDestroy);
    mb->capacity = capacity;
    return mb;
}

void KMailboxPost(KMailbox* mb, const KMailboxMessage& msg)
{
    sched::MutexLock(&mb->inner);
    while (mb->count == mb->capacity)
    {
        sched::CondvarWait(&mb->not_full, &mb->inner);
    }
    mb->slots[mb->head] = msg;
    mb->head = (mb->head + 1) % mb->capacity;
    ++mb->count;
    // Wake one blocked consumer if any.
    sched::CondvarSignal(&mb->not_empty);
    sched::MutexUnlock(&mb->inner);
}

bool KMailboxTryPost(KMailbox* mb, const KMailboxMessage& msg)
{
    sched::MutexLock(&mb->inner);
    if (mb->count == mb->capacity)
    {
        sched::MutexUnlock(&mb->inner);
        return false;
    }
    mb->slots[mb->head] = msg;
    mb->head = (mb->head + 1) % mb->capacity;
    ++mb->count;
    sched::CondvarSignal(&mb->not_empty);
    sched::MutexUnlock(&mb->inner);
    return true;
}

void KMailboxReceive(KMailbox* mb, KMailboxMessage* out)
{
    sched::MutexLock(&mb->inner);
    while (mb->count == 0)
    {
        sched::CondvarWait(&mb->not_empty, &mb->inner);
    }
    *out = mb->slots[mb->tail];
    mb->tail = (mb->tail + 1) % mb->capacity;
    --mb->count;
    // Wake one blocked producer if any.
    sched::CondvarSignal(&mb->not_full);
    sched::MutexUnlock(&mb->inner);
}

bool KMailboxTryReceive(KMailbox* mb, KMailboxMessage* out)
{
    sched::MutexLock(&mb->inner);
    if (mb->count == 0)
    {
        sched::MutexUnlock(&mb->inner);
        return false;
    }
    *out = mb->slots[mb->tail];
    mb->tail = (mb->tail + 1) % mb->capacity;
    --mb->count;
    sched::CondvarSignal(&mb->not_full);
    sched::MutexUnlock(&mb->inner);
    return true;
}

u32 KMailboxCount(const KMailbox* mb)
{
    return mb->count;
}

void KMailboxSelfTest()
{
    arch::SerialWrite("[ipc] kmailbox self-test: bounded-queue state machine + HandleTable round-trip\n");

    constexpr u32 kCap = 4;
    auto create_r = KMailboxCreate(kCap);
    if (!create_r.has_value())
    {
        core::Panic("ipc/kmailbox", "self-test: KMailboxCreate failed");
    }
    KMailbox* mb = create_r.value();
    if (KMailboxCount(mb) != 0)
    {
        core::Panic("ipc/kmailbox", "self-test: fresh mailbox count != 0");
    }

    // Bad-arg: capacity 0 returns InvalidArgument without
    // allocating.
    auto bad_r = KMailboxCreate(0);
    if (bad_r.has_value())
    {
        core::Panic("ipc/kmailbox", "self-test: capacity=0 create succeeded");
    }
    if (bad_r.error() != ::duetos::core::ErrorCode::InvalidArgument)
    {
        core::Panic("ipc/kmailbox", "self-test: bad-arg returned wrong error");
    }

    // Try-receive on empty queue returns false.
    KMailboxMessage tmp{};
    if (KMailboxTryReceive(mb, &tmp))
    {
        core::Panic("ipc/kmailbox", "self-test: try-receive on empty returned true");
    }

    // Post one, receive one. Round-trip the message contents.
    const KMailboxMessage sentinel = {0xAA, 0xBB, 0xCC, 0xDD};
    KMailboxPost(mb, sentinel);
    if (KMailboxCount(mb) != 1)
    {
        core::Panic("ipc/kmailbox", "self-test: count != 1 after post");
    }
    KMailboxMessage got{};
    KMailboxReceive(mb, &got);
    if (got.type != 0xAA || got.payload0 != 0xBB || got.payload1 != 0xCC || got.payload2 != 0xDD)
    {
        core::Panic("ipc/kmailbox", "self-test: round-trip corrupted message");
    }
    if (KMailboxCount(mb) != 0)
    {
        core::Panic("ipc/kmailbox", "self-test: count != 0 after receive");
    }

    // Fill to capacity (4 posts), try-post returns false.
    for (u64 i = 0; i < kCap; ++i)
    {
        KMailboxPost(mb, KMailboxMessage{i, i + 1, i + 2, i + 3});
    }
    if (KMailboxCount(mb) != kCap)
    {
        core::Panic("ipc/kmailbox", "self-test: count != capacity after fill");
    }
    if (KMailboxTryPost(mb, KMailboxMessage{0, 0, 0, 0}))
    {
        core::Panic("ipc/kmailbox", "self-test: try-post on full returned true");
    }

    // Drain — receive 4 messages, verify FIFO order.
    for (u64 i = 0; i < kCap; ++i)
    {
        KMailboxMessage m{};
        KMailboxReceive(mb, &m);
        if (m.type != i || m.payload0 != i + 1 || m.payload1 != i + 2 || m.payload2 != i + 3)
        {
            core::Panic("ipc/kmailbox", "self-test: FIFO order violated on drain");
        }
    }
    if (KMailboxCount(mb) != 0)
    {
        core::Panic("ipc/kmailbox", "self-test: count != 0 after drain");
    }

    // HandleTable round-trip.
    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &mb->base);
    if (!insert_r.has_value())
    {
        core::Panic("ipc/kmailbox", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    if (HandleTableLookup(table, h, KObjectType::Mailbox) != &mb->base)
    {
        core::Panic("ipc/kmailbox", "self-test: lookup did not return mailbox");
    }
    if (HandleTableLookup(table, h, KObjectType::Mutex) != nullptr)
    {
        core::Panic("ipc/kmailbox", "self-test: lookup with wrong type-tag returned non-null");
    }
    if (!HandleTableRemove(table, h).has_value())
    {
        core::Panic("ipc/kmailbox", "self-test: HandleTableRemove failed");
    }
    if (HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/kmailbox", "self-test: live count != 0 at end");
    }

    arch::SerialWrite("[ipc] kmailbox self-test OK (bounded-queue + FIFO + HandleTable round-trip).\n");
}

} // namespace duetos::ipc
