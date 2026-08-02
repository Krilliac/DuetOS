#include "drivers/video/gui_message_queue.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "sync/spinlock.h"

namespace duetos::drivers::video
{

namespace
{

struct QueuedMessage
{
    WindowMsg message;
    u64 ticket;
};

struct TaskMessageQueue
{
    sync::SpinLock lock;
    QueuedMessage entries[kGuiTaskQueueDepth];
    u64 owner_pid;
    u64 owner_tid;
    u64 next_ticket;
    u64 epoch;
    u32 head;
    u32 count;
    bool active;
    bool retired;
};

constinit sync::SpinLock g_queue_registry_lock{};
constinit TaskMessageQueue g_task_queues[kGuiTaskQueueCapacity]{};
constinit bool g_queue_selftest_passed = false;

constexpr u64 kMaxQueueEpoch = static_cast<u64>(-1);

bool NextEpoch(u64 current, u64* next)
{
    if (next == nullptr || current == kMaxQueueEpoch)
    {
        return false;
    }
    *next = current + 1;
    return true;
}

u32 FindQueueLocked(u64 pid, u64 tid)
{
    sync::SpinLockAssertHeld(g_queue_registry_lock);
    for (u32 i = 0; i < kGuiTaskQueueCapacity; ++i)
    {
        const TaskMessageQueue& queue = g_task_queues[i];
        if (queue.active && queue.owner_pid == pid && queue.owner_tid == tid)
        {
            return i;
        }
    }
    return kGuiTaskQueueCapacity;
}

u32 AllocateQueueLocked(u64 pid, u64 tid)
{
    sync::SpinLockAssertHeld(g_queue_registry_lock);
    for (u32 i = 0; i < kGuiTaskQueueCapacity; ++i)
    {
        TaskMessageQueue& queue = g_task_queues[i];
        if (queue.active || queue.retired)
        {
            continue;
        }
        u64 next_epoch = 0;
        if (!NextEpoch(queue.epoch, &next_epoch))
        {
            queue.retired = true;
            continue;
        }

        queue.epoch = next_epoch;
        queue.owner_pid = pid;
        queue.owner_tid = tid;
        queue.next_ticket = 1;
        queue.head = 0;
        queue.count = 0;
        queue.active = true;
        return i;
    }
    return kGuiTaskQueueCapacity;
}

u32 FindOrAllocateQueueLocked(u64 pid, u64 tid)
{
    const u32 existing = FindQueueLocked(pid, tid);
    return (existing != kGuiTaskQueueCapacity) ? existing : AllocateQueueLocked(pid, tid);
}

void ClearQueueLocked(TaskMessageQueue& queue)
{
    sync::SpinLockAssertHeld(queue.lock);
    queue.owner_pid = 0;
    queue.owner_tid = 0;
    queue.next_ticket = 0;
    queue.head = 0;
    queue.count = 0;
    queue.active = false;
    if (queue.epoch == kMaxQueueEpoch)
    {
        queue.retired = true;
    }
}

bool AdvanceEpochOrRetireLocked(TaskMessageQueue& queue)
{
    sync::SpinLockAssertHeld(queue.lock);
    u64 next_epoch = 0;
    if (!NextEpoch(queue.epoch, &next_epoch))
    {
        // Epoch ABA is worse than losing this one saturated queue. Make the
        // slot permanently Gone and discard its contents rather than wrap.
        ClearQueueLocked(queue);
        queue.retired = true;
        return false;
    }
    queue.epoch = next_epoch;
    return true;
}

bool ClaimMatchesLocked(const TaskMessageQueue& queue, const GuiMessageClaim& claim)
{
    sync::SpinLockAssertHeld(queue.lock);
    if (!claim.valid || !queue.active || queue.epoch != claim.queue_epoch || queue.owner_pid != claim.owner_pid ||
        queue.owner_tid != claim.owner_tid || queue.count == 0)
    {
        return false;
    }
    return queue.entries[queue.head].ticket == claim.head_ticket;
}

u32 FindTicketOffsetLocked(const TaskMessageQueue& queue, u64 ticket)
{
    sync::SpinLockAssertHeld(queue.lock);
    for (u32 offset = 0; offset < queue.count; ++offset)
    {
        const u32 index = (queue.head + offset) % kGuiTaskQueueDepth;
        if (queue.entries[index].ticket == ticket)
        {
            return offset;
        }
    }
    return kGuiTaskQueueDepth;
}

void RemoveOffsetLocked(TaskMessageQueue& queue, u32 offset)
{
    sync::SpinLockAssertHeld(queue.lock);
    for (u32 i = offset; i + 1 < queue.count; ++i)
    {
        const u32 dst = (queue.head + i) % kGuiTaskQueueDepth;
        const u32 src = (queue.head + i + 1) % kGuiTaskQueueDepth;
        queue.entries[dst] = queue.entries[src];
    }
    --queue.count;
    if (queue.count == 0)
    {
        queue.head = 0;
    }
}

} // namespace

bool GuiMessageEnsureQueue(u64 pid, u64 tid)
{
    if (pid == 0 || tid == 0 || tid == static_cast<u64>(-1))
    {
        return false;
    }
    sync::SpinLockGuard registry_guard(g_queue_registry_lock);
    return FindOrAllocateQueueLocked(pid, tid) != kGuiTaskQueueCapacity;
}

bool GuiMessagePost(u64 pid, u64 tid, const WindowMsg& message)
{
    if (pid == 0 || tid == 0 || tid == static_cast<u64>(-1))
    {
        return false;
    }

    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    // Posting must not allocate. If task teardown won the registry lock and
    // cleared this identity, a late sender fails instead of resurrecting a
    // queue that no future reaper will visit.
    const u32 slot = FindQueueLocked(pid, tid);
    if (slot == kGuiTaskQueueCapacity)
    {
        sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
        return false;
    }
    TaskMessageQueue& queue = g_task_queues[slot];
    const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);

    bool posted = false;
    if (queue.active && queue.owner_pid == pid && queue.owner_tid == tid && queue.epoch == kMaxQueueEpoch)
    {
        (void)AdvanceEpochOrRetireLocked(queue);
    }
    else if (queue.active && queue.owner_pid == pid && queue.owner_tid == tid && queue.count < kGuiTaskQueueDepth &&
             queue.next_ticket != 0 && queue.next_ticket != static_cast<u64>(-1) && AdvanceEpochOrRetireLocked(queue))
    {
        const u32 tail = (queue.head + queue.count) % kGuiTaskQueueDepth;
        queue.entries[tail].message = message;
        queue.entries[tail].ticket = queue.next_ticket++;
        ++queue.count;
        posted = true;
    }

    sync::SpinLockRelease(queue.lock, queue_flags);
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return posted;
}

GuiMessageProbeResult GuiMessageProbeQueue(u64 pid, u64 tid, u32 hwnd_filter, GuiMessageClaim* claim_out,
                                           GuiMessageProbeToken* token_out)
{
    if (claim_out != nullptr)
    {
        *claim_out = {};
    }
    if (token_out != nullptr)
    {
        *token_out = {};
    }
    if (pid == 0 || tid == 0 || tid == static_cast<u64>(-1) || claim_out == nullptr || token_out == nullptr)
    {
        return GuiMessageProbeResult::Gone;
    }

    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    const u32 slot = FindQueueLocked(pid, tid);
    if (slot == kGuiTaskQueueCapacity)
    {
        sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
        return GuiMessageProbeResult::Gone;
    }
    TaskMessageQueue& queue = g_task_queues[slot];
    const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);

    GuiMessageProbeResult result = GuiMessageProbeResult::Gone;
    if (queue.active && queue.owner_pid == pid && queue.owner_tid == tid)
    {
        token_out->opaque[0] = static_cast<u64>(slot) + 1;
        token_out->opaque[1] = queue.epoch;
        result = GuiMessageProbeResult::Empty;
        for (u32 offset = 0; offset < queue.count; ++offset)
        {
            const u32 index = (queue.head + offset) % kGuiTaskQueueDepth;
            const QueuedMessage& queued = queue.entries[index];
            if (hwnd_filter != 0 && queued.message.hwnd != hwnd_filter)
            {
                continue;
            }
            claim_out->message = queued.message;
            claim_out->owner_pid = pid;
            claim_out->owner_tid = tid;
            claim_out->head_ticket = queue.entries[queue.head].ticket;
            claim_out->message_ticket = queued.ticket;
            claim_out->queue_epoch = queue.epoch;
            claim_out->queue_slot = slot;
            claim_out->valid = true;
            result = GuiMessageProbeResult::Message;
            break;
        }
    }

    sync::SpinLockRelease(queue.lock, queue_flags);
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return result;
}

bool GuiMessageProbeTokenCurrent(u64 pid, u64 tid, const GuiMessageProbeToken& token)
{
    if (pid == 0 || tid == 0 || token.opaque[0] == 0 || token.opaque[0] > kGuiTaskQueueCapacity || token.opaque[1] == 0)
    {
        return false;
    }

    const u32 slot = static_cast<u32>(token.opaque[0] - 1);
    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    TaskMessageQueue& queue = g_task_queues[slot];
    const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);
    const bool current = queue.active && !queue.retired && queue.owner_pid == pid && queue.owner_tid == tid &&
                         queue.epoch == token.opaque[1];
    sync::SpinLockRelease(queue.lock, queue_flags);
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return current;
}

bool GuiMessageSnapshot(u64 pid, u64 tid, u32 hwnd_filter, GuiMessageClaim* claim_out)
{
    GuiMessageProbeToken token{};
    return GuiMessageProbeQueue(pid, tid, hwnd_filter, claim_out, &token) == GuiMessageProbeResult::Message;
}

bool GuiMessageCommit(const GuiMessageClaim& claim, bool remove)
{
    if (!claim.valid || claim.queue_slot >= kGuiTaskQueueCapacity)
    {
        return false;
    }

    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    TaskMessageQueue& queue = g_task_queues[claim.queue_slot];
    const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);

    bool committed = false;
    if (ClaimMatchesLocked(queue, claim))
    {
        const u32 offset = FindTicketOffsetLocked(queue, claim.message_ticket);
        if (offset != kGuiTaskQueueDepth)
        {
            if (remove)
            {
                if (AdvanceEpochOrRetireLocked(queue))
                {
                    RemoveOffsetLocked(queue, offset);
                    committed = true;
                }
            }
            else
            {
                committed = true;
            }
        }
    }

    sync::SpinLockRelease(queue.lock, queue_flags);
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return committed;
}

u32 GuiMessagePurgeWindow(u64 pid, u64 tid, u32 hwnd)
{
    if (pid == 0 || tid == 0 || hwnd == 0)
    {
        return 0;
    }

    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    const u32 slot = FindQueueLocked(pid, tid);
    if (slot == kGuiTaskQueueCapacity)
    {
        sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
        return 0;
    }
    TaskMessageQueue& queue = g_task_queues[slot];
    const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);

    u32 matching = 0;
    for (u32 offset = 0; offset < queue.count; ++offset)
    {
        const u32 index = (queue.head + offset) % kGuiTaskQueueDepth;
        if (queue.entries[index].message.hwnd == hwnd)
        {
            ++matching;
        }
    }

    if (!AdvanceEpochOrRetireLocked(queue))
    {
        sync::SpinLockRelease(queue.lock, queue_flags);
        sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
        return matching;
    }

    u32 removed = 0;
    u32 offset = 0;
    while (offset < queue.count)
    {
        const u32 index = (queue.head + offset) % kGuiTaskQueueDepth;
        if (queue.entries[index].message.hwnd == hwnd)
        {
            RemoveOffsetLocked(queue, offset);
            ++removed;
            continue;
        }
        ++offset;
    }

    sync::SpinLockRelease(queue.lock, queue_flags);
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return removed;
}

u32 GuiMessageReapTask(u64 pid, u64 tid)
{
    if (pid == 0 || tid == 0)
    {
        return 0;
    }

    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    const u32 slot = FindQueueLocked(pid, tid);
    if (slot == kGuiTaskQueueCapacity)
    {
        sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
        return 0;
    }
    TaskMessageQueue& queue = g_task_queues[slot];
    const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);
    const u32 discarded = queue.count;
    if (AdvanceEpochOrRetireLocked(queue))
    {
        ClearQueueLocked(queue);
    }
    sync::SpinLockRelease(queue.lock, queue_flags);
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return discarded;
}

u32 GuiMessageReapProcess(u64 pid)
{
    if (pid == 0)
    {
        return 0;
    }

    u32 discarded = 0;
    const sync::IrqFlags registry_flags = sync::SpinLockAcquire(g_queue_registry_lock);
    for (u32 slot = 0; slot < kGuiTaskQueueCapacity; ++slot)
    {
        TaskMessageQueue& queue = g_task_queues[slot];
        if (!queue.active || queue.owner_pid != pid)
        {
            continue;
        }
        const sync::IrqFlags queue_flags = sync::SpinLockAcquire(queue.lock);
        discarded += queue.count;
        if (AdvanceEpochOrRetireLocked(queue))
        {
            ClearQueueLocked(queue);
        }
        sync::SpinLockRelease(queue.lock, queue_flags);
    }
    sync::SpinLockRelease(g_queue_registry_lock, registry_flags);
    return discarded;
}

void GuiMessageQueueSelfTest()
{
    using arch::SerialWrite;

    g_queue_selftest_passed = false;

    constexpr u64 kPid = 0x7FFF0001u;
    constexpr u64 kTid = 0x7FFF1001u;
    constexpr u32 kHwndA = 0x41u;
    constexpr u32 kHwndB = 0x42u;
    u32 fail_code = 0;
    const char* fail_message = nullptr;

    (void)GuiMessageReapTask(kPid, kTid);
    if (!GuiMessageEnsureQueue(kPid, kTid))
    {
        fail_code = 0x710;
        fail_message = "[gui-queue-selftest] FAIL ensure";
    }

    GuiMessageClaim initial_empty_claim{};
    GuiMessageProbeToken initial_empty_token{};
    if (fail_message == nullptr && (GuiMessageProbeQueue(kPid, kTid, 0, &initial_empty_claim, &initial_empty_token) !=
                                        GuiMessageProbeResult::Empty ||
                                    !GuiMessageProbeTokenCurrent(kPid, kTid, initial_empty_token)))
    {
        fail_code = 0x71A;
        fail_message = "[gui-queue-selftest] FAIL initial empty probe";
    }

    WindowMsg first{kHwndA, 0x401u, 1, 2};
    WindowMsg second{kHwndB, 0x402u, 3, 4};
    GuiMessageClaim abandoned{};
    if (fail_message == nullptr && (!GuiMessagePost(kPid, kTid, first) || !GuiMessagePost(kPid, kTid, second) ||
                                    !GuiMessageSnapshot(kPid, kTid, 0, &abandoned)))
    {
        fail_code = 0x711;
        fail_message = "[gui-queue-selftest] FAIL initial snapshot";
    }
    if (fail_message == nullptr && GuiMessageProbeTokenCurrent(kPid, kTid, initial_empty_token))
    {
        fail_code = 0x71B;
        fail_message = "[gui-queue-selftest] FAIL post preserved empty epoch";
    }

    // Model CopyToUser failure by abandoning the claim.  The next snapshot
    // must return the same exact ticket; no queue mutation happened.
    GuiMessageClaim after_failed_copy{};
    if (fail_message == nullptr && (!GuiMessageSnapshot(kPid, kTid, 0, &after_failed_copy) ||
                                    after_failed_copy.message_ticket != abandoned.message_ticket))
    {
        fail_code = 0x712;
        fail_message = "[gui-queue-selftest] FAIL abandoned claim dropped head";
    }

    // A peer wins the commit.  The stale consumer must fail, not remove the
    // next message that moved into the same ring position.
    GuiMessageClaim peer = after_failed_copy;
    if (fail_message == nullptr && (!GuiMessageCommit(peer, true) || GuiMessageCommit(after_failed_copy, true)))
    {
        fail_code = 0x713;
        fail_message = "[gui-queue-selftest] FAIL competing commit ABA";
    }

    GuiMessageClaim filtered{};
    if (fail_message == nullptr && (!GuiMessageSnapshot(kPid, kTid, kHwndB, &filtered) ||
                                    filtered.message.message != second.message || !GuiMessageCommit(filtered, true)))
    {
        fail_code = 0x714;
        fail_message = "[gui-queue-selftest] FAIL filtered order";
    }

    GuiMessageClaim before_zero_purge_claim{};
    GuiMessageProbeToken before_zero_purge_token{};
    if (fail_message == nullptr && (GuiMessageProbeQueue(kPid, kTid, 0, &before_zero_purge_claim,
                                                         &before_zero_purge_token) != GuiMessageProbeResult::Empty ||
                                    GuiMessagePurgeWindow(kPid, kTid, 0x43u) != 0 ||
                                    GuiMessageProbeTokenCurrent(kPid, kTid, before_zero_purge_token)))
    {
        fail_code = 0x71C;
        fail_message = "[gui-queue-selftest] FAIL zero-removal purge epoch";
    }

    // Fill exactly to the bound.  The next post must fail truthfully rather
    // than evicting the oldest entry.
    if (fail_message == nullptr)
    {
        for (u32 i = 0; i < kGuiTaskQueueDepth; ++i)
        {
            WindowMsg message{kHwndA, 0x500u + i, i, 0};
            if (!GuiMessagePost(kPid, kTid, message))
            {
                fail_code = 0x715;
                fail_message = "[gui-queue-selftest] FAIL fill";
                break;
            }
        }
        WindowMsg overflow{kHwndA, 0x5FFu, 0, 0};
        if (fail_message == nullptr && GuiMessagePost(kPid, kTid, overflow))
        {
            fail_code = 0x716;
            fail_message = "[gui-queue-selftest] FAIL overflow accepted";
        }
    }

    GuiMessageClaim before_reap{};
    if (fail_message == nullptr && !GuiMessageSnapshot(kPid, kTid, 0, &before_reap))
    {
        fail_code = 0x717;
        fail_message = "[gui-queue-selftest] FAIL pre-reap snapshot";
    }
    (void)GuiMessageReapTask(kPid, kTid);
    WindowMsg late_after_reap{kHwndA, 0x600u, 0, 0};
    if (fail_message == nullptr && GuiMessagePost(kPid, kTid, late_after_reap))
    {
        fail_code = 0x718;
        fail_message = "[gui-queue-selftest] FAIL reap resurrected queue";
    }
    if (fail_message == nullptr && (!GuiMessageEnsureQueue(kPid, kTid) || GuiMessageCommit(before_reap, true)))
    {
        fail_code = 0x719;
        fail_message = "[gui-queue-selftest] FAIL queue epoch reuse";
    }

    GuiMessageClaim before_empty_reap_claim{};
    GuiMessageProbeToken before_empty_reap_token{};
    const bool empty_reap_fixture = GuiMessageProbeQueue(kPid, kTid, 0, &before_empty_reap_claim,
                                                         &before_empty_reap_token) == GuiMessageProbeResult::Empty &&
                                    GuiMessageProbeTokenCurrent(kPid, kTid, before_empty_reap_token);
    const u32 empty_reap_discarded = GuiMessageReapTask(kPid, kTid);
    GuiMessageClaim gone_claim{};
    GuiMessageProbeToken gone_token{};
    if (fail_message == nullptr &&
        (!empty_reap_fixture || empty_reap_discarded != 0 ||
         GuiMessageProbeQueue(kPid, kTid, 0, &gone_claim, &gone_token) != GuiMessageProbeResult::Gone ||
         GuiMessageProbeTokenCurrent(kPid, kTid, before_empty_reap_token)))
    {
        fail_code = 0x71D;
        fail_message = "[gui-queue-selftest] FAIL empty reap gone probe";
    }

    u64 impossible_next_epoch = 0;
    if (fail_message == nullptr && NextEpoch(kMaxQueueEpoch, &impossible_next_epoch))
    {
        fail_code = 0x71E;
        fail_message = "[gui-queue-selftest] FAIL epoch overflow accepted";
    }

    if (fail_message != nullptr)
    {
        SerialWrite(fail_message);
        SerialWrite("\n");
        KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, fail_code);
        return;
    }

    g_queue_selftest_passed = true;
    SerialWrite("[gui-queue-selftest] PASS\n");
}

bool GuiMessageQueueSelfTestPassed()
{
    return g_queue_selftest_passed;
}

} // namespace duetos::drivers::video
