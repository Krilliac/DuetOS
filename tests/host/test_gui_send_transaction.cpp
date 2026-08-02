// Hosted state-machine, race, generation, ancestry, and concurrency coverage
// for drivers/video/gui_send_transaction.{h,cpp}.

#define DUETOS_HOST_TEST 1

#include "host_test_helper.h"
#include "drivers/video/gui_send_transaction.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstdlib>
#include <thread>
#include <vector>

#include "drivers/video/gui_send_transaction.cpp"

namespace
{

constexpr duetos::u32 kHostHeldLockCapacity = 4;
thread_local std::array<const duetos::sync::SpinLock*, kHostHeldLockCapacity> g_host_held_locks{};
thread_local duetos::u32 g_host_held_lock_count = 0;

bool HostLockIsHeld(const duetos::sync::SpinLock& lock)
{
    for (duetos::u32 index = 0; index < g_host_held_lock_count; ++index)
    {
        if (g_host_held_locks[index] == &lock)
            return true;
    }
    return false;
}

} // namespace

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock& lock)
{
    if (g_host_held_lock_count >= kHostHeldLockCapacity || HostLockIsHeld(lock))
        std::abort();

    u32& next_word = const_cast<u32&>(lock.next_ticket);
    u32& serving_word = const_cast<u32&>(lock.now_serving);
    std::atomic_ref<u32> next(next_word);
    std::atomic_ref<u32> serving(serving_word);
    const u32 ticket = next.fetch_add(1, std::memory_order_relaxed);
    while (serving.load(std::memory_order_acquire) != ticket)
        std::this_thread::yield();
    g_host_held_locks[g_host_held_lock_count++] = &lock;
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock& lock, IrqFlags)
{
    if (g_host_held_lock_count == 0 || g_host_held_locks[g_host_held_lock_count - 1] != &lock)
        std::abort();
    g_host_held_locks[--g_host_held_lock_count] = nullptr;

    u32& serving_word = const_cast<u32&>(lock.now_serving);
    std::atomic_ref<u32> serving(serving_word);
    (void)serving.fetch_add(1, std::memory_order_release);
}

void SpinLockAssertHeld(const SpinLock& lock)
{
    if (!HostLockIsHeld(lock))
        std::abort();
}

} // namespace duetos::sync

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::drivers::video;

GuiSendPrincipalSnapshot Principal(u64 endpoint, u64 process, u64 task)
{
    GuiSendPrincipalSnapshot principal{};
    principal.endpoint_identity = endpoint;
    principal.process_identity = process;
    principal.task_identity = task;
    return principal;
}

GuiSendTaskIdentity Task(const GuiSendPrincipalSnapshot& principal)
{
    return GuiSendTaskIdentity{principal.process_identity, principal.task_identity};
}

GuiSendFrozenCall Call(const GuiSendPrincipalSnapshot& sender, const GuiSendTaskIdentity& target, u64 request_sequence,
                       u64 deadline, GuiSendCallIdentity parent = kInvalidGuiSendCallIdentity, duetos::u8 depth = 0)
{
    GuiSendFrozenCall call{};
    call.parent_call = parent;
    call.sender_endpoint_identity = sender.endpoint_identity;
    call.sender_process_identity = sender.process_identity;
    call.sender_task_identity = sender.task_identity;
    call.target_process_identity = target.process_identity;
    call.target_task_identity = target.task_identity;
    call.target_window_identity = 0xABCDEF0100000000ULL | request_sequence;
    call.policy_authority_identity = 0x9000000000000000ULL | request_sequence;
    call.request_sequence = request_sequence;
    call.wparam = request_sequence ^ 0x55AAULL;
    call.lparam = request_sequence ^ 0xAA55ULL;
    call.absolute_deadline = deadline;
    call.message = 0x8000U + static_cast<u32>(request_sequence & 0xFFFULL);
    call.reentrancy_depth = depth;
    return call;
}

GuiSendCallIdentity BeginCreated(GuiSendTransactionTable& table, const GuiSendFrozenCall& call, u64 now)
{
    GuiSendCallIdentity identity{};
    EXPECT_EQ(table.Begin(call, now, &identity), GuiSendBeginResult::Created);
    EXPECT_TRUE(GuiSendCallIdentityIsValid(identity));
    return identity;
}

GuiSendDispatchClaim ClaimCreated(GuiSendTransactionTable& table, GuiSendCallIdentity identity,
                                  const GuiSendPrincipalSnapshot& dispatcher, u64 now)
{
    GuiSendDispatchClaim claim{};
    EXPECT_EQ(table.ClaimDispatch(identity, dispatcher, now, &claim), GuiSendDispatchResult::Claimed);
    EXPECT_TRUE(GuiSendDispatchTokenIsCanonical(claim.token));
    return claim;
}

GuiSendTransactionPhase Phase(GuiSendTransactionTable& table, GuiSendCallIdentity identity)
{
    GuiSendTransactionSnapshot snapshot{};
    if (!table.Inspect(identity, &snapshot))
        return GuiSendTransactionPhase::Vacant;
    return snapshot.phase;
}

} // namespace

int main()
{
    static_assert(duetos::sync::kLockClassGuiSendTransaction != duetos::sync::kLockClassUnclassified);

    {
        GuiSendTransactionTable table{};
        EXPECT_EQ(table.HostTransactionLockClass(), duetos::sync::kLockClassGuiSendTransaction);
    }

    const GuiSendPrincipalSnapshot caller_a = Principal(0xA001, 0xA101, 0xA201);
    const GuiSendPrincipalSnapshot target_b = Principal(0xB001, 0xB101, 0xB201);
    const GuiSendPrincipalSnapshot target_c = Principal(0xC001, 0xC101, 0xC201);

    EXPECT_TRUE(GuiSendCallIdentityIsValid(GuiSendCallIdentity{0, 0, 1}));
    EXPECT_FALSE(GuiSendCallIdentityIsValid(GuiSendCallIdentity{0, 1, 1}));
    EXPECT_FALSE(GuiSendCallIdentityIsValid(GuiSendCallIdentity{0, 0, 0}));
    EXPECT_FALSE(GuiSendCallIdentityIsValid(kInvalidGuiSendCallIdentity));
    EXPECT_TRUE(GuiSendPrincipalSnapshotIsCanonical(caller_a));
    GuiSendPrincipalSnapshot malformed_principal = caller_a;
    malformed_principal.endpoint_identity = 0;
    EXPECT_FALSE(GuiSendPrincipalSnapshotIsCanonical(malformed_principal));
    malformed_principal = caller_a;
    malformed_principal.reserved[7] = 1;
    EXPECT_FALSE(GuiSendPrincipalSnapshotIsCanonical(malformed_principal));
    EXPECT_TRUE(GuiSendTaskIdentityIsCanonical(Task(target_b)));
    EXPECT_FALSE(GuiSendTaskIdentityIsCanonical(GuiSendTaskIdentity{0, target_b.task_identity}));

    GuiSendFrozenCall canonical = Call(caller_a, Task(target_b), 1, 100);
    EXPECT_TRUE(GuiSendFrozenCallShapeIsCanonical(canonical));
    GuiSendFrozenCall malformed_call = canonical;
    malformed_call.target_window_identity = 0;
    EXPECT_FALSE(GuiSendFrozenCallShapeIsCanonical(malformed_call));
    malformed_call = canonical;
    malformed_call.message = 0x10000U;
    EXPECT_FALSE(GuiSendFrozenCallShapeIsCanonical(malformed_call));
    malformed_call = canonical;
    malformed_call.reserved[2] = 1;
    EXPECT_FALSE(GuiSendFrozenCallShapeIsCanonical(malformed_call));
    malformed_call = canonical;
    malformed_call.target_task_identity = caller_a.task_identity;
    EXPECT_FALSE(GuiSendFrozenCallShapeIsCanonical(malformed_call));
    malformed_call = canonical;
    malformed_call.parent_call = GuiSendCallIdentity{0, 0, 1};
    EXPECT_FALSE(GuiSendFrozenCallShapeIsCanonical(malformed_call));

    // Cross-task happy path freezes every trusted scalar, claims one exact
    // dispatcher endpoint, rejects wrong principals, and consumes once.
    {
        GuiSendTransactionTable table{};
        EXPECT_EQ(table.Begin(canonical, 1, nullptr), GuiSendBeginResult::Rejected);
        EXPECT_EQ(table.ActiveCount(), 0U);
        const GuiSendCallIdentity identity = BeginCreated(table, canonical, 1);
        EXPECT_EQ(identity.slot, 0U);
        EXPECT_EQ(identity.generation, 1ULL);
        EXPECT_EQ(table.ActiveCount(), 1U);
        GuiSendTransactionSnapshot snapshot{};
        EXPECT_TRUE(table.Inspect(identity, &snapshot));
        EXPECT_EQ(snapshot.phase, GuiSendTransactionPhase::Pending);
        EXPECT_EQ(snapshot.call.sender_endpoint_identity, caller_a.endpoint_identity);
        EXPECT_EQ(snapshot.call.target_window_identity, canonical.target_window_identity);
        EXPECT_EQ(snapshot.call.policy_authority_identity, canonical.policy_authority_identity);
        EXPECT_EQ(snapshot.call.request_sequence, canonical.request_sequence);
        EXPECT_EQ(snapshot.call.absolute_deadline, canonical.absolute_deadline);
        GuiSendCallIdentity duplicate{};
        EXPECT_EQ(table.Begin(canonical, 1, &duplicate), GuiSendBeginResult::DuplicateRequest);
        EXPECT_EQ(duplicate, kInvalidGuiSendCallIdentity);
        EXPECT_EQ(table.ClaimDispatch(identity, target_b, 2, nullptr), GuiSendDispatchResult::Rejected);
        GuiSendCompletion premature{};
        premature.valid = 1;
        EXPECT_EQ(table.Consume(identity, caller_a, &premature), GuiSendConsumeResult::NotReady);
        EXPECT_EQ(premature.valid, 0U);
        EXPECT_EQ(table.RetireAbandoned(identity), GuiSendRetireResult::NotTerminal);

        GuiSendDispatchClaim rejected_claim{};
        rejected_claim.token.valid = 1;
        EXPECT_EQ(table.ClaimDispatch(identity, target_c, 2, &rejected_claim), GuiSendDispatchResult::WrongPrincipal);
        EXPECT_EQ(rejected_claim.token.valid, 0U);

        const GuiSendDispatchClaim claim = ClaimCreated(table, identity, target_b, 2);
        EXPECT_EQ(claim.call.wparam, canonical.wparam);
        EXPECT_EQ(claim.call.lparam, canonical.lparam);
        GuiSendDispatchToken malformed_token = claim.token;
        malformed_token.reserved[0] = 1;
        EXPECT_FALSE(GuiSendDispatchTokenIsCanonical(malformed_token));
        EXPECT_EQ(table.CommitReply(malformed_token, target_b, 3, 0x1234), GuiSendReplyResult::Rejected);
        malformed_token = claim.token;
        malformed_token.valid = 2;
        EXPECT_FALSE(GuiSendDispatchTokenIsCanonical(malformed_token));
        EXPECT_EQ(table.ClaimDispatch(identity, target_b, 3, &rejected_claim), GuiSendDispatchResult::NotPending);

        GuiSendPrincipalSnapshot wrong_endpoint = target_b;
        ++wrong_endpoint.endpoint_identity;
        EXPECT_EQ(table.CommitReply(claim.token, wrong_endpoint, 3, 0x1234), GuiSendReplyResult::WrongPrincipal);
        GuiSendDispatchToken wrong_token = claim.token;
        ++wrong_token.request_sequence;
        EXPECT_EQ(table.CommitReply(wrong_token, target_b, 3, 0x1234), GuiSendReplyResult::WrongClaim);
        EXPECT_EQ(table.CommitReply(claim.token, target_b, 3, 0x12345678), GuiSendReplyResult::Committed);
        EXPECT_EQ(Phase(table, identity), GuiSendTransactionPhase::ReplyReady);
        EXPECT_EQ(table.CommitReply(claim.token, target_b, 4, 0), GuiSendReplyResult::Terminal);
        EXPECT_EQ(table.CancelByCaller(identity, caller_a), GuiSendCancelResult::TooLate);

        GuiSendCompletion completion{};
        completion.valid = 1;
        GuiSendPrincipalSnapshot wrong_caller = caller_a;
        ++wrong_caller.endpoint_identity;
        EXPECT_EQ(table.Consume(identity, wrong_caller, &completion), GuiSendConsumeResult::WrongPrincipal);
        EXPECT_EQ(completion.valid, 0U);
        EXPECT_EQ(table.Consume(identity, caller_a, &completion), GuiSendConsumeResult::Consumed);
        EXPECT_EQ(completion.valid, 1U);
        EXPECT_EQ(completion.phase, GuiSendTransactionPhase::ReplyReady);
        EXPECT_EQ(completion.request_sequence, canonical.request_sequence);
        EXPECT_EQ(completion.reply_value, 0x12345678ULL);
        EXPECT_EQ(Phase(table, identity), GuiSendTransactionPhase::Retired);
        EXPECT_EQ(table.Consume(identity, caller_a, &completion), GuiSendConsumeResult::Stale);
        EXPECT_EQ(table.ActiveCount(), 0U);
    }

    // Same-task and same-process/cross-task routes are representable. An
    // identical task generation under a different process is malformed.
    {
        GuiSendTransactionTable table{};
        GuiSendFrozenCall same_task = Call(caller_a, Task(caller_a), 2, 100);
        EXPECT_TRUE(GuiSendFrozenCallShapeIsCanonical(same_task));
        const GuiSendCallIdentity same_id = BeginCreated(table, same_task, 1);
        const GuiSendDispatchClaim same_claim = ClaimCreated(table, same_id, caller_a, 2);
        EXPECT_EQ(table.CommitReply(same_claim.token, caller_a, 3, 7), GuiSendReplyResult::Committed);
        GuiSendCompletion completion{};
        EXPECT_EQ(table.Consume(same_id, caller_a, &completion), GuiSendConsumeResult::Consumed);

        const GuiSendPrincipalSnapshot sibling = Principal(0xA002, caller_a.process_identity, 0xA202);
        GuiSendFrozenCall cross_task = Call(caller_a, Task(sibling), 3, 100);
        EXPECT_TRUE(GuiSendFrozenCallShapeIsCanonical(cross_task));
        const GuiSendCallIdentity cross_id = BeginCreated(table, cross_task, 1);
        const GuiSendDispatchClaim cross_claim = ClaimCreated(table, cross_id, sibling, 2);
        EXPECT_EQ(table.CommitReply(cross_claim.token, sibling, 3, 8), GuiSendReplyResult::Committed);
        EXPECT_EQ(table.Consume(cross_id, caller_a, &completion), GuiSendConsumeResult::Consumed);
    }

    // Cancellation wins against a late reply, preserves exact caller
    // authority, and reaches Retired only through consume/abandon.
    {
        GuiSendTransactionTable table{};
        GuiSendFrozenCall call = Call(caller_a, Task(target_b), 4, 100);
        const GuiSendCallIdentity identity = BeginCreated(table, call, 1);
        GuiSendPrincipalSnapshot wrong_caller = caller_a;
        ++wrong_caller.task_identity;
        EXPECT_EQ(table.CancelByCaller(identity, wrong_caller), GuiSendCancelResult::WrongPrincipal);
        const GuiSendDispatchClaim claim = ClaimCreated(table, identity, target_b, 2);
        EXPECT_EQ(table.CancelByCaller(identity, caller_a), GuiSendCancelResult::Cancelled);
        EXPECT_EQ(table.CommitReply(claim.token, target_b, 3, 9), GuiSendReplyResult::Terminal);
        EXPECT_EQ(Phase(table, identity), GuiSendTransactionPhase::Cancelled);
        GuiSendCompletion completion{};
        EXPECT_EQ(table.Consume(identity, caller_a, &completion), GuiSendConsumeResult::Consumed);
        EXPECT_EQ(completion.phase, GuiSendTransactionPhase::Cancelled);
        EXPECT_EQ(completion.reply_value, 0ULL);

        call.request_sequence = 5;
        const GuiSendCallIdentity pending = BeginCreated(table, call, 1);
        EXPECT_EQ(table.CancelByCaller(pending, caller_a), GuiSendCancelResult::Cancelled);
        EXPECT_EQ(table.RetireAbandoned(pending), GuiSendRetireResult::Retired);
        EXPECT_EQ(table.RetireAbandoned(pending), GuiSendRetireResult::Stale);

        GuiSendTransactionTable nested_table{};
        const GuiSendCallIdentity root = BeginCreated(nested_table, Call(caller_a, Task(target_b), 50, 1000), 1);
        (void)ClaimCreated(nested_table, root, target_b, 2);
        const GuiSendCallIdentity child =
            BeginCreated(nested_table, Call(target_b, Task(target_c), 51, 900, root, 1), 3);
        const GuiSendDispatchClaim child_claim = ClaimCreated(nested_table, child, target_c, 4);
        EXPECT_EQ(nested_table.CommitReply(child_claim.token, target_c, 5, 10), GuiSendReplyResult::Committed);
        EXPECT_EQ(nested_table.CancelByCaller(root, caller_a), GuiSendCancelResult::Cancelled);
        EXPECT_EQ(Phase(nested_table, root), GuiSendTransactionPhase::Cancelled);
        EXPECT_EQ(Phase(nested_table, child), GuiSendTransactionPhase::ReplyReady);
        EXPECT_EQ(nested_table.Consume(child, target_b, &completion), GuiSendConsumeResult::Consumed);
        EXPECT_EQ(nested_table.Consume(root, caller_a, &completion), GuiSendConsumeResult::Consumed);
    }

    // Deadline checks linearize at begin, claim, timer, and commit.
    {
        GuiSendTransactionTable table{};
        GuiSendCallIdentity invalid{};
        GuiSendFrozenCall elapsed = Call(caller_a, Task(target_b), 6, 10);
        EXPECT_EQ(table.Begin(elapsed, 10, &invalid), GuiSendBeginResult::DeadlineElapsed);
        EXPECT_EQ(invalid, kInvalidGuiSendCallIdentity);

        GuiSendFrozenCall pending_call = Call(caller_a, Task(target_b), 7, 20);
        const GuiSendCallIdentity pending = BeginCreated(table, pending_call, 1);
        EXPECT_EQ(table.TimeoutAt(pending, 19), GuiSendTimeoutResult::NotDue);
        EXPECT_EQ(table.TimeoutAt(pending, 20), GuiSendTimeoutResult::TimedOut);
        EXPECT_EQ(table.TimeoutAt(pending, 21), GuiSendTimeoutResult::TooLate);
        GuiSendCompletion completion{};
        EXPECT_EQ(table.Consume(pending, caller_a, &completion), GuiSendConsumeResult::Consumed);
        EXPECT_EQ(completion.phase, GuiSendTransactionPhase::TimedOut);

        GuiSendFrozenCall claim_expired = Call(caller_a, Task(target_b), 8, 30);
        const GuiSendCallIdentity expired_id = BeginCreated(table, claim_expired, 1);
        GuiSendDispatchClaim expired_claim{};
        EXPECT_EQ(table.ClaimDispatch(expired_id, target_b, 30, &expired_claim), GuiSendDispatchResult::TimedOut);
        EXPECT_EQ(expired_claim.token.valid, 0U);
        EXPECT_EQ(table.RetireAbandoned(expired_id), GuiSendRetireResult::Retired);

        GuiSendFrozenCall reply_expired = Call(caller_a, Task(target_b), 9, 40);
        const GuiSendCallIdentity reply_id = BeginCreated(table, reply_expired, 1);
        const GuiSendDispatchClaim reply_claim = ClaimCreated(table, reply_id, target_b, 2);
        EXPECT_EQ(table.CommitReply(reply_claim.token, target_b, 40, 1), GuiSendReplyResult::TimedOut);
        EXPECT_EQ(Phase(table, reply_id), GuiSendTransactionPhase::TimedOut);
    }

    // Exact parent ancestry permits bounded acyclic reentrancy, refuses an
    // active sibling, cycles, inconsistent depth, stale parents, and deadline
    // extension. Parents cannot reply until their child is consumed.
    {
        GuiSendTransactionTable table{};
        GuiSendFrozenCall root_call = Call(caller_a, Task(target_b), 10, 1000);
        const GuiSendCallIdentity root = BeginCreated(table, root_call, 1);
        const GuiSendDispatchClaim root_claim = ClaimCreated(table, root, target_b, 2);

        GuiSendFrozenCall child_call = Call(target_b, Task(target_c), 11, 900, root, 1);
        const GuiSendCallIdentity child = BeginCreated(table, child_call, 3);
        GuiSendCallIdentity rejected{};
        GuiSendFrozenCall sibling_call = child_call;
        sibling_call.request_sequence = 12;
        EXPECT_EQ(table.Begin(sibling_call, 3, &rejected), GuiSendBeginResult::ParentUnavailable);
        EXPECT_EQ(rejected, kInvalidGuiSendCallIdentity);

        GuiSendFrozenCall cycle_call = Call(target_b, Task(caller_a), 13, 900, root, 1);
        EXPECT_EQ(table.Begin(cycle_call, 3, &rejected), GuiSendBeginResult::Cycle);
        GuiSendFrozenCall wrong_depth = child_call;
        wrong_depth.request_sequence = 14;
        wrong_depth.reentrancy_depth = 2;
        EXPECT_EQ(table.Begin(wrong_depth, 3, &rejected), GuiSendBeginResult::DepthMismatch);
        GuiSendFrozenCall extended = child_call;
        extended.request_sequence = 15;
        extended.absolute_deadline = 1001;
        EXPECT_EQ(table.Begin(extended, 3, &rejected), GuiSendBeginResult::ParentUnavailable);

        const GuiSendDispatchClaim child_claim = ClaimCreated(table, child, target_c, 4);
        EXPECT_EQ(table.CommitReply(root_claim.token, target_b, 5, 1), GuiSendReplyResult::ActiveChild);
        EXPECT_EQ(table.CommitReply(child_claim.token, target_c, 5, 2), GuiSendReplyResult::Committed);
        GuiSendCompletion child_completion{};
        EXPECT_EQ(table.Consume(child, target_b, &child_completion), GuiSendConsumeResult::Consumed);
        EXPECT_EQ(table.CommitReply(root_claim.token, target_b, 6, 3), GuiSendReplyResult::Committed);
        GuiSendCompletion root_completion{};
        EXPECT_EQ(table.Consume(root, caller_a, &root_completion), GuiSendConsumeResult::Consumed);

        GuiSendFrozenCall stale_child = Call(target_b, Task(target_c), 16, 900, root, 1);
        EXPECT_EQ(table.Begin(stale_child, 3, &rejected), GuiSendBeginResult::ParentUnavailable);
    }

    // A full valid chain reaches the declared bound. One more nested call is
    // rejected before any row reservation, and root cancellation cascades
    // through every exact descendant.
    {
        GuiSendTransactionTable table{};
        std::array<GuiSendPrincipalSnapshot, kGuiSendMaximumReentrancyDepth + 2> principals{};
        for (u32 index = 0; index < static_cast<u32>(principals.size()); ++index)
            principals[index] = Principal(0x1000ULL + index, 0x2000ULL + index, 0x3000ULL + index);

        std::array<GuiSendCallIdentity, kGuiSendMaximumReentrancyDepth + 1> identities{};
        for (u32 depth = 0; depth <= static_cast<u32>(kGuiSendMaximumReentrancyDepth); ++depth)
        {
            const GuiSendCallIdentity parent = depth == 0 ? kInvalidGuiSendCallIdentity : identities[depth - 1];
            GuiSendFrozenCall call = Call(principals[depth], Task(principals[depth + 1]), 100ULL + depth,
                                          2000ULL - depth, parent, static_cast<duetos::u8>(depth));
            identities[depth] = BeginCreated(table, call, 1);
            (void)ClaimCreated(table, identities[depth], principals[depth + 1], 2);
        }

        GuiSendFrozenCall too_deep = Call(principals[kGuiSendMaximumReentrancyDepth + 1], Task(caller_a), 200, 1000,
                                          identities[kGuiSendMaximumReentrancyDepth],
                                          static_cast<duetos::u8>(kGuiSendMaximumReentrancyDepth + 1U));
        GuiSendCallIdentity rejected{};
        EXPECT_EQ(table.Begin(too_deep, 3, &rejected), GuiSendBeginResult::DepthMismatch);
        EXPECT_EQ(table.CancelByCaller(identities[0], principals[0]), GuiSendCancelResult::Cancelled);
        EXPECT_EQ(table.ActiveCount(), static_cast<u32>(identities.size()));
        for (u32 depth = 0; depth < static_cast<u32>(identities.size()); ++depth)
        {
            EXPECT_EQ(Phase(table, identities[depth]), GuiSendTransactionPhase::Cancelled);
            GuiSendCompletion completion{};
            EXPECT_EQ(table.Consume(identities[depth], principals[depth], &completion), GuiSendConsumeResult::Consumed);
        }
        EXPECT_EQ(table.ActiveCount(), 0U);
    }

    // Caller and target death use exact opaque generations and cancel active
    // descendants without callbacks under the table lock.
    {
        GuiSendTransactionTable table{};
        const GuiSendCallIdentity root = BeginCreated(table, Call(caller_a, Task(target_b), 300, 1000), 1);
        (void)ClaimCreated(table, root, target_b, 2);
        const GuiSendCallIdentity child = BeginCreated(table, Call(target_b, Task(target_c), 301, 900, root, 1), 3);
        EXPECT_EQ(table.CancelCallerDeath(
                      Principal(caller_a.endpoint_identity + 1, caller_a.process_identity, caller_a.task_identity)),
                  0U);
        EXPECT_EQ(table.CancelCallerDeath(caller_a), 2U);
        EXPECT_EQ(Phase(table, root), GuiSendTransactionPhase::Cancelled);
        EXPECT_EQ(Phase(table, child), GuiSendTransactionPhase::Cancelled);

        GuiSendTransactionTable target_table{};
        const GuiSendCallIdentity target_call =
            BeginCreated(target_table, Call(caller_a, Task(target_b), 302, 1000), 1);
        EXPECT_EQ(target_table.CancelTargetDeath(Task(target_c)), 0U);
        EXPECT_EQ(target_table.CancelTargetDeath(Task(target_b)), 1U);
        EXPECT_EQ(Phase(target_table, target_call), GuiSendTransactionPhase::Cancelled);
    }

    // Retired reuse increments the exact generation. Old dispatch tokens,
    // caller operations, and fabricated generations cannot affect the row.
    {
        GuiSendTransactionTable table{};
        GuiSendFrozenCall first_call = Call(caller_a, Task(target_b), 400, 1000);
        const GuiSendCallIdentity first = BeginCreated(table, first_call, 1);
        const GuiSendDispatchClaim first_claim = ClaimCreated(table, first, target_b, 2);
        EXPECT_EQ(table.CancelByCaller(first, caller_a), GuiSendCancelResult::Cancelled);
        GuiSendCompletion completion{};
        EXPECT_EQ(table.Consume(first, caller_a, &completion), GuiSendConsumeResult::Consumed);

        GuiSendFrozenCall second_call = Call(caller_a, Task(target_b), 401, 1000);
        const GuiSendCallIdentity second = BeginCreated(table, second_call, 1);
        EXPECT_EQ(second.slot, first.slot);
        EXPECT_EQ(second.generation, first.generation + 1);
        EXPECT_EQ(table.CommitReply(first_claim.token, target_b, 3, 1), GuiSendReplyResult::Stale);
        EXPECT_EQ(table.CancelByCaller(first, caller_a), GuiSendCancelResult::Stale);
        GuiSendCallIdentity fabricated = second;
        ++fabricated.generation;
        EXPECT_FALSE(table.Inspect(fabricated, nullptr));
        GuiSendTransactionSnapshot snapshot{};
        EXPECT_FALSE(table.Inspect(fabricated, &snapshot));
        GuiSendDispatchClaim stale_claim{};
        stale_claim.token.valid = 1;
        EXPECT_EQ(table.ClaimDispatch(fabricated, target_b, 3, &stale_claim), GuiSendDispatchResult::Stale);
        EXPECT_EQ(stale_claim.token.valid, 0U);
        EXPECT_EQ(table.CancelByCaller(fabricated, caller_a), GuiSendCancelResult::Stale);
        EXPECT_EQ(table.TimeoutAt(fabricated, 1000), GuiSendTimeoutResult::Stale);
        GuiSendCompletion stale_completion{};
        stale_completion.valid = 1;
        EXPECT_EQ(table.Consume(fabricated, caller_a, &stale_completion), GuiSendConsumeResult::Stale);
        EXPECT_EQ(stale_completion.valid, 0U);
    }

    // Capacity is truthful: no eviction, implicit retirement, or overwrite.
    {
        GuiSendTransactionTable table{};
        std::array<GuiSendCallIdentity, kGuiSendTransactionCapacity> identities{};
        for (u32 index = 0; index < kGuiSendTransactionCapacity; ++index)
        {
            identities[index] = BeginCreated(table, Call(caller_a, Task(target_b), 500ULL + index, 1000), 1);
        }
        EXPECT_EQ(table.ActiveCount(), kGuiSendTransactionCapacity);
        GuiSendCallIdentity overflow{};
        EXPECT_EQ(table.Begin(Call(caller_a, Task(target_b), 999, 1000), 1, &overflow), GuiSendBeginResult::TableFull);
        EXPECT_EQ(overflow, kInvalidGuiSendCallIdentity);
        for (GuiSendCallIdentity identity : identities)
        {
            EXPECT_EQ(table.CancelByCaller(identity, caller_a), GuiSendCancelResult::Cancelled);
            EXPECT_EQ(table.RetireAbandoned(identity), GuiSendRetireResult::Retired);
        }
    }

    // The terminal generation is usable exactly once and never wraps. Fully
    // exhausted storage reports generation exhaustion distinctly from load.
    {
        GuiSendTransactionTable table{};
        EXPECT_TRUE(table.HostPositionInactiveGeneration(0, kGuiSendGenerationMaximum - 1));
        const GuiSendCallIdentity terminal = BeginCreated(table, Call(caller_a, Task(target_b), 600, 1000), 1);
        EXPECT_EQ(terminal.slot, 0U);
        EXPECT_EQ(terminal.generation, kGuiSendGenerationMaximum);
        EXPECT_EQ(table.CancelByCaller(terminal, caller_a), GuiSendCancelResult::Cancelled);
        EXPECT_EQ(table.RetireAbandoned(terminal), GuiSendRetireResult::Retired);
        const GuiSendCallIdentity next = BeginCreated(table, Call(caller_a, Task(target_b), 601, 1000), 1);
        EXPECT_NE(next.slot, terminal.slot);

        GuiSendTransactionTable exhausted{};
        for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
            EXPECT_TRUE(exhausted.HostPositionInactiveGeneration(slot, kGuiSendGenerationMaximum));
        GuiSendCallIdentity rejected{};
        EXPECT_EQ(exhausted.Begin(Call(caller_a, Task(target_b), 602, 1000), 1, &rejected),
                  GuiSendBeginResult::GenerationExhausted);
        EXPECT_EQ(rejected, kInvalidGuiSendCallIdentity);
    }

    // Barrier-synchronized cancel-vs-complete: exactly one terminal result
    // wins the table lock and the loser observes that terminal state.
    for (u32 iteration = 0; iteration < 128; ++iteration)
    {
        GuiSendTransactionTable table{};
        const GuiSendCallIdentity identity =
            BeginCreated(table, Call(caller_a, Task(target_b), 1000ULL + iteration, 10000), 1);
        const GuiSendDispatchClaim claim = ClaimCreated(table, identity, target_b, 2);
        std::barrier start(3);
        GuiSendCancelResult cancel_result = GuiSendCancelResult::Rejected;
        GuiSendReplyResult reply_result = GuiSendReplyResult::Rejected;
        std::thread cancel_thread(
            [&]()
            {
                start.arrive_and_wait();
                cancel_result = table.CancelByCaller(identity, caller_a);
            });
        std::thread reply_thread(
            [&]()
            {
                start.arrive_and_wait();
                reply_result = table.CommitReply(claim.token, target_b, 3, iteration);
            });
        start.arrive_and_wait();
        cancel_thread.join();
        reply_thread.join();
        const bool cancel_won =
            cancel_result == GuiSendCancelResult::Cancelled && reply_result == GuiSendReplyResult::Terminal;
        const bool reply_won =
            reply_result == GuiSendReplyResult::Committed && cancel_result == GuiSendCancelResult::TooLate;
        EXPECT_TRUE(cancel_won || reply_won);
        EXPECT_EQ(Phase(table, identity),
                  cancel_won ? GuiSendTransactionPhase::Cancelled : GuiSendTransactionPhase::ReplyReady);
        GuiSendCompletion completion{};
        EXPECT_EQ(table.Consume(identity, caller_a, &completion), GuiSendConsumeResult::Consumed);
    }

    // Timeout-vs-dispatch: timeout always linearizes by the deadline; dispatch
    // either claimed just before it or observes the already-terminal row.
    for (u32 iteration = 0; iteration < 128; ++iteration)
    {
        GuiSendTransactionTable table{};
        const GuiSendCallIdentity identity =
            BeginCreated(table, Call(caller_a, Task(target_b), 2000ULL + iteration, 100), 1);
        std::barrier start(3);
        GuiSendDispatchResult dispatch_result = GuiSendDispatchResult::Rejected;
        GuiSendTimeoutResult timeout_result = GuiSendTimeoutResult::Rejected;
        GuiSendDispatchClaim claim{};
        std::thread dispatch_thread(
            [&]()
            {
                start.arrive_and_wait();
                dispatch_result = table.ClaimDispatch(identity, target_b, 99, &claim);
            });
        std::thread timeout_thread(
            [&]()
            {
                start.arrive_and_wait();
                timeout_result = table.TimeoutAt(identity, 100);
            });
        start.arrive_and_wait();
        dispatch_thread.join();
        timeout_thread.join();
        EXPECT_EQ(timeout_result, GuiSendTimeoutResult::TimedOut);
        EXPECT_TRUE(dispatch_result == GuiSendDispatchResult::Claimed ||
                    dispatch_result == GuiSendDispatchResult::NotPending);
        EXPECT_EQ(Phase(table, identity), GuiSendTransactionPhase::TimedOut);
        if (dispatch_result == GuiSendDispatchResult::Claimed)
            EXPECT_EQ(table.CommitReply(claim.token, target_b, 99, 1), GuiSendReplyResult::Terminal);
        EXPECT_EQ(table.RetireAbandoned(identity), GuiSendRetireResult::Retired);
    }

    // Concurrent churn keeps at most one live call per worker, while mixing
    // cancel, reply, timeout, and death transitions through the shared table.
    {
        GuiSendTransactionTable table{};
        constexpr u32 kThreadCount = 8;
        constexpr u32 kIterations = 2000;
        std::atomic<u64> next_sequence{10000};
        std::atomic<u32> errors{0};
        std::vector<std::thread> threads;
        threads.reserve(kThreadCount);
        for (u32 worker = 0; worker < kThreadCount; ++worker)
        {
            threads.emplace_back(
                [&, worker]()
                {
                    const GuiSendPrincipalSnapshot sender =
                        Principal(0x100000ULL + worker, 0x200000ULL + worker, 0x300000ULL + worker);
                    const GuiSendPrincipalSnapshot target =
                        Principal(0x400000ULL + worker, 0x500000ULL + worker, 0x600000ULL + worker);
                    for (u32 iteration = 0; iteration < kIterations; ++iteration)
                    {
                        const u64 sequence = next_sequence.fetch_add(1, std::memory_order_relaxed);
                        const u64 deadline = sequence + 1000ULL;
                        GuiSendCallIdentity identity{};
                        if (table.Begin(Call(sender, Task(target), sequence, deadline), sequence, &identity) !=
                            GuiSendBeginResult::Created)
                        {
                            errors.fetch_add(1, std::memory_order_relaxed);
                            continue;
                        }

                        if ((iteration & 3U) == 0)
                        {
                            if (table.CancelByCaller(identity, sender) != GuiSendCancelResult::Cancelled)
                                errors.fetch_add(1, std::memory_order_relaxed);
                        }
                        else
                        {
                            GuiSendDispatchClaim claim{};
                            if (table.ClaimDispatch(identity, target, sequence, &claim) !=
                                GuiSendDispatchResult::Claimed)
                            {
                                errors.fetch_add(1, std::memory_order_relaxed);
                                continue;
                            }
                            if ((iteration & 3U) == 1)
                            {
                                if (table.CommitReply(claim.token, target, sequence, sequence) !=
                                    GuiSendReplyResult::Committed)
                                {
                                    errors.fetch_add(1, std::memory_order_relaxed);
                                }
                            }
                            else if ((iteration & 3U) == 2)
                            {
                                if (table.TimeoutAt(identity, deadline) != GuiSendTimeoutResult::TimedOut)
                                    errors.fetch_add(1, std::memory_order_relaxed);
                            }
                            else if (table.CancelCallerDeath(sender) == 0)
                            {
                                errors.fetch_add(1, std::memory_order_relaxed);
                            }
                        }

                        GuiSendCompletion completion{};
                        if (table.Consume(identity, sender, &completion) != GuiSendConsumeResult::Consumed ||
                            completion.valid != 1)
                        {
                            errors.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                });
        }
        for (std::thread& thread : threads)
            thread.join();
        EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(table.ActiveCount(), 0U);
    }

    return duetos_host_test::finish_main("test_gui_send_transaction");
}
