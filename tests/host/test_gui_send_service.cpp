// Hosted ownership, FIFO, pump, deadline, cancellation, death, ABA, model,
// and concurrency coverage for drivers/video/gui_send_service.{h,cpp}.

#define DUETOS_HOST_TEST 1

#include "host_test_helper.h"
#include "drivers/video/gui_send_service.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstdlib>
#include <thread>
#include <vector>

#include "drivers/video/gui_send_transaction.cpp"
#include "drivers/video/gui_send_service.cpp"

namespace
{

constexpr duetos::u32 kHostHeldLockCapacity = 8;
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

GuiSendTaskEndpointIdentity EnsureEndpoint(GuiSendService& service, u64 process, u64 task)
{
    GuiSendTaskEndpointIdentity endpoint{};
    EXPECT_EQ(service.EnsureTaskEndpoint(process, task, &endpoint), GuiSendEndpointResult::Created);
    EXPECT_TRUE(GuiSendTaskEndpointIdentityIsCanonical(endpoint));
    return endpoint;
}

GuiSendServiceBeginRequest Request(GuiSendTaskEndpointIdentity caller, GuiSendTaskEndpointIdentity target, u64 hwnd,
                                   u32 message, u64 deadline,
                                   GuiSendServiceDispatchToken parent = kInvalidGuiSendServiceDispatchToken)
{
    GuiSendServiceBeginRequest request{};
    request.caller_endpoint = caller;
    request.target_endpoint = target;
    request.parent_dispatch = parent;
    request.target_window_identity = hwnd;
    request.wparam = hwnd ^ 0x55AA55AA55AA55AAULL;
    request.lparam = hwnd ^ 0xAA55AA55AA55AA55ULL;
    request.absolute_deadline = deadline;
    request.message = message;
    return request;
}

GuiSendServiceBeginOutput BeginCreated(GuiSendService& service, const GuiSendServiceBeginRequest& request, u64 now = 1)
{
    GuiSendServiceBeginOutput output{};
    EXPECT_EQ(service.Begin(request, now, &output), GuiSendServiceBeginResult::Created);
    EXPECT_TRUE(GuiSendServiceCallIdentityIsCanonical(output.call));
    EXPECT_TRUE(output.request_sequence != 0);
    EXPECT_EQ(output.wake.wake_all, 1U);
    return output;
}

GuiSendServicePumpOutput PumpDispatch(GuiSendService& service, GuiSendTaskEndpointIdentity endpoint, u64 now = 2)
{
    GuiSendServicePumpOutput output{};
    EXPECT_EQ(service.Pump(endpoint, kInvalidGuiSendServiceCallIdentity, now, &output),
              GuiSendServicePumpResult::Pumped);
    EXPECT_EQ(output.kind, GuiSendServicePumpKind::Dispatch);
    EXPECT_TRUE(GuiSendServiceDispatchTokenIsCanonical(output.dispatch.reply_token));
    return output;
}

GuiSendServiceCompletion PumpCompletion(GuiSendService& service, GuiSendTaskEndpointIdentity endpoint,
                                        GuiSendServiceCallIdentity call, u64 now = 3)
{
    GuiSendServicePumpOutput output{};
    EXPECT_EQ(service.Pump(endpoint, call, now, &output), GuiSendServicePumpResult::Pumped);
    EXPECT_EQ(output.kind, GuiSendServicePumpKind::Completion);
    EXPECT_EQ(output.completion.valid, 1U);
    EXPECT_EQ(output.completion.call, call);
    return output.completion;
}

void CommitReply(GuiSendService& service, GuiSendTaskEndpointIdentity endpoint,
                 const GuiSendServiceDispatchToken& token, u64 reply, u64 now = 3)
{
    GuiSendServiceWakeAction wake{};
    EXPECT_EQ(service.CommitReply(endpoint, token, now, reply, &wake), GuiSendServiceReplyResult::Committed);
    EXPECT_EQ(wake.wake_all, 1U);
}

} // namespace

int main()
{
    static_assert(duetos::sync::kLockClassGuiSendService != duetos::sync::kLockClassGuiSendTransaction);

    // Endpoint encoding is canonical, biased, generation-tagged, idempotent,
    // and refuses malformed/global-TID aliases.
    {
        GuiSendService service{};
        EXPECT_EQ(service.HostServiceLockClass(), duetos::sync::kLockClassGuiSendService);
        GuiSendTaskEndpointIdentity endpoint{};
        EXPECT_FALSE(GuiSendTaskEndpointIdentityIsCanonical(kInvalidGuiSendTaskEndpoint));
        EXPECT_EQ(service.EnsureTaskEndpoint(0, 1, &endpoint), GuiSendEndpointResult::Rejected);
        EXPECT_EQ(service.EnsureTaskEndpoint(1, 0, &endpoint), GuiSendEndpointResult::Rejected);
        EXPECT_EQ(service.EnsureTaskEndpoint(1, static_cast<u64>(-1), &endpoint), GuiSendEndpointResult::Rejected);
        EXPECT_EQ(service.EnsureTaskEndpoint(1, 1, nullptr), GuiSendEndpointResult::Rejected);

        const GuiSendTaskEndpointIdentity first = EnsureEndpoint(service, 0x100, 0x101);
        EXPECT_EQ(GuiSendTaskEndpointSlot(first), 0U);
        EXPECT_EQ(GuiSendTaskEndpointGeneration(first), 1ULL);
        EXPECT_EQ(service.EnsureTaskEndpoint(0x100, 0x101, &endpoint), GuiSendEndpointResult::Existing);
        EXPECT_EQ(endpoint, first);
        EXPECT_EQ(service.EnsureTaskEndpoint(0x200, 0x101, &endpoint), GuiSendEndpointResult::Rejected);
        EXPECT_EQ(service.ActiveEndpointCount(), 1U);
    }

    // Every public capability is scoped to one non-reused service
    // incarnation. Fresh tables intentionally collide in their inner slot and
    // generation values; cross-instance endpoints, calls, wait tokens, and
    // dispatch proofs must still fail closed.
    {
        GuiSendService left{};
        GuiSendService right{};
        const auto left_caller = EnsureEndpoint(left, 0x1800, 0x1801);
        const auto left_target = EnsureEndpoint(left, 0x1800, 0x1802);
        const auto right_caller = EnsureEndpoint(right, 0x1800, 0x1801);
        const auto right_target = EnsureEndpoint(right, 0x1800, 0x1802);
        EXPECT_NE(left_caller.service_incarnation, right_caller.service_incarnation);
        EXPECT_EQ(left_caller.value, right_caller.value);

        GuiSendServicePumpOutput left_idle{};
        EXPECT_EQ(left.Pump(left_target, kInvalidGuiSendServiceCallIdentity, 1, &left_idle),
                  GuiSendServicePumpResult::Pumped);
        EXPECT_TRUE(left.WaitTokenCurrent(left_idle.wait_token));
        EXPECT_FALSE(right.WaitTokenCurrent(left_idle.wait_token));

        const auto left_call = BeginCreated(left, Request(left_caller, left_target, 0x1810, 0x101, 100));
        const auto right_call = BeginCreated(right, Request(right_caller, right_target, 0x1810, 0x101, 100));
        EXPECT_EQ(left_call.call.slot, right_call.call.slot);
        EXPECT_EQ(left_call.call.generation, right_call.call.generation);
        EXPECT_NE(left_call.call.service_incarnation, right_call.call.service_incarnation);

        GuiSendServiceCallSnapshot snapshot{};
        EXPECT_FALSE(right.InspectCall(left_call.call, &snapshot));
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(right.Cancel(right_caller, left_call.call, &wake), GuiSendServiceCancelResult::Stale);
        GuiSendServicePumpOutput cross_wait{};
        EXPECT_EQ(right.Pump(right_caller, left_call.call, 2, &cross_wait), GuiSendServicePumpResult::WaitingCallStale);

        const auto left_dispatch = PumpDispatch(left, left_target, 2);
        const auto right_dispatch = PumpDispatch(right, right_target, 2);
        EXPECT_EQ(right.CommitReply(right_target, left_dispatch.dispatch.reply_token, 3, 1, &wake),
                  GuiSendServiceReplyResult::Stale);
        GuiSendServiceBeginOutput nested{};
        EXPECT_EQ(
            right.Begin(Request(right_target, right_caller, 0x1811, 0x102, 100, left_dispatch.dispatch.reply_token), 3,
                        &nested),
            GuiSendServiceBeginResult::ParentUnavailable);

        GuiSendEndpointCloseSummary close{};
        EXPECT_EQ(right.CloseTaskEndpoint(left_target, &close), GuiSendEndpointCloseResult::Stale);
        CommitReply(left, left_target, left_dispatch.dispatch.reply_token, 0x11, 4);
        CommitReply(right, right_target, right_dispatch.dispatch.reply_token, 0x22, 4);
        EXPECT_EQ(PumpCompletion(left, left_caller, left_call.call, 5).reply_value, 0x11ULL);
        EXPECT_EQ(PumpCompletion(right, right_caller, right_call.call, 5).reply_value, 0x22ULL);
    }

    // Same-task stays on user32's direct fast path; cross-process and malformed
    // payloads fail before consuming a transaction/FIFO generation.
    {
        GuiSendService service{};
        const auto a = EnsureEndpoint(service, 0x1000, 0x1001);
        const auto b = EnsureEndpoint(service, 0x1000, 0x1002);
        const auto foreign = EnsureEndpoint(service, 0x2000, 0x2001);
        GuiSendServiceBeginOutput output{};

        auto request = Request(a, a, 0x1101, 0x10, 100);
        EXPECT_EQ(service.Begin(request, 1, &output), GuiSendServiceBeginResult::SameTaskDirectRequired);
        request = Request(a, foreign, 0x1102, 0x10, 100);
        EXPECT_EQ(service.Begin(request, 1, &output), GuiSendServiceBeginResult::CrossProcessDenied);
        request = Request(a, b, 0, 0x10, 100);
        EXPECT_EQ(service.Begin(request, 1, &output), GuiSendServiceBeginResult::InvalidTargetWindow);
        request = Request(a, b, 0x1103, 0x10000, 100);
        EXPECT_EQ(service.Begin(request, 1, &output), GuiSendServiceBeginResult::InvalidMessage);
        request = Request(a, b, 0x1104, 0x10, 1);
        EXPECT_EQ(service.Begin(request, 1, &output), GuiSendServiceBeginResult::DeadlineElapsed);
        request = Request(a, b, 0x1105, 0x10, 100);
        request.reserved = 1;
        EXPECT_EQ(service.Begin(request, 1, &output), GuiSendServiceBeginResult::Rejected);
        EXPECT_EQ(service.ActiveCallCount(), 0U);
    }

    // Happy path: Begin publishes target readiness, Pump returns a private
    // dispatch, CommitReply invalidates an old sender wait token, and completion
    // consumes the exact call once.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0x3000, 0x3001);
        const auto target = EnsureEndpoint(service, 0x3000, 0x3002);

        GuiSendServicePumpOutput idle_before{};
        EXPECT_EQ(service.Pump(target, kInvalidGuiSendServiceCallIdentity, 1, &idle_before),
                  GuiSendServicePumpResult::Pumped);
        EXPECT_EQ(idle_before.kind, GuiSendServicePumpKind::Idle);
        EXPECT_TRUE(service.WaitTokenCurrent(idle_before.wait_token));

        const auto begun = BeginCreated(service, Request(caller, target, 0x3301, 0x1234, 100));
        EXPECT_FALSE(service.WaitTokenCurrent(idle_before.wait_token));
        EXPECT_EQ(service.ActiveCallCount(), 1U);

        GuiSendServiceCallSnapshot snapshot{};
        EXPECT_TRUE(service.InspectCall(begun.call, &snapshot));
        EXPECT_EQ(snapshot.caller_endpoint, caller);
        EXPECT_EQ(snapshot.target_endpoint, target);
        EXPECT_EQ(snapshot.target_window_identity, 0x3301ULL);
        EXPECT_EQ(snapshot.state, GuiSendServiceCallState::Queued);
        EXPECT_EQ(snapshot.transaction.call.policy_authority_identity, kGuiSendSameProcessScalarAuthority);

        GuiSendServicePumpOutput caller_idle{};
        EXPECT_EQ(service.Pump(caller, begun.call, 2, &caller_idle), GuiSendServicePumpResult::Pumped);
        EXPECT_EQ(caller_idle.kind, GuiSendServicePumpKind::Idle);
        EXPECT_TRUE(service.WaitTokenCurrent(caller_idle.wait_token));

        const auto dispatch = PumpDispatch(service, target);
        EXPECT_EQ(dispatch.dispatch.target_window_identity, 0x3301ULL);
        EXPECT_EQ(dispatch.dispatch.message, 0x1234U);
        CommitReply(service, target, dispatch.dispatch.reply_token, 0xC0FFEE);
        EXPECT_FALSE(service.WaitTokenCurrent(caller_idle.wait_token));

        const auto completion = PumpCompletion(service, caller, begun.call);
        EXPECT_EQ(completion.reason, GuiSendServiceCompletionReason::Reply);
        EXPECT_EQ(completion.transaction_phase, GuiSendTransactionPhase::ReplyReady);
        EXPECT_EQ(completion.reply_value, 0xC0FFEEULL);
        EXPECT_EQ(service.ActiveCallCount(), 0U);

        GuiSendServicePumpOutput stale{};
        EXPECT_EQ(service.Pump(caller, begun.call, 4, &stale), GuiSendServicePumpResult::WaitingCallStale);
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.CommitReply(target, dispatch.dispatch.reply_token, 4, 0, &wake),
                  GuiSendServiceReplyResult::Stale);
    }

    // Caller and dispatcher authorization binds to exact endpoint generations,
    // not merely to another task in the same process.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0x4A00, 0x4A01);
        const auto target = EnsureEndpoint(service, 0x4A00, 0x4A02);
        const auto bystander = EnsureEndpoint(service, 0x4A00, 0x4A03);
        const auto begun = BeginCreated(service, Request(caller, target, 0x4A10, 0x7010, 100));
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.Cancel(bystander, begun.call, &wake), GuiSendServiceCancelResult::WrongCaller);
        const auto dispatch = PumpDispatch(service, target);
        EXPECT_EQ(service.CommitReply(bystander, dispatch.dispatch.reply_token, 3, 1, &wake),
                  GuiSendServiceReplyResult::WrongDispatcher);
        CommitReply(service, target, dispatch.dispatch.reply_token, 0x4A10);
        EXPECT_EQ(PumpCompletion(service, caller, begun.call).reply_value, 0x4A10ULL);
    }

    // Reference-model FIFO: cancellation removes modeled entries, while the
    // remaining calls dispatch in global Begin order across three callers.
    {
        constexpr u32 kModelCalls = 24;
        struct ModelRow
        {
            GuiSendTaskEndpointIdentity caller{};
            GuiSendServiceCallIdentity call{};
            bool cancelled = false;
        };

        GuiSendService service{};
        const auto target = EnsureEndpoint(service, 0x4000, 0x4004);
        const std::array<GuiSendTaskEndpointIdentity, 3> callers = {
            EnsureEndpoint(service, 0x4000, 0x4001),
            EnsureEndpoint(service, 0x4000, 0x4002),
            EnsureEndpoint(service, 0x4000, 0x4003),
        };
        std::array<ModelRow, kModelCalls> model{};
        u64 previous_ticket = 0;
        for (u32 index = 0; index < kModelCalls; ++index)
        {
            model[index].caller = callers[index % callers.size()];
            const auto begun =
                BeginCreated(service, Request(model[index].caller, target, 0x4400 + index, 0x8000 + index, 1000));
            model[index].call = begun.call;
            GuiSendServiceCallSnapshot snapshot{};
            EXPECT_TRUE(service.InspectCall(begun.call, &snapshot));
            EXPECT_TRUE(snapshot.fifo_ticket > previous_ticket);
            previous_ticket = snapshot.fifo_ticket;
        }

        for (u32 index = 0; index < kModelCalls; index += 5)
        {
            GuiSendServiceWakeAction wake{};
            EXPECT_EQ(service.Cancel(model[index].caller, model[index].call, &wake),
                      GuiSendServiceCancelResult::Cancelled);
            model[index].cancelled = true;
        }

        for (u32 expected = 0; expected < kModelCalls; ++expected)
        {
            if (model[expected].cancelled)
                continue;
            const auto dispatch = PumpDispatch(service, target, 10);
            EXPECT_EQ(GuiSendServiceDispatchCall(dispatch.dispatch.reply_token), model[expected].call);
            CommitReply(service, target, dispatch.dispatch.reply_token, 0x90000000ULL + expected, 11);
        }

        GuiSendServicePumpOutput target_idle{};
        EXPECT_EQ(service.Pump(target, kInvalidGuiSendServiceCallIdentity, 12, &target_idle),
                  GuiSendServicePumpResult::Pumped);
        EXPECT_EQ(target_idle.kind, GuiSendServicePumpKind::Idle);

        for (u32 index = 0; index < kModelCalls; ++index)
        {
            const auto completion = PumpCompletion(service, model[index].caller, model[index].call, 12);
            EXPECT_EQ(completion.reason, model[index].cancelled ? GuiSendServiceCompletionReason::CallerCancelled
                                                                : GuiSendServiceCompletionReason::Reply);
            if (!model[index].cancelled)
                EXPECT_EQ(completion.reply_value, 0x90000000ULL + index);
        }
        EXPECT_EQ(service.ActiveCallCount(), 0U);
    }

    // Nested dispatch derives depth and authenticates the parent dispatcher.
    // A direct cycle is denied, and the parent cannot reply before its child is
    // consumed and retired.
    {
        GuiSendService service{};
        const auto a = EnsureEndpoint(service, 0x5000, 0x5001);
        const auto b = EnsureEndpoint(service, 0x5000, 0x5002);
        const auto c = EnsureEndpoint(service, 0x5000, 0x5003);
        const auto parent = BeginCreated(service, Request(a, b, 0x5501, 0x8001, 100));
        const auto parent_dispatch = PumpDispatch(service, b, 2);

        GuiSendServiceBeginOutput rejected{};
        EXPECT_EQ(service.Begin(Request(b, c, 0x5500, 0x8000, 90), 3, &rejected),
                  GuiSendServiceBeginResult::ParentRequired);
        auto forged_parent = parent_dispatch.dispatch.reply_token;
        ++forged_parent.transaction.request_sequence;
        EXPECT_EQ(service.Begin(Request(b, c, 0x5500, 0x8000, 90, forged_parent), 3, &rejected),
                  GuiSendServiceBeginResult::ParentUnavailable);
        EXPECT_EQ(service.Begin(Request(b, a, 0x5502, 0x8002, 90, parent_dispatch.dispatch.reply_token), 3, &rejected),
                  GuiSendServiceBeginResult::Cycle);

        const auto child =
            BeginCreated(service, Request(b, c, 0x5503, 0x8003, 90, parent_dispatch.dispatch.reply_token), 3);
        const auto child_dispatch = PumpDispatch(service, c, 4);
        EXPECT_EQ(child_dispatch.dispatch.reentrancy_depth, 1U);
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.CommitReply(b, parent_dispatch.dispatch.reply_token, 5, 1, &wake),
                  GuiSendServiceReplyResult::ActiveChild);

        CommitReply(service, c, child_dispatch.dispatch.reply_token, 0x55, 5);
        const auto child_completion = PumpCompletion(service, b, child.call, 6);
        EXPECT_EQ(child_completion.reply_value, 0x55ULL);
        CommitReply(service, b, parent_dispatch.dispatch.reply_token, 0x66, 7);
        const auto parent_completion = PumpCompletion(service, a, parent.call, 8);
        EXPECT_EQ(parent_completion.reply_value, 0x66ULL);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);
    }

    // Execution context outlives transaction state. Cancellation and caller
    // consumption cannot let a still-running WndProc omit its parent proof and
    // escape into a fresh root; the exact stale reply boundary finally pops
    // the retained dispatch frame.
    {
        GuiSendService service{};
        const auto a = EnsureEndpoint(service, 0x5600, 0x5601);
        const auto b = EnsureEndpoint(service, 0x5600, 0x5602);
        const auto c = EnsureEndpoint(service, 0x5600, 0x5603);
        const auto parent = BeginCreated(service, Request(a, b, 0x5610, 0x8100, 100));
        const auto dispatch = PumpDispatch(service, b, 2);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 1U);

        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.Cancel(a, parent.call, &wake), GuiSendServiceCancelResult::Cancelled);
        (void)PumpCompletion(service, a, parent.call, 3);
        EXPECT_EQ(service.ActiveCallCount(), 0U);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 1U);

        GuiSendServiceBeginOutput rejected{};
        EXPECT_EQ(service.Begin(Request(b, c, 0x5611, 0x8101, 100), 3, &rejected),
                  GuiSendServiceBeginResult::ParentRequired);
        EXPECT_EQ(service.Begin(Request(b, c, 0x5611, 0x8101, 100, dispatch.dispatch.reply_token), 3, &rejected),
                  GuiSendServiceBeginResult::ParentUnavailable);
        EXPECT_EQ(service.CommitReply(b, dispatch.dispatch.reply_token, 4, 0, &wake), GuiSendServiceReplyResult::Stale);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);

        const auto root = BeginCreated(service, Request(b, c, 0x5612, 0x8102, 100), 4);
        EXPECT_EQ(service.Cancel(b, root.call, &wake), GuiSendServiceCancelResult::Cancelled);
        (void)PumpCompletion(service, b, root.call, 5);
    }

    // A timeout has the same execution-frame lifetime as cancellation. The
    // timed-out WndProc remains a nested context until its adapter return
    // boundary reports the terminal reply.
    {
        GuiSendService service{};
        const auto a = EnsureEndpoint(service, 0x5700, 0x5701);
        const auto b = EnsureEndpoint(service, 0x5700, 0x5702);
        const auto c = EnsureEndpoint(service, 0x5700, 0x5703);
        const auto parent = BeginCreated(service, Request(a, b, 0x5710, 0x8200, 10));
        const auto dispatch = PumpDispatch(service, b, 2);
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.ExpireDeadlines(10, &wake), 1U);

        GuiSendServiceBeginOutput rejected{};
        EXPECT_EQ(service.Begin(Request(b, c, 0x5711, 0x8201, 100), 10, &rejected),
                  GuiSendServiceBeginResult::ParentRequired);
        EXPECT_EQ(service.Begin(Request(b, c, 0x5711, 0x8201, 100, dispatch.dispatch.reply_token), 10, &rejected),
                  GuiSendServiceBeginResult::ParentUnavailable);
        EXPECT_EQ(service.CommitReply(b, dispatch.dispatch.reply_token, 10, 0, &wake),
                  GuiSendServiceReplyResult::Terminal);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);
        EXPECT_EQ(PumpCompletion(service, a, parent.call, 11).reason, GuiSendServiceCompletionReason::DeadlineExpired);

        const auto root = BeginCreated(service, Request(b, c, 0x5712, 0x8202, 100), 11);
        EXPECT_EQ(service.Cancel(b, root.call, &wake), GuiSendServiceCancelResult::Cancelled);
        (void)PumpCompletion(service, b, root.call, 12);
    }

    // Reentrant pumping can create two independent live WndProc frames on one
    // endpoint. Only the exact top token can parent a child or return; replaying
    // the still-live outer proof is rejected until the inner frame unwinds.
    {
        GuiSendService service{};
        const auto a = EnsureEndpoint(service, 0x5900, 0x5901);
        const auto b = EnsureEndpoint(service, 0x5900, 0x5902);
        const auto c = EnsureEndpoint(service, 0x5900, 0x5903);
        const auto d = EnsureEndpoint(service, 0x5900, 0x5904);
        const auto outer = BeginCreated(service, Request(a, b, 0x5910, 0x8300, 100));
        const auto outer_dispatch = PumpDispatch(service, b, 2);
        const auto inner = BeginCreated(service, Request(d, b, 0x5911, 0x8301, 100), 3);
        const auto inner_dispatch = PumpDispatch(service, b, 4);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 2U);

        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.CommitReply(b, outer_dispatch.dispatch.reply_token, 5, 0, &wake),
                  GuiSendServiceReplyResult::WrongClaim);
        GuiSendServiceBeginOutput rejected{};
        EXPECT_EQ(service.Begin(Request(b, c, 0x5912, 0x8302, 100, outer_dispatch.dispatch.reply_token), 5, &rejected),
                  GuiSendServiceBeginResult::ParentUnavailable);

        const auto child =
            BeginCreated(service, Request(b, c, 0x5913, 0x8303, 100, inner_dispatch.dispatch.reply_token), 5);
        const auto child_dispatch = PumpDispatch(service, c, 6);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 3U);
        CommitReply(service, c, child_dispatch.dispatch.reply_token, 0x31, 7);
        (void)PumpCompletion(service, b, child.call, 8);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 2U);

        CommitReply(service, b, inner_dispatch.dispatch.reply_token, 0x32, 9);
        EXPECT_EQ(PumpCompletion(service, d, inner.call, 10).reply_value, 0x32ULL);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 1U);
        CommitReply(service, b, outer_dispatch.dispatch.reply_token, 0x33, 11);
        EXPECT_EQ(PumpCompletion(service, a, outer.call, 12).reply_value, 0x33ULL);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);
    }

    // Root cancellation invalidates a retained descendant dispatch token and
    // preserves distinct root/ancestor completion reasons.
    {
        GuiSendService service{};
        const auto a = EnsureEndpoint(service, 0x5800, 0x5801);
        const auto b = EnsureEndpoint(service, 0x5800, 0x5802);
        const auto c = EnsureEndpoint(service, 0x5800, 0x5803);
        const auto parent = BeginCreated(service, Request(a, b, 0x5810, 0x8010, 100));
        const auto parent_dispatch = PumpDispatch(service, b, 2);
        const auto child =
            BeginCreated(service, Request(b, c, 0x5820, 0x8011, 90, parent_dispatch.dispatch.reply_token), 3);
        const auto child_dispatch = PumpDispatch(service, c, 4);
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.Cancel(a, parent.call, &wake), GuiSendServiceCancelResult::Cancelled);
        EXPECT_EQ(service.CommitReply(c, child_dispatch.dispatch.reply_token, 5, 1, &wake),
                  GuiSendServiceReplyResult::Terminal);
        EXPECT_EQ(service.CommitReply(b, parent_dispatch.dispatch.reply_token, 5, 1, &wake),
                  GuiSendServiceReplyResult::Terminal);
        EXPECT_EQ(PumpCompletion(service, b, child.call, 5).reason, GuiSendServiceCompletionReason::AncestorCancelled);
        EXPECT_EQ(PumpCompletion(service, a, parent.call, 5).reason, GuiSendServiceCompletionReason::CallerCancelled);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);
    }

    // Exact HWND cancellation does not poison another window owned by the same
    // target task, and queued cancellation is observable by the caller.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0x6000, 0x6001);
        const auto target = EnsureEndpoint(service, 0x6000, 0x6002);
        const auto closed = BeginCreated(service, Request(caller, target, 0x6601, 0x10, 100));
        const auto live = BeginCreated(service, Request(caller, target, 0x6602, 0x11, 100));
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.CancelTargetWindow(target, 0x6601, &wake), 1U);
        EXPECT_EQ(wake.wake_all, 1U);
        EXPECT_EQ(service.CancelTargetWindow(target, 0x6601, &wake), 0U);

        const auto cancelled = PumpCompletion(service, caller, closed.call, 3);
        EXPECT_EQ(cancelled.reason, GuiSendServiceCompletionReason::TargetWindowClosed);
        EXPECT_EQ(cancelled.transaction_phase, GuiSendTransactionPhase::Cancelled);
        const auto dispatch = PumpDispatch(service, target, 3);
        EXPECT_EQ(GuiSendServiceDispatchCall(dispatch.dispatch.reply_token), live.call);
        CommitReply(service, target, dispatch.dispatch.reply_token, 0x6602, 4);
        EXPECT_EQ(PumpCompletion(service, caller, live.call, 5).reply_value, 0x6602ULL);
    }

    // Deadline transitions work both from the timer sweep and at reply
    // linearization. A target can never dispatch an expired queued call.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0x7000, 0x7001);
        const auto target = EnsureEndpoint(service, 0x7000, 0x7002);
        const auto queued = BeginCreated(service, Request(caller, target, 0x7701, 0x20, 10));
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.ExpireDeadlines(9, &wake), 0U);
        EXPECT_EQ(wake.wake_all, 0U);
        EXPECT_EQ(service.ExpireDeadlines(10, &wake), 1U);
        EXPECT_EQ(wake.wake_all, 1U);
        const auto timed_out = PumpCompletion(service, caller, queued.call, 10);
        EXPECT_EQ(timed_out.reason, GuiSendServiceCompletionReason::DeadlineExpired);
        EXPECT_EQ(timed_out.transaction_phase, GuiSendTransactionPhase::TimedOut);
        GuiSendServicePumpOutput idle{};
        EXPECT_EQ(service.Pump(target, kInvalidGuiSendServiceCallIdentity, 10, &idle),
                  GuiSendServicePumpResult::Pumped);
        EXPECT_EQ(idle.kind, GuiSendServicePumpKind::Idle);

        const auto dispatching = BeginCreated(service, Request(caller, target, 0x7702, 0x21, 20), 11);
        const auto dispatch = PumpDispatch(service, target, 12);
        EXPECT_EQ(service.CommitReply(target, dispatch.dispatch.reply_token, 20, 1, &wake),
                  GuiSendServiceReplyResult::DeadlineExpired);
        EXPECT_EQ(PumpCompletion(service, caller, dispatching.call, 20).reason,
                  GuiSendServiceCompletionReason::DeadlineExpired);
    }

    // Target death leaves an exact completion for a live caller. Caller death
    // cancels and retires its own rows so a dead endpoint cannot exhaust the
    // transaction table.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0x8000, 0x8001);
        const auto target = EnsureEndpoint(service, 0x8000, 0x8002);
        const auto inbound = BeginCreated(service, Request(caller, target, 0x8801, 0x30, 100));
        GuiSendEndpointCloseSummary target_close{};
        EXPECT_EQ(service.CloseTaskEndpoint(target, &target_close), GuiSendEndpointCloseResult::Closed);
        EXPECT_TRUE(target_close.target_transitions >= 1U);
        EXPECT_EQ(target_close.wake.wake_all, 1U);
        GuiSendServicePumpOutput stale_target{};
        EXPECT_EQ(service.Pump(target, kInvalidGuiSendServiceCallIdentity, 2, &stale_target),
                  GuiSendServicePumpResult::EndpointStale);
        const auto completion = PumpCompletion(service, caller, inbound.call, 2);
        EXPECT_EQ(completion.reason, GuiSendServiceCompletionReason::TargetTaskExited);

        GuiSendTaskEndpointIdentity target_reopened{};
        EXPECT_EQ(service.EnsureTaskEndpoint(0x8000, 0x8002, &target_reopened), GuiSendEndpointResult::Created);
        EXPECT_NE(target_reopened, target);
        EXPECT_EQ(GuiSendTaskEndpointSlot(target_reopened), GuiSendTaskEndpointSlot(target));
        EXPECT_TRUE(GuiSendTaskEndpointGeneration(target_reopened) > GuiSendTaskEndpointGeneration(target));

        const auto abandoned = BeginCreated(service, Request(caller, target_reopened, 0x8802, 0x31, 100));
        GuiSendEndpointCloseSummary caller_close{};
        EXPECT_EQ(service.CloseTaskEndpoint(caller, &caller_close), GuiSendEndpointCloseResult::Closed);
        EXPECT_TRUE(caller_close.caller_transitions >= 1U);
        EXPECT_EQ(caller_close.caller_rows_retired, 1U);
        GuiSendServiceCallSnapshot abandoned_snapshot{};
        EXPECT_FALSE(service.InspectCall(abandoned.call, &abandoned_snapshot));
        EXPECT_EQ(service.ActiveCallCount(), 0U);
        GuiSendServicePumpOutput no_abandoned{};
        EXPECT_EQ(service.Pump(target_reopened, kInvalidGuiSendServiceCallIdentity, 3, &no_abandoned),
                  GuiSendServicePumpResult::Pumped);
        EXPECT_EQ(no_abandoned.kind, GuiSendServicePumpKind::Idle);
    }

    // Endpoint and transaction ABA: stale generations fail after exact slot
    // reuse; generation saturation retires an endpoint slot rather than wrap.
    {
        GuiSendService service{};
        EXPECT_TRUE(service.HostPositionEndpointGeneration(0, kGuiSendEndpointGenerationMaximum - 1));
        const auto saturated = EnsureEndpoint(service, 0x9000, 0x9001);
        EXPECT_EQ(GuiSendTaskEndpointSlot(saturated), 0U);
        EXPECT_EQ(GuiSendTaskEndpointGeneration(saturated), kGuiSendEndpointGenerationMaximum);
        GuiSendEndpointCloseSummary close{};
        EXPECT_EQ(service.CloseTaskEndpoint(saturated, &close), GuiSendEndpointCloseResult::Closed);
        EXPECT_FALSE(service.HostPositionEndpointGeneration(0, kGuiSendEndpointGenerationMaximum - 1));
        const auto next = EnsureEndpoint(service, 0x9000, 0x9002);
        EXPECT_NE(GuiSendTaskEndpointSlot(next), 0U);
        EXPECT_EQ(service.CloseTaskEndpoint(saturated, &close), GuiSendEndpointCloseResult::Stale);
    }

    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0x9100, 0x9101);
        const auto target = EnsureEndpoint(service, 0x9100, 0x9102);
        const auto first = BeginCreated(service, Request(caller, target, 0x9111, 0x40, 100));
        const auto first_dispatch = PumpDispatch(service, target);
        CommitReply(service, target, first_dispatch.dispatch.reply_token, 1);
        (void)PumpCompletion(service, caller, first.call);

        const auto second = BeginCreated(service, Request(caller, target, 0x9112, 0x41, 100));
        EXPECT_EQ(second.call.slot, first.call.slot);
        EXPECT_TRUE(second.call.generation > first.call.generation);
        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.Cancel(caller, first.call, &wake), GuiSendServiceCancelResult::Stale);
        GuiSendServiceCallSnapshot second_snapshot{};
        EXPECT_TRUE(service.InspectCall(second.call, &second_snapshot));
        EXPECT_EQ(second_snapshot.state, GuiSendServiceCallState::Queued);
    }

    // FIFO ticket exhaustion cannot wrap while a live queued/dispatching call
    // retains the maximum ticket. Once no ordered work remains, 1 is safe.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0xA000, 0xA001);
        const auto target = EnsureEndpoint(service, 0xA000, 0xA002);
        EXPECT_TRUE(service.HostPositionNextFifoTicket(static_cast<u64>(-1)));
        const auto maximum = BeginCreated(service, Request(caller, target, 0xAA01, 0x50, 100));
        GuiSendServiceCallSnapshot snapshot{};
        EXPECT_TRUE(service.InspectCall(maximum.call, &snapshot));
        EXPECT_EQ(snapshot.fifo_ticket, static_cast<u64>(-1));
        GuiSendServiceBeginOutput rejected{};
        EXPECT_EQ(service.Begin(Request(caller, target, 0xAA02, 0x51, 100), 1, &rejected),
                  GuiSendServiceBeginResult::TableFull);
        EXPECT_EQ(service.ActiveCallCount(), 1U);
        const auto dispatch = PumpDispatch(service, target);
        CommitReply(service, target, dispatch.dispatch.reply_token, 1);
        (void)PumpCompletion(service, caller, maximum.call);
        const auto reset = BeginCreated(service, Request(caller, target, 0xAA03, 0x52, 100));
        EXPECT_TRUE(service.InspectCall(reset.call, &snapshot));
        EXPECT_EQ(snapshot.fifo_ticket, 1ULL);
        EXPECT_EQ(reset.request_sequence, 2ULL);
    }

    // One caller cannot consume the whole global transaction table. Its
    // bounded outgoing quota preserves capacity for another endpoint, and
    // consuming a terminal row immediately returns quota to the owner.
    {
        GuiSendService service{};
        const auto hog = EnsureEndpoint(service, 0xA800, 0xA801);
        const auto survivor = EnsureEndpoint(service, 0xA800, 0xA802);
        const auto target = EnsureEndpoint(service, 0xA800, 0xA803);
        std::array<GuiSendServiceCallIdentity, kGuiSendServicePerCallerCallLimit> hog_calls{};
        for (u32 index = 0; index < hog_calls.size(); ++index)
        {
            hog_calls[index] = BeginCreated(service, Request(hog, target, 0xA810 + index, 0x6000 + index, 100)).call;
        }

        GuiSendServiceBeginOutput denied{};
        EXPECT_EQ(service.Begin(Request(hog, target, 0xA8F0, 0x60F0, 100), 1, &denied),
                  GuiSendServiceBeginResult::CallerQuotaExceeded);
        EXPECT_TRUE(GuiSendServiceCallIdentityIsInvalidCanonical(denied.call));
        const auto survivor_call = BeginCreated(service, Request(survivor, target, 0xA8F1, 0x60F1, 100));
        EXPECT_EQ(service.ActiveCallCount(), kGuiSendServicePerCallerCallLimit + 1U);

        GuiSendServiceWakeAction wake{};
        EXPECT_EQ(service.Cancel(hog, hog_calls[0], &wake), GuiSendServiceCancelResult::Cancelled);
        (void)PumpCompletion(service, hog, hog_calls[0], 2);
        const auto reclaimed = BeginCreated(service, Request(hog, target, 0xA8F2, 0x60F2, 100), 2);
        EXPECT_TRUE(GuiSendServiceCallIdentityIsCanonical(reclaimed.call));
        EXPECT_EQ(reclaimed.request_sequence, static_cast<u64>(kGuiSendServicePerCallerCallLimit) + 1ULL);

        for (u32 index = 1; index < hog_calls.size(); ++index)
        {
            EXPECT_EQ(service.Cancel(hog, hog_calls[index], &wake), GuiSendServiceCancelResult::Cancelled);
            (void)PumpCompletion(service, hog, hog_calls[index], 3);
        }
        EXPECT_EQ(service.Cancel(hog, reclaimed.call, &wake), GuiSendServiceCancelResult::Cancelled);
        (void)PumpCompletion(service, hog, reclaimed.call, 3);
        EXPECT_EQ(service.Cancel(survivor, survivor_call.call, &wake), GuiSendServiceCancelResult::Cancelled);
        (void)PumpCompletion(service, survivor, survivor_call.call, 3);
        EXPECT_EQ(service.ActiveCallCount(), 0U);
    }

    // Capacity is hard and allocation-free. A mixed full table containing
    // both active and permanently exhausted rows is temporarily full, not
    // globally generation-exhausted; closing one active row restores service.
    {
        GuiSendService service{};
        EXPECT_TRUE(service.HostPositionEndpointGeneration(0, kGuiSendEndpointGenerationMaximum));
        std::array<GuiSendTaskEndpointIdentity, kGuiSendServiceEndpointCapacity> endpoints{};
        for (u32 index = 0; index + 1U < endpoints.size(); ++index)
            endpoints[index] = EnsureEndpoint(service, 0xB000, 0xB100 + index);
        GuiSendTaskEndpointIdentity overflow{};
        EXPECT_EQ(service.EnsureTaskEndpoint(0xB000, 0xBFFF, &overflow), GuiSendEndpointResult::TableFull);
        EXPECT_EQ(overflow, kInvalidGuiSendTaskEndpoint);
        EXPECT_EQ(service.ActiveEndpointCount(), kGuiSendServiceEndpointCapacity - 1U);

        GuiSendEndpointCloseSummary close{};
        EXPECT_EQ(service.CloseTaskEndpoint(endpoints[0], &close), GuiSendEndpointCloseResult::Closed);
        const auto reopened = EnsureEndpoint(service, 0xB000, 0xBFFF);
        EXPECT_EQ(GuiSendTaskEndpointSlot(reopened), GuiSendTaskEndpointSlot(endpoints[0]));
    }

    {
        GuiSendService service{};
        for (u32 slot = 0; slot < kGuiSendServiceEndpointCapacity; ++slot)
            EXPECT_TRUE(service.HostPositionEndpointGeneration(slot, kGuiSendEndpointGenerationMaximum));
        GuiSendTaskEndpointIdentity endpoint{};
        EXPECT_EQ(service.EnsureTaskEndpoint(0xB800, 0xB801, &endpoint), GuiSendEndpointResult::GenerationExhausted);
        EXPECT_EQ(endpoint, kInvalidGuiSendTaskEndpoint);
    }

    // Dispatch execution frames are independently bounded because a caller
    // may consume a cancelled transaction while its target WndProc is still
    // unwinding. Full context storage refuses another claim without mutating
    // the queued call; one exact LIFO return restores progress.
    {
        constexpr u32 kFrameCallers = 8;
        constexpr u32 kFramesPerCaller = kGuiSendServicePerCallerCallLimit;
        constexpr u32 kFrameCount = kFrameCallers * kFramesPerCaller;
        static_assert(kFrameCount == kGuiSendServiceDispatchFrameCapacity);

        GuiSendService service{};
        const auto target = EnsureEndpoint(service, 0xBC00, 0xBC01);
        std::array<GuiSendTaskEndpointIdentity, kFrameCallers> callers{};
        std::array<GuiSendServiceCallIdentity, kFrameCount> calls{};
        std::array<GuiSendServiceDispatchToken, kFrameCount> tokens{};
        for (u32 caller = 0; caller < kFrameCallers; ++caller)
        {
            callers[caller] = EnsureEndpoint(service, 0xBC00, 0xBC10 + caller);
            for (u32 offset = 0; offset < kFramesPerCaller; ++offset)
            {
                const u32 index = caller * kFramesPerCaller + offset;
                calls[index] =
                    BeginCreated(service, Request(callers[caller], target, 0xBC100 + index, 0x7000 + index, 1000)).call;
            }
        }
        for (u32 index = 0; index < kFrameCount; ++index)
            tokens[index] = PumpDispatch(service, target, 2).dispatch.reply_token;
        EXPECT_EQ(service.ActiveDispatchFrameCount(), kFrameCount);

        GuiSendServiceWakeAction wake{};
        for (u32 index = 0; index < kFrameCount; ++index)
        {
            const auto caller = callers[index / kFramesPerCaller];
            EXPECT_EQ(service.Cancel(caller, calls[index], &wake), GuiSendServiceCancelResult::Cancelled);
            (void)PumpCompletion(service, caller, calls[index], 3);
        }
        EXPECT_EQ(service.ActiveCallCount(), 0U);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), kFrameCount);

        const auto queued = BeginCreated(service, Request(callers[0], target, 0xBCFFF, 0x7FFF, 1000), 4);
        GuiSendServicePumpOutput full{};
        EXPECT_EQ(service.Pump(target, kInvalidGuiSendServiceCallIdentity, 4, &full),
                  GuiSendServicePumpResult::DispatchContextFull);
        GuiSendServiceCallSnapshot queued_snapshot{};
        EXPECT_TRUE(service.InspectCall(queued.call, &queued_snapshot));
        EXPECT_EQ(queued_snapshot.state, GuiSendServiceCallState::Queued);

        EXPECT_EQ(service.CommitReply(target, tokens[0], 4, 0, &wake), GuiSendServiceReplyResult::WrongClaim);
        EXPECT_EQ(service.ActiveDispatchFrameCount(), kFrameCount);
        EXPECT_EQ(service.CommitReply(target, tokens[kFrameCount - 1U], 4, 0, &wake), GuiSendServiceReplyResult::Stale);
        const auto resumed = PumpDispatch(service, target, 5);
        EXPECT_EQ(GuiSendServiceDispatchCall(resumed.dispatch.reply_token), queued.call);
        CommitReply(service, target, resumed.dispatch.reply_token, 0xBC, 6);
        EXPECT_EQ(PumpCompletion(service, callers[0], queued.call, 7).reply_value, 0xBCULL);

        for (u32 index = kFrameCount - 1U; index != 0; --index)
        {
            EXPECT_EQ(service.CommitReply(target, tokens[index - 1U], 8, 0, &wake), GuiSendServiceReplyResult::Stale);
        }
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);
    }

    // Concurrent producers serialize into one exact FIFO without duplicate
    // call slots. The target drains every call and each caller consumes its own
    // reply under real hosted ticket-lock contention.
    {
        constexpr u32 kCallers = 6;
        constexpr u32 kCallsPerCaller = 8;
        constexpr u32 kTotalCalls = kCallers * kCallsPerCaller;
        GuiSendService service{};
        const auto target = EnsureEndpoint(service, 0xC000, 0xC100);
        std::array<GuiSendTaskEndpointIdentity, kCallers> callers{};
        for (u32 caller = 0; caller < kCallers; ++caller)
            callers[caller] = EnsureEndpoint(service, 0xC000, 0xC200 + caller);

        std::array<std::array<GuiSendServiceCallIdentity, kCallsPerCaller>, kCallers> calls{};
        std::array<std::array<GuiSendServiceBeginResult, kCallsPerCaller>, kCallers> results{};
        std::barrier start(static_cast<std::ptrdiff_t>(kCallers + 1));
        std::vector<std::thread> workers;
        workers.reserve(kCallers);
        for (u32 caller = 0; caller < kCallers; ++caller)
        {
            workers.emplace_back(
                [&, caller]()
                {
                    start.arrive_and_wait();
                    for (u32 index = 0; index < kCallsPerCaller; ++index)
                    {
                        GuiSendServiceBeginOutput output{};
                        results[caller][index] =
                            service.Begin(Request(callers[caller], target, 0xCC000 + caller * 0x100 + index,
                                                  0x8000 + caller * kCallsPerCaller + index, 10000),
                                          1, &output);
                        calls[caller][index] = output.call;
                    }
                });
        }
        start.arrive_and_wait();
        for (auto& worker : workers)
            worker.join();

        for (u32 caller = 0; caller < kCallers; ++caller)
        {
            for (u32 index = 0; index < kCallsPerCaller; ++index)
            {
                EXPECT_EQ(results[caller][index], GuiSendServiceBeginResult::Created);
                EXPECT_TRUE(GuiSendServiceCallIdentityIsCanonical(calls[caller][index]));
            }
        }
        EXPECT_EQ(service.ActiveCallCount(), kTotalCalls);

        std::array<bool, kGuiSendTransactionCapacity> seen_slots{};
        for (u32 index = 0; index < kTotalCalls; ++index)
        {
            const auto dispatch = PumpDispatch(service, target, 2);
            const auto call = GuiSendServiceDispatchCall(dispatch.dispatch.reply_token);
            EXPECT_FALSE(seen_slots[call.slot]);
            seen_slots[call.slot] = true;
            CommitReply(service, target, dispatch.dispatch.reply_token,
                        (static_cast<u64>(call.slot) << 32U) | call.generation, 3);
        }

        for (u32 caller = 0; caller < kCallers; ++caller)
        {
            for (u32 index = 0; index < kCallsPerCaller; ++index)
            {
                const auto call = calls[caller][index];
                const auto completion = PumpCompletion(service, callers[caller], call, 4);
                EXPECT_EQ(completion.reply_value, (static_cast<u64>(call.slot) << 32U) | call.generation);
            }
        }
        EXPECT_EQ(service.ActiveCallCount(), 0U);
    }

    // Reply-vs-cancel linearizes to exactly one terminal reason.
    {
        constexpr u32 kRaceIterations = 64;
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0xD000, 0xD001);
        const auto target = EnsureEndpoint(service, 0xD000, 0xD002);
        for (u32 iteration = 0; iteration < kRaceIterations; ++iteration)
        {
            const auto begun =
                BeginCreated(service, Request(caller, target, 0xDD00 + iteration, 0x8000 + iteration, 1000));
            const auto dispatch = PumpDispatch(service, target, 2);
            GuiSendServiceReplyResult reply_result = GuiSendServiceReplyResult::Rejected;
            GuiSendServiceCancelResult cancel_result = GuiSendServiceCancelResult::Rejected;
            std::barrier start(3);
            std::thread reply(
                [&]()
                {
                    GuiSendServiceWakeAction wake{};
                    start.arrive_and_wait();
                    reply_result =
                        service.CommitReply(target, dispatch.dispatch.reply_token, 3, 0xD000 + iteration, &wake);
                });
            std::thread cancel(
                [&]()
                {
                    GuiSendServiceWakeAction wake{};
                    start.arrive_and_wait();
                    cancel_result = service.Cancel(caller, begun.call, &wake);
                });
            start.arrive_and_wait();
            reply.join();
            cancel.join();

            const bool reply_won = reply_result == GuiSendServiceReplyResult::Committed &&
                                   cancel_result == GuiSendServiceCancelResult::TooLate;
            const bool cancel_won = cancel_result == GuiSendServiceCancelResult::Cancelled &&
                                    reply_result == GuiSendServiceReplyResult::Terminal;
            EXPECT_TRUE(reply_won || cancel_won);
            const auto completion = PumpCompletion(service, caller, begun.call, 4);
            EXPECT_EQ(completion.reason, reply_won ? GuiSendServiceCompletionReason::Reply
                                                   : GuiSendServiceCompletionReason::CallerCancelled);
        }
    }

    // Target-close vs dispatch claim is deterministic under the service lock:
    // either claim wins then death cancels Dispatching, or close wins and the
    // old endpoint is stale. The caller always receives TargetTaskExited.
    {
        GuiSendService service{};
        const auto caller = EnsureEndpoint(service, 0xE000, 0xE001);
        const auto target = EnsureEndpoint(service, 0xE000, 0xE002);
        const auto begun = BeginCreated(service, Request(caller, target, 0xEE01, 0x9000, 100));
        GuiSendServicePumpResult pump_result = GuiSendServicePumpResult::Rejected;
        GuiSendServicePumpOutput pump_output{};
        GuiSendEndpointCloseResult close_result = GuiSendEndpointCloseResult::Rejected;
        GuiSendEndpointCloseSummary close_summary{};
        std::barrier start(3);
        std::thread pump(
            [&]()
            {
                start.arrive_and_wait();
                pump_result = service.Pump(target, kInvalidGuiSendServiceCallIdentity, 2, &pump_output);
            });
        std::thread close(
            [&]()
            {
                start.arrive_and_wait();
                close_result = service.CloseTaskEndpoint(target, &close_summary);
            });
        start.arrive_and_wait();
        pump.join();
        close.join();

        EXPECT_EQ(close_result, GuiSendEndpointCloseResult::Closed);
        const bool claim_won =
            pump_result == GuiSendServicePumpResult::Pumped && pump_output.kind == GuiSendServicePumpKind::Dispatch;
        const bool close_won = pump_result == GuiSendServicePumpResult::EndpointStale;
        EXPECT_TRUE(claim_won || close_won);
        const auto completion = PumpCompletion(service, caller, begun.call, 3);
        EXPECT_EQ(completion.reason, GuiSendServiceCompletionReason::TargetTaskExited);
        if (claim_won)
        {
            GuiSendServiceWakeAction wake{};
            EXPECT_EQ(service.CommitReply(target, pump_output.dispatch.reply_token, 3, 0, &wake),
                      GuiSendServiceReplyResult::EndpointStale);
        }
        EXPECT_EQ(service.ActiveDispatchFrameCount(), 0U);
    }

    return duetos_host_test::finish_main("gui_send_service");
}
