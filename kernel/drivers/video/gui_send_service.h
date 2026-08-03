#pragma once

#include "drivers/video/gui_send_transaction.h"
#include "sync/spinlock.h"
#include "util/types.h"

/*
 * DuetOS -- same-process synchronous GUI send service foundation.
 *
 * This non-hot-reloadable service owns the kernel state that cannot live in a
 * public Win32 MSG: generation-tagged task endpoints, FIFO dispatch order,
 * exact call metadata, wait epochs, and the GuiSendTransactionTable. It does
 * not own a compositor window, scheduler Task, Process, wait queue, callback,
 * user pointer, credential, or IPC endpoint.
 *
 * Ownership:
 *
 *   scheduler/GUI adapter         authenticates live {process, task}
 *             |                  and exact HWND generations
 *             v
 *   GuiSendService               owns endpoint/call/FIFO/wait state
 *             |
 *             v
 *   GuiSendTransactionTable      owns call generations/transitions
 *             |
 *             v
 *   user32 syscall adapter       invokes WndProc on the target task and
 *                                blocks/wakes only after service locks drop
 *
 * v1 deliberately accepts only same-process, cross-task scalar envelopes:
 * message is a 16-bit Win32 id and wParam/lParam are copied as opaque u64
 * values. The service never dereferences or marshals them. Cross-process sends,
 * credentials, pointer-bearing schemas, HWND lookup, and ring-3 token exposure
 * are outside this layer.
 *
 * Lock order and affinity:
 *
 *   optional compositor snapshot -> service lock -> transaction-table lock
 *
 * Public methods are bounded, allocation-free, and thread-safe in kernel task
 * context on any CPU. No method invokes a callback, compositor operation,
 * scheduler/wait operation, user copy, allocator, logger, KObject operation,
 * or transport while m_lock is held. A window adapter may freeze an exact HWND
 * under the compositor and call Begin/CancelTargetWindow before releasing that
 * outer lock; it must publish the returned wake action only after compositor
 * unlock. No service or transaction method ever acquires the compositor.
 *
 * Sender pump contract:
 *
 *   Pump(endpoint, waiting_call)
 *     1. returns the oldest private sent call targeting endpoint, if any;
 *     2. otherwise returns waiting_call's terminal completion, if ready;
 *     3. otherwise returns an exact wait token.
 *
 * Dispatch tokens and private dispatch records stay in the trusted syscall
 * adapter. Ring 3 receives only a separately encoded opaque cookie. Before
 * blocking, the adapter must hold its wait-queue interlock across
 * WaitTokenCurrent and enqueue so a producer cannot publish between those two
 * steps. If the scheduler cannot yet provide that atomic adapter boundary, it
 * must retain a bounded timeout. Every wake action is only a hint to broadcast
 * after all locks drop; it is never proof that a waiter was enqueued.
 *
 * Lockdep integration note: this service lock is tagged separately from the
 * nested transaction-table class. The transaction-table owner must initialize
 * its private lock with kLockClassGuiSendTransaction before production wiring;
 * leaving it unclassified would make the documented inner edge invisible.
 */

namespace duetos::drivers::video
{

inline constexpr u32 kGuiSendServiceEndpointCapacity = 64;
inline constexpr u32 kGuiSendServicePerCallerCallLimit = 8;
inline constexpr u32 kGuiSendServiceDispatchFrameCapacity = kGuiSendTransactionCapacity;
inline constexpr u32 kGuiSendEndpointSlotBits = 7;
inline constexpr u64 kGuiSendEndpointSlotMask = (1ULL << kGuiSendEndpointSlotBits) - 1ULL;
inline constexpr u64 kGuiSendEndpointGenerationMaximum = static_cast<u64>(-1) >> kGuiSendEndpointSlotBits;
inline constexpr u64 kGuiSendSameProcessScalarAuthority = 0x47534E4453505631ULL; // "GSNDSPV1"

static_assert(kGuiSendServicePerCallerCallLimit > 0);
static_assert(kGuiSendServicePerCallerCallLimit < kGuiSendTransactionCapacity);
static_assert(kGuiSendServiceDispatchFrameCapacity >= kGuiSendTransactionCapacity);

struct GuiSendTaskEndpointIdentity
{
    u64 service_incarnation;
    u64 value;
};

inline constexpr GuiSendTaskEndpointIdentity kInvalidGuiSendTaskEndpoint{0, 0};

constexpr bool operator==(GuiSendTaskEndpointIdentity lhs, GuiSendTaskEndpointIdentity rhs)
{
    return lhs.service_incarnation == rhs.service_incarnation && lhs.value == rhs.value;
}

constexpr bool operator!=(GuiSendTaskEndpointIdentity lhs, GuiSendTaskEndpointIdentity rhs)
{
    return !(lhs == rhs);
}

constexpr bool GuiSendTaskEndpointIdentityIsCanonical(GuiSendTaskEndpointIdentity identity)
{
    const u64 biased_slot = identity.value & kGuiSendEndpointSlotMask;
    const u64 generation = identity.value >> kGuiSendEndpointSlotBits;
    return identity.service_incarnation != 0 && biased_slot != 0 && biased_slot <= kGuiSendServiceEndpointCapacity &&
           generation != 0 && generation <= kGuiSendEndpointGenerationMaximum;
}

constexpr u32 GuiSendTaskEndpointSlot(GuiSendTaskEndpointIdentity identity)
{
    return GuiSendTaskEndpointIdentityIsCanonical(identity)
               ? static_cast<u32>((identity.value & kGuiSendEndpointSlotMask) - 1ULL)
               : kGuiSendServiceEndpointCapacity;
}

constexpr u64 GuiSendTaskEndpointGeneration(GuiSendTaskEndpointIdentity identity)
{
    return GuiSendTaskEndpointIdentityIsCanonical(identity) ? identity.value >> kGuiSendEndpointSlotBits : 0;
}

// The reusable transaction table has no knowledge of its owning service
// instance. Every authority-bearing identity crossing the service boundary
// therefore carries the non-reused service incarnation too.
struct GuiSendServiceCallIdentity
{
    u32 slot;
    u32 reserved;
    u64 generation;
    u64 service_incarnation;
};

inline constexpr GuiSendServiceCallIdentity kInvalidGuiSendServiceCallIdentity{kGuiSendInvalidSlot, 0, 0, 0};

constexpr bool GuiSendServiceCallIdentityIsCanonical(GuiSendServiceCallIdentity identity)
{
    return identity.service_incarnation != 0 &&
           GuiSendCallIdentityIsValid(GuiSendCallIdentity{identity.slot, identity.reserved, identity.generation});
}

constexpr bool GuiSendServiceCallIdentityIsInvalidCanonical(GuiSendServiceCallIdentity identity)
{
    return identity.slot == kGuiSendInvalidSlot && identity.reserved == 0 && identity.generation == 0 &&
           identity.service_incarnation == 0;
}

constexpr bool operator==(GuiSendServiceCallIdentity lhs, GuiSendServiceCallIdentity rhs)
{
    return lhs.slot == rhs.slot && lhs.reserved == rhs.reserved && lhs.generation == rhs.generation &&
           lhs.service_incarnation == rhs.service_incarnation;
}

constexpr bool operator!=(GuiSendServiceCallIdentity lhs, GuiSendServiceCallIdentity rhs)
{
    return !(lhs == rhs);
}

constexpr GuiSendCallIdentity GuiSendTransactionIdentity(GuiSendServiceCallIdentity identity)
{
    return GuiSendCallIdentity{identity.slot, identity.reserved, identity.generation};
}

constexpr GuiSendServiceCallIdentity GuiSendServiceIdentity(u64 service_incarnation, GuiSendCallIdentity identity)
{
    return service_incarnation != 0 && GuiSendCallIdentityIsValid(identity)
               ? GuiSendServiceCallIdentity{identity.slot, identity.reserved, identity.generation, service_incarnation}
               : kInvalidGuiSendServiceCallIdentity;
}

struct GuiSendServiceDispatchToken
{
    u64 service_incarnation;
    GuiSendDispatchToken transaction;
};

inline constexpr GuiSendServiceDispatchToken kInvalidGuiSendServiceDispatchToken{
    0, {kInvalidGuiSendCallIdentity, {}, 0, 0, {}}};

inline bool GuiSendServiceDispatchTokenIsCanonical(const GuiSendServiceDispatchToken& token)
{
    return token.service_incarnation != 0 && GuiSendDispatchTokenIsCanonical(token.transaction);
}

constexpr GuiSendServiceCallIdentity GuiSendServiceDispatchCall(const GuiSendServiceDispatchToken& token)
{
    return GuiSendServiceIdentity(token.service_incarnation, token.transaction.call);
}

constexpr bool GuiSendServiceDispatchTokenIsInvalidCanonical(const GuiSendServiceDispatchToken& token)
{
    return token.service_incarnation == 0 && token.transaction.call == kInvalidGuiSendCallIdentity &&
           token.transaction.dispatcher.endpoint_identity == 0 && token.transaction.dispatcher.process_identity == 0 &&
           token.transaction.dispatcher.task_identity == 0 && token.transaction.dispatcher.reserved[0] == 0 &&
           token.transaction.dispatcher.reserved[1] == 0 && token.transaction.dispatcher.reserved[2] == 0 &&
           token.transaction.dispatcher.reserved[3] == 0 && token.transaction.dispatcher.reserved[4] == 0 &&
           token.transaction.dispatcher.reserved[5] == 0 && token.transaction.dispatcher.reserved[6] == 0 &&
           token.transaction.dispatcher.reserved[7] == 0 && token.transaction.request_sequence == 0 &&
           token.transaction.valid == 0 && token.transaction.reserved[0] == 0 && token.transaction.reserved[1] == 0 &&
           token.transaction.reserved[2] == 0 && token.transaction.reserved[3] == 0 &&
           token.transaction.reserved[4] == 0 && token.transaction.reserved[5] == 0 &&
           token.transaction.reserved[6] == 0;
}

static_assert(!GuiSendTaskEndpointIdentityIsCanonical(kInvalidGuiSendTaskEndpoint));
static_assert(GuiSendServiceCallIdentityIsInvalidCanonical(kInvalidGuiSendServiceCallIdentity));
static_assert(!GuiSendServiceCallIdentityIsCanonical(kInvalidGuiSendServiceCallIdentity));
static_assert(GuiSendServiceDispatchTokenIsInvalidCanonical(kInvalidGuiSendServiceDispatchToken));

struct GuiSendServiceWakeAction
{
    u64 mutation_epoch;
    u8 wake_all;
    u8 reserved[7];
};

struct GuiSendServiceWaitToken
{
    GuiSendTaskEndpointIdentity endpoint;
    u64 mutation_epoch;
    u8 valid;
    u8 reserved[7];
};

enum class GuiSendEndpointResult : u8
{
    Rejected = 0,
    Created,
    Existing,
    TableFull,
    GenerationExhausted,
};

enum class GuiSendEndpointCloseResult : u8
{
    Rejected = 0,
    Closed,
    Stale,
};

struct GuiSendEndpointCloseSummary
{
    u32 caller_transitions;
    u32 target_transitions;
    u32 caller_rows_retired;
    u32 reserved;
    GuiSendServiceWakeAction wake;
};

struct GuiSendServiceBeginRequest
{
    GuiSendTaskEndpointIdentity caller_endpoint;
    GuiSendTaskEndpointIdentity target_endpoint;
    // Exact kernel-private proof for the WndProc frame issuing a nested
    // send. Root sends use kInvalidGuiSendServiceDispatchToken. Ring 3 must
    // never populate this field.
    GuiSendServiceDispatchToken parent_dispatch;
    u64 target_window_identity;
    u64 wparam;
    u64 lparam;
    u64 absolute_deadline;
    u32 message;
    u32 reserved;
};

enum class GuiSendServiceBeginResult : u8
{
    Rejected = 0,
    Created,
    CallerEndpointStale,
    TargetEndpointStale,
    CrossProcessDenied,
    SameTaskDirectRequired,
    InvalidTargetWindow,
    InvalidMessage,
    DeadlineElapsed,
    SequenceExhausted,
    ParentUnavailable,
    ParentRequired,
    DepthLimit,
    Cycle,
    CallerQuotaExceeded,
    TableFull,
    GenerationExhausted,
    InvariantViolation,
};

struct GuiSendServiceBeginOutput
{
    GuiSendServiceCallIdentity call;
    u64 request_sequence;
    GuiSendServiceWakeAction wake;
};

enum class GuiSendServiceCompletionReason : u8
{
    Invalid = 0,
    Reply,
    CallerCancelled,
    DeadlineExpired,
    TargetWindowClosed,
    TargetTaskExited,
    AncestorCancelled,
};

struct GuiSendServiceDispatch
{
    // Kernel-private proof retained by the syscall adapter. Never copy this
    // structure directly to ring 3.
    GuiSendServiceDispatchToken reply_token;
    GuiSendTaskEndpointIdentity target_endpoint;
    u64 target_window_identity;
    u64 request_sequence;
    u64 wparam;
    u64 lparam;
    u64 absolute_deadline;
    u32 message;
    u8 reentrancy_depth;
    u8 reserved[3];
};

struct GuiSendServiceCompletion
{
    GuiSendServiceCallIdentity call;
    GuiSendServiceCompletionReason reason;
    GuiSendTransactionPhase transaction_phase;
    u8 valid;
    u8 reserved[5];
    u64 request_sequence;
    u64 reply_value;
};

enum class GuiSendServicePumpKind : u8
{
    Invalid = 0,
    Idle,
    Dispatch,
    Completion,
};

enum class GuiSendServicePumpResult : u8
{
    Rejected = 0,
    Pumped,
    EndpointStale,
    WaitingCallStale,
    WrongCaller,
    DispatchContextFull,
    InvariantViolation,
};

struct GuiSendServicePumpOutput
{
    GuiSendServicePumpKind kind;
    u8 reserved[7];
    GuiSendServiceDispatch dispatch;
    GuiSendServiceCompletion completion;
    GuiSendServiceWaitToken wait_token;
    GuiSendServiceWakeAction wake;
};

enum class GuiSendServiceReplyResult : u8
{
    Rejected = 0,
    Committed,
    DeadlineExpired,
    EndpointStale,
    WrongDispatcher,
    WrongClaim,
    ActiveChild,
    Terminal,
    Stale,
    InvariantViolation,
};

enum class GuiSendServiceCancelResult : u8
{
    Rejected = 0,
    Cancelled,
    EndpointStale,
    WrongCaller,
    TooLate,
    Stale,
    InvariantViolation,
};

enum class GuiSendServiceCallState : u8
{
    Vacant = 0,
    Queued,
    Dispatching,
    Terminal,
};

struct GuiSendServiceCallSnapshot
{
    GuiSendServiceCallIdentity call;
    GuiSendTaskEndpointIdentity caller_endpoint;
    GuiSendTaskEndpointIdentity target_endpoint;
    u64 target_window_identity;
    u64 fifo_ticket;
    GuiSendServiceCallState state;
    GuiSendServiceCompletionReason reason;
    u8 valid;
    u8 reserved[5];
    GuiSendTransactionSnapshot transaction;
};

class GuiSendService
{
  public:
    // Non-hot-reloadable: endpoint/call generations and wait epochs must live
    // for the whole kernel boot. The eventual owner should be one kernel
    // service instance, not a reloadable compositor module.
    GuiSendService();
    GuiSendService(const GuiSendService&) = delete;
    GuiSendService& operator=(const GuiSendService&) = delete;
    GuiSendService(GuiSendService&&) = delete;
    GuiSendService& operator=(GuiSendService&&) = delete;

    /// Ensure one canonical endpoint for an authenticated live task identity.
    /// Existing returns the exact current endpoint. The caller authenticates
    /// task liveness; this service stores only scalar identities.
    /// [kernel task context, any CPU, thread-safe, allocation-free]
    GuiSendEndpointResult EnsureTaskEndpoint(u64 process_identity, u64 task_identity,
                                             GuiSendTaskEndpointIdentity* out_endpoint);

    /// Close one exact endpoint generation. Outbound rows are cancelled and
    /// retired because their caller can no longer consume; inbound rows become
    /// TargetTaskExited completions for their still-live callers.
    /// [task teardown, kernel task context, any CPU, thread-safe]
    GuiSendEndpointCloseResult CloseTaskEndpoint(GuiSendTaskEndpointIdentity endpoint,
                                                 GuiSendEndpointCloseSummary* out_summary);

    /// Begin one same-process cross-task scalar call. The window adapter must
    /// freeze target endpoint + exact public HWND generation atomically with
    /// window liveness. parent_dispatch is the invalid canonical token for a
    /// root call. A caller already executing a dispatched WndProc must supply
    /// that frame's exact retained kernel-private token; omitting it is denied.
    /// Publish output.wake only after every outer compositor lock drops.
    /// [kernel task context, any CPU, thread-safe, allocation-free]
    GuiSendServiceBeginResult Begin(const GuiSendServiceBeginRequest& request, u64 now, GuiSendServiceBeginOutput* out);

    /// Service inbound sent calls before checking one outbound completion.
    /// waiting_call may be kInvalidGuiSendServiceCallIdentity for Get/Peek.
    /// Idle returns a wait token. Dispatch records and reply tokens remain
    /// kernel-private; the adapter invokes no WndProc while inside this call.
    /// A Dispatch result also pushes an exact per-endpoint execution frame.
    /// The adapter must call CommitReply after that WndProc returns even if
    /// cancellation, timeout, or caller consumption already made it terminal.
    /// [target/sender pump, kernel task context, any CPU, thread-safe]
    GuiSendServicePumpResult Pump(GuiSendTaskEndpointIdentity endpoint, GuiSendServiceCallIdentity waiting_call,
                                  u64 now, GuiSendServicePumpOutput* out);

    /// Commit the scalar WndProc result from the exact retained dispatch token.
    /// The token must be the endpoint's current/top execution frame. A final
    /// Committed, DeadlineExpired, Terminal, or Stale result pops that frame;
    /// ActiveChild and proof failures retain it for an exact retry.
    /// [target reply boundary, kernel task context, any CPU, thread-safe]
    GuiSendServiceReplyResult CommitReply(GuiSendTaskEndpointIdentity dispatcher_endpoint,
                                          const GuiSendServiceDispatchToken& token, u64 completed_at, u64 reply_value,
                                          GuiSendServiceWakeAction* out_wake);

    /// Cancel one exact call on behalf of its authenticated caller endpoint.
    /// [caller boundary, kernel task context, any CPU, thread-safe]
    GuiSendServiceCancelResult Cancel(GuiSendTaskEndpointIdentity caller_endpoint, GuiSendServiceCallIdentity call,
                                      GuiSendServiceWakeAction* out_wake);

    /// Cancel only mutable calls targeting this exact endpoint+HWND generation.
    /// Invoke while close is serialized against Begin's target snapshot; defer
    /// the returned wake until compositor unlock. Returns roots transitioned;
    /// descendant cancellation is reflected in Pump completions as well.
    /// [window close boundary, kernel task context, any CPU, thread-safe]
    u32 CancelTargetWindow(GuiSendTaskEndpointIdentity target_endpoint, u64 target_window_identity,
                           GuiSendServiceWakeAction* out_wake);

    /// Transition every due mutable call. Intended for a service tick after
    /// compositor unlock; no time source is sampled inside this service.
    /// [timer task, any CPU, thread-safe]
    u32 ExpireDeadlines(u64 now, GuiSendServiceWakeAction* out_wake);

    /// Revalidate an Idle pump token. The scheduler adapter must combine this
    /// comparison with wait-queue enqueue atomically or retain bounded polling.
    /// [any context able to take an IRQ-safe spinlock, thread-safe]
    bool WaitTokenCurrent(const GuiSendServiceWaitToken& token);

    /// Bounded diagnostics. No retained reference is returned.
    /// [kernel task context, any CPU, thread-safe]
    bool InspectCall(GuiSendServiceCallIdentity call, GuiSendServiceCallSnapshot* out_snapshot);
    u32 ActiveEndpointCount();
    u32 ActiveCallCount();
    u32 ActiveDispatchFrameCount();

#if defined(DUETOS_HOST_TEST)
    bool HostPositionEndpointGeneration(u32 slot, u64 generation);
    bool HostPositionNextFifoTicket(u64 ticket);
    sync::LockClass HostServiceLockClass() const;
#endif

  private:
    struct EndpointRow
    {
        u64 process_identity = 0;
        u64 task_identity = 0;
        u64 generation = 0;
        u64 next_request_sequence = 1;
        u32 top_dispatch_frame_biased = 0;
        bool active = false;
        bool retired = false;
    };

    struct CallRow
    {
        GuiSendServiceCallIdentity call{};
        GuiSendTaskEndpointIdentity caller_endpoint{};
        GuiSendTaskEndpointIdentity target_endpoint{};
        u64 target_window_identity = 0;
        u64 fifo_ticket = 0;
        GuiSendServiceCallState state = GuiSendServiceCallState::Vacant;
        GuiSendServiceCompletionReason reason = GuiSendServiceCompletionReason::Invalid;
        bool active = false;
    };

    struct DispatchFrame
    {
        GuiSendServiceDispatchToken token = kInvalidGuiSendServiceDispatchToken;
        GuiSendTaskEndpointIdentity endpoint = kInvalidGuiSendTaskEndpoint;
        u32 previous_frame_biased = 0;
        bool active = false;
    };

    EndpointRow* ResolveEndpointLocked(GuiSendTaskEndpointIdentity endpoint);
    const EndpointRow* ResolveEndpointLocked(GuiSendTaskEndpointIdentity endpoint) const;
    CallRow* ResolveCallLocked(GuiSendServiceCallIdentity call);
    const CallRow* ResolveCallLocked(GuiSendServiceCallIdentity call) const;
    GuiSendPrincipalSnapshot PrincipalLocked(GuiSendTaskEndpointIdentity endpoint, const EndpointRow& row) const;
    GuiSendTaskEndpointIdentity IdentityForEndpointLocked(u32 slot, const EndpointRow& row) const;
    bool AllocateFifoTicketLocked(u64* out_ticket);
    u32 CallerActiveCallCountLocked(GuiSendTaskEndpointIdentity endpoint) const;
    DispatchFrame* TopDispatchFrameLocked(GuiSendTaskEndpointIdentity endpoint, EndpointRow& row);
    const DispatchFrame* TopDispatchFrameLocked(GuiSendTaskEndpointIdentity endpoint, const EndpointRow& row) const;
    DispatchFrame* FindVacantDispatchFrameLocked();
    bool PushDispatchFrameLocked(GuiSendTaskEndpointIdentity endpoint, EndpointRow& row,
                                 const GuiSendServiceDispatchToken& token);
    void PopDispatchFrameLocked(EndpointRow& row, DispatchFrame& frame);
    void ClearDispatchFramesLocked(GuiSendTaskEndpointIdentity endpoint, EndpointRow& row);
    void ReconcileTerminalLocked(GuiSendServiceCompletionReason cancelled_reason);
    void PublishWakeLocked(GuiSendServiceWakeAction* out_wake);
    GuiSendServiceBeginResult MapBeginResultLocked(GuiSendBeginResult result) const;
    void ClearCallLocked(CallRow& row);

    sync::SpinLock m_lock{0, 0, 0xFFFFFFFFu, sync::kLockClassGuiSendService};
    EndpointRow m_endpoints[kGuiSendServiceEndpointCapacity]{};
    CallRow m_calls[kGuiSendTransactionCapacity]{};
    DispatchFrame m_dispatch_frames[kGuiSendServiceDispatchFrameCapacity]{};
    GuiSendTransactionTable m_transactions{};
    u64 m_service_incarnation = 0;
    u64 m_next_fifo_ticket = 1;
    u64 m_mutation_epoch = 1;
    bool m_mutation_epoch_saturated = false;
};

} // namespace duetos::drivers::video
