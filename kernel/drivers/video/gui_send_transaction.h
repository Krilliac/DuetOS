#pragma once

#include "sync/spinlock.h"
#include "util/types.h"

/*
 * DuetOS -- synchronous GUI SendMessage transaction state.
 *
 * A non-hot-reloadable GUI broker owns one caller-allocated table. The table
 * contains a fixed number of rows, performs no allocation, and stores no raw
 * Task, Process, Window, KObject, wait-queue, callback, or user pointer. All
 * identities are opaque full-width generations authenticated by the caller
 * before entry; values from message bytes never create endpoint, process,
 * task, window, dispatcher, or policy authority here.
 *
 * Ownership and lock boundary:
 *
 *   transport + GUI policy       authenticate/freeze scalar identities
 *              |                 (outside this table)
 *              v
 *   GuiSendTransactionTable      owns rows, generations, and transitions
 *              |
 *              v
 *   scheduler/wait adapter       blocks/wakes only after the table lock drops
 *
 * Every public operation takes the one table lock for a bounded scan and
 * returns scalar copies. No callback, logging, allocation, scheduler call,
 * KObject operation, user copy, or secondary lock occurs while it is held.
 * Integration must recheck the exact call generation when coupling a state
 * observation to a scheduler wait so completion cannot become a lost wakeup.
 *
 * Lifecycle:
 *
 *   Pending -> Dispatching -> ReplyReady -> Retired
 *      |            |
 *      +------------+-> Cancelled -> Retired
 *      +------------+-> TimedOut  -> Retired
 *
 * Cancel, timeout, death, dispatcher claim, and reply commit linearize at the
 * table lock. A terminal transition cancels still-mutable descendants without
 * overwriting a reply that already won its own race. A dispatcher cannot
 * complete a parent while an exact child remains unretired. Retired slots may
 * be reused only after incrementing their generation; the maximum generation
 * permanently exhausts the slot rather than wrapping.
 */

namespace duetos::drivers::video
{

inline constexpr u32 kGuiSendTransactionCapacity = 64;
inline constexpr u8 kGuiSendMaximumReentrancyDepth = 8;
inline constexpr u32 kGuiSendInvalidSlot = static_cast<u32>(~0U);
inline constexpr u64 kGuiSendGenerationMaximum = static_cast<u64>(~0ULL);

struct GuiSendCallIdentity
{
    u32 slot;
    u32 reserved;
    u64 generation;
};

inline constexpr GuiSendCallIdentity kInvalidGuiSendCallIdentity{kGuiSendInvalidSlot, 0, 0};

constexpr bool GuiSendCallIdentityIsValid(GuiSendCallIdentity identity)
{
    return identity.slot < kGuiSendTransactionCapacity && identity.reserved == 0 && identity.generation != 0;
}

constexpr bool operator==(GuiSendCallIdentity lhs, GuiSendCallIdentity rhs)
{
    return lhs.slot == rhs.slot && lhs.reserved == rhs.reserved && lhs.generation == rhs.generation;
}

constexpr bool operator!=(GuiSendCallIdentity lhs, GuiSendCallIdentity rhs)
{
    return !(lhs == rhs);
}

struct GuiSendPrincipalSnapshot
{
    u64 endpoint_identity;
    u64 process_identity;
    u64 task_identity;
    u8 reserved[8];
};

struct GuiSendTaskIdentity
{
    u64 process_identity;
    u64 task_identity;
};

// All fields are trusted scalar snapshots. `request_sequence` is the exact
// authenticated transport request sequence. `policy_authority_identity` names
// the already-approved policy/grant generation; this table does not evaluate
// message policy. Deadline units come from one broker-owned monotonic clock.
struct GuiSendFrozenCall
{
    GuiSendCallIdentity parent_call;
    u64 sender_endpoint_identity;
    u64 sender_process_identity;
    u64 sender_task_identity;
    u64 target_process_identity;
    u64 target_task_identity;
    u64 target_window_identity;
    u64 policy_authority_identity;
    u64 request_sequence;
    u64 wparam;
    u64 lparam;
    u64 absolute_deadline;
    u32 message;
    u8 reentrancy_depth;
    u8 reserved[3];
};

enum class GuiSendTransactionPhase : u8
{
    Vacant = 0,
    Pending,
    Dispatching,
    ReplyReady,
    Cancelled,
    TimedOut,
    Retired,
    GenerationExhausted,
};

struct GuiSendDispatchToken
{
    // Kernel-local proof of the exact ClaimDispatch result. This shape is not
    // a wire capability and must never be populated from caller message bytes.
    GuiSendCallIdentity call;
    GuiSendPrincipalSnapshot dispatcher;
    u64 request_sequence;
    u8 valid;
    u8 reserved[7];
};

struct GuiSendDispatchClaim
{
    GuiSendDispatchToken token;
    GuiSendFrozenCall call;
};

struct GuiSendCompletion
{
    GuiSendCallIdentity call;
    GuiSendTransactionPhase phase;
    u8 valid;
    u8 reserved[6];
    u64 request_sequence;
    u64 reply_value;
};

struct GuiSendTransactionSnapshot
{
    GuiSendCallIdentity identity;
    GuiSendTransactionPhase phase;
    u8 valid;
    u8 reserved[6];
    GuiSendFrozenCall call;
    GuiSendPrincipalSnapshot dispatcher;
    u64 reply_value;
};

enum class GuiSendBeginResult : u8
{
    Rejected = 0,
    Created,
    DeadlineElapsed,
    DuplicateRequest,
    ParentUnavailable,
    DepthMismatch,
    Cycle,
    TableFull,
    GenerationExhausted,
};

enum class GuiSendDispatchResult : u8
{
    Rejected = 0,
    Claimed,
    TimedOut,
    WrongPrincipal,
    NotPending,
    Stale,
};

enum class GuiSendReplyResult : u8
{
    Rejected = 0,
    Committed,
    TimedOut,
    WrongPrincipal,
    WrongClaim,
    ActiveChild,
    Terminal,
    Stale,
};

enum class GuiSendCancelResult : u8
{
    Rejected = 0,
    Cancelled,
    WrongPrincipal,
    TooLate,
    Stale,
};

enum class GuiSendTimeoutResult : u8
{
    Rejected = 0,
    TimedOut,
    NotDue,
    TooLate,
    Stale,
};

enum class GuiSendConsumeResult : u8
{
    Rejected = 0,
    Consumed,
    NotReady,
    WrongPrincipal,
    Stale,
};

enum class GuiSendRetireResult : u8
{
    Rejected = 0,
    Retired,
    NotTerminal,
    Stale,
};

/// Pure representation checks; none authenticates its input.
/// [any thread, pure, allocation-free]
bool GuiSendPrincipalSnapshotIsCanonical(const GuiSendPrincipalSnapshot& principal);
bool GuiSendTaskIdentityIsCanonical(const GuiSendTaskIdentity& task);
bool GuiSendFrozenCallShapeIsCanonical(const GuiSendFrozenCall& call);
bool GuiSendDispatchTokenIsCanonical(const GuiSendDispatchToken& token);

class GuiSendTransactionTable
{
  public:
    GuiSendTransactionTable() = default;
    GuiSendTransactionTable(const GuiSendTransactionTable&) = delete;
    GuiSendTransactionTable& operator=(const GuiSendTransactionTable&) = delete;
    GuiSendTransactionTable(GuiSendTransactionTable&&) = delete;
    GuiSendTransactionTable& operator=(GuiSendTransactionTable&&) = delete;

    /// Reserve one exact non-wrapping call generation. `now` and the absolute
    /// deadline use the same trusted monotonic clock. For nested calls the
    /// exact parent must still be Dispatching, its dispatcher must equal this
    /// sender, depth must increase by one, the deadline may not extend the
    /// parent, and the ancestry route must remain acyclic.
    /// [broker boundary, any thread, IRQ-safe, thread-safe]
    GuiSendBeginResult Begin(const GuiSendFrozenCall& call, u64 now, GuiSendCallIdentity* out_identity);

    /// Claim Pending for the exact target process/task. The authenticated
    /// dispatcher endpoint is frozen into the row and token. No target work is
    /// invoked while the lock is held.
    /// [target dispatch boundary, any thread, IRQ-safe, thread-safe]
    GuiSendDispatchResult ClaimDispatch(GuiSendCallIdentity identity, const GuiSendPrincipalSnapshot& dispatcher,
                                        u64 now, GuiSendDispatchClaim* out_claim);

    /// Commit one scalar reply from the exact claim and dispatcher. Completion
    /// at or after the absolute deadline loses to timeout even if no timer scan
    /// ran first. Active nested children prevent parent completion.
    /// [target reply boundary, any thread, IRQ-safe, thread-safe]
    GuiSendReplyResult CommitReply(const GuiSendDispatchToken& token, const GuiSendPrincipalSnapshot& dispatcher,
                                   u64 completed_at, u64 reply_value);

    /// Linearized caller cancellation. Pending or Dispatching becomes
    /// Cancelled and active descendants are cancelled in the same section.
    /// [authenticated caller boundary, any thread, IRQ-safe, thread-safe]
    GuiSendCancelResult CancelByCaller(GuiSendCallIdentity identity, const GuiSendPrincipalSnapshot& caller);

    /// Linearized deadline transition using the broker's trusted clock.
    /// [broker timer boundary, any thread, IRQ-safe, thread-safe]
    GuiSendTimeoutResult TimeoutAt(GuiSendCallIdentity identity, u64 now);

    /// Cancel every active call owned by this exact caller endpoint generation,
    /// including descendants. Returns the number of rows transitioned.
    /// [caller teardown, any thread, IRQ-safe, thread-safe]
    u32 CancelCallerDeath(const GuiSendPrincipalSnapshot& caller);

    /// Cancel every active call targeting this exact process/task generation,
    /// including descendants. Returns the number of rows transitioned.
    /// [target teardown, any thread, IRQ-safe, thread-safe]
    u32 CancelTargetDeath(const GuiSendTaskIdentity& target);

    /// Atomically copy a terminal result for the exact caller and transition
    /// the row to Retired. Failure always clears `out_completion`.
    /// [authenticated caller boundary, any thread, IRQ-safe, thread-safe]
    GuiSendConsumeResult Consume(GuiSendCallIdentity identity, const GuiSendPrincipalSnapshot& caller,
                                 GuiSendCompletion* out_completion);

    /// Broker-only cleanup for a terminal result whose caller can no longer
    /// consume it. Never retires Pending or Dispatching work.
    /// [broker cleanup, any thread, IRQ-safe, thread-safe]
    GuiSendRetireResult RetireAbandoned(GuiSendCallIdentity identity);

    /// Exact broker diagnostic snapshot. Retired is observable until reuse;
    /// stale generations and permanently exhausted rows fail closed.
    /// [broker diagnostics, any thread, IRQ-safe, thread-safe]
    bool Inspect(GuiSendCallIdentity identity, GuiSendTransactionSnapshot* out_snapshot);

    /// Count non-retired rows. Intended for bounded broker diagnostics only.
    /// [broker diagnostics, any thread, IRQ-safe, thread-safe]
    u32 ActiveCount();

#if defined(DUETOS_HOST_TEST)
    bool HostPositionInactiveGeneration(u32 slot, u64 generation);
    sync::LockClass HostTransactionLockClass() const;
#endif

  private:
    struct Row
    {
        GuiSendFrozenCall call{};
        GuiSendPrincipalSnapshot dispatcher{};
        u64 generation = 0;
        u64 reply_value = 0;
        GuiSendTransactionPhase phase = GuiSendTransactionPhase::Vacant;
    };

    Row* FindExactLocked(GuiSendCallIdentity identity);
    const Row* FindExactLocked(GuiSendCallIdentity identity) const;
    bool ParentChainIsAvailableLocked(const GuiSendFrozenCall& call, GuiSendBeginResult* out_error) const;
    bool HasActiveChildLocked(GuiSendCallIdentity identity) const;
    u32 CancelWithDescendantsLocked(GuiSendCallIdentity identity, GuiSendTransactionPhase root_phase);
    void RetireLocked(Row& row);

    sync::SpinLock m_lock{0, 0, 0xFFFFFFFFu, sync::kLockClassGuiSendTransaction};
    Row m_rows[kGuiSendTransactionCapacity]{};
};

} // namespace duetos::drivers::video
