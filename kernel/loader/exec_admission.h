#pragma once

/*
 * Allocation-free executable-plan admission.
 *
 * Prepare copies one hostile plan blob exactly once into caller-provided
 * storage owned exclusively by this object. Consume validates only that frozen
 * copy and is the sole operation that can return a decoded LoadPlan view.
 * Expected source identity and backing authority are supplied by the kernel at
 * consume time; neither can be authored by the plan.
 *
 * A successful consume is terminal, keeping every returned view stable for the
 * admission object's lifetime. Cancelled or rejected attempts retire their
 * exact token and may be followed by a new prepare. Tokens never wrap: issuing
 * UINT64_MAX poisons the object after that attempt retires.
 *
 * This layer has no allocator, process, address-space, mapper, service, IPC, or
 * publication dependency. In particular, the complete v1 maximum is 18,496
 * bytes, so a 4,096-byte MessagePort cannot inline it. Future IPC transport must
 * use a sealed typed-object handle or a bounded authenticated chunk contract.
 */

#include "loader/load_plan.h"
#include "util/types.h"

#if !defined(DUETOS_HOST_TEST)
#include "sync/spinlock.h"
#endif

namespace duetos::loader
{

inline constexpr u32 kExecAdmissionMaxPlanBytes = kLoadPlanV1HeaderBytes + kLoadPlanMaxRegions * kLoadRegionV1Bytes;
static_assert(kExecAdmissionMaxPlanBytes == 18496, "exec admission v1 maximum changed");

enum class ExecAdmissionState : u8
{
    Uninitialized = 0,
    Idle,
    Copying,
    Prepared,
    Validating,
    Consumed,
    Poisoned,
};

enum class ExecAdmissionStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    StorageTooSmall,
    AliasedBuffer,
    Busy,
    Terminal,
    PlanTooLarge,
    StaleToken,
    TokenReplayed,
    IdentityExhausted,
    CancelPending,
    Cancelled,
    PlanRejected,
    CorruptState,
    NotQuiescent,
};

struct ExecAdmissionPrepareResult
{
    ExecAdmissionStatus status;
    u64 token;
};

struct ExecAdmissionConsumeResult
{
    ExecAdmissionStatus status;
    LoadPlanValidationError validation_error;
};

#if defined(DUETOS_HOST_TEST)
struct ExecAdmissionHostLock
{
    u32 next_ticket;
    u32 now_serving;
};
#endif

// Implementation storage is public only so callers can embed it without an
// allocator. Treat every field as opaque after initialization.
struct ExecAdmission
{
#if defined(DUETOS_HOST_TEST)
    ExecAdmissionHostLock lock;
#else
    sync::SpinLock lock;
#endif
    u8* storage;
    u32 storage_capacity;
    u32 frozen_bytes;
    u32 initialized;
    ExecAdmissionState state;
    u8 cancel_requested;
    u8 identity_exhausted;
    u8 reserved;
    u64 next_identity;
    u64 active_identity;
    u64 retired_identity;
};

// [unpublished/quiescent object]
// Initialize over storage large enough for every v1 plan. `first_identity`
// exists so deterministic tests can exercise exhaustion; production uses 1.
ExecAdmissionStatus ExecAdmissionInitialize(ExecAdmission* admission, void* storage, u32 storage_bytes,
                                            u64 first_identity = 1);

// [exclusive unpublished owner, quiescent]
// Snapshot the next nonwrapping token for a successor fixed bank. Consumed is
// the normal handoff state; Idle is accepted for failure cleanup. No active or
// cancel-pending attempt and no lock holder/waiter may exist. The output is not
// modified on failure and must not alias this object or its frozen storage.
ExecAdmissionStatus ExecAdmissionQuiescentSuccessorIdentity(const ExecAdmission* admission, u64* first_identity_out);

// [exclusive unpublished owner, quiescent]
// Validate, without mutation, that an initialized Idle/Consumed/Poisoned bank
// has no active/cancel-pending attempt or lock participant and can be reset.
ExecAdmissionStatus ExecAdmissionCanResetQuiescent(const ExecAdmission* admission);

// Apply the same proof, clear frozen bytes, and return the object and lock to
// canonical-zero form field-by-field. This is the sole supported path before
// reuse. Call QuiescentSuccessorIdentity first when another bank must continue
// the same logical nonwrapping token namespace. Failure changes no byte.
ExecAdmissionStatus ExecAdmissionResetQuiescent(ExecAdmission* admission);

// [any task, thread-safe; source must be readable/non-faulting for this call]
// Reserve a nonwrapping token and copy exactly `byte_count` bytes into frozen
// storage. No plan field is decoded and no authority callback runs here.
ExecAdmissionPrepareResult ExecAdmissionPrepare(ExecAdmission* admission, const void* plan_bytes, u64 byte_count);

// [any task, thread-safe]
// Validate the exact prepared token. The backing callback runs with no
// admission lock held; expected source identity is snapshotted before that
// callback can run. On success `view_out` is the only borrowed exposure of the
// frozen bytes and remains valid because the object becomes terminal.
// `expected_source_hash`, when present, must be trusted caller storage and may
// not alias the admission object or frozen plan.
// `view_out` must be writable and must not overlap the admission object or its
// frozen storage. Such overlap returns AliasedBuffer without touching the
// output, because clearing it would corrupt admission state; every other
// failure clears `view_out`. Validation rejection retires the token.
ExecAdmissionConsumeResult ExecAdmissionConsume(ExecAdmission* admission, u64 token,
                                                const Hash256* expected_source_hash, LoadBackingQueryV1 query_backing,
                                                void* query_context, LoadPlanViewV1* view_out);

// [any task, thread-safe]
// Cancel only the exact prepared token. During validation this installs a
// cancellation request; Consume observes it after the unlocked callback pass
// and returns Cancelled without publishing a view.
ExecAdmissionStatus ExecAdmissionCancel(ExecAdmission* admission, u64 token);

const char* ExecAdmissionStatusName(ExecAdmissionStatus status);

} // namespace duetos::loader
