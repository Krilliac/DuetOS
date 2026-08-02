#pragma once

/*
 * Authenticated native-userland ingress for ServiceEndpoint.
 *
 * The syscall wrapper copies a fixed control block and at most one 4 KiB frame
 * into kernel storage.  This core accepts kernel buffers only, which keeps the
 * authority and receipt state directly host-testable.  A completion receipt is
 * bound to the current full ProcessKey and exact endpoint generation; it owns
 * no endpoint reference or operation pin between syscalls.
 */

#include "core/service_endpoint.h"
#include "core/service_runtime.h"
#include "ipc/handle_table.h"
#include "proc/process.h"
#include "util/types.h"

#include "../../userland/libc/include/duet/service_endpoint.h"

#if defined(DUETOS_HOST_TEST)
#include <mutex>
#else
#include "sync/spinlock.h"
#endif

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::core
{

inline constexpr u32 kServiceEndpointIngressReceiptCapacity = 128;
inline constexpr u32 kServiceEndpointIngressReceiptPerProcess = 32;
inline constexpr u32 kServiceEndpointIngressCursorCapacity = 64;
inline constexpr u32 kServiceEndpointIngressConnectRollbackCapacity = 16;
inline constexpr u32 kServiceEndpointIngressReceiptGenerationMaximum = 0x00FFFFFFU;
inline constexpr u32 kServiceEndpointIngressInitializedMarker = 0x53454931U; // "SEI1"

enum class ServiceEndpointIngressStatus : u8
{
    Ok = 0,
    InvalidArgument,
    AlreadyInitialized,
    NotInitialized,
    CorruptState,
};

enum class ServiceEndpointIngressReceiptState : u8
{
    Free = 0,
    Pending,
    Live,
    Replying,
    Retired,
};

struct ServiceEndpointIngressReceiptRow
{
    ProcessKey owner;
    ServiceEndpointIdentity endpoint;
    ipc::EndpointRequestCompletionAuthority completion;
    u64 request_id;
    u32 generation;
    ServiceEndpointIngressReceiptState state;
    u8 reserved[3];
};

struct ServiceEndpointIngressCursorRow
{
    ProcessKey owner;
    ServiceEndpointIdentity endpoint;
    u64 last_committed_request_sequence;
    bool live;
    u8 reserved[7];
};

enum class ServiceEndpointIngressConnectRollbackState : u8
{
    Free = 0,
    Reserved,
    Live,
    Driving,
};

// Exact detached ownership returned by a failed directory CONNECT. A slot is
// reserved before ServiceDirectoryConnect mutates anything, so a Busy cleanup
// receipt can never be lost from syscall-stack storage.
struct ServiceEndpointIngressConnectRollbackRow
{
    ServiceDirectory* directory;
    ServiceDirectoryOwnedChannel channel;
    ServiceEndpointIngressConnectRollbackState state;
    u8 reserved[7];
};

// Public only for one static kernel owner and hostile hosted tests. Treat every
// field as opaque after ServiceEndpointIngressInitialize succeeds.
struct ServiceEndpointIngressState
{
#if defined(DUETOS_HOST_TEST)
    std::mutex lock;
#else
    sync::SpinLock lock;
#endif
    u32 initialized;
    u32 next_receipt_hint;
    u32 next_cursor_hint;
    u32 next_connect_rollback_hint;
    u64 next_object_identity;
    u64 next_protocol_authority_identity;
    ServiceEndpointIngressReceiptRow receipts[kServiceEndpointIngressReceiptCapacity];
    ServiceEndpointIngressCursorRow cursors[kServiceEndpointIngressCursorCapacity];
    ServiceEndpointIngressConnectRollbackRow connect_rollbacks[kServiceEndpointIngressConnectRollbackCapacity];
};

struct ServiceEndpointIngressCaller
{
    ProcessKey process;
    ipc::HandleTable* handles;
    CredentialKey credential_key;
    CredentialSecurityContext credential;
    CapSet capabilities;
    ResourceDomainKey resource_domain;
    ServiceRuntimeV1* runtime;
};

ServiceEndpointIngressStatus ServiceEndpointIngressInitialize(ServiceEndpointIngressState* state);

// Execute one already-snapshotted request. `request_frame` and `result_frame`
// may alias: ReplyAck consumes the input but emits no frame, while Receive has
// no input frame. No caller pointer is retained after return.
ServiceEndpointIngressStatus ServiceEndpointIngressExecute(ServiceEndpointIngressState* state,
                                                           const ServiceEndpointIngressCaller* caller,
                                                           const duet_service_endpoint_request_v1* request,
                                                           const u8* request_frame,
                                                           duet_service_endpoint_result_v1* result, u8* result_frame,
                                                           u32 result_frame_capacity);

// Process teardown invalidates every pending/live receipt and delivery cursor
// before the process HandleTable drains. No external subsystem call occurs
// while the ingress lock is held.
void ServiceEndpointIngressCancelProcess(ServiceEndpointIngressState* state, ProcessKey process);

// Drive one fair pass over exact retained CONNECT cleanup receipts. Busy rows
// remain durable for a later pass; no bounded retry count can discard them.
void ServiceEndpointIngressDriveConnectRollbacks(ServiceEndpointIngressState* state);

#if !defined(DUETOS_HOST_TEST)
ServiceEndpointIngressStatus ServiceEndpointIngressInitializeKernel();
void ServiceEndpointIngressCancelProcessKernel(ProcessKey process);
void DoServiceEndpointOp(arch::TrapFrame* frame);
#endif

const char* ServiceEndpointIngressStatusName(ServiceEndpointIngressStatus status);

} // namespace duetos::core
