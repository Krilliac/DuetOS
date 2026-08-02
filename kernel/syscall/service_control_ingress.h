#pragma once

/*
 * Authenticated native service-control ingress.
 *
 * The syscall boundary copies only the fixed pointer-free v1 structures.  The
 * core is host-testable with kernel buffers and receives the caller's identity
 * and effective capability snapshot from trusted kernel state.  Supervisor
 * authority is never accepted from the wire.
 *
 * Activation, scheduler stop, two-bank restage, and exit-ledger operations are
 * deliberately narrow callbacks.  The callback table is copied under the
 * ingress lock and invoked only after that lock is released.  A Busy result
 * therefore leaves the callback owner's exact durable authority untouched for
 * a later call; the ingress has no bounded retry/drop path of its own.
 */

#include "core/service_runtime.h"
#include "proc/process.h"
#include "util/types.h"

#include "../../userland/libc/include/duet/service_control.h"

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

inline constexpr u32 kServiceControlIngressInitializedMarker = 0x53434931U; // "SCI1"
inline constexpr u32 kServiceControlPlatformVersion1 = 1;

enum class ServiceControlIngressStatus : u8
{
    Ok = 0,
    InvalidArgument,
    AlreadyInitialized,
    NotInitialized,
    PlatformAlreadyInstalled,
    CorruptState,
};

enum class ServiceControlPlatformStatusV1 : u8
{
    Ok = 0,
    InvalidArgument,
    NotReady,
    NotFound,
    Stale,
    ReplayRejected,
    WouldBlock,
    Busy,
    CapacityExhausted,
    GenerationExhausted,
    AlreadyRequested,
    AlreadyStopped,
    CorruptState,
    InternalError,
};

// Exact target authority passed only to trusted kernel callbacks.  The first
// three fields bind the broker incarnation, stable service identity, and the
// currently observed transition generation (which is legitimately zero before
// a service's first activation). `process` is invalid only for ACTIVATE;
// RESTAGE additionally carries the nonzero exit-ledger event sequence.
struct ServiceControlPlatformTargetV1
{
    u64 broker_epoch;
    u64 service_identity;
    u64 transition_generation;
    ProcessKey process;
    u64 event_sequence;
};

struct ServiceControlPlatformExitEventV1
{
    ServiceLifecycleInstanceToken instance;
    u64 event_sequence;
    u64 acknowledgement_token;
    i64 exit_status;
    bool failed;
    u8 reserved[7];
};

using ServiceControlPlatformActivateFnV1 =
    ServiceControlPlatformStatusV1 (*)(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                       ProcessKey supervisor, ServiceControlPlatformTargetV1 target);
using ServiceControlPlatformStopFnV1 =
    ServiceControlPlatformStatusV1 (*)(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                       ProcessKey supervisor, ServiceControlPlatformTargetV1 target);
using ServiceControlPlatformRestageFnV1 =
    ServiceControlPlatformStatusV1 (*)(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                       ProcessKey supervisor, ServiceControlPlatformTargetV1 target);
using ServiceControlPlatformExitDequeueFnV1 =
    ServiceControlPlatformStatusV1 (*)(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                       ProcessKey supervisor, ServiceControlPlatformExitEventV1* event_out);
using ServiceControlPlatformExitAckFnV1 = ServiceControlPlatformStatusV1 (*)(
    void* context, const ServiceRuntimeActivationAuthorityV1* authority, ProcessKey supervisor,
    ServiceControlPlatformTargetV1 target, u64 acknowledgement_token);

// Installed once from kernel trust-domain storage.  The context is never
// exposed to userland and must remain valid for the kernel lifetime.
struct ServiceControlIngressPlatformV1
{
    u32 struct_size;
    u32 version;
    void* context;
    ServiceControlPlatformActivateFnV1 activate;
    ServiceControlPlatformStopFnV1 stop;
    ServiceControlPlatformRestageFnV1 restage;
    ServiceControlPlatformExitDequeueFnV1 exit_dequeue;
    ServiceControlPlatformExitAckFnV1 exit_ack;
    u64 reserved[2];
};

struct ServiceControlIngressCaller
{
    ProcessKey process;
    CapSet capabilities;
    ServiceRuntimeV1* runtime;
};

// Public only for one static kernel owner and hostile hosted tests. Treat all
// fields as opaque after Initialize succeeds.
struct ServiceControlIngressState
{
#if defined(DUETOS_HOST_TEST)
    std::mutex lock;
#else
    sync::SpinLock lock;
#endif
    u32 initialized;
    u32 platform_installed;
    ServiceControlIngressPlatformV1 platform;
};

// [boot, one shot, before concurrent Execute/Install callers]
// The initialized marker is immutable after publication. Platform installation
// may happen later and is synchronized independently by the state lock.
ServiceControlIngressStatus ServiceControlIngressInitialize(ServiceControlIngressState* state);
ServiceControlIngressStatus ServiceControlIngressInstallPlatformV1(ServiceControlIngressState* state,
                                                                   const ServiceControlIngressPlatformV1* platform);

// Execute one fully snapshotted request. Request and result may alias; the
// implementation takes a local request copy before touching the output.
ServiceControlIngressStatus ServiceControlIngressExecute(ServiceControlIngressState* state,
                                                         const ServiceControlIngressCaller* caller,
                                                         const duet_service_control_request_v1* request,
                                                         duet_service_control_result_v1* result);

#if !defined(DUETOS_HOST_TEST)
ServiceControlIngressStatus ServiceControlIngressInitializeKernel();
ServiceControlIngressStatus ServiceControlIngressInstallKernelPlatformV1(
    const ServiceControlIngressPlatformV1* platform);
void DoServiceControl(arch::TrapFrame* frame);
#endif

const char* ServiceControlIngressStatusName(ServiceControlIngressStatus status);

} // namespace duetos::core
