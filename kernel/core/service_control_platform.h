#pragma once

/*
 * Typed production adapter for ServiceControlIngressPlatformV1.
 *
 * Initialization is a one-shot publication transaction.  It validates the
 * complete live bootstrap/runtime authority, lifecycle broker, exit/reap
 * ledger, and callback backend before publishing an all-or-nothing ingress
 * table.  No service is activated during initialization.
 *
 * After publication every field is immutable.  Callback execution therefore
 * holds no adapter lock while calling the loader, scheduler, live restager, or
 * reap ledger.  All user-originated values remain scalar exact identities;
 * no Process, Task, image, or ledger-row pointer crosses the ingress boundary.
 */

#include "core/service_bootstrap_activation.h"
#include "core/service_bootstrap_live.h"
#include "core/service_exit_reap_ledger.h"
#include "syscall/service_control_ingress.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u32 kServiceControlPlatformAdapterVersion1 = 1;
inline constexpr u32 kServiceControlPlatformOperationsVersion1 = 1;

enum class ServiceControlPlatformAdapterStateV1 : u32
{
    Uninitialized = 0,
    Initializing,
    Open,
    Failed,
};

enum class ServiceControlPlatformAdapterStatusV1 : u8
{
    Ok = 0,
    NullArgument,
    InvalidOperations,
    AlreadyAttempted,
    RuntimeNotReady,
    BrokerNotReady,
    LedgerNotReady,
    LiveBootstrapNotReady,
    InstallRejected,
    CorruptState,
};

enum class ServiceControlPlatformKillExactResultV1 : u8
{
    Visited = 0,
    AlreadyGone,
    Rejected,
};

// Typed backend seam.  Production constructs this table only from the real
// kernel APIs below; hosted tests inject deterministic hostile outcomes.  The
// single context is kernel-private and never reaches userland.
struct ServiceControlPlatformOperationsV1
{
    u32 struct_size;
    u32 version;
    void* context;

    u64 (*monotonic_ns)(void* context);
    ServiceRuntimeStatusV1 (*runtime_inspect)(void* context, const ServiceRuntimeV1* runtime,
                                              ServiceRuntimeSnapshotV1* snapshot_out);
    ServiceRuntimeStatusV1 (*bind_authority)(void* context, ServiceRuntimeV1* runtime,
                                             ServiceRuntimeActivationAuthorityV1* authority_out);
    ServiceLifecycleBrokerInspectResult (*broker_describe)(void* context, ServiceLifecycleBroker* broker);
    ServiceLifecycleInspectResult (*lifecycle_inspect)(void* context, ServiceLifecycleBroker* broker,
                                                       u64 service_identity);
    ServiceBootstrapActivationResultV1 (*activate)(void* context, const ServiceBootstrapActivationRequestV1& request);
    ServiceLifecycleStopResult (*request_stop)(void* context, ServiceLifecycleBroker* broker, u64 service_identity,
                                               u64 expected_generation, u64 now_ns);
    ServiceControlPlatformKillExactResultV1 (*kill_exact_process)(void* context, ProcessKey process);
    ServiceBootstrapStageStatus (*stage_find_service)(void* context, const ServiceBootstrapStageRuntimeV1* stage,
                                                      u64 service_identity,
                                                      ServiceBootstrapServiceSnapshotV1* snapshot_out);
    ServiceBootstrapLiveStatusV1 (*live_inspect)(void* context, ServiceBootstrapLiveSnapshotV1* snapshot_out);
    ServiceBootstrapLiveRestageResultV1 (*live_restage)(
        void* context, u64 service_identity, u64 expected_activation_generation,
        ServiceBootstrapLiveRetiredTargetTeardownV1 retired_target_teardown);
    ServiceExitReapStatus (*ledger_inspect)(void* context, ServiceExitReapLedger* ledger,
                                            ServiceExitReapLedgerSnapshot* snapshot_out);
    ServiceExitReapDeliveryResult (*exit_dequeue)(void* context, ServiceExitReapLedger* ledger,
                                                  ProcessKey delivery_owner);
    ServiceExitReapRestageResult (*restage_query_exact)(void* context, ServiceExitReapLedger* ledger,
                                                        ServiceExitReapEventKey event);
    ServiceExitReapStatus (*exit_acknowledge_exact)(void* context, ServiceExitReapLedger* ledger,
                                                    ServiceExitReapEventKey event, u64 delivery_token,
                                                    ProcessKey delivery_owner);
    ServiceControlIngressStatus (*install_ingress)(void* context, const ServiceControlIngressPlatformV1* platform);

    u64 reserved[2];
};

struct ServiceControlPlatformAdapterV1
{
    u32 state;
    u32 version;
    ServiceRuntimeV1* runtime;
    ServiceExitReapLedger* ledger;
    ServiceRuntimeActivationAuthorityV1 authority;
    ServiceControlPlatformOperationsV1 operations;

    ServiceControlPlatformAdapterV1();
    ServiceControlPlatformAdapterV1(const ServiceControlPlatformAdapterV1&) = delete;
    ServiceControlPlatformAdapterV1& operator=(const ServiceControlPlatformAdapterV1&) = delete;
    ServiceControlPlatformAdapterV1(ServiceControlPlatformAdapterV1&&) = delete;
    ServiceControlPlatformAdapterV1& operator=(ServiceControlPlatformAdapterV1&&) = delete;
};

struct ServiceControlPlatformInitializeResultV1
{
    ServiceControlPlatformAdapterStatusV1 status;
    ServiceRuntimeStatusV1 runtime_status;
    ServiceLifecycleStatus broker_status;
    ServiceExitReapStatus ledger_status;
    ServiceBootstrapLiveStatusV1 live_status;
    ServiceControlIngressStatus ingress_status;
};

#if !defined(DUETOS_HOST_TEST)
// Validate and install the sole production adapter.  The ledger is derived
// from the static-lifetime runtime owner; production callers cannot substitute
// a peer ledger from another runtime incarnation.
ServiceControlPlatformInitializeResultV1 ServiceControlPlatformInstallKernelV1();
#else
// Hosted one-shot initializer using the exact production transaction and
// callback implementation with deterministic typed backend operations.
ServiceControlPlatformInitializeResultV1 ServiceControlPlatformInitializeForTestV1(
    ServiceControlPlatformAdapterV1* platform, ServiceRuntimeV1* runtime, ServiceExitReapLedger* ledger,
    const ServiceControlPlatformOperationsV1* operations);
#endif

ServiceControlPlatformAdapterStateV1 ServiceControlPlatformStateV1(const ServiceControlPlatformAdapterV1* platform);
const char* ServiceControlPlatformAdapterStatusNameV1(ServiceControlPlatformAdapterStatusV1 status);

} // namespace duetos::core
