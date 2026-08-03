#ifndef DUETOS_SERVICED_SUPERVISOR_H
#define DUETOS_SERVICED_SUPERVISOR_H

/*
 * Allocation-free serviced policy state machine.
 *
 * This interface is C11-compatible and contains no kernel headers, handles,
 * pointers, capability bits, or wire authority.  A single serviced event-loop
 * thread owns every call.  Transport code must authenticate and decode input
 * before constructing these scalar records, then execute returned actions in
 * order through the separately retained LifecycleBroker capability.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SERVICED_SUPERVISOR_MAX_SERVICES 64U
#define SERVICED_SUPERVISOR_MAX_RESTARTS 16U
#define SERVICED_SUPERVISOR_MAX_CLIENTS 16U
#define SERVICED_SUPERVISOR_ACTION_CAPACITY 64U
#define SERVICED_SUPERVISOR_STORAGE_BYTES 196608U

    typedef enum ServicedSupervisorRestartPolicy
    {
        SERVICED_RESTART_NEVER = 0,
        SERVICED_RESTART_ALWAYS = 1,
        SERVICED_RESTART_ON_FAILURE = 2
    } ServicedSupervisorRestartPolicy;

    typedef enum ServicedSupervisorDesiredState
    {
        SERVICED_DESIRED_STOPPED = 0,
        SERVICED_DESIRED_RUNNING = 1
    } ServicedSupervisorDesiredState;

    typedef enum ServicedSupervisorPhase
    {
        SERVICED_PHASE_STOPPED = 0,
        SERVICED_PHASE_STARTING,
        SERVICED_PHASE_RUNNING,
        SERVICED_PHASE_READY,
        SERVICED_PHASE_STOPPING,
        SERVICED_PHASE_EXITED,
        SERVICED_PHASE_FAILED,
        SERVICED_PHASE_CRASH_LOOP,
        SERVICED_PHASE_GENERATION_EXHAUSTED
    } ServicedSupervisorPhase;

    typedef enum ServicedSupervisorStatus
    {
        SERVICED_SUPERVISOR_OK = 0,
        SERVICED_SUPERVISOR_NULL_ARGUMENT,
        SERVICED_SUPERVISOR_ALIASED_STORAGE,
        SERVICED_SUPERVISOR_INVALID_MANIFEST,
        SERVICED_SUPERVISOR_ALREADY_INITIALIZED,
        SERVICED_SUPERVISOR_NOT_INITIALIZED,
        SERVICED_SUPERVISOR_CORRUPT_STATE,
        SERVICED_SUPERVISOR_NOT_FOUND,
        SERVICED_SUPERVISOR_INVALID_TIMESTAMP,
        SERVICED_SUPERVISOR_STALE_GENERATION,
        SERVICED_SUPERVISOR_GENERATION_EXHAUSTED,
        SERVICED_SUPERVISOR_DEPENDENCY_NOT_READY,
        SERVICED_SUPERVISOR_CRASH_LOOP,
        SERVICED_SUPERVISOR_INVALID_EVENT,
        SERVICED_SUPERVISOR_REPLAYED_EVENT,
        SERVICED_SUPERVISOR_OUT_OF_ORDER_EVENT,
        SERVICED_SUPERVISOR_WRONG_INSTANCE,
        SERVICED_SUPERVISOR_PENDING_ACKNOWLEDGEMENT,
        SERVICED_SUPERVISOR_INVALID_ACKNOWLEDGEMENT,
        SERVICED_SUPERVISOR_INVALID_COMMAND,
        SERVICED_SUPERVISOR_REPLAYED_REQUEST,
        SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT,
        SERVICED_SUPERVISOR_CLIENT_CAPACITY,
        SERVICED_SUPERVISOR_ACTION_OVERFLOW,
        SERVICED_SUPERVISOR_RECONCILE_REJECTED
    } ServicedSupervisorStatus;

    typedef struct ServicedSupervisorProcessKey
    {
        uint64_t identity;
        uint64_t pid;
    } ServicedSupervisorProcessKey;

    /* Full service identity.  Partial identities are never canonical. */
    typedef struct ServicedSupervisorObservedIdentity
    {
        uint32_t service_slot;
        uint32_t reserved32;
        uint64_t instance_generation;
        ServicedSupervisorProcessKey process;
        uint64_t endpoint_epoch;
    } ServicedSupervisorObservedIdentity;

    typedef struct ServicedSupervisorManifestService
    {
        uint64_t service_identity;
        uint64_t dependency_mask;
        uint64_t restart_window_ns;
        uint32_t service_slot;
        uint8_t restart_policy;
        uint8_t autostart;
        uint8_t restart_limit;
        uint8_t reserved8;
    } ServicedSupervisorManifestService;

    typedef struct ServicedSupervisorManifest
    {
        uint64_t manifest_identity;
        uint64_t manifest_generation;
        uint32_t service_count;
        uint32_t reserved32;
        ServicedSupervisorManifestService services[SERVICED_SUPERVISOR_MAX_SERVICES];
    } ServicedSupervisorManifest;

    typedef enum ServicedSupervisorActionType
    {
        SERVICED_ACTION_NONE = 0,
        SERVICED_ACTION_START,
        SERVICED_ACTION_CANCEL_START,
        SERVICED_ACTION_STOP_INSTANCE,
        SERVICED_ACTION_ACKNOWLEDGE_EVENT
    } ServicedSupervisorActionType;

    typedef enum ServicedSupervisorActionReason
    {
        SERVICED_ACTION_REASON_NONE = 0,
        SERVICED_ACTION_REASON_MANIFEST_DESIRED,
        SERVICED_ACTION_REASON_OPERATOR,
        SERVICED_ACTION_REASON_RESTART_POLICY,
        SERVICED_ACTION_REASON_DEPENDENCY_LOST,
        SERVICED_ACTION_REASON_ENDPOINT_LOST,
        SERVICED_ACTION_REASON_RECONCILE_MISMATCH
    } ServicedSupervisorActionReason;

    typedef struct ServicedSupervisorAction
    {
        uint8_t type;
        uint8_t reason;
        uint16_t reserved16;
        uint32_t service_slot;
        uint64_t service_identity;
        uint64_t expected_transition_generation;
        uint64_t target_instance_generation;
        ServicedSupervisorObservedIdentity observed;
        uint64_t event_sequence;
    } ServicedSupervisorAction;

    typedef struct ServicedSupervisorActionBatch
    {
        uint32_t count;
        uint32_t reserved32;
        ServicedSupervisorAction actions[SERVICED_SUPERVISOR_ACTION_CAPACITY];
    } ServicedSupervisorActionBatch;

    typedef enum ServicedSupervisorEventType
    {
        SERVICED_EVENT_PUBLISHED = 1,
        SERVICED_EVENT_ENDPOINT_READY,
        SERVICED_EVENT_ENDPOINT_CLOSED,
        SERVICED_EVENT_EXITED,
        SERVICED_EVENT_START_FAILED,
        SERVICED_EVENT_START_CANCELLED
    } ServicedSupervisorEventType;

    typedef struct ServicedSupervisorLifecycleEvent
    {
        uint64_t event_sequence;
        uint64_t now_ns;
        uint64_t service_identity;
        uint64_t instance_generation;
        ServicedSupervisorObservedIdentity observed;
        uint32_t service_slot;
        uint32_t exit_code;
        uint8_t type;
        uint8_t failed;
        uint16_t reserved16;
        uint32_t reserved32;
    } ServicedSupervisorLifecycleEvent;

    typedef struct ServicedSupervisorEventReceipt
    {
        uint64_t manifest_identity;
        uint64_t manifest_generation;
        uint64_t event_sequence;
        uint64_t event_fingerprint;
    } ServicedSupervisorEventReceipt;

    typedef struct ServicedSupervisorEventResult
    {
        ServicedSupervisorStatus status;
        ServicedSupervisorEventReceipt receipt;
        ServicedSupervisorActionBatch actions;
    } ServicedSupervisorEventResult;

    typedef enum ServicedSupervisorCommandType
    {
        SERVICED_COMMAND_START = 1,
        SERVICED_COMMAND_STOP,
        SERVICED_COMMAND_RESTART
    } ServicedSupervisorCommandType;

    /*
 * client_identity is a trusted transport binding, not sender-controlled wire
 * data.  The caller must first validate ServicedProtocol v1 and commit its
 * endpoint replay ledger.  This record intentionally contains no authority.
 */
    typedef struct ServicedSupervisorCommand
    {
        uint64_t client_identity;
        uint64_t request_id;
        uint64_t service_identity;
        uint64_t expected_transition_generation;
        uint64_t now_ns;
        uint8_t type;
        uint8_t reserved8[7];
    } ServicedSupervisorCommand;

    typedef struct ServicedSupervisorCommandResult
    {
        ServicedSupervisorStatus status;
        uint8_t duplicate;
        uint8_t reserved8[3];
        uint32_t reserved32;
        ServicedSupervisorActionBatch actions;
    } ServicedSupervisorCommandResult;

    typedef struct ServicedSupervisorReconcileRow
    {
        uint64_t service_identity;
        uint64_t transition_generation;
        ServicedSupervisorObservedIdentity lifecycle_identity;
        ServicedSupervisorObservedIdentity directory_identity;
        uint32_t service_slot;
        uint8_t phase;
        uint8_t endpoint_ready;
        uint16_t reserved16;
    } ServicedSupervisorReconcileRow;

    typedef struct ServicedSupervisorReconcileSnapshot
    {
        uint64_t manifest_identity;
        uint64_t manifest_generation;
        uint64_t acknowledged_event_sequence;
        uint64_t now_ns;
        uint32_t row_count;
        uint32_t reserved32;
        ServicedSupervisorReconcileRow rows[SERVICED_SUPERVISOR_MAX_SERVICES];
    } ServicedSupervisorReconcileSnapshot;

    typedef struct ServicedSupervisorServiceSnapshot
    {
        uint64_t service_identity;
        uint64_t dependency_mask;
        uint64_t transition_generation;
        uint64_t last_start_ns;
        uint64_t last_exit_ns;
        ServicedSupervisorObservedIdentity observed;
        uint32_t service_slot;
        uint32_t lifetime_restarts;
        uint32_t restarts_in_window;
        uint32_t last_exit_code;
        uint8_t restart_policy;
        uint8_t desired_state;
        uint8_t phase;
        uint8_t adopted;
    } ServicedSupervisorServiceSnapshot;

    typedef struct ServicedSupervisorSnapshot
    {
        uint64_t manifest_identity;
        uint64_t manifest_generation;
        uint64_t last_acknowledged_event_sequence;
        uint64_t last_applied_event_sequence;
        uint64_t last_now_ns;
        uint32_t service_count;
        uint32_t client_count;
        uint8_t has_pending_acknowledgement;
        uint8_t reconciled;
        uint8_t reserved8[6];
    } ServicedSupervisorSnapshot;

    /* Opaque, caller-owned fixed storage.  Static/BSS allocation is recommended. */
    typedef union ServicedSupervisor
    {
        uint64_t alignment;
        uint8_t bytes[SERVICED_SUPERVISOR_STORAGE_BYTES];
    } ServicedSupervisor;

    /* [serviced event-loop thread only; no allocation, waiting, or callbacks] */
    ServicedSupervisorStatus ServicedSupervisorInitialize(ServicedSupervisor* supervisor,
                                                          const ServicedSupervisorManifest* manifest);

    /*
 * Adopt a trusted kernel snapshot transactionally.  Active rows are adopted
 * only when lifecycle and directory views contain the same complete observed
 * identity.  Mismatches produce exact drain actions and remain unadopted.
 */
    ServicedSupervisorStatus ServicedSupervisorReconcile(ServicedSupervisor* supervisor,
                                                         const ServicedSupervisorReconcileSnapshot* snapshot,
                                                         ServicedSupervisorActionBatch* actions_out);

    /*
 * Apply exactly the next ordered event and retain its deterministic effects.
 * No ACK is returned here.  The adapter may replay the retained effects, then
 * build/send the ACK, and commit it locally only after the broker accepts it.
 */
    ServicedSupervisorStatus ServicedSupervisorApplyLifecycleEvent(ServicedSupervisor* supervisor,
                                                                   const ServicedSupervisorLifecycleEvent* event,
                                                                   ServicedSupervisorEventResult* result_out);
    ServicedSupervisorStatus ServicedSupervisorGetPendingEventActions(const ServicedSupervisor* supervisor,
                                                                      const ServicedSupervisorEventReceipt* receipt,
                                                                      ServicedSupervisorActionBatch* actions_out);
    ServicedSupervisorStatus ServicedSupervisorBuildEventAcknowledgement(const ServicedSupervisor* supervisor,
                                                                         const ServicedSupervisorEventReceipt* receipt,
                                                                         ServicedSupervisorAction* action_out);
    ServicedSupervisorStatus ServicedSupervisorCommitEventAcknowledgement(
        ServicedSupervisor* supervisor, const ServicedSupervisorEventReceipt* receipt);

    /* Command input is already authenticated/validated; this layer owns policy. */
    ServicedSupervisorStatus ServicedSupervisorApplyCommand(ServicedSupervisor* supervisor,
                                                            const ServicedSupervisorCommand* command,
                                                            ServicedSupervisorCommandResult* result_out);

    ServicedSupervisorStatus ServicedSupervisorDescribe(const ServicedSupervisor* supervisor,
                                                        ServicedSupervisorSnapshot* snapshot_out);
    ServicedSupervisorStatus ServicedSupervisorInspect(const ServicedSupervisor* supervisor, uint64_t service_identity,
                                                       ServicedSupervisorServiceSnapshot* snapshot_out);
    ServicedSupervisorStatus ServicedSupervisorInspectAt(const ServicedSupervisor* supervisor, uint32_t ordinal,
                                                         ServicedSupervisorServiceSnapshot* snapshot_out);

    uint8_t ServicedSupervisorObservedIdentityIsCanonical(const ServicedSupervisorObservedIdentity* identity);
    const char* ServicedSupervisorStatusName(ServicedSupervisorStatus status);

#ifdef __cplusplus
}
#endif

#endif
