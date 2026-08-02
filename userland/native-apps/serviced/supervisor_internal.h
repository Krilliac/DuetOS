#ifndef DUETOS_SERVICED_SUPERVISOR_INTERNAL_H
#define DUETOS_SERVICED_SUPERVISOR_INTERNAL_H

#include "supervisor.h"

#define SERVICED_SUPERVISOR_MAGIC UINT64_C(0x5355504552563153)

typedef struct ServicedSupervisorRow
{
    uint64_t service_identity;
    uint64_t dependency_mask;
    uint64_t restart_window_ns;
    uint64_t transition_generation;
    uint64_t last_start_ns;
    uint64_t last_exit_ns;
    uint64_t restart_times[SERVICED_SUPERVISOR_MAX_RESTARTS];
    ServicedSupervisorObservedIdentity observed;
    uint32_t service_slot;
    uint32_t lifetime_restarts;
    uint32_t last_exit_code;
    uint8_t restart_policy;
    uint8_t autostart;
    uint8_t restart_limit;
    uint8_t desired_state;
    uint8_t phase;
    uint8_t adopted;
    uint8_t restart_head;
    uint8_t restart_count;
    uint8_t restart_requested;
    uint8_t terminal_after_stop;
    uint8_t start_reason;
    uint8_t reserved8[5];
} ServicedSupervisorRow;

typedef struct ServicedSupervisorClientLedger
{
    uint64_t client_identity;
    uint64_t request_id;
    uint64_t service_identity;
    uint64_t expected_transition_generation;
    uint64_t now_ns;
    ServicedSupervisorStatus status;
    uint8_t command_type;
    uint8_t in_use;
    uint8_t reserved8[2];
    ServicedSupervisorActionBatch actions;
} ServicedSupervisorClientLedger;

typedef struct ServicedSupervisorImpl
{
    uint64_t magic;
    uint64_t manifest_identity;
    uint64_t manifest_generation;
    uint64_t last_acknowledged_event_sequence;
    uint64_t last_applied_event_sequence;
    uint64_t last_now_ns;
    uint64_t present_mask;
    uint32_t service_count;
    uint32_t client_count;
    uint8_t reconciled;
    uint8_t has_pending_acknowledgement;
    uint8_t topological_order[SERVICED_SUPERVISOR_MAX_SERVICES];
    uint8_t reserved8[6];
    ServicedSupervisorEventReceipt pending_receipt;
    ServicedSupervisorActionBatch pending_actions;
    ServicedSupervisorRow rows[SERVICED_SUPERVISOR_MAX_SERVICES];
    ServicedSupervisorClientLedger clients[SERVICED_SUPERVISOR_MAX_CLIENTS];
} ServicedSupervisorImpl;

#if defined(__cplusplus)
static_assert(sizeof(ServicedSupervisorImpl) <= SERVICED_SUPERVISOR_STORAGE_BYTES,
              "serviced supervisor fixed storage is too small");
#else
_Static_assert(sizeof(ServicedSupervisorImpl) <= SERVICED_SUPERVISOR_STORAGE_BYTES,
               "serviced supervisor fixed storage is too small");
#endif

ServicedSupervisorImpl* ServicedSupervisorInternalMutable(ServicedSupervisor* supervisor);
const ServicedSupervisorImpl* ServicedSupervisorInternalReadOnly(const ServicedSupervisor* supervisor);
ServicedSupervisorStatus ServicedSupervisorInternalValidate(const ServicedSupervisorImpl* supervisor);
void ServicedSupervisorInternalClear(void* storage, uint32_t bytes);
void ServicedSupervisorInternalClearBatch(ServicedSupervisorActionBatch* batch);
void ServicedSupervisorInternalClearObserved(ServicedSupervisorObservedIdentity* identity);
uint8_t ServicedSupervisorInternalObservedIsZero(const ServicedSupervisorObservedIdentity* identity);
uint8_t ServicedSupervisorInternalObservedEqual(const ServicedSupervisorObservedIdentity* left,
                                                const ServicedSupervisorObservedIdentity* right);
ServicedSupervisorRow* ServicedSupervisorInternalFind(ServicedSupervisorImpl* supervisor, uint64_t service_identity);
const ServicedSupervisorRow* ServicedSupervisorInternalFindConst(const ServicedSupervisorImpl* supervisor,
                                                                 uint64_t service_identity);
uint8_t ServicedSupervisorInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right,
                                                uint64_t right_bytes);
ServicedSupervisorStatus ServicedSupervisorPolicyReady(ServicedSupervisorImpl* supervisor);
uint8_t ServicedSupervisorPolicyPhaseCanStart(uint8_t phase);
uint8_t ServicedSupervisorPolicyPhaseCanStop(uint8_t phase);
uint8_t ServicedSupervisorPolicyDependenciesReady(const ServicedSupervisorImpl* supervisor,
                                                  const ServicedSupervisorRow* row);
ServicedSupervisorStatus ServicedSupervisorPolicyScheduleStop(ServicedSupervisorRow* row, uint8_t reason,
                                                              ServicedSupervisorActionBatch* actions);
ServicedSupervisorStatus ServicedSupervisorPolicyReconcileDesired(ServicedSupervisorImpl* supervisor, uint64_t now_ns,
                                                                  ServicedSupervisorActionBatch* actions);
uint8_t ServicedSupervisorPolicyArmAutomaticRestart(ServicedSupervisorRow* row, uint64_t now_ns);
uint8_t ServicedSupervisorPolicyClearCrashLoopAfterWindow(ServicedSupervisorRow* row, uint64_t now_ns);
uint8_t ServicedSupervisorPolicyAcceptTimestamp(ServicedSupervisorImpl* supervisor, uint64_t now_ns);

#endif
