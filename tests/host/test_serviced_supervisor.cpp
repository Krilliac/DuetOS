// Hosted hostile-state coverage for the allocation-free serviced supervisor.

#include "host_test_helper.h"
#include "supervisor.h"

#include <cstdint>
#include <limits>

namespace
{

constexpr std::uint64_t kManifestIdentity = 0x4455455453564331ULL;
constexpr std::uint64_t kManifestGeneration = 7;

ServicedSupervisor g_supervisors[11]{};

std::uint64_t ServiceIdentity(std::uint32_t slot)
{
    return 0x5356430000000000ULL | static_cast<std::uint64_t>(slot + 1U);
}

void SetService(ServicedSupervisorManifest& manifest, std::uint32_t index, std::uint32_t slot,
                ServicedSupervisorRestartPolicy policy, bool autostart, std::uint64_t dependencies = 0,
                std::uint8_t restart_limit = 0, std::uint64_t restart_window_ns = 0)
{
    auto& service = manifest.services[index];
    service.service_identity = ServiceIdentity(slot);
    service.dependency_mask = dependencies;
    service.restart_window_ns = restart_window_ns;
    service.service_slot = slot;
    service.restart_policy = static_cast<std::uint8_t>(policy);
    service.autostart = autostart ? 1U : 0U;
    service.restart_limit = restart_limit;
}

ServicedSupervisorManifest ChainManifest()
{
    ServicedSupervisorManifest manifest{};
    manifest.manifest_identity = kManifestIdentity;
    manifest.manifest_generation = kManifestGeneration;
    manifest.service_count = 3;
    SetService(manifest, 0, 0, SERVICED_RESTART_ALWAYS, true, 0, 2, 100);
    SetService(manifest, 1, 1, SERVICED_RESTART_ALWAYS, true, 1ULL << 0U, 2, 100);
    SetService(manifest, 2, 2, SERVICED_RESTART_ON_FAILURE, false, 0, 2, 100);
    return manifest;
}

ServicedSupervisorObservedIdentity Observed(std::uint32_t slot, std::uint64_t generation, std::uint64_t seed)
{
    return ServicedSupervisorObservedIdentity{
        slot, 0, generation, {0x9000000000000000ULL | seed, 1000 + seed}, 0xA000000000000000ULL | seed};
}

ServicedSupervisorReconcileSnapshot StoppedSnapshot(const ServicedSupervisorManifest& manifest,
                                                    std::uint64_t acknowledged_sequence = 0, std::uint64_t now_ns = 0)
{
    ServicedSupervisorReconcileSnapshot snapshot{};
    snapshot.manifest_identity = manifest.manifest_identity;
    snapshot.manifest_generation = manifest.manifest_generation;
    snapshot.acknowledged_event_sequence = acknowledged_sequence;
    snapshot.now_ns = now_ns;
    snapshot.row_count = manifest.service_count;
    for (std::uint32_t index = 0; index < manifest.service_count; ++index)
    {
        const auto& service = manifest.services[index];
        auto& row = snapshot.rows[index];
        row.service_identity = service.service_identity;
        row.service_slot = service.service_slot;
        row.phase = SERVICED_PHASE_STOPPED;
    }
    return snapshot;
}

ServicedSupervisorLifecycleEvent Event(ServicedSupervisorEventType type, std::uint64_t sequence, std::uint64_t now_ns,
                                       std::uint32_t slot, std::uint64_t generation,
                                       ServicedSupervisorObservedIdentity observed = {}, bool failed = false,
                                       std::uint32_t exit_code = 0)
{
    ServicedSupervisorLifecycleEvent event{};
    event.event_sequence = sequence;
    event.now_ns = now_ns;
    event.service_identity = ServiceIdentity(slot);
    event.instance_generation = generation;
    event.observed = observed;
    event.service_slot = slot;
    event.exit_code = exit_code;
    event.type = static_cast<std::uint8_t>(type);
    event.failed = failed ? 1U : 0U;
    return event;
}

void Acknowledge(ServicedSupervisor& supervisor, const ServicedSupervisorEventResult& result)
{
    ServicedSupervisorActionBatch replay{};
    ServicedSupervisorAction acknowledgement{};
    EXPECT_EQ(ServicedSupervisorGetPendingEventActions(&supervisor, &result.receipt, &replay), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(replay.count, result.actions.count);
    EXPECT_EQ(ServicedSupervisorBuildEventAcknowledgement(&supervisor, &result.receipt, &acknowledgement),
              SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(acknowledgement.type, SERVICED_ACTION_ACKNOWLEDGE_EVENT);
    EXPECT_EQ(acknowledgement.event_sequence, result.receipt.event_sequence);
    EXPECT_EQ(ServicedSupervisorCommitEventAcknowledgement(&supervisor, &result.receipt), SERVICED_SUPERVISOR_OK);
}

ServicedSupervisorEventResult Apply(ServicedSupervisor& supervisor, const ServicedSupervisorLifecycleEvent& event)
{
    ServicedSupervisorEventResult result{};
    EXPECT_EQ(ServicedSupervisorApplyLifecycleEvent(&supervisor, &event, &result), SERVICED_SUPERVISOR_OK);
    return result;
}

ServicedSupervisorServiceSnapshot Inspect(ServicedSupervisor& supervisor, std::uint32_t slot)
{
    ServicedSupervisorServiceSnapshot snapshot{};
    EXPECT_EQ(ServicedSupervisorInspect(&supervisor, ServiceIdentity(slot), &snapshot), SERVICED_SUPERVISOR_OK);
    return snapshot;
}

ServicedSupervisorCommand MakeCommand(ServicedSupervisorCommandType type, std::uint64_t client_identity,
                                      std::uint64_t request_id, std::uint32_t slot, std::uint64_t expected_generation,
                                      std::uint64_t now_ns)
{
    ServicedSupervisorCommand command{};
    command.client_identity = client_identity;
    command.request_id = request_id;
    command.service_identity = ServiceIdentity(slot);
    command.expected_transition_generation = expected_generation;
    command.now_ns = now_ns;
    command.type = static_cast<std::uint8_t>(type);
    return command;
}

ServicedSupervisorCommandResult Command(ServicedSupervisor& supervisor, const ServicedSupervisorCommand& command,
                                        ServicedSupervisorStatus expected)
{
    ServicedSupervisorCommandResult result{};
    EXPECT_EQ(ServicedSupervisorApplyCommand(&supervisor, &command, &result), expected);
    EXPECT_EQ(result.status, expected);
    return result;
}

void TestManifestValidation()
{
    auto valid = ChainManifest();
    EXPECT_EQ(ServicedSupervisorInitialize(nullptr, &valid), SERVICED_SUPERVISOR_NULL_ARGUMENT);
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], nullptr), SERVICED_SUPERVISOR_NULL_ARGUMENT);

    auto invalid = valid;
    invalid.services[1].service_slot = 0;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], &invalid), SERVICED_SUPERVISOR_INVALID_MANIFEST);
    invalid = valid;
    invalid.services[1].service_identity = invalid.services[0].service_identity;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], &invalid), SERVICED_SUPERVISOR_INVALID_MANIFEST);
    invalid = valid;
    invalid.services[0].dependency_mask = 1ULL << 1U;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], &invalid), SERVICED_SUPERVISOR_INVALID_MANIFEST);
    invalid = valid;
    invalid.services[2].dependency_mask = 1ULL << 63U;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], &invalid), SERVICED_SUPERVISOR_INVALID_MANIFEST);

    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], &valid), SERVICED_SUPERVISOR_OK);
    valid.services[0].service_identity = 99; // The supervisor retained its immutable copy.
    EXPECT_EQ(Inspect(g_supervisors[0], 0).service_identity, ServiceIdentity(0));
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[0], &valid), SERVICED_SUPERVISOR_ALREADY_INITIALIZED);
}

void TestOrderedEventsAndDependencies()
{
    auto manifest = ChainManifest();
    auto snapshot = StoppedSnapshot(manifest);
    ServicedSupervisorActionBatch actions{};
    ServicedSupervisorEventResult rejected{};

    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[1], &manifest), SERVICED_SUPERVISOR_OK);
    auto premature = MakeCommand(SERVICED_COMMAND_START, 1, 1, 2, 0, 0);
    Command(g_supervisors[1], premature, SERVICED_SUPERVISOR_RECONCILE_REJECTED);

    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[1], &snapshot, &actions), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(actions.count, 1U);
    EXPECT_EQ(actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(actions.actions[0].service_slot, 0U);
    EXPECT_EQ(actions.actions[0].expected_transition_generation, 0ULL);
    EXPECT_EQ(actions.actions[0].target_instance_generation, 1ULL);
    EXPECT_EQ(Inspect(g_supervisors[1], 1).phase, SERVICED_PHASE_STOPPED);

    const auto root1 = Observed(0, 1, 1);
    auto out_of_order = Event(SERVICED_EVENT_PUBLISHED, 2, 1, 0, 1, root1);
    EXPECT_EQ(ServicedSupervisorApplyLifecycleEvent(&g_supervisors[1], &out_of_order, &rejected),
              SERVICED_SUPERVISOR_OUT_OF_ORDER_EVENT);
    auto invalid_shape = Event(SERVICED_EVENT_PUBLISHED, 1, 1, 0, 1, root1);
    invalid_shape.reserved32 = 1;
    EXPECT_EQ(ServicedSupervisorApplyLifecycleEvent(&g_supervisors[1], &invalid_shape, &rejected),
              SERVICED_SUPERVISOR_INVALID_EVENT);

    auto published = Apply(g_supervisors[1], Event(SERVICED_EVENT_PUBLISHED, 1, 1, 0, 1, root1));
    EXPECT_EQ(published.actions.count, 0U);
    auto blocked = MakeCommand(SERVICED_COMMAND_START, 1, 1, 2, 0, 1);
    Command(g_supervisors[1], blocked, SERVICED_SUPERVISOR_PENDING_ACKNOWLEDGEMENT);
    EXPECT_EQ(ServicedSupervisorApplyLifecycleEvent(&g_supervisors[1], &out_of_order, &rejected),
              SERVICED_SUPERVISOR_PENDING_ACKNOWLEDGEMENT);

    auto wrong_receipt = published.receipt;
    ++wrong_receipt.event_fingerprint;
    EXPECT_EQ(ServicedSupervisorCommitEventAcknowledgement(&g_supervisors[1], &wrong_receipt),
              SERVICED_SUPERVISOR_INVALID_ACKNOWLEDGEMENT);
    Acknowledge(g_supervisors[1], published);

    auto replay = Event(SERVICED_EVENT_PUBLISHED, 1, 1, 0, 1, root1);
    EXPECT_EQ(ServicedSupervisorApplyLifecycleEvent(&g_supervisors[1], &replay, &rejected),
              SERVICED_SUPERVISOR_REPLAYED_EVENT);
    auto wrong_ready = Event(SERVICED_EVENT_ENDPOINT_READY, 2, 2, 0, 1, Observed(0, 1, 99));
    EXPECT_EQ(ServicedSupervisorApplyLifecycleEvent(&g_supervisors[1], &wrong_ready, &rejected),
              SERVICED_SUPERVISOR_WRONG_INSTANCE);

    auto ready = Apply(g_supervisors[1], Event(SERVICED_EVENT_ENDPOINT_READY, 2, 2, 0, 1, root1));
    EXPECT_EQ(ready.actions.count, 1U);
    EXPECT_EQ(ready.actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(ready.actions.actions[0].service_slot, 1U);
    EXPECT_EQ(ready.actions.actions[0].target_instance_generation, 1ULL);
    Acknowledge(g_supervisors[1], ready);

    const auto dependent1 = Observed(1, 1, 2);
    auto dependent_published = Apply(g_supervisors[1], Event(SERVICED_EVENT_PUBLISHED, 3, 3, 1, 1, dependent1));
    Acknowledge(g_supervisors[1], dependent_published);
    auto dependent_ready = Apply(g_supervisors[1], Event(SERVICED_EVENT_ENDPOINT_READY, 4, 4, 1, 1, dependent1));
    Acknowledge(g_supervisors[1], dependent_ready);
    EXPECT_EQ(Inspect(g_supervisors[1], 0).phase, SERVICED_PHASE_READY);
    EXPECT_EQ(Inspect(g_supervisors[1], 1).phase, SERVICED_PHASE_READY);
}

void TestCrashLoopAndDependencyDrain()
{
    const auto root1 = Observed(0, 1, 1);
    const auto dependent1 = Observed(1, 1, 2);

    auto first_exit = Apply(g_supervisors[1], Event(SERVICED_EVENT_EXITED, 5, 10, 0, 1, root1, false, 0));
    EXPECT_EQ(first_exit.actions.count, 2U);
    EXPECT_EQ(first_exit.actions.actions[0].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(first_exit.actions.actions[0].service_slot, 1U);
    EXPECT_EQ(first_exit.actions.actions[0].reason, SERVICED_ACTION_REASON_DEPENDENCY_LOST);
    EXPECT_EQ(first_exit.actions.actions[0].observed.process.identity, dependent1.process.identity);
    EXPECT_EQ(first_exit.actions.actions[1].type, SERVICED_ACTION_START);
    EXPECT_EQ(first_exit.actions.actions[1].service_slot, 0U);
    EXPECT_EQ(first_exit.actions.actions[1].target_instance_generation, 2ULL);
    Acknowledge(g_supervisors[1], first_exit);

    auto dependent_exit = Apply(g_supervisors[1], Event(SERVICED_EVENT_EXITED, 6, 11, 1, 1, dependent1, false, 0));
    EXPECT_EQ(dependent_exit.actions.count, 0U);
    Acknowledge(g_supervisors[1], dependent_exit);

    const auto root2 = Observed(0, 2, 3);
    auto root2_published = Apply(g_supervisors[1], Event(SERVICED_EVENT_PUBLISHED, 7, 12, 0, 2, root2));
    Acknowledge(g_supervisors[1], root2_published);
    auto root2_ready = Apply(g_supervisors[1], Event(SERVICED_EVENT_ENDPOINT_READY, 8, 13, 0, 2, root2));
    EXPECT_EQ(root2_ready.actions.count, 1U);
    EXPECT_EQ(root2_ready.actions.actions[0].service_slot, 1U);
    EXPECT_EQ(root2_ready.actions.actions[0].target_instance_generation, 2ULL);
    Acknowledge(g_supervisors[1], root2_ready);

    const auto dependent2 = Observed(1, 2, 4);
    auto dependent2_published = Apply(g_supervisors[1], Event(SERVICED_EVENT_PUBLISHED, 9, 14, 1, 2, dependent2));
    Acknowledge(g_supervisors[1], dependent2_published);
    auto dependent2_ready = Apply(g_supervisors[1], Event(SERVICED_EVENT_ENDPOINT_READY, 10, 15, 1, 2, dependent2));
    Acknowledge(g_supervisors[1], dependent2_ready);

    auto second_exit = Apply(g_supervisors[1], Event(SERVICED_EVENT_EXITED, 11, 20, 0, 2, root2, true, 0xC0000005U));
    EXPECT_EQ(second_exit.actions.count, 2U);
    EXPECT_EQ(second_exit.actions.actions[0].service_slot, 1U);
    EXPECT_EQ(second_exit.actions.actions[1].service_slot, 0U);
    EXPECT_EQ(second_exit.actions.actions[1].target_instance_generation, 3ULL);
    Acknowledge(g_supervisors[1], second_exit);

    auto dependent2_exit = Apply(g_supervisors[1], Event(SERVICED_EVENT_EXITED, 12, 21, 1, 2, dependent2, false, 0));
    Acknowledge(g_supervisors[1], dependent2_exit);
    const auto root3 = Observed(0, 3, 5);
    auto root3_published = Apply(g_supervisors[1], Event(SERVICED_EVENT_PUBLISHED, 13, 22, 0, 3, root3));
    Acknowledge(g_supervisors[1], root3_published);
    auto root3_ready = Apply(g_supervisors[1], Event(SERVICED_EVENT_ENDPOINT_READY, 14, 23, 0, 3, root3));
    EXPECT_EQ(root3_ready.actions.count, 1U);
    EXPECT_EQ(root3_ready.actions.actions[0].target_instance_generation, 3ULL);
    Acknowledge(g_supervisors[1], root3_ready);

    const auto dependent3 = Observed(1, 3, 6);
    auto dependent3_published = Apply(g_supervisors[1], Event(SERVICED_EVENT_PUBLISHED, 15, 24, 1, 3, dependent3));
    Acknowledge(g_supervisors[1], dependent3_published);
    auto dependent3_ready = Apply(g_supervisors[1], Event(SERVICED_EVENT_ENDPOINT_READY, 16, 25, 1, 3, dependent3));
    Acknowledge(g_supervisors[1], dependent3_ready);

    auto third_exit = Apply(g_supervisors[1], Event(SERVICED_EVENT_EXITED, 17, 30, 0, 3, root3, true, 7));
    EXPECT_EQ(third_exit.actions.count, 1U);
    EXPECT_EQ(third_exit.actions.actions[0].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(third_exit.actions.actions[0].service_slot, 1U);
    Acknowledge(g_supervisors[1], third_exit);
    auto dependent3_exit = Apply(g_supervisors[1], Event(SERVICED_EVENT_EXITED, 18, 31, 1, 3, dependent3, false, 0));
    Acknowledge(g_supervisors[1], dependent3_exit);

    auto root = Inspect(g_supervisors[1], 0);
    EXPECT_EQ(root.phase, SERVICED_PHASE_CRASH_LOOP);
    EXPECT_EQ(root.desired_state, SERVICED_DESIRED_STOPPED);
    EXPECT_EQ(root.restarts_in_window, 2U);
    EXPECT_EQ(root.transition_generation, 3ULL);

    const auto blocked = MakeCommand(SERVICED_COMMAND_START, 100, 2, 0, 3, 50);
    auto blocked_result = Command(g_supervisors[1], blocked, SERVICED_SUPERVISOR_CRASH_LOOP);
    EXPECT_EQ(blocked_result.duplicate, 0U);
    auto duplicate = Command(g_supervisors[1], blocked, SERVICED_SUPERVISOR_CRASH_LOOP);
    EXPECT_EQ(duplicate.duplicate, 1U);

    auto changed_timestamp = blocked;
    changed_timestamp.now_ns = 51;
    Command(g_supervisors[1], changed_timestamp, SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT);
    auto changed_type = blocked;
    changed_type.type = SERVICED_COMMAND_STOP;
    Command(g_supervisors[1], changed_type, SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT);
    auto replayed = blocked;
    replayed.request_id = 1;
    Command(g_supervisors[1], replayed, SERVICED_SUPERVISOR_REPLAYED_REQUEST);

    auto recovered = MakeCommand(SERVICED_COMMAND_START, 100, 3, 0, 3, 110);
    auto recovered_result = Command(g_supervisors[1], recovered, SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(recovered_result.actions.count, 1U);
    EXPECT_EQ(recovered_result.actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(recovered_result.actions.actions[0].target_instance_generation, 4ULL);
    EXPECT_EQ(Inspect(g_supervisors[1], 0).phase, SERVICED_PHASE_STARTING);
}

void TestOnFailurePolicy()
{
    ServicedSupervisorManifest manifest{};
    manifest.manifest_identity = kManifestIdentity;
    manifest.manifest_generation = kManifestGeneration;
    manifest.service_count = 1;
    SetService(manifest, 0, 2, SERVICED_RESTART_ON_FAILURE, true, 0, 2, 100);
    auto snapshot = StoppedSnapshot(manifest);
    ServicedSupervisorActionBatch actions{};

    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[2], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[2], &snapshot, &actions), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(actions.count, 1U);
    EXPECT_EQ(actions.actions[0].target_instance_generation, 1ULL);

    const auto instance1 = Observed(2, 1, 20);
    auto published1 = Apply(g_supervisors[2], Event(SERVICED_EVENT_PUBLISHED, 1, 1, 2, 1, instance1));
    Acknowledge(g_supervisors[2], published1);
    auto ready1 = Apply(g_supervisors[2], Event(SERVICED_EVENT_ENDPOINT_READY, 2, 2, 2, 1, instance1));
    Acknowledge(g_supervisors[2], ready1);
    auto clean_exit = Apply(g_supervisors[2], Event(SERVICED_EVENT_EXITED, 3, 3, 2, 1, instance1, false, 0));
    EXPECT_EQ(clean_exit.actions.count, 0U);
    Acknowledge(g_supervisors[2], clean_exit);
    EXPECT_EQ(Inspect(g_supervisors[2], 2).desired_state, SERVICED_DESIRED_STOPPED);

    auto start = MakeCommand(SERVICED_COMMAND_START, 200, 1, 2, 1, 4);
    auto start_result = Command(g_supervisors[2], start, SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(start_result.actions.count, 1U);
    EXPECT_EQ(start_result.actions.actions[0].target_instance_generation, 2ULL);
    const auto instance2 = Observed(2, 2, 21);
    auto published2 = Apply(g_supervisors[2], Event(SERVICED_EVENT_PUBLISHED, 4, 5, 2, 2, instance2));
    Acknowledge(g_supervisors[2], published2);
    auto ready2 = Apply(g_supervisors[2], Event(SERVICED_EVENT_ENDPOINT_READY, 5, 6, 2, 2, instance2));
    Acknowledge(g_supervisors[2], ready2);
    auto failed_exit = Apply(g_supervisors[2], Event(SERVICED_EVENT_EXITED, 6, 7, 2, 2, instance2, true, 0xDEADU));
    EXPECT_EQ(failed_exit.actions.count, 1U);
    EXPECT_EQ(failed_exit.actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(failed_exit.actions.actions[0].reason, SERVICED_ACTION_REASON_RESTART_POLICY);
    EXPECT_EQ(failed_exit.actions.actions[0].target_instance_generation, 3ULL);
    Acknowledge(g_supervisors[2], failed_exit);
}

void TestRestartReconciliation()
{
    auto manifest = ChainManifest();
    ServicedSupervisorActionBatch actions{};

    auto adopted = StoppedSnapshot(manifest, 40, 1000);
    const auto root = Observed(0, 5, 30);
    adopted.rows[0].transition_generation = 5;
    adopted.rows[0].lifecycle_identity = root;
    adopted.rows[0].directory_identity = root;
    adopted.rows[0].phase = SERVICED_PHASE_RUNNING;
    adopted.rows[0].endpoint_ready = 1;
    const auto manually_started = Observed(2, 8, 34);
    adopted.rows[2].transition_generation = 8;
    adopted.rows[2].lifecycle_identity = manually_started;
    adopted.rows[2].directory_identity = manually_started;
    adopted.rows[2].phase = SERVICED_PHASE_READY;
    adopted.rows[2].endpoint_ready = 1;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[3], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[3], &adopted, &actions), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(Inspect(g_supervisors[3], 0).adopted, 1U);
    EXPECT_EQ(Inspect(g_supervisors[3], 0).phase, SERVICED_PHASE_READY);
    EXPECT_EQ(Inspect(g_supervisors[3], 2).adopted, 1U);
    EXPECT_EQ(Inspect(g_supervisors[3], 2).desired_state, SERVICED_DESIRED_RUNNING);
    EXPECT_EQ(Inspect(g_supervisors[3], 2).phase, SERVICED_PHASE_READY);
    EXPECT_EQ(actions.count, 1U);
    EXPECT_EQ(actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(actions.actions[0].service_slot, 1U);

    auto mismatch = adopted;
    const auto dependent_lifecycle = Observed(1, 9, 31);
    mismatch.rows[0].directory_identity = Observed(0, 5, 32);
    mismatch.rows[1].transition_generation = 9;
    mismatch.rows[1].lifecycle_identity = dependent_lifecycle;
    mismatch.rows[1].directory_identity = dependent_lifecycle;
    mismatch.rows[1].phase = SERVICED_PHASE_READY;
    mismatch.rows[1].endpoint_ready = 1;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[4], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[4], &mismatch, &actions), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(actions.count, 2U);
    EXPECT_EQ(actions.actions[0].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(actions.actions[0].service_slot, 1U);
    EXPECT_EQ(actions.actions[0].reason, SERVICED_ACTION_REASON_DEPENDENCY_LOST);
    EXPECT_EQ(actions.actions[0].observed.process.identity, dependent_lifecycle.process.identity);
    EXPECT_EQ(actions.actions[1].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(actions.actions[1].service_slot, 0U);
    EXPECT_EQ(actions.actions[1].reason, SERVICED_ACTION_REASON_RECONCILE_MISMATCH);
    EXPECT_EQ(actions.actions[1].observed.process.identity, root.process.identity);
    EXPECT_EQ(Inspect(g_supervisors[4], 0).adopted, 0U);
    EXPECT_EQ(Inspect(g_supervisors[4], 0).phase, SERVICED_PHASE_STOPPING);
    EXPECT_EQ(Inspect(g_supervisors[4], 1).adopted, 1U);

    auto duplicate_identity = adopted;
    auto duplicate = Observed(1, 4, 33);
    duplicate.process.identity = root.process.identity;
    duplicate_identity.rows[1].transition_generation = 4;
    duplicate_identity.rows[1].lifecycle_identity = duplicate;
    duplicate_identity.rows[1].directory_identity = duplicate;
    duplicate_identity.rows[1].phase = SERVICED_PHASE_READY;
    duplicate_identity.rows[1].endpoint_ready = 1;
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[5], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[5], &duplicate_identity, &actions),
              SERVICED_SUPERVISOR_RECONCILE_REJECTED);
    ServicedSupervisorSnapshot description{};
    EXPECT_EQ(ServicedSupervisorDescribe(&g_supervisors[5], &description), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(description.reconciled, 0U);

    auto wrong_manifest = adopted;
    ++wrong_manifest.manifest_generation;
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[5], &wrong_manifest, &actions),
              SERVICED_SUPERVISOR_RECONCILE_REJECTED);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[5], &adopted, &actions), SERVICED_SUPERVISOR_OK);
}

void TestGenerationExhaustion()
{
    ServicedSupervisorManifest manifest{};
    manifest.manifest_identity = kManifestIdentity;
    manifest.manifest_generation = kManifestGeneration;
    manifest.service_count = 1;
    SetService(manifest, 0, 0, SERVICED_RESTART_NEVER, true);
    auto snapshot = StoppedSnapshot(manifest);
    snapshot.rows[0].transition_generation = std::numeric_limits<std::uint64_t>::max();
    snapshot.rows[0].phase = SERVICED_PHASE_GENERATION_EXHAUSTED;
    ServicedSupervisorActionBatch actions{};
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[6], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[6], &snapshot, &actions), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(actions.count, 0U);

    auto command = MakeCommand(SERVICED_COMMAND_START, 300, 1, 0, std::numeric_limits<std::uint64_t>::max(), 1);
    auto result = Command(g_supervisors[6], command, SERVICED_SUPERVISOR_GENERATION_EXHAUSTED);
    EXPECT_EQ(result.actions.count, 0U);
    EXPECT_EQ(Inspect(g_supervisors[6], 0).transition_generation, std::numeric_limits<std::uint64_t>::max());
}

void TestCommandLedgerCapacity()
{
    ServicedSupervisorManifest manifest{};
    manifest.manifest_identity = kManifestIdentity;
    manifest.manifest_generation = kManifestGeneration;
    manifest.service_count = 1;
    SetService(manifest, 0, 0, SERVICED_RESTART_NEVER, false);
    auto snapshot = StoppedSnapshot(manifest);
    ServicedSupervisorActionBatch actions{};
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[7], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[7], &snapshot, &actions), SERVICED_SUPERVISOR_OK);

    for (std::uint64_t client = 1; client <= SERVICED_SUPERVISOR_MAX_CLIENTS; ++client)
    {
        auto command = MakeCommand(SERVICED_COMMAND_STOP, 1000 + client, 2, 0, 0, client);
        auto result = Command(g_supervisors[7], command, SERVICED_SUPERVISOR_OK);
        EXPECT_EQ(result.actions.count, 0U);
    }
    auto overflow = MakeCommand(SERVICED_COMMAND_STOP, 9999, 1, 0, 0, 17);
    Command(g_supervisors[7], overflow, SERVICED_SUPERVISOR_CLIENT_CAPACITY);

    auto first = MakeCommand(SERVICED_COMMAND_STOP, 1001, 2, 0, 0, 1);
    auto duplicate = Command(g_supervisors[7], first, SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(duplicate.duplicate, 1U);
    auto replay = first;
    replay.request_id = 1;
    Command(g_supervisors[7], replay, SERVICED_SUPERVISOR_REPLAYED_REQUEST);
    auto conflict = first;
    conflict.now_ns = 18;
    Command(g_supervisors[7], conflict, SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT);

    ServicedSupervisorSnapshot description{};
    EXPECT_EQ(ServicedSupervisorDescribe(&g_supervisors[7], &description), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(description.client_count, SERVICED_SUPERVISOR_MAX_CLIENTS);
}

void TestRejectedCommandCannotPoisonClock()
{
    ServicedSupervisorManifest manifest{};
    manifest.manifest_identity = kManifestIdentity;
    manifest.manifest_generation = kManifestGeneration;
    manifest.service_count = 1;
    SetService(manifest, 0, 0, SERVICED_RESTART_NEVER, false);
    auto snapshot = StoppedSnapshot(manifest);
    ServicedSupervisorActionBatch actions{};
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[8], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[8], &snapshot, &actions), SERVICED_SUPERVISOR_OK);

    auto missing = MakeCommand(SERVICED_COMMAND_START, 400, 1, 0, 0, std::numeric_limits<std::uint64_t>::max());
    missing.service_identity = 0xBAD0000000000001ULL;
    Command(g_supervisors[8], missing, SERVICED_SUPERVISOR_NOT_FOUND);

    auto start = MakeCommand(SERVICED_COMMAND_START, 400, 2, 0, 0, 1);
    auto started = Command(g_supervisors[8], start, SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(started.actions.count, 1U);
    EXPECT_EQ(started.actions.actions[0].target_instance_generation, 1ULL);

    auto stale = MakeCommand(SERVICED_COMMAND_STOP, 401, 1, 0, 0, std::numeric_limits<std::uint64_t>::max());
    Command(g_supervisors[8], stale, SERVICED_SUPERVISOR_STALE_GENERATION);
    auto stop = MakeCommand(SERVICED_COMMAND_STOP, 401, 2, 0, 1, 2);
    auto stopped = Command(g_supervisors[8], stop, SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(stopped.actions.count, 1U);
    EXPECT_EQ(stopped.actions.actions[0].type, SERVICED_ACTION_CANCEL_START);
}

void TestStartFailureEndpointCloseAndCancellation()
{
    ServicedSupervisorManifest manifest{};
    manifest.manifest_identity = kManifestIdentity;
    manifest.manifest_generation = kManifestGeneration;
    manifest.service_count = 1;
    SetService(manifest, 0, 0, SERVICED_RESTART_ALWAYS, true, 0, 2, 100);
    auto snapshot = StoppedSnapshot(manifest);
    ServicedSupervisorActionBatch actions{};
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[9], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[9], &snapshot, &actions), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(actions.count, 1U);

    auto failed = Apply(g_supervisors[9], Event(SERVICED_EVENT_START_FAILED, 1, 1, 0, 1, {}, true, 5));
    EXPECT_EQ(failed.actions.count, 1U);
    EXPECT_EQ(failed.actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(failed.actions.actions[0].target_instance_generation, 2ULL);
    Acknowledge(g_supervisors[9], failed);

    const auto instance2 = Observed(0, 2, 50);
    auto published = Apply(g_supervisors[9], Event(SERVICED_EVENT_PUBLISHED, 2, 2, 0, 2, instance2));
    Acknowledge(g_supervisors[9], published);
    auto ready = Apply(g_supervisors[9], Event(SERVICED_EVENT_ENDPOINT_READY, 3, 3, 0, 2, instance2));
    Acknowledge(g_supervisors[9], ready);
    auto closed = Apply(g_supervisors[9], Event(SERVICED_EVENT_ENDPOINT_CLOSED, 4, 4, 0, 2, instance2));
    EXPECT_EQ(closed.actions.count, 1U);
    EXPECT_EQ(closed.actions.actions[0].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(closed.actions.actions[0].reason, SERVICED_ACTION_REASON_ENDPOINT_LOST);
    Acknowledge(g_supervisors[9], closed);

    auto exited = Apply(g_supervisors[9], Event(SERVICED_EVENT_EXITED, 5, 5, 0, 2, instance2, false, 0));
    EXPECT_EQ(exited.actions.count, 1U);
    EXPECT_EQ(exited.actions.actions[0].type, SERVICED_ACTION_START);
    EXPECT_EQ(exited.actions.actions[0].target_instance_generation, 3ULL);
    Acknowledge(g_supervisors[9], exited);

    auto stop = MakeCommand(SERVICED_COMMAND_STOP, 500, 1, 0, 3, 6);
    auto cancel = Command(g_supervisors[9], stop, SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(cancel.actions.count, 1U);
    EXPECT_EQ(cancel.actions.actions[0].type, SERVICED_ACTION_CANCEL_START);
    auto cancelled = Apply(g_supervisors[9], Event(SERVICED_EVENT_START_CANCELLED, 6, 7, 0, 3));
    EXPECT_EQ(cancelled.actions.count, 0U);
    Acknowledge(g_supervisors[9], cancelled);
    EXPECT_EQ(Inspect(g_supervisors[9], 0).phase, SERVICED_PHASE_STOPPED);
}

void TestEndpointCloseDrainsDependentsFirst()
{
    auto manifest = ChainManifest();
    auto snapshot = StoppedSnapshot(manifest);
    ServicedSupervisorActionBatch actions{};
    EXPECT_EQ(ServicedSupervisorInitialize(&g_supervisors[10], &manifest), SERVICED_SUPERVISOR_OK);
    EXPECT_EQ(ServicedSupervisorReconcile(&g_supervisors[10], &snapshot, &actions), SERVICED_SUPERVISOR_OK);

    const auto root = Observed(0, 1, 60);
    auto root_published = Apply(g_supervisors[10], Event(SERVICED_EVENT_PUBLISHED, 1, 1, 0, 1, root));
    Acknowledge(g_supervisors[10], root_published);
    auto root_ready = Apply(g_supervisors[10], Event(SERVICED_EVENT_ENDPOINT_READY, 2, 2, 0, 1, root));
    Acknowledge(g_supervisors[10], root_ready);
    const auto dependent = Observed(1, 1, 61);
    auto dependent_published = Apply(g_supervisors[10], Event(SERVICED_EVENT_PUBLISHED, 3, 3, 1, 1, dependent));
    Acknowledge(g_supervisors[10], dependent_published);
    auto dependent_ready = Apply(g_supervisors[10], Event(SERVICED_EVENT_ENDPOINT_READY, 4, 4, 1, 1, dependent));
    Acknowledge(g_supervisors[10], dependent_ready);

    auto closed = Apply(g_supervisors[10], Event(SERVICED_EVENT_ENDPOINT_CLOSED, 5, 5, 0, 1, root));
    EXPECT_EQ(closed.actions.count, 2U);
    EXPECT_EQ(closed.actions.actions[0].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(closed.actions.actions[0].service_slot, 1U);
    EXPECT_EQ(closed.actions.actions[0].reason, SERVICED_ACTION_REASON_DEPENDENCY_LOST);
    EXPECT_EQ(closed.actions.actions[1].type, SERVICED_ACTION_STOP_INSTANCE);
    EXPECT_EQ(closed.actions.actions[1].service_slot, 0U);
    EXPECT_EQ(closed.actions.actions[1].reason, SERVICED_ACTION_REASON_ENDPOINT_LOST);
    Acknowledge(g_supervisors[10], closed);
}

} // namespace

int main()
{
    TestManifestValidation();
    TestOrderedEventsAndDependencies();
    TestCrashLoopAndDependencyDrain();
    TestOnFailurePolicy();
    TestRestartReconciliation();
    TestGenerationExhaustion();
    TestCommandLedgerCapacity();
    TestRejectedCommandCannotPoisonClock();
    TestStartFailureEndpointCloseAndCancellation();
    TestEndpointCloseDrainsDependentsFirst();
    return duetos_host_test::finish_main("serviced_supervisor");
}
