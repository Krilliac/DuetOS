#include "test/cancellation_smp_oracle.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "fs/ramfs.h"
#include "ipc/handle_table.h"
#include "ipc/iocp.h"
#include "ipc/kmessage_port.h"
#include "ipc/kmutex.h"
#include "ipc/kobject.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::test
{

namespace
{

constexpr u64 kControlWaitTicks = 300;
constexpr u64 kWorkerWaitTicks = 500;
constexpr u64 kIocpRaceTicks = 8;
constexpr u64 kWorkerGateYieldLimit = 100000;
constexpr u32 kBlockedSnapshotCapacity = 192;
constexpr u32 kUnsetResult = ~u32{0};

struct AffinityPrepare
{
    u32 cpu_id;
    bool applied;
};

void PrepareAffinity(sched::Task* task, void* context)
{
    auto* prepare = static_cast<AffinityPrepare*>(context);
    prepare->applied = sched::SchedSetAffinity(task, prepare->cpu_id);
}

u32 Load(const volatile u32* value)
{
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

u64 Load(const volatile u64* value)
{
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

void Store(volatile u32* value, u32 replacement)
{
    __atomic_store_n(value, replacement, __ATOMIC_RELEASE);
}

void Store(volatile u64* value, u64 replacement)
{
    __atomic_store_n(value, replacement, __ATOMIC_RELEASE);
}

void Increment(volatile u32* value)
{
    (void)__atomic_add_fetch(value, 1u, __ATOMIC_ACQ_REL);
}

bool WaitForAtLeast(const volatile u32* value, u32 target, u64 ticks = kControlWaitTicks)
{
    for (u64 waited = 0; waited < ticks; ++waited)
    {
        if (Load(value) >= target)
            return true;
        sched::SchedSleepTicks(1);
    }
    return Load(value) >= target;
}

bool WaitForFlagWorker(const volatile u32* value)
{
    const u64 start = sched::SchedNowTicks();
    for (u64 attempts = 0;
         attempts < kWorkerGateYieldLimit && Load(value) == 0 && sched::SchedNowTicks() - start < kControlWaitTicks;
         ++attempts)
    {
        sched::SchedYield();
    }
    return Load(value) != 0;
}

bool WaitForTaskBlocked(u64 tid)
{
    sched::SchedBlockedTaskInfo rows[kBlockedSnapshotCapacity]{};
    for (u64 waited = 0; waited < kControlWaitTicks; ++waited)
    {
        const u64 count = sched::SchedSnapshotBlockedTasks(rows, kBlockedSnapshotCapacity);
        for (u64 index = 0; index < count; ++index)
        {
            if (rows[index].id == tid)
                return true;
        }
        sched::SchedSleepTicks(1);
    }
    return false;
}

bool WaitForProcessReaped(core::Process* process)
{
    for (u64 waited = 0; waited < kControlWaitTicks; ++waited)
    {
        if (core::ProcessLifecycleLoad(process) == core::ProcessLifecycleState::Exited &&
            sched::SchedCountLiveTasksForProcess(process) == 0 &&
            __atomic_load_n(&process->refcount, __ATOMIC_ACQUIRE) == 1)
        {
            return true;
        }
        sched::SchedSleepTicks(1);
    }
    return core::ProcessLifecycleLoad(process) == core::ProcessLifecycleState::Exited &&
           sched::SchedCountLiveTasksForProcess(process) == 0 &&
           __atomic_load_n(&process->refcount, __ATOMIC_ACQUIRE) == 1;
}

core::Process* CreateOracleProcess(const char* name)
{
    auto as_result = mm::AddressSpaceCreate(mm::kFrameBudgetSandbox);
    if (!as_result.has_value())
        return nullptr;
    mm::AddressSpace* address_space = as_result.value();
    core::Process* process = core::ProcessCreate(name, address_space, core::CapSetEmpty(), fs::RamfsSandboxRoot(),
                                                 /*user_code_va=*/0, /*user_stack_va=*/0, core::kTickBudgetTrusted);
    if (process == nullptr)
        mm::AddressSpaceRelease(address_space);
    return process;
}

sched::TaskCreateResult CreateKernelPinned(sched::TaskEntry entry, void* argument, const char* name, u32 cpu_id,
                                           bool* affinity_applied)
{
    AffinityPrepare prepare{cpu_id, false};
    const sched::TaskCreateResult result =
        sched::SchedCreatePrepared(entry, argument, name, &PrepareAffinity, &prepare);
    if (affinity_applied != nullptr)
        *affinity_applied = prepare.applied;
    return result;
}

sched::TaskCreateResult CreateUserPinned(sched::TaskEntry entry, void* argument, const char* name,
                                         core::Process* process, u32 cpu_id, bool* affinity_applied)
{
    core::ProcessRetain(process);
    AffinityPrepare prepare{cpu_id, false};
    const sched::TaskCreateResult result =
        sched::SchedCreateUserPrepared(entry, argument, name, process, &PrepareAffinity, &prepare);
    if (affinity_applied != nullptr)
        *affinity_applied = prepare.applied;
    return result;
}

void WriteDecimal(u64 value)
{
    char digits[21]{};
    u32 count = 0;
    do
    {
        digits[count++] = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count != 0)
    {
        char text[2]{digits[--count], '\0'};
        arch::SerialWrite(text);
    }
}

bool Fail(const char* test_case, const char* reason)
{
    arch::SerialLineGuard line;
    arch::SerialWrite("[cancel-smp] FAIL case=");
    arch::SerialWrite(test_case);
    arch::SerialWrite(" reason=");
    arch::SerialWrite(reason);
    arch::SerialWrite("\n");
    return false;
}

void Pass(const char* test_case, const char* detail, u64 references)
{
    arch::SerialLineGuard line;
    arch::SerialWrite("[cancel-smp] case=");
    arch::SerialWrite(test_case);
    arch::SerialWrite(" PASS result=");
    arch::SerialWrite(detail);
    arch::SerialWrite(" refs=");
    WriteDecimal(references);
    arch::SerialWrite("\n");
}

const char* KMutexResultName(ipc::KMutexWaitResult result)
{
    switch (result)
    {
    case ipc::KMutexWaitResult::Acquired:
        return "acquired";
    case ipc::KMutexWaitResult::Cancelled:
        return "cancelled";
    case ipc::KMutexWaitResult::TimedOut:
        return "timed-out";
    default:
        return "invalid";
    }
}

const char* IocpResultName(ipc::IocpWaitResult result)
{
    switch (result)
    {
    case ipc::IocpWaitResult::TimedOut:
        return "timed-out";
    case ipc::IocpWaitResult::Cancelled:
        return "cancelled";
    default:
        return "invalid";
    }
}

const char* MessagePortResultName(ipc::KMessagePortStatus result)
{
    switch (result)
    {
    case ipc::KMessagePortStatus::Closed:
        return "closed";
    case ipc::KMessagePortStatus::Cancelled:
        return "cancelled";
    default:
        return "invalid";
    }
}

struct PublicationRace
{
    core::Process* process;
    sched::WaitQueue child_waiters;
    u32 child_cpu;
    volatile u32 gate;
    volatile u32 racers_ready;
    volatile u32 racers_done;
    volatile u32 gate_timeout;
    volatile u32 spawn_created;
    volatile u32 spawn_affinity;
    volatile u64 killed;
};

void PublicationChild(void* argument)
{
    auto* race = static_cast<PublicationRace*>(argument);
    sched::ScopedTaskCancellationDeferral cancellation;
    sched::SchedUserBootstrapComplete();
    (void)sched::WaitQueueBlockTimeoutCancellable(&race->child_waiters, kWorkerWaitTicks);
}

void PublicationSpawner(void* argument)
{
    auto* race = static_cast<PublicationRace*>(argument);
    Increment(&race->racers_ready);
    if (!WaitForFlagWorker(&race->gate))
        Store(&race->gate_timeout, 1);

    bool affinity_applied = false;
    const sched::TaskCreateResult spawned = CreateUserPinned(&PublicationChild, race, "cancel-publish-late",
                                                             race->process, race->child_cpu, &affinity_applied);
    Store(&race->spawn_created, spawned.created ? 1u : 0u);
    Store(&race->spawn_affinity, affinity_applied ? 1u : 0u);
    Increment(&race->racers_done);
}

void PublicationKiller(void* argument)
{
    auto* race = static_cast<PublicationRace*>(argument);
    Increment(&race->racers_ready);
    if (!WaitForFlagWorker(&race->gate))
        Store(&race->gate_timeout, 1);
    Store(&race->killed, sched::SchedKillByProcess(race->process));
    Increment(&race->racers_done);
}

bool RunPublicationBarrier(u32 cpu_count)
{
    const u32 rounds = cpu_count >= 4 ? 2u : 1u;
    u32 published = 0;
    for (u32 round = 0; round < rounds; ++round)
    {
        core::Process* process = CreateOracleProcess("cancel-smp-publish");
        if (process == nullptr)
            return Fail("publication-barrier", "process-create");

        const u32 spawn_cpu = (round * 2u) % cpu_count;
        const u32 kill_cpu = (spawn_cpu + 1u) % cpu_count;
        PublicationRace race{};
        race.process = process;
        race.child_cpu = spawn_cpu;

        bool anchor_affinity = false;
        const sched::TaskCreateResult anchor =
            CreateUserPinned(&PublicationChild, &race, "cancel-publish-anchor", process, spawn_cpu, &anchor_affinity);
        if (!anchor.created || !anchor_affinity || !WaitForTaskBlocked(anchor.tid))
        {
            if (anchor.created)
                (void)sched::SchedKillByProcess(process);
            if (anchor.created)
                (void)WaitForProcessReaped(process);
            core::ProcessRelease(process);
            return Fail("publication-barrier", "anchor-not-blocked");
        }

        bool spawner_affinity = false;
        bool killer_affinity = false;
        const sched::TaskCreateResult spawner =
            CreateKernelPinned(&PublicationSpawner, &race, "cancel-publish-spawn", spawn_cpu, &spawner_affinity);
        const sched::TaskCreateResult killer =
            CreateKernelPinned(&PublicationKiller, &race, "cancel-publish-kill", kill_cpu, &killer_affinity);
        if (!spawner.created || !killer.created || !spawner_affinity || !killer_affinity ||
            !WaitForAtLeast(&race.racers_ready, 2))
        {
            Store(&race.gate, 1);
            (void)sched::SchedKillByProcess(process);
            (void)WaitForAtLeast(&race.racers_done,
                                 static_cast<u32>(spawner.created) + static_cast<u32>(killer.created));
            (void)WaitForProcessReaped(process);
            core::ProcessRelease(process);
            return Fail("publication-barrier", "race-start");
        }

        Store(&race.gate, 1);
        if (!WaitForAtLeast(&race.racers_done, 2))
        {
            (void)sched::SchedKillByProcess(process);
            // Both helpers retain pointers into this stack frame. Give each
            // bounded helper one final chance to publish completion before
            // returning the failure to the fail-closed profile.
            (void)WaitForAtLeast(&race.racers_done, 2);
            (void)WaitForProcessReaped(process);
            core::ProcessRelease(process);
            return Fail("publication-barrier", "race-timeout");
        }

        const bool created = Load(&race.spawn_created) != 0;
        const u64 expected_killed = created ? 2u : 1u;
        if (Load(&race.gate_timeout) != 0 || (created && Load(&race.spawn_affinity) == 0) ||
            Load(&race.killed) != expected_killed ||
            core::ProcessTerminationLoad(process) != core::ProcessTerminationState::Closed)
        {
            (void)sched::SchedKillByProcess(process);
            (void)WaitForProcessReaped(process);
            core::ProcessRelease(process);
            return Fail("publication-barrier", "linearization");
        }

        // The concurrent result has two legal linearizations. This second
        // attempt is deliberately after kill returned and therefore has only
        // one: the closed tombstone must reject publication.
        bool rejected_affinity = false;
        const sched::TaskCreateResult rejected =
            CreateUserPinned(&PublicationChild, &race, "cancel-publish-reject", process, spawn_cpu, &rejected_affinity);
        if (rejected.created)
            (void)sched::SchedKillByProcess(process);
        if (rejected.created || !WaitForProcessReaped(process))
        {
            core::ProcessRelease(process);
            return Fail("publication-barrier", "post-kill-publish");
        }
        published += created ? 1u : 0u;
        core::ProcessRelease(process);
    }

    arch::SerialLineGuard line;
    arch::SerialWrite("[cancel-smp] case=publication-barrier PASS result=linearized refs=1 rounds=");
    WriteDecimal(rounds);
    arch::SerialWrite(" published=");
    WriteDecimal(published);
    arch::SerialWrite("\n");
    return true;
}

struct KMutexRace
{
    ipc::KMutex* mutex;
    volatile u32 release_gate;
    volatile u32 cleanup_gate;
    volatile u32 holder_ready;
    volatile u32 holder_done;
    volatile u32 waiter_done;
    volatile u32 gate_timeout;
    volatile u32 holder_acquired;
    volatile u32 waiter_result;
};

void KMutexHolder(void* argument)
{
    auto* race = static_cast<KMutexRace*>(argument);
    const ipc::KMutexWaitResult result = ipc::KMutexAcquireTimed(race->mutex, kWorkerWaitTicks);
    Store(&race->holder_acquired, result == ipc::KMutexWaitResult::Acquired ? 1u : 0u);
    Store(&race->holder_ready, 1);
    if (!WaitForFlagWorker(&race->release_gate))
        Store(&race->gate_timeout, 1);
    if (result == ipc::KMutexWaitResult::Acquired)
        (void)ipc::KMutexRelease(race->mutex);
    Store(&race->holder_done, 1);
}

void KMutexWaiter(void* argument)
{
    auto* race = static_cast<KMutexRace*>(argument);
    sched::ScopedTaskCancellationDeferral cancellation;
    sched::SchedUserBootstrapComplete();
    const ipc::KMutexWaitResult result = ipc::KMutexAcquireTimed(race->mutex, kWorkerWaitTicks);
    Store(&race->waiter_result, static_cast<u32>(result));
    if (!WaitForFlagWorker(&race->cleanup_gate))
        Store(&race->gate_timeout, 1);
    if (result == ipc::KMutexWaitResult::Acquired || result == ipc::KMutexWaitResult::Abandoned)
        (void)ipc::KMutexRelease(race->mutex);
    ipc::KObjectRelease(&race->mutex->base);
    Store(&race->waiter_done, 1);
}

bool RunKMutexWakeRace(u32 cpu_count)
{
    auto create_result = ipc::KMutexCreate();
    if (!create_result.has_value())
        return Fail("kmutex-wake", "object-create");
    ipc::KMutex* mutex = create_result.value();
    KMutexRace race{};
    race.mutex = mutex;
    race.waiter_result = kUnsetResult;

    bool holder_affinity = false;
    const sched::TaskCreateResult holder =
        CreateKernelPinned(&KMutexHolder, &race, "cancel-kmutex-hold", 1u % cpu_count, &holder_affinity);
    if (!holder.created || !holder_affinity || !WaitForAtLeast(&race.holder_ready, 1) ||
        Load(&race.holder_acquired) == 0)
    {
        Store(&race.release_gate, 1);
        (void)WaitForAtLeast(&race.holder_done, static_cast<u32>(holder.created));
        ipc::KObjectRelease(&mutex->base);
        return Fail("kmutex-wake", "holder-start");
    }

    core::Process* process = CreateOracleProcess("cancel-smp-kmutex");
    if (process == nullptr || !ipc::KObjectAcquire(&mutex->base))
    {
        if (process != nullptr)
            core::ProcessRelease(process);
        Store(&race.release_gate, 1);
        (void)WaitForAtLeast(&race.holder_done, 1);
        ipc::KObjectRelease(&mutex->base);
        return Fail("kmutex-wake", "waiter-setup");
    }

    bool waiter_affinity = false;
    const sched::TaskCreateResult waiter =
        CreateUserPinned(&KMutexWaiter, &race, "cancel-kmutex-wait", process, 0, &waiter_affinity);
    if (!waiter.created)
        ipc::KObjectRelease(&mutex->base);
    if (!waiter.created || !waiter_affinity || !WaitForTaskBlocked(waiter.tid) ||
        ipc::KObjectRefcount(&mutex->base) != 4)
    {
        Store(&race.release_gate, 1);
        (void)sched::SchedKillByProcess(process);
        Store(&race.cleanup_gate, 1);
        (void)WaitForAtLeast(&race.holder_done, 1);
        (void)WaitForProcessReaped(process);
        core::ProcessRelease(process);
        ipc::KObjectRelease(&mutex->base);
        return Fail("kmutex-wake", "waiter-not-blocked");
    }

    Store(&race.release_gate, 1);
    const u64 killed = sched::SchedKillByProcess(process);
    Store(&race.cleanup_gate, 1);
    const bool workers_done = WaitForAtLeast(&race.holder_done, 1) && WaitForAtLeast(&race.waiter_done, 1);
    const auto result = static_cast<ipc::KMutexWaitResult>(Load(&race.waiter_result));
    const bool valid_result = result == ipc::KMutexWaitResult::Acquired || result == ipc::KMutexWaitResult::Cancelled;
    const bool clean = workers_done && killed == 1 && valid_result && Load(&race.gate_timeout) == 0 &&
                       WaitForProcessReaped(process) && ipc::KObjectRefcount(&mutex->base) == 1 &&
                       !ipc::KMutexHeld(mutex);
    core::ProcessRelease(process);
    if (!clean)
    {
        ipc::KObjectRelease(&mutex->base);
        return Fail("kmutex-wake", "unwind-or-refcount");
    }
    Pass("kmutex-wake", KMutexResultName(result), ipc::KObjectRefcount(&mutex->base));
    ipc::KObjectRelease(&mutex->base);
    return true;
}

struct IocpRace
{
    ipc::IocpPort* port;
    volatile u32 cleanup_gate;
    volatile u32 waiter_returned;
    volatile u32 waiter_done;
    volatile u32 gate_timeout;
    volatile u32 waiter_result;
};

void IocpWaiter(void* argument)
{
    auto* race = static_cast<IocpRace*>(argument);
    sched::ScopedTaskCancellationDeferral cancellation;
    sched::SchedUserBootstrapComplete();
    ipc::IocpCompletion completion{};
    const ipc::IocpWaitResult result = ipc::IocpWait(race->port, &completion, kIocpRaceTicks);
    Store(&race->waiter_result, static_cast<u32>(result));
    Store(&race->waiter_returned, 1);
    if (!WaitForFlagWorker(&race->cleanup_gate))
        Store(&race->gate_timeout, 1);
    ipc::KObjectRelease(&race->port->base);
    Store(&race->waiter_done, 1);
}

bool RunIocpTimeoutRace(u32 cpu_count)
{
    auto create_result = ipc::IocpCreate();
    if (!create_result.has_value())
        return Fail("iocp-timeout", "object-create");
    ipc::IocpPort* port = create_result.value();
    IocpRace race{};
    race.port = port;
    race.waiter_result = kUnsetResult;
    core::Process* process = CreateOracleProcess("cancel-smp-iocp");
    if (process == nullptr || !ipc::KObjectAcquire(&port->base))
    {
        if (process != nullptr)
            core::ProcessRelease(process);
        ipc::KObjectRelease(&port->base);
        return Fail("iocp-timeout", "waiter-setup");
    }

    bool waiter_affinity = false;
    const sched::TaskCreateResult waiter =
        CreateUserPinned(&IocpWaiter, &race, "cancel-iocp-wait", process, 1u % cpu_count, &waiter_affinity);
    if (!waiter.created)
        ipc::KObjectRelease(&port->base);
    if (!waiter.created || !waiter_affinity || !WaitForTaskBlocked(waiter.tid) ||
        ipc::KObjectRefcount(&port->base) != 2)
    {
        (void)sched::SchedKillByProcess(process);
        Store(&race.cleanup_gate, 1);
        (void)WaitForProcessReaped(process);
        core::ProcessRelease(process);
        ipc::KObjectRelease(&port->base);
        return Fail("iocp-timeout", "waiter-not-blocked");
    }

    sched::SchedSleepTicks(kIocpRaceTicks - 1);
    const u64 killed = sched::SchedKillByProcess(process);
    Store(&race.cleanup_gate, 1);
    const bool done = WaitForAtLeast(&race.waiter_returned, 1) && WaitForAtLeast(&race.waiter_done, 1);
    const auto result = static_cast<ipc::IocpWaitResult>(Load(&race.waiter_result));
    const bool valid_result = result == ipc::IocpWaitResult::TimedOut || result == ipc::IocpWaitResult::Cancelled;
    const bool clean = done && killed == 1 && valid_result && Load(&race.gate_timeout) == 0 &&
                       WaitForProcessReaped(process) && ipc::KObjectRefcount(&port->base) == 1;
    core::ProcessRelease(process);
    if (!clean)
    {
        ipc::KObjectRelease(&port->base);
        return Fail("iocp-timeout", "unwind-or-refcount");
    }
    Pass("iocp-timeout", IocpResultName(result), ipc::KObjectRefcount(&port->base));
    ipc::KObjectRelease(&port->base);
    return true;
}

struct MessagePortRace
{
    ipc::HandleTable table;
    ipc::Handle handle;
    volatile u32 close_gate;
    volatile u32 cleanup_gate;
    volatile u32 closer_done;
    volatile u32 waiter_done;
    volatile u32 gate_timeout;
    volatile u32 close_result;
    volatile u32 waiter_result;
};

void MessagePortWaiter(void* argument)
{
    auto* race = static_cast<MessagePortRace*>(argument);
    sched::ScopedTaskCancellationDeferral cancellation;
    sched::SchedUserBootstrapComplete();
    const ipc::KMessagePortStatus result = ipc::KMessagePortWaitReadableHandle(race->table, race->handle);
    Store(&race->waiter_result, static_cast<u32>(result));
    if (!WaitForFlagWorker(&race->cleanup_gate))
        Store(&race->gate_timeout, 1);
    Store(&race->waiter_done, 1);
}

void MessagePortCloser(void* argument)
{
    auto* race = static_cast<MessagePortRace*>(argument);
    if (!WaitForFlagWorker(&race->close_gate))
        Store(&race->gate_timeout, 1);
    Store(&race->close_result, static_cast<u32>(ipc::KMessagePortCloseHandle(race->table, race->handle)));
    Store(&race->closer_done, 1);
}

bool RunMessagePortCloseRace(u32 cpu_count)
{
    auto create_result = ipc::KMessagePortCreate();
    if (!create_result.has_value())
        return Fail("message-port-close", "object-create");
    ipc::KMessagePort* port = create_result.value();
    if (!ipc::KObjectAcquire(&port->base))
    {
        ipc::KObjectRelease(&port->base);
        return Fail("message-port-close", "coordinator-ref");
    }

    MessagePortRace race{};
    auto insert_result =
        ipc::HandleTableInsert(race.table, &port->base, ipc::TypeAllowedRights(ipc::KObjectType::MessagePort));
    if (!insert_result.has_value())
    {
        ipc::KObjectRelease(&port->base);
        ipc::KObjectRelease(&port->base);
        return Fail("message-port-close", "handle-insert");
    }
    race.handle = insert_result.value();
    race.close_result = kUnsetResult;
    race.waiter_result = kUnsetResult;

    core::Process* process = CreateOracleProcess("cancel-smp-message");
    if (process == nullptr)
    {
        (void)ipc::KMessagePortCloseHandle(race.table, race.handle);
        ipc::KObjectRelease(&port->base);
        return Fail("message-port-close", "process-create");
    }

    bool waiter_affinity = false;
    const sched::TaskCreateResult waiter =
        CreateUserPinned(&MessagePortWaiter, &race, "cancel-message-wait", process, 0, &waiter_affinity);
    if (!waiter.created || !waiter_affinity || !WaitForTaskBlocked(waiter.tid) ||
        ipc::KObjectRefcount(&port->base) != 3)
    {
        (void)sched::SchedKillByProcess(process);
        (void)ipc::KMessagePortCloseHandle(race.table, race.handle);
        Store(&race.cleanup_gate, 1);
        (void)WaitForProcessReaped(process);
        core::ProcessRelease(process);
        ipc::KObjectRelease(&port->base);
        return Fail("message-port-close", "waiter-not-blocked");
    }

    bool closer_affinity = false;
    const sched::TaskCreateResult closer =
        CreateKernelPinned(&MessagePortCloser, &race, "cancel-message-close", 1u % cpu_count, &closer_affinity);
    if (!closer.created || !closer_affinity)
    {
        // A created-but-misconfigured closer still owns a pointer to race.
        // Release its gate and observe completion before this frame unwinds.
        Store(&race.close_gate, 1);
        (void)ipc::KMessagePortCloseHandle(race.table, race.handle);
        (void)sched::SchedKillByProcess(process);
        Store(&race.cleanup_gate, 1);
        if (closer.created)
            (void)WaitForAtLeast(&race.closer_done, 1);
        (void)WaitForProcessReaped(process);
        core::ProcessRelease(process);
        ipc::KObjectRelease(&port->base);
        return Fail("message-port-close", "closer-start");
    }

    Store(&race.close_gate, 1);
    const u64 killed = sched::SchedKillByProcess(process);
    const bool closer_done = WaitForAtLeast(&race.closer_done, 1);
    Store(&race.cleanup_gate, 1);
    const bool waiter_done = WaitForAtLeast(&race.waiter_done, 1);
    const auto wait_result = static_cast<ipc::KMessagePortStatus>(Load(&race.waiter_result));
    const auto close_result = static_cast<ipc::KMessagePortStatus>(Load(&race.close_result));
    const bool valid_result =
        wait_result == ipc::KMessagePortStatus::Closed || wait_result == ipc::KMessagePortStatus::Cancelled;
    ipc::KObject* stale = ipc::HandleTableLookupRef(race.table, race.handle, ipc::KObjectType::MessagePort);
    if (stale != nullptr)
        ipc::KObjectRelease(stale);
    const bool clean = closer_done && waiter_done && killed == 1 && valid_result &&
                       close_result == ipc::KMessagePortStatus::Ok && Load(&race.gate_timeout) == 0 &&
                       stale == nullptr && WaitForProcessReaped(process) && ipc::KObjectRefcount(&port->base) == 1;
    core::ProcessRelease(process);
    if (!clean)
    {
        ipc::KObjectRelease(&port->base);
        return Fail("message-port-close", "unwind-or-refcount");
    }
    Pass("message-port-close", MessagePortResultName(wait_result), ipc::KObjectRefcount(&port->base));
    ipc::KObjectRelease(&port->base);
    return true;
}

} // namespace

bool RunCancellationSmpOracle()
{
    const u64 online = arch::SmpCpusOnline();
    if (online < 2 || online > 32)
        return Fail("topology", "requires-2-to-32-online-cpus");
    const u32 cpu_count = static_cast<u32>(online);

    {
        arch::SerialLineGuard line;
        arch::SerialWrite("[cancel-smp] begin cpus=");
        WriteDecimal(cpu_count);
        arch::SerialWrite("\n");
    }

    if (!RunPublicationBarrier(cpu_count) || !RunKMutexWakeRace(cpu_count) || !RunIocpTimeoutRace(cpu_count) ||
        !RunMessagePortCloseRace(cpu_count))
    {
        return false;
    }

    arch::SerialLineGuard line;
    arch::SerialWrite("[cancel-smp] PASS cpus=");
    WriteDecimal(cpu_count);
    arch::SerialWrite(" cases=4\n");
    return true;
}

} // namespace duetos::test
