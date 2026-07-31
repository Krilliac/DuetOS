/*
 * Win32 Job-object adapter.
 *
 * proc/job.{h,cpp} is the protocol-neutral owner of Job state, generations,
 * references, membership, accounting, termination pins, and owner-exit drain.
 * This file owns the public 0xC00 handle band, creator capability/ownership
 * policy, Win32 information-class byte layouts, user copies, and scheduler
 * kill requests.
 *
 * A termination intent borrows member Process pointers from the core.  Its
 * operation pin keeps the membership references attached while scheduler calls
 * run outside the core pool lock.  Close and owner drain can tombstone the Job
 * concurrently, but retirement and ProcessRelease wait for intent completion.
 *
 * Known gaps retained by this adapter/service split:
 *   - information classes other than BasicAccountingInformation,
 *     BasicProcessIdList, and BasicAndIoAccountingInformation are rejected;
 *   - configured CPU/working-set/resource limits are not enforced;
 *   - non-owner member process exit does not detach membership;
 *   - nested Jobs are not represented, so a null query selects the first Job
 *     containing the caller rather than an immediate parent in a nesting tree.
 */

#include "subsystems/win32/job_syscall.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "util/string.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kJobInfoBasicAccounting = 1;
constexpr u64 kJobInfoBasicProcessIdList = 3;
constexpr u64 kJobInfoBasicAndIoAccounting = 8;
constexpr u64 kJobProcessIdListHeaderSize = 8;
constexpr u64 kJobBasicAccountingSize = 48;
constexpr u64 kJobBasicAndIoAccountingSize = 96;
constexpr u64 kAdapterGenerationMaximum = ((~0ULL) >> 1) >> kJobHandleGenerationShift;

static_assert(kJobPoolCap == core::kJobPoolCapacity);
static_assert(core::kJobGenerationMaximum == kAdapterGenerationMaximum);
static_assert(kJobHandleBase + kJobPoolCap <= kJobHandleTagMask + 1);

u64 MakeJobHandle(core::JobKey key)
{
    return (key.generation << kJobHandleGenerationShift) | (kJobHandleBase + key.slot);
}

bool DecodeJobHandle(u64 handle, core::JobKey* out_key)
{
    if (out_key == nullptr || !IsJobHandle(handle))
        return false;
    out_key->slot = static_cast<u32>((handle & kJobHandleTagMask) - kJobHandleBase);
    out_key->generation = handle >> kJobHandleGenerationShift;
    return true;
}

void PutLe32(u8* dst, u64 offset, u32 value)
{
    for (u32 index = 0; index < sizeof(value); ++index)
        dst[offset + index] = static_cast<u8>(value >> (index * 8));
}

void PutLe64(u8* dst, u64 offset, u64 value)
{
    for (u32 index = 0; index < sizeof(value); ++index)
        dst[offset + index] = static_cast<u8>(value >> (index * 8));
}

u32 GetLe32(const u8* src, u64 offset)
{
    u32 value = 0;
    for (u32 index = 0; index < sizeof(value); ++index)
        value |= static_cast<u32>(src[offset + index]) << (index * 8);
    return value;
}

u64 GetLe64(const u8* src, u64 offset)
{
    u64 value = 0;
    for (u32 index = 0; index < sizeof(value); ++index)
        value |= static_cast<u64>(src[offset + index]) << (index * 8);
    return value;
}

u64 EncodeProcessIdList(const core::JobSnapshot& snapshot, u8* output)
{
    PutLe32(output, 0, snapshot.member_count);
    PutLe32(output, 4, snapshot.member_count);
    for (u32 index = 0; index < snapshot.member_count; ++index)
    {
        PutLe64(output, kJobProcessIdListHeaderSize + static_cast<u64>(index) * sizeof(u64),
                snapshot.member_pids[index]);
    }
    return kJobProcessIdListHeaderSize + static_cast<u64>(snapshot.member_count) * sizeof(u64);
}

void EncodeAccounting(const core::JobSnapshot& snapshot, u8* output)
{
    PutLe32(output, 36, snapshot.total_processes);
    PutLe32(output, 40, snapshot.member_count);
    PutLe32(output, 44, snapshot.total_terminated_processes);
}

bool SnapshotForQuery(u64 job_handle, const core::Process* caller, core::JobSnapshot* snapshot)
{
    if (caller == nullptr)
        return false;
    if (job_handle == 0)
        return core::JobSnapshotContaining(caller, snapshot);

    core::JobKey key{};
    return DecodeJobHandle(job_handle, &key) && core::JobSnapshotOwned(key, static_cast<u64>(caller->pid), snapshot);
}

void JobTestExpect(bool condition, const char* message)
{
    if (!condition)
        core::Panic("subsystems/win32/job", message);
}

} // namespace

i64 SysJobCreate()
{
    using ::duetos::core::kCapSpawnThread;
    core::Process* process = core::CurrentProcess();
    if (process == nullptr)
        return -1;
    if (!core::ProcessHasCap(process, kCapSpawnThread))
    {
        core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }

    core::JobKey key{};
    if (!core::JobCreate(static_cast<u64>(process->pid), &key))
        return -1;
    const u64 handle = MakeJobHandle(key);
    arch::SerialWrite("[win32/job] create handle=");
    arch::SerialWriteHex(handle);
    arch::SerialWrite("\n");
    return static_cast<i64>(handle);
}

i64 SysJobAssign(u64 job_handle, u64 process_handle)
{
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;

    // Acquire the target reference before entering the core.  Assigned adopts
    // it; every other result leaves it here to be released after the core lock.
    core::Process* target = nullptr;
    if (process_handle == static_cast<u64>(-1))
    {
        target = caller;
        core::ProcessRetain(target);
    }
    else
    {
        target = core::ProcessLookupWin32ProcessHandleRetained(caller, process_handle);
    }
    if (target == nullptr)
        return -1;

    core::JobKey key{};
    core::JobAssignResult result = core::JobAssignResult::InvalidJob;
    if (DecodeJobHandle(job_handle, &key))
        result = core::JobAssignRetained(key, static_cast<u64>(caller->pid), target);

    if (result == core::JobAssignResult::Assigned)
        target = nullptr; // the membership owns this reference now
    core::ProcessRelease(target);

    if (result == core::JobAssignResult::Assigned || result == core::JobAssignResult::AlreadyMember)
        return 0;
    if (result == core::JobAssignResult::MembershipConflict || result == core::JobAssignResult::Capacity)
        return -1;
    if (result == core::JobAssignResult::InvalidJob || result == core::JobAssignResult::Terminated)
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobAssign job_handle bad/foreign", job_handle);
    return -1;
}

i64 SysJobIsProcessIn(u64 job_handle, u64 process_handle, u64 user_out)
{
    if (user_out == 0)
        return -1;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;

    core::Process* target = nullptr;
    if (process_handle == static_cast<u64>(-1) || process_handle == 0)
    {
        target = caller;
        core::ProcessRetain(target);
    }
    else
    {
        target = core::ProcessLookupWin32ProcessHandleRetained(caller, process_handle);
    }
    if (target == nullptr)
        return -1;

    bool in_job = false;
    bool valid_job = true;
    if (job_handle == 0)
    {
        in_job = core::JobContainsAny(target);
    }
    else
    {
        core::JobKey key{};
        valid_job = DecodeJobHandle(job_handle, &key) &&
                    core::JobContainsOwned(key, static_cast<u64>(caller->pid), target, &in_job);
    }
    core::ProcessRelease(target);

    if (!valid_job)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobIsProcessIn job_handle bad/foreign", job_handle);
        return -1;
    }

    const u32 output = in_job ? 1u : 0u;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_out), &output, sizeof(output)))
        return -1;
    return 0;
}

i64 SysJobTerminate(u64 job_handle, u64 exit_code)
{
    (void)exit_code;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;

    core::JobKey key{};
    if (!DecodeJobHandle(job_handle, &key))
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle bad/foreign", job_handle);
        return -1;
    }

    core::JobTerminationIntent intent{};
    const core::JobTerminateResult result = core::JobBeginTermination(key, static_cast<u64>(caller->pid), &intent);
    if (result == core::JobTerminateResult::InvalidJob)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle bad/foreign", job_handle);
        return -1;
    }
    if (result == core::JobTerminateResult::AlreadyTerminated)
        return 0;

    // The core operation pin, not an extra retain under the pool lock, keeps
    // these borrowed pointers live through the unlocked scheduler calls.
    for (u32 index = 0; index < intent.member_count; ++index)
        sched::SchedKillByProcess(intent.members[index]);
    if (!core::JobFinishTermination(&intent))
        core::Panic("subsystems/win32/job", "termination intent completion failed");
    return 0;
}

i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len)
{
    core::Process* caller = core::CurrentProcess();

    // JOBOBJECTINFOCLASS values are part of the Win32 ABI:
    //   1 = JobObjectBasicAccountingInformation
    //   3 = JobObjectBasicProcessIdList
    //   8 = JobObjectBasicAndIoAccountingInformation
    if (info_class == kJobInfoBasicProcessIdList)
    {
        core::JobSnapshot snapshot{};
        if (!SnapshotForQuery(job_handle, caller, &snapshot))
        {
            KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle bad/foreign", job_handle);
            return -1;
        }

        // JOBOBJECT_BASIC_PROCESS_ID_LIST is an 8-byte header followed by
        // ULONG_PTR process IDs.  DuetOS' Win64 ABI uses 8-byte pointers.
        u8 stage[kJobProcessIdListHeaderSize + core::kJobMemberCapacity * sizeof(u64)]{};
        const u64 needed = EncodeProcessIdList(snapshot, stage);
        if (buf_len < needed)
            return -1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, needed))
            return -1;
        return static_cast<i64>(needed);
    }

    if (info_class == kJobInfoBasicAccounting || info_class == kJobInfoBasicAndIoAccounting)
    {
        core::JobSnapshot snapshot{};
        if (!SnapshotForQuery(job_handle, caller, &snapshot))
        {
            KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle bad/foreign", job_handle);
            return -1;
        }

        // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION is 48 bytes.  The first 36
        // bytes remain zero until timing/page-fault accounting exists; the
        // process counters occupy offsets 36, 40, and 44.  The BasicAndIo
        // form appends 48 zeroed IO_COUNTERS bytes.
        u8 stage[kJobBasicAndIoAccountingSize]{};
        EncodeAccounting(snapshot, stage);
        const u64 needed =
            info_class == kJobInfoBasicAndIoAccounting ? kJobBasicAndIoAccountingSize : kJobBasicAccountingSize;
        if (buf_len < needed)
            return -1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, needed))
            return -1;
        return static_cast<i64>(needed);
    }
    return -1;
}

i64 SysJobClose(u64 job_handle)
{
    core::Process* caller = core::CurrentProcess();
    core::JobKey key{};
    if (caller == nullptr || !DecodeJobHandle(job_handle, &key) || !core::JobClose(key, static_cast<u64>(caller->pid)))
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobClose job_handle bad/foreign", job_handle);
        return -1;
    }
    return 0;
}

void JobDrainOwnedByProcess(core::Process* owner)
{
    if (owner != nullptr)
        core::JobDrainOwned(static_cast<u64>(owner->pid));
}

void JobOwnerExitSelfTest()
{
    auto* owner = static_cast<core::Process*>(mm::KMalloc(sizeof(core::Process)));
    if (owner == nullptr)
        core::Panic("subsystems/win32/job", "owner-exit self-test fixture allocation failed");
    memset(owner, 0, sizeof(core::Process));
    owner->pid = 0x4A4F4254; // "JOBT", outside the monotonic live PID source
    owner->refcount = 2;     // one synthetic task ref + one transferable member ref

    core::JobKey key{};
    JobTestExpect(core::JobCreate(static_cast<u64>(owner->pid), &key), "owner-exit self-test could not allocate Job");
    JobTestExpect(core::JobAssignRetained(key, static_cast<u64>(owner->pid), owner) == core::JobAssignResult::Assigned,
                  "owner-exit self-test could not assign owner");

    JobDrainOwnedByProcess(owner);
    JobDrainOwnedByProcess(owner);
    JobTestExpect(__atomic_load_n(&owner->refcount, __ATOMIC_ACQUIRE) == 1, "owner-exit self-test reference imbalance");

    core::JobLifecycleSnapshot lifecycle{};
    JobTestExpect(core::JobInspectLifecycle(key, &lifecycle) && lifecycle.state == core::JobState::Retired &&
                      lifecycle.references == 0 && lifecycle.member_count == 0,
                  "owner-exit self-test Job did not retire");

    mm::KFree(owner);
    arch::SerialWrite("[win32/job] owner-exit self-test PASS\n");
}

void JobHandleLifetimeSelfTest()
{
    auto* owner = static_cast<core::Process*>(mm::KMalloc(sizeof(core::Process)));
    auto* other = static_cast<core::Process*>(mm::KMalloc(sizeof(core::Process)));
    JobTestExpect(owner != nullptr && other != nullptr, "handle-lifetime self-test fixture allocation failed");
    memset(owner, 0, sizeof(core::Process));
    memset(other, 0, sizeof(core::Process));
    owner->pid = 0x4A4F4248; // "JOBH", outside the monotonic live PID source
    other->pid = 0x4A4F4246; // "JOBF"
    owner->refcount = 1;
    other->refcount = 2; // one fixture ref + one transferable Job-member ref

    JobTestExpect(!IsJobHandle(kJobHandleBase), "slot-only legacy Job handle accepted");
    JobTestExpect(!IsJobHandle((1ULL << 63) | kJobHandleBase), "negative Job handle accepted");

    core::JobKey first_key{};
    JobTestExpect(core::JobCreate(static_cast<u64>(owner->pid), &first_key),
                  "handle-lifetime self-test could not allocate first Job");
    const u64 first_handle = MakeJobHandle(first_key);
    core::JobKey decoded{};
    JobTestExpect(IsJobHandle(first_handle) && DecodeJobHandle(first_handle, &decoded) &&
                      decoded.slot == first_key.slot && decoded.generation == first_key.generation,
                  "allocated Job handle did not round-trip through adapter");

    core::JobLifecycleSnapshot lifecycle{};
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Live &&
                      lifecycle.references == 1 && lifecycle.operation_pins == 0,
                  "fresh Job did not publish in Live state with one reference");

    core::JobSnapshot foreign_snapshot{};
    JobTestExpect(!core::JobSnapshotOwned(first_key, static_cast<u64>(other->pid), &foreign_snapshot),
                  "foreign Process resolved Job key");
    JobTestExpect(core::JobAssignRetained(first_key, static_cast<u64>(owner->pid), other) ==
                      core::JobAssignResult::Assigned,
                  "fresh Job did not adopt retained member");
    core::ProcessRetain(other);
    JobTestExpect(core::JobAssignRetained(first_key, static_cast<u64>(owner->pid), other) ==
                      core::JobAssignResult::AlreadyMember,
                  "same-Job repeat assignment was not idempotent");
    core::ProcessRelease(other); // repeat assignment did not adopt this reference

    core::JobKey conflict_key{};
    JobTestExpect(core::JobCreate(static_cast<u64>(owner->pid), &conflict_key),
                  "cross-Job conflict fixture could not allocate Job");
    core::ProcessRetain(other);
    JobTestExpect(core::JobAssignRetained(conflict_key, static_cast<u64>(owner->pid), other) ==
                      core::JobAssignResult::MembershipConflict,
                  "Live cross-Job membership was accepted");
    core::ProcessRelease(other); // conflict leaves ownership with the caller

    core::JobSnapshot snapshot{};
    core::JobSnapshot containing{};
    JobTestExpect(core::JobSnapshotOwned(first_key, static_cast<u64>(owner->pid), &snapshot),
                  "owner could not snapshot fresh Job");
    JobTestExpect(core::JobSnapshotContaining(other, &containing) && containing.member_count == 1,
                  "null-handle query did not resolve containing Job");

    u8 process_list[kJobProcessIdListHeaderSize + core::kJobMemberCapacity * sizeof(u64)]{};
    u8 accounting[kJobBasicAndIoAccountingSize]{};
    EncodeProcessIdList(snapshot, process_list);
    EncodeAccounting(snapshot, accounting);
    JobTestExpect(GetLe32(process_list, 0) == 1 && GetLe32(process_list, 4) == 1,
                  "process-id-list header ABI mismatch");
    JobTestExpect(GetLe64(process_list, kJobProcessIdListHeaderSize) == static_cast<u64>(other->pid),
                  "process-id-list PID ABI mismatch");
    JobTestExpect(GetLe32(accounting, 36) == 1 && GetLe32(accounting, 40) == 1 && GetLe32(accounting, 44) == 0,
                  "basic-accounting counter ABI mismatch");

    core::JobTerminationIntent first_intent{};
    JobTestExpect(core::JobBeginTermination(first_key, static_cast<u64>(owner->pid), &first_intent) ==
                      core::JobTerminateResult::Begun,
                  "Live Job did not begin termination");
    JobTestExpect(first_intent.member_count == 1 && first_intent.members[0] == other,
                  "termination intent did not borrow exact member");
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Terminating &&
                      lifecycle.operation_pins == 1,
                  "termination operation pin was not visible");

    JobTestExpect(core::JobSnapshotOwned(first_key, static_cast<u64>(owner->pid), &snapshot) &&
                      snapshot.total_terminated_processes == 1,
                  "termination accounting did not snapshot exact row");
    JobTestExpect(core::JobClose(first_key, static_cast<u64>(owner->pid)),
                  "close during termination did not consume reference");
    JobTestExpect(!core::JobClose(first_key, static_cast<u64>(owner->pid)), "stale Job double-close succeeded");
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Terminating &&
                      lifecycle.references == 0 && lifecycle.operation_pins == 1 && lifecycle.retire_pending,
                  "last-close did not defer retirement behind termination pin");
    JobTestExpect(__atomic_load_n(&other->refcount, __ATOMIC_ACQUIRE) == 2,
                  "close released member while termination intent was active");

    core::ProcessRetain(other);
    JobTestExpect(core::JobAssignRetained(conflict_key, static_cast<u64>(owner->pid), other) ==
                      core::JobAssignResult::MembershipConflict,
                  "zero-ref Terminating membership was ignored by cross-Job admission");
    core::ProcessRelease(other); // pinned-row conflict did not adopt this reference
    JobTestExpect(core::JobClose(conflict_key, static_cast<u64>(owner->pid)),
                  "cross-Job conflict fixture close failed");

    JobTestExpect(core::JobFinishTermination(&first_intent), "termination intent did not complete");
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Retired &&
                      lifecycle.references == 0 && lifecycle.operation_pins == 0,
                  "pinned last-close did not retire after termination completion");
    JobTestExpect(__atomic_load_n(&other->refcount, __ATOMIC_ACQUIRE) == 1,
                  "termination completion did not balance member reference");

    core::JobKey second_key{};
    JobTestExpect(core::JobCreate(static_cast<u64>(owner->pid), &second_key),
                  "handle-lifetime self-test could not reallocate Job");
    const u64 second_handle = MakeJobHandle(second_key);
    JobTestExpect((second_handle & kJobHandleTagMask) == (first_handle & kJobHandleTagMask),
                  "Job reallocation did not exercise same pool row");
    JobTestExpect(second_handle != first_handle && second_key.generation == first_key.generation + 1,
                  "Job generation did not advance exactly once");
    JobTestExpect(!core::JobSnapshotOwned(first_key, static_cast<u64>(owner->pid), &snapshot),
                  "stale Job key aliased reallocated row");
    JobTestExpect(core::JobSnapshotOwned(second_key, static_cast<u64>(owner->pid), &snapshot),
                  "replacement Job key did not resolve exact row");

    core::JobTerminationIntent second_intent{};
    JobTestExpect(core::JobBeginTermination(second_key, static_cast<u64>(owner->pid), &second_intent) ==
                          core::JobTerminateResult::Begun &&
                      core::JobFinishTermination(&second_intent),
                  "replacement Job termination transition failed");
    JobTestExpect(core::JobInspectLifecycle(second_key, &lifecycle) && lifecycle.state == core::JobState::Tombstone &&
                      lifecycle.references == 1,
                  "terminated Job did not remain an open tombstone");
    JobTestExpect(core::JobBeginTermination(second_key, static_cast<u64>(owner->pid), &second_intent) ==
                      core::JobTerminateResult::AlreadyTerminated,
                  "tombstoned Job did not make repeat termination idempotent");
    JobTestExpect(core::JobClose(second_key, static_cast<u64>(owner->pid)), "replacement Job close failed");
    JobTestExpect(core::JobInspectLifecycle(second_key, &lifecycle) && lifecycle.state == core::JobState::Retired,
                  "replacement Job did not retire after last close");

    mm::KFree(other);
    mm::KFree(owner);
    arch::SerialWrite("[win32/job] handle-lifetime self-test PASS\n");
}

} // namespace duetos::subsystems::win32
