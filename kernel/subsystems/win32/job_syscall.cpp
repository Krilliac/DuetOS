/*
 * Win32 Job-object adapter.
 *
 * proc/job.{h,cpp} is the protocol-neutral owner of Job state, generations,
 * references, membership, accounting, termination pins, and owner-exit drain.
 * This file owns the public 0xC00 handle band, creator capability/ownership
 * policy, Win32 information-class byte layouts, user copies, and scheduler
 * kill requests.
 *
 * A termination intent carries exact ProcessKeys, never borrowed Process
 * pointers. The scheduler holds its registry lock across intent creation,
 * one all-Task dispatch pass, and ticket completion. The operation pin
 * prevents Job-row generation reuse while close or owner drain races it.
 *
 * Known gaps retained by this adapter/service split:
 *   - information classes other than BasicAccountingInformation,
 *     BasicProcessIdList, and BasicAndIoAccountingInformation are rejected;
 *   - configured CPU/working-set/resource limits are not enforced;
 *   - nested Jobs are not represented, so a null query selects the first Job
 *     containing the caller rather than an immediate parent in a nesting tree.
 */

#include "subsystems/win32/job_syscall.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

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

u64 EncodeProcessIdList(const core::JobSnapshot& snapshot, u32 capacity, u8* output)
{
    PutLe32(output, 0, snapshot.member_count);
    const u32 returned = snapshot.process_id_count < capacity ? snapshot.process_id_count : capacity;
    PutLe32(output, 4, returned);
    for (u32 index = 0; index < returned; ++index)
    {
        PutLe64(output, kJobProcessIdListHeaderSize + static_cast<u64>(index) * sizeof(u64),
                snapshot.member_pids[index]);
    }
    return kJobProcessIdListHeaderSize + static_cast<u64>(returned) * sizeof(u64);
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
    const core::ProcessKey caller_key = core::ProcessKeySnapshot(caller);
    if (job_handle == 0)
        return core::JobSnapshotContaining(caller_key, snapshot);

    core::JobKey key{};
    return DecodeJobHandle(job_handle, &key) && core::JobSnapshotOwned(key, caller_key, snapshot);
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
    if (!core::JobCreate(core::ProcessKeySnapshot(process), &key))
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

    // Keep the lookup reference as an audit pin. The scheduler holds its
    // lifetime lock across the live-Task check and pointer-free Job mutation,
    // so a retained Exited header can never consume a member slot.
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
    const core::ProcessKey caller_key = core::ProcessKeySnapshot(caller);
    if (DecodeJobHandle(job_handle, &key))
        result = sched::SchedAssignProcessToJob(key, caller_key, target);
    core::ProcessRelease(target); // independent lookup/audit reference

    if (result == core::JobAssignResult::Assigned || result == core::JobAssignResult::AlreadyMember)
        return 0;
    if (result == core::JobAssignResult::MembershipConflict || result == core::JobAssignResult::Capacity ||
        result == core::JobAssignResult::NotLive)
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
    const core::ProcessKey caller_key = core::ProcessKeySnapshot(caller);
    const core::ProcessKey target_key = core::ProcessKeySnapshot(target);
    if (job_handle == 0)
    {
        in_job = core::JobContainsAny(target_key);
    }
    else
    {
        core::JobKey key{};
        valid_job = DecodeJobHandle(job_handle, &key) && core::JobContainsOwned(key, caller_key, target_key, &in_job);
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
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;

    core::JobKey key{};
    if (!DecodeJobHandle(job_handle, &key))
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle bad/foreign", job_handle);
        return -1;
    }

    const core::ProcessKey caller_key = core::ProcessKeySnapshot(caller);
    const core::JobTerminateResult result =
        sched::SchedTerminateJob(key, caller_key, static_cast<u32>(exit_code));
    if (result == core::JobTerminateResult::InvalidJob)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle bad/foreign", job_handle);
        return -1;
    }
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
        // ULONG_PTR process IDs. DuetOS' Win64 ABI uses 8-byte pointers. A
        // header-only or partially sized buffer succeeds: NumberOfAssigned-
        // Processes remains the full total, while NumberOfProcessIdsInList
        // reports exactly how many complete IDs fit.
        if (user_buf == 0 || buf_len < kJobProcessIdListHeaderSize)
            return -1;
        u8 stage[kJobProcessIdListHeaderSize + core::kJobMemberCapacity * sizeof(u64)]{};
        u64 capacity = (buf_len - kJobProcessIdListHeaderSize) / sizeof(u64);
        if (capacity > core::kJobMemberCapacity)
            capacity = core::kJobMemberCapacity;
        const u64 returned_bytes = EncodeProcessIdList(snapshot, static_cast<u32>(capacity), stage);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, returned_bytes))
            return -1;
        return static_cast<i64>(returned_bytes);
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
    if (caller == nullptr || !DecodeJobHandle(job_handle, &key) ||
        !core::JobClose(key, core::ProcessKeySnapshot(caller)))
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobClose job_handle bad/foreign", job_handle);
        return -1;
    }
    return 0;
}

void JobDrainOwnedByProcess(core::Process* owner)
{
    if (owner != nullptr)
        core::JobDrainOwned(core::ProcessKeySnapshot(owner));
}

void JobOwnerExitSelfTest()
{
    core::Process owner{};
    owner.pid = 0x4A4F4254;              // "JOBT", outside the live PID source
    owner.process_identity = 0x4A4F4255; // distinct exact incarnation
    owner.refcount = 1;
    const core::ProcessKey owner_key = core::ProcessKeySnapshot(&owner);

    core::JobKey key{};
    JobTestExpect(core::JobCreate(owner_key, &key), "owner-exit self-test could not allocate Job");
    JobTestExpect(core::JobAssign(key, owner_key, owner_key) == core::JobAssignResult::Assigned,
                  "owner-exit self-test could not assign owner");
    JobTestExpect(__atomic_load_n(&owner.refcount, __ATOMIC_ACQUIRE) == 1, "Job membership retained ProcessCore");

    JobDrainOwnedByProcess(&owner);
    JobDrainOwnedByProcess(&owner);
    JobTestExpect(__atomic_load_n(&owner.refcount, __ATOMIC_ACQUIRE) == 1,
                  "owner drain changed ProcessCore reference count");

    core::JobOnProcessExit(owner_key);
    core::JobOnProcessExit(owner_key);

    core::JobLifecycleSnapshot lifecycle{};
    JobTestExpect(core::JobInspectLifecycle(key, &lifecycle) && lifecycle.state == core::JobState::Retired &&
                      lifecycle.references == 0 && lifecycle.member_count == 0,
                  "owner-exit self-test Job did not retire");

    // An exit notification for an identity that was never a member is inert;
    // a later scheduler-linearized assignment owns one exact removal.
    core::JobOnProcessExit(owner_key);
    core::JobKey exit_first_key{};
    JobTestExpect(core::JobCreate(owner_key, &exit_first_key), "exit-first owner self-test could not allocate Job");
    JobTestExpect(core::JobAssign(exit_first_key, owner_key, owner_key) == core::JobAssignResult::Assigned,
                  "exit-first owner self-test could not assign owner");
    core::JobOnProcessExit(owner_key);
    core::JobOnProcessExit(owner_key);

    core::JobSnapshot exit_first_snapshot{};
    JobTestExpect(core::JobSnapshotOwned(exit_first_key, owner_key, &exit_first_snapshot) &&
                      exit_first_snapshot.member_count == 0 && exit_first_snapshot.total_processes == 1 &&
                      exit_first_snapshot.total_terminated_processes == 0,
                  "exit-first owner accounting was not exact");
    JobDrainOwnedByProcess(&owner);
    JobTestExpect(core::JobInspectLifecycle(exit_first_key, &lifecycle) && lifecycle.state == core::JobState::Retired &&
                      lifecycle.references == 0 && lifecycle.member_count == 0,
                  "exit-first owner Job did not retire after drain");

    arch::SerialWrite("[win32/job] owner-exit self-test PASS\n");
}

void JobHandleLifetimeSelfTest()
{
    constexpr core::ProcessKey owner_key{0x4A4F4248, 0x4A4F4248}; // "JOBH"
    constexpr core::ProcessKey other_key{0x4A4F4246, 0x4A4F4246}; // "JOBF"

    JobTestExpect(!IsJobHandle(kJobHandleBase), "slot-only legacy Job handle accepted");
    JobTestExpect(!IsJobHandle((1ULL << 63) | kJobHandleBase), "negative Job handle accepted");
    core::JobKey invalid_key{};
    JobTestExpect(!core::JobCreate(core::kInvalidProcessKey, &invalid_key), "invalid owner created Job authority");

    core::JobKey first_key{};
    JobTestExpect(core::JobCreate(owner_key, &first_key), "handle-lifetime self-test could not allocate first Job");
    const u64 first_handle = MakeJobHandle(first_key);
    core::JobKey decoded{};
    JobTestExpect(IsJobHandle(first_handle) && DecodeJobHandle(first_handle, &decoded) &&
                      decoded.slot == first_key.slot && decoded.generation == first_key.generation,
                  "allocated Job handle did not round-trip through adapter");

    core::JobLifecycleSnapshot lifecycle{};
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Live &&
                      lifecycle.owner == owner_key && lifecycle.references == 1 && lifecycle.operation_pins == 0,
                  "fresh Job did not publish in Live state with one reference");

    core::JobSnapshot foreign_snapshot{};
    JobTestExpect(!core::JobSnapshotOwned(first_key, other_key, &foreign_snapshot), "foreign Process resolved Job key");
    JobTestExpect(core::JobAssign(first_key, owner_key, other_key) == core::JobAssignResult::Assigned,
                  "fresh Job did not publish exact member");
    JobTestExpect(core::JobAssign(first_key, owner_key, other_key) == core::JobAssignResult::AlreadyMember,
                  "same-Job repeat assignment was not idempotent");

    core::JobKey conflict_key{};
    JobTestExpect(core::JobCreate(owner_key, &conflict_key), "cross-Job conflict fixture could not allocate Job");
    JobTestExpect(core::JobAssign(conflict_key, owner_key, other_key) == core::JobAssignResult::MembershipConflict,
                  "Live cross-Job membership was accepted");

    core::JobSnapshot snapshot{};
    core::JobSnapshot containing{};
    JobTestExpect(core::JobSnapshotOwned(first_key, owner_key, &snapshot), "owner could not snapshot fresh Job");
    JobTestExpect(core::JobSnapshotContaining(other_key, &containing) && containing.member_count == 1,
                  "null-handle query did not resolve containing Job");

    u8 process_list[kJobProcessIdListHeaderSize + core::kJobMemberCapacity * sizeof(u64)]{};
    u8 accounting[kJobBasicAndIoAccountingSize]{};
    EncodeProcessIdList(snapshot, core::kJobMemberCapacity, process_list);
    EncodeAccounting(snapshot, accounting);
    JobTestExpect(GetLe32(process_list, 0) == 1 && GetLe32(process_list, 4) == 1,
                  "process-id-list header ABI mismatch");
    JobTestExpect(GetLe64(process_list, kJobProcessIdListHeaderSize) == other_key.pid,
                  "process-id-list PID ABI mismatch");
    JobTestExpect(GetLe32(accounting, 36) == 1 && GetLe32(accounting, 40) == 1 && GetLe32(accounting, 44) == 0,
                  "basic-accounting counter ABI mismatch");

    core::JobTerminationIntent first_intent{};
    JobTestExpect(core::JobBeginTermination(first_key, owner_key, 0x12345678u, &first_intent) ==
                      core::JobTerminateResult::Begun,
                  "Live Job did not begin termination");
    JobTestExpect(first_intent.member_count == 1 && first_intent.members[0] == other_key &&
                      first_intent.exit_code == 0x12345678u,
                  "termination intent did not copy exact member key");
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Terminating &&
                      lifecycle.operation_pins == 1,
                  "termination operation pin was not visible");

    JobTestExpect(core::JobSnapshotOwned(first_key, owner_key, &snapshot) && snapshot.total_terminated_processes == 0,
                  "explicit termination incorrectly changed limit-termination accounting");
    JobTestExpect(core::JobClose(first_key, owner_key), "close during termination did not consume reference");
    JobTestExpect(!core::JobClose(first_key, owner_key), "stale Job double-close succeeded");
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Terminating &&
                      lifecycle.references == 0 && lifecycle.operation_pins == 1 && lifecycle.retire_pending,
                  "last-close did not defer retirement behind termination pin");
    containing = {};
    JobTestExpect(core::JobContainsAny(other_key),
                  "zero-ref Terminating Job disappeared from null-handle membership test");
    JobTestExpect(core::JobSnapshotContaining(other_key, &containing) && containing.member_count == 1 &&
                      containing.member_pids[0] == other_key.pid,
                  "zero-ref Terminating Job disappeared from null-handle membership snapshot");

    core::JobOnProcessExit(other_key);
    core::JobOnProcessExit(other_key);
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Terminating &&
                      lifecycle.references == 0 && lifecycle.operation_pins == 1 && lifecycle.member_count == 0 &&
                      lifecycle.retire_pending,
                  "exit notification did not remove pinned logical membership exactly once");
    JobTestExpect(!core::JobContainsAny(other_key),
                  "exited member remained visible through zero-ref Terminating membership test");
    containing = {};
    JobTestExpect(!core::JobSnapshotContaining(other_key, &containing),
                  "exited member remained visible through zero-ref Terminating membership snapshot");

    JobTestExpect(core::JobAssign(conflict_key, owner_key, other_key) == core::JobAssignResult::Assigned,
                  "exited member slot was not reusable by another Job");
    core::JobOnProcessExit(other_key);
    JobTestExpect(core::JobClose(conflict_key, owner_key), "cross-Job conflict fixture close failed");

    JobTestExpect(core::JobFinishTermination(&first_intent), "termination intent did not complete");
    JobTestExpect(core::JobInspectLifecycle(first_key, &lifecycle) && lifecycle.state == core::JobState::Retired &&
                      lifecycle.references == 0 && lifecycle.operation_pins == 0,
                  "pinned last-close did not retire after termination completion");

    core::JobKey second_key{};
    JobTestExpect(core::JobCreate(owner_key, &second_key), "handle-lifetime self-test could not reallocate Job");
    const u64 second_handle = MakeJobHandle(second_key);
    JobTestExpect((second_handle & kJobHandleTagMask) == (first_handle & kJobHandleTagMask),
                  "Job reallocation did not exercise same pool row");
    JobTestExpect(second_handle != first_handle && second_key.generation == first_key.generation + 1,
                  "Job generation did not advance exactly once");
    JobTestExpect(!core::JobSnapshotOwned(first_key, owner_key, &snapshot), "stale Job key aliased reallocated row");
    JobTestExpect(core::JobSnapshotOwned(second_key, owner_key, &snapshot),
                  "replacement Job key did not resolve exact row");

    JobTestExpect(core::JobAssign(second_key, owner_key, other_key) == core::JobAssignResult::Assigned,
                  "replacement Job did not publish exact member");

    core::JobTerminationIntent second_intent{};
    JobTestExpect(core::JobBeginTermination(second_key, owner_key, 0x87654321u, &second_intent) ==
                      core::JobTerminateResult::Begun &&
                      second_intent.member_count == 1 && second_intent.members[0] == other_key &&
                      core::JobFinishTermination(&second_intent),
                  "replacement Job termination transition failed");
    JobTestExpect(core::JobInspectLifecycle(second_key, &lifecycle) &&
                      lifecycle.state == core::JobState::Terminating &&
                      lifecycle.references == 1,
                  "terminated Job did not remain Terminating with a live member");
    core::JobOnProcessExit(other_key);
    core::JobOnProcessExit(other_key);
    JobTestExpect(core::JobSnapshotOwned(second_key, owner_key, &snapshot) && snapshot.member_count == 0 &&
                      snapshot.total_processes == 1 && snapshot.total_terminated_processes == 0,
                  "Tombstone exit accounting was not exact");
    JobTestExpect(!core::JobContainsAny(other_key), "Tombstone kept exited member logically visible");
    JobTestExpect(core::JobBeginTermination(second_key, owner_key, 0, &second_intent) ==
                      core::JobTerminateResult::AlreadyTerminated,
                  "tombstoned Job did not make repeat termination idempotent");
    JobTestExpect(core::JobClose(second_key, owner_key), "replacement Job close failed");
    JobTestExpect(core::JobInspectLifecycle(second_key, &lifecycle) && lifecycle.state == core::JobState::Retired,
                  "replacement Job did not retire after last close");

    arch::SerialWrite("[win32/job] handle-lifetime self-test PASS\n");
}

} // namespace duetos::subsystems::win32
