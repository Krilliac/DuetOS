#include "custom.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/hpet.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/timer.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"
#include "../../mm/kheap.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"

namespace duetos::arch
{
u64 TimerTicks();
} // namespace duetos::arch

namespace duetos::subsystems::win32::custom
{

namespace
{

// Global structures: input replay ring + wait graph. Both are
// kernel-wide because the WM is a kernel singleton and the wait
// graph crosses processes (a process A holding a mutex that
// process B's threads are waiting on is a possible cycle).
//
// All accesses guarded by arch::Cli/Sti — every consumer is a
// syscall handler running in a task context.
InputReplayEntry g_input_replay[kInputReplayDepth];
u32 g_input_replay_head;
u32 g_input_replay_count;

WaitEdge g_wait_graph[kWaitGraphCap];

// Kernel-wide default policy mask applied to every Win32 PE at
// load. Initialised to the auto-on tier (observability features
// only — see custom.h `kPolicyAutoOnDefault`). Mutable at runtime
// via SYS_WIN32_CUSTOM op=SetSystemDefault.
u64 g_system_default_policy = kPolicyAutoOnDefault;

u64 NowNs()
{
    const u64 counter = arch::HpetReadCounter();
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    return (counter * period_fs) / 1'000'000ULL;
}

void ZeroBytes(void* dst, u64 n)
{
    auto* p = static_cast<u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        p[i] = 0;
}

const char* PolicyName(u64 bit)
{
    switch (bit)
    {
    case kPolicyFlightRecorder:
        return "flight";
    case kPolicyHandleProvenance:
        return "handles";
    case kPolicyErrorProvenance:
        return "errprov";
    case kPolicyQuarantineFree:
        return "quar";
    case kPolicyDeadlockDetect:
        return "ddet";
    case kPolicyContentionProfile:
        return "cont";
    case kPolicyAsyncPaint:
        return "async";
    case kPolicyPixelIsolation:
        return "pixiso";
    case kPolicyInputReplay:
        return "replay";
    case kPolicyStrictRwx:
        return "rwx";
    case kPolicyStrictHandleInherit:
        return "handle-inherit";
    default:
        return "?";
    }
}

bool PolicyOn(const ProcessCustomState* s, u64 bit)
{
    return s != nullptr && (s->policy & bit) != 0;
}

// Find the wait-graph slot for a given waiter task id, or
// kWaitGraphCap if none. Caller must hold IRQs off.
u32 FindWaitEdge(u64 waiter_tid)
{
    for (u32 i = 0; i < kWaitGraphCap; ++i)
    {
        if (g_wait_graph[i].in_use && g_wait_graph[i].waiter_tid == waiter_tid)
            return i;
    }
    return kWaitGraphCap;
}

// Reserve a free wait-graph slot (returns kWaitGraphCap if full).
// Caller must hold IRQs off.
u32 AcquireWaitEdge()
{
    for (u32 i = 0; i < kWaitGraphCap; ++i)
    {
        if (!g_wait_graph[i].in_use)
            return i;
    }
    return kWaitGraphCap;
}

// Walk the wait-for graph starting from `start_tid`, following
// edges from waiter -> holder. Returns true iff we revisit a tid
// that was already on the path (= a cycle). Bounded to
// kWaitGraphCap steps so we always terminate.
bool DetectCycle(u64 start_tid)
{
    u64 visited[kWaitGraphCap];
    u32 visited_n = 0;
    u64 cur = start_tid;
    for (u32 step = 0; step < kWaitGraphCap; ++step)
    {
        for (u32 j = 0; j < visited_n; ++j)
        {
            if (visited[j] == cur)
                return true;
        }
        visited[visited_n++] = cur;
        const u32 idx = FindWaitEdge(cur);
        if (idx == kWaitGraphCap)
            return false;
        const u64 nxt = g_wait_graph[idx].holder_tid;
        if (nxt == 0)
            return false;
        cur = nxt;
    }
    return false;
}

void LogCycle(u64 start_tid)
{
    arch::SerialWrite("[w32-custom] DEADLOCK detected from tid=");
    arch::SerialWriteHex(start_tid);
    arch::SerialWrite(" graph:\n");
    u64 cur = start_tid;
    for (u32 step = 0; step < kWaitGraphCap; ++step)
    {
        const u32 idx = FindWaitEdge(cur);
        if (idx == kWaitGraphCap)
            break;
        arch::SerialWrite("    tid=");
        arch::SerialWriteHex(g_wait_graph[idx].waiter_tid);
        arch::SerialWrite(" pid=");
        arch::SerialWriteHex(g_wait_graph[idx].waiter_pid);
        arch::SerialWrite(" -> waits handle=");
        arch::SerialWriteHex(g_wait_graph[idx].handle);
        arch::SerialWrite(" held by tid=");
        arch::SerialWriteHex(g_wait_graph[idx].holder_tid);
        arch::SerialWrite(" pid=");
        arch::SerialWriteHex(g_wait_graph[idx].holder_pid);
        arch::SerialWrite("\n");
        cur = g_wait_graph[idx].holder_tid;
        if (cur == 0 || cur == start_tid)
            break;
    }
}

} // namespace

ProcessCustomState* EnsureState(core::Process* proc)
{
    if (proc == nullptr)
        return nullptr;
    if (proc->win32_custom_state != nullptr)
        return static_cast<ProcessCustomState*>(proc->win32_custom_state);
    auto* s = static_cast<ProcessCustomState*>(mm::KMalloc(sizeof(ProcessCustomState)));
    if (s == nullptr)
        return nullptr;
    ZeroBytes(s, sizeof(ProcessCustomState));
    proc->win32_custom_state = s;
    return s;
}

ProcessCustomState* GetState(core::Process* proc)
{
    if (proc == nullptr)
        return nullptr;
    return static_cast<ProcessCustomState*>(proc->win32_custom_state);
}

void ApplySystemDefaultPolicy(core::Process* proc)
{
    if (proc == nullptr)
        return;
    const u64 mask = g_system_default_policy & kPolicyAllMask;
    if (mask == 0)
        return; // operator turned everything off — skip the alloc
    auto* s = EnsureState(proc);
    if (s == nullptr)
        return; // OOM — diagnostics are best-effort
    arch::Cli();
    s->policy |= mask;
    arch::Sti();
    arch::SerialWrite("[w32-custom] auto-on pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" policy=");
    arch::SerialWriteHex(s->policy);
    arch::SerialWrite("\n");
}

u64 GetSystemDefaultPolicy()
{
    return g_system_default_policy;
}

void SetSystemDefaultPolicy(u64 mask)
{
    g_system_default_policy = mask & kPolicyAllMask;
}

void CleanupProcess(core::Process* proc)
{
    if (proc == nullptr || proc->win32_custom_state == nullptr)
        return;
    auto* s = static_cast<ProcessCustomState*>(proc->win32_custom_state);
    proc->win32_custom_state = nullptr;
    // Also wipe any wait edges this process held — every such
    // edge points at a tid that's about to disappear.
    arch::Cli();
    for (u32 i = 0; i < kWaitGraphCap; ++i)
    {
        if (g_wait_graph[i].in_use && g_wait_graph[i].waiter_pid == proc->pid)
            g_wait_graph[i].in_use = false;
    }
    arch::Sti();
    mm::KFree(s);
}

// ---------- Hook: syscall entry (flight recorder) ----------
void OnSyscallEntry(core::Process* proc, u64 num, const arch::TrapFrame* frame)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyFlightRecorder))
        return;
    arch::Cli();
    FlightRecord& rec = s->flight[s->flight_head];
    rec.timestamp_ns = NowNs();
    rec.rip = frame->rip;
    rec.rdi = frame->rdi;
    rec.rsi = frame->rsi;
    rec.rdx = frame->rdx;
    rec.syscall_num = static_cast<u32>(num & 0xFFFFFFFFu);
    rec._pad = 0;
    s->flight_head = (s->flight_head + 1) % kFlightRecorderDepth;
    if (s->flight_count < kFlightRecorderDepth)
        s->flight_count += 1;
    arch::Sti();
}

// ---------- Hook: handle alloc / close / lookup ----------
void OnHandleAlloc(core::Process* proc, u64 handle, u32 syscall_num, u64 caller_rip)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyHandleProvenance))
        return;
    arch::Cli();
    // Search for an existing inactive entry with the same handle
    // (handle slots get reused) — reuse it and bump generation.
    for (u32 i = 0; i < s->handles_count; ++i)
    {
        if (s->handles[i].handle == handle && !s->handles[i].active)
        {
            s->handles[i].generation += 1;
            s->handles[i].active = true;
            s->handles[i].creator_rip = caller_rip;
            s->handles[i].timestamp_ns = NowNs();
            s->handles[i].syscall_num = syscall_num;
            arch::Sti();
            return;
        }
    }
    if (s->handles_count >= kHandleProvenanceCap)
    {
        // Table full — evict oldest. O(N) scan; N=64 so fine.
        u32 oldest = 0;
        u64 oldest_ts = s->handles[0].timestamp_ns;
        for (u32 i = 1; i < s->handles_count; ++i)
        {
            if (s->handles[i].timestamp_ns < oldest_ts)
            {
                oldest = i;
                oldest_ts = s->handles[i].timestamp_ns;
            }
        }
        s->handles[oldest].handle = handle;
        s->handles[oldest].creator_rip = caller_rip;
        s->handles[oldest].timestamp_ns = NowNs();
        s->handles[oldest].syscall_num = syscall_num;
        s->handles[oldest].generation = 0;
        s->handles[oldest].active = true;
        arch::Sti();
        return;
    }
    HandleProvenance& rec = s->handles[s->handles_count++];
    rec.handle = handle;
    rec.creator_rip = caller_rip;
    rec.timestamp_ns = NowNs();
    rec.syscall_num = syscall_num;
    rec.generation = 0;
    rec.active = true;
    arch::Sti();
}

void OnHandleClose(core::Process* proc, u64 handle)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyHandleProvenance))
        return;
    arch::Cli();
    for (u32 i = 0; i < s->handles_count; ++i)
    {
        if (s->handles[i].handle == handle && s->handles[i].active)
        {
            s->handles[i].active = false;
            // Generation is bumped on the next OnHandleAlloc reuse —
            // any read-after-close in the meantime sees `active=false`
            // and can be flagged as a UAF by IsHandleActive.
            arch::Sti();
            return;
        }
    }
    arch::Sti();
}

bool IsHandleActive(core::Process* proc, u64 handle)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyHandleProvenance))
        return true; // policy off — caller proceeds as normal
    arch::Cli();
    for (u32 i = 0; i < s->handles_count; ++i)
    {
        if (s->handles[i].handle == handle && s->handles[i].active)
        {
            arch::Sti();
            return true;
        }
    }
    arch::Sti();
    arch::SerialWrite("[w32-custom] use-after-close handle=");
    arch::SerialWriteHex(handle);
    arch::SerialWrite(" pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite("\n");
    return false;
}

// ---------- Hook: SetLastError provenance ----------
void OnLastErrorSet(core::Process* proc, u32 value, u64 caller_rip, u32 syscall_num)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyErrorProvenance))
        return;
    arch::Cli();
    s->error.last_value = value;
    s->error.set_rip = caller_rip;
    s->error.set_timestamp_ns = NowNs();
    s->error.set_syscall_num = syscall_num;
    arch::Sti();
}

// ---------- Hook: heap free / quarantine ----------
void OnHeapFree(core::Process* proc, u64 user_va, u64 size)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyQuarantineFree))
        return;
    arch::Cli();
    if (s->quarantine_count >= kQuarantineDepth)
    {
        // Ring is full — drop the oldest. The dropped entry's
        // backing block is NOT reclaimed here; it stays on the
        // heap free list. We just stop tracking it for UAF
        // detection, which is the intended degradation.
        const u32 dropped = s->quarantine_head;
        (void)dropped;
        s->quarantine_head = (s->quarantine_head + 1) % kQuarantineDepth;
        s->quarantine_count -= 1;
    }
    const u32 idx = (s->quarantine_head + s->quarantine_count) % kQuarantineDepth;
    s->quarantine[idx].user_va = user_va;
    s->quarantine[idx].size = size;
    s->quarantine[idx].release_tick = arch::TimerTicks() + kQuarantineTicks;
    s->quarantine_count += 1;
    arch::Sti();
}

bool IsQuarantined(core::Process* proc, u64 user_va)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyQuarantineFree))
        return false;
    arch::Cli();
    const u64 now_tick = arch::TimerTicks();
    // Drain expired entries from the head.
    while (s->quarantine_count > 0 && s->quarantine[s->quarantine_head].release_tick <= now_tick)
    {
        s->quarantine_head = (s->quarantine_head + 1) % kQuarantineDepth;
        s->quarantine_count -= 1;
    }
    bool found = false;
    for (u32 step = 0; step < s->quarantine_count; ++step)
    {
        const u32 i = (s->quarantine_head + step) % kQuarantineDepth;
        const u64 base = s->quarantine[i].user_va;
        const u64 end = base + s->quarantine[i].size;
        if (user_va >= base && user_va < end)
        {
            found = true;
            break;
        }
    }
    arch::Sti();
    return found;
}

// ---------- Hook: mutex wait / contention / deadlock ----------
bool OnMutexWaitStart(core::Process* proc, u32 mutex_slot, u64 handle, u64 holder_tid, u64 holder_pid)
{
    auto* s = GetState(proc);
    if (s == nullptr)
        return false;
    sched::Task* me = sched::CurrentTask();
    const u64 me_tid = sched::CurrentTaskId();
    (void)me;

    if ((s->policy & kPolicyContentionProfile) != 0 && mutex_slot < kContentionSlotCap)
    {
        arch::Cli();
        s->contention[mutex_slot].wait_count += 1;
        arch::Sti();
    }

    if ((s->policy & kPolicyDeadlockDetect) == 0)
        return false;

    arch::Cli();
    u32 idx = FindWaitEdge(me_tid);
    if (idx == kWaitGraphCap)
        idx = AcquireWaitEdge();
    if (idx == kWaitGraphCap)
    {
        // Wait graph full — silently degrade (no detection this
        // time around). Better than blocking the wait itself.
        arch::Sti();
        return false;
    }
    g_wait_graph[idx].in_use = true;
    g_wait_graph[idx].waiter_tid = me_tid;
    g_wait_graph[idx].waiter_pid = proc->pid;
    g_wait_graph[idx].holder_tid = holder_tid;
    g_wait_graph[idx].holder_pid = holder_pid;
    g_wait_graph[idx].handle = handle;
    const bool cycle = DetectCycle(me_tid);
    if (cycle && !s->cycle_reported)
    {
        s->cycle_reported = true;
        LogCycle(me_tid);
    }
    arch::Sti();
    return cycle;
}

void OnMutexWaitEnd(core::Process* proc, u32 mutex_slot, u64 wait_ticks)
{
    auto* s = GetState(proc);
    if (s == nullptr)
        return;
    const u64 me_tid = sched::CurrentTaskId();
    arch::Cli();
    const u32 idx = FindWaitEdge(me_tid);
    if (idx != kWaitGraphCap)
        g_wait_graph[idx].in_use = false;
    s->cycle_reported = false;
    if ((s->policy & kPolicyContentionProfile) != 0 && mutex_slot < kContentionSlotCap)
    {
        // 100 Hz scheduler tick — wait_ticks * 10 ms.
        s->contention[mutex_slot].total_wait_ms += wait_ticks * 10ULL;
    }
    arch::Sti();
}

void OnMutexAcquire(core::Process* proc, u32 mutex_slot)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyContentionProfile))
        return;
    if (mutex_slot >= kContentionSlotCap)
        return;
    arch::Cli();
    s->contention[mutex_slot].acquire_count += 1;
    arch::Sti();
}

// ---------- Window-manager additions ----------
bool PixelIsolationDenies(core::Process* src_proc, core::Process* dst_proc)
{
    if (src_proc == nullptr || dst_proc == nullptr || src_proc == dst_proc)
        return false;
    auto* sa = GetState(src_proc);
    auto* sb = GetState(dst_proc);
    return PolicyOn(sa, kPolicyPixelIsolation) && PolicyOn(sb, kPolicyPixelIsolation);
}

bool AsyncPaintActive(core::Process* proc)
{
    return PolicyOn(GetState(proc), kPolicyAsyncPaint);
}

void InputReplayPush(core::Process* owner_proc, u32 hwnd_biased, u32 message, u64 wparam, u64 lparam)
{
    auto* s = GetState(owner_proc);
    if (!PolicyOn(s, kPolicyInputReplay))
        return;
    arch::Cli();
    InputReplayEntry& e = g_input_replay[g_input_replay_head];
    e.timestamp_ns = NowNs();
    e.wparam = wparam;
    e.lparam = lparam;
    e.hwnd_biased = hwnd_biased;
    e.message = message;
    e.owner_pid = owner_proc->pid;
    g_input_replay_head = (g_input_replay_head + 1) % kInputReplayDepth;
    if (g_input_replay_count < kInputReplayDepth)
        g_input_replay_count += 1;
    arch::Sti();
}

// ---------- PE loader policy ----------
bool StrictRwxRejectsSection(core::Process* proc, u32 characteristics)
{
    auto* s = GetState(proc);
    if (!PolicyOn(s, kPolicyStrictRwx))
        return false;
    // IMAGE_SCN_MEM_EXECUTE = 0x20000000, IMAGE_SCN_MEM_WRITE = 0x80000000.
    constexpr u32 kExec = 0x20000000u;
    constexpr u32 kWrite = 0x80000000u;
    return (characteristics & kExec) != 0 && (characteristics & kWrite) != 0;
}

// ---------- Crash-dump path ----------
void DumpOnAbnormalExit(core::Process* proc)
{
    auto* s = GetState(proc);
    if (s == nullptr)
        return;
    arch::SerialWrite("[w32-custom] abnormal-exit dump pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" policy=");
    arch::SerialWriteHex(s->policy);
    arch::SerialWrite("\n");

    if ((s->policy & kPolicyFlightRecorder) != 0 && s->flight_count > 0)
    {
        arch::SerialWrite("  flight (last ");
        arch::SerialWriteHex(s->flight_count);
        arch::SerialWrite("):\n");
        // Emit oldest -> newest: head points to next-write slot,
        // so oldest = (head - count + N) % N.
        const u32 base = (s->flight_head + kFlightRecorderDepth - s->flight_count) % kFlightRecorderDepth;
        for (u32 step = 0; step < s->flight_count; ++step)
        {
            const u32 i = (base + step) % kFlightRecorderDepth;
            arch::SerialWrite("    sys=");
            arch::SerialWriteHex(s->flight[i].syscall_num);
            arch::SerialWrite(" rip=");
            arch::SerialWriteHex(s->flight[i].rip);
            arch::SerialWrite(" rdi=");
            arch::SerialWriteHex(s->flight[i].rdi);
            arch::SerialWrite(" t=");
            arch::SerialWriteHex(s->flight[i].timestamp_ns);
            arch::SerialWrite("\n");
        }
    }
    if ((s->policy & kPolicyHandleProvenance) != 0)
    {
        arch::SerialWrite("  handles (");
        arch::SerialWriteHex(s->handles_count);
        arch::SerialWrite("):\n");
        for (u32 i = 0; i < s->handles_count; ++i)
        {
            arch::SerialWrite("    handle=");
            arch::SerialWriteHex(s->handles[i].handle);
            arch::SerialWrite(" gen=");
            arch::SerialWriteHex(s->handles[i].generation);
            arch::SerialWrite(" active=");
            arch::SerialWrite(s->handles[i].active ? "1" : "0");
            arch::SerialWrite(" rip=");
            arch::SerialWriteHex(s->handles[i].creator_rip);
            arch::SerialWrite("\n");
        }
    }
}

// ---------- Syscall entry ----------
void DoCustom(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 op = frame->rdi;

    switch (op)
    {
    case kOpGetPolicy:
    {
        const auto* s = GetState(proc);
        frame->rax = (s != nullptr) ? s->policy : 0;
        return;
    }
    case kOpSetPolicy:
    {
        // rsi = new policy bitmask. Caller-supplied bits outside
        // kPolicyAllMask are silently dropped — keeps the policy
        // word forward-compatible without requiring callers to
        // check for unknown bits.
        const u64 new_policy = frame->rsi & kPolicyAllMask;
        ProcessCustomState* s = EnsureState(proc);
        if (s == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        arch::Cli();
        const u64 old = s->policy;
        s->policy = new_policy;
        arch::Sti();
        arch::SerialWrite("[w32-custom] policy pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" 0x");
        arch::SerialWriteHex(old);
        arch::SerialWrite(" -> 0x");
        arch::SerialWriteHex(new_policy);
        arch::SerialWrite("\n");
        // Log the named bits that flipped on.
        const u64 turned_on = new_policy & ~old;
        for (u64 bit = 1ULL; bit != 0 && bit <= kPolicyAllMask; bit <<= 1)
        {
            if ((turned_on & bit) != 0)
            {
                arch::SerialWrite("    +");
                arch::SerialWrite(PolicyName(bit));
                arch::SerialWrite("\n");
            }
        }
        frame->rax = old;
        return;
    }
    case kOpDumpFlight:
    case kOpDumpHandles:
    case kOpDumpQuarantine:
    case kOpDumpContention:
    case kOpDumpInputReplay:
    {
        // All "dump" ops emit to the serial console — the post-
        // mortem path is the same as DumpOnAbnormalExit but
        // gated to the requested section. rsi=0 means "this
        // section only"; reusing DumpOnAbnormalExit for the
        // simplicity of one code path is fine because every
        // section's gate is its own policy bit.
        DumpOnAbnormalExit(proc);
        if (op == kOpDumpQuarantine)
        {
            const auto* s = GetState(proc);
            if (s != nullptr && (s->policy & kPolicyQuarantineFree) != 0)
            {
                arch::SerialWrite("  quarantine (");
                arch::SerialWriteHex(s->quarantine_count);
                arch::SerialWrite("):\n");
                for (u32 step = 0; step < s->quarantine_count; ++step)
                {
                    const u32 i = (s->quarantine_head + step) % kQuarantineDepth;
                    arch::SerialWrite("    va=");
                    arch::SerialWriteHex(s->quarantine[i].user_va);
                    arch::SerialWrite(" size=");
                    arch::SerialWriteHex(s->quarantine[i].size);
                    arch::SerialWrite(" rel_tick=");
                    arch::SerialWriteHex(s->quarantine[i].release_tick);
                    arch::SerialWrite("\n");
                }
            }
        }
        if (op == kOpDumpContention)
        {
            const auto* s = GetState(proc);
            if (s != nullptr && (s->policy & kPolicyContentionProfile) != 0)
            {
                arch::SerialWrite("  contention:\n");
                for (u32 i = 0; i < kContentionSlotCap; ++i)
                {
                    if (s->contention[i].acquire_count == 0 && s->contention[i].wait_count == 0)
                        continue;
                    arch::SerialWrite("    slot=");
                    arch::SerialWriteHex(i);
                    arch::SerialWrite(" acq=");
                    arch::SerialWriteHex(s->contention[i].acquire_count);
                    arch::SerialWrite(" wait=");
                    arch::SerialWriteHex(s->contention[i].wait_count);
                    arch::SerialWrite(" wait_ms=");
                    arch::SerialWriteHex(s->contention[i].total_wait_ms);
                    arch::SerialWrite("\n");
                }
            }
        }
        if (op == kOpDumpInputReplay)
        {
            arch::Cli();
            const u32 count = g_input_replay_count;
            const u32 head = g_input_replay_head;
            arch::Sti();
            arch::SerialWrite("  input replay (");
            arch::SerialWriteHex(count);
            arch::SerialWrite("):\n");
            const u32 base = (head + kInputReplayDepth - count) % kInputReplayDepth;
            for (u32 step = 0; step < count; ++step)
            {
                const u32 i = (base + step) % kInputReplayDepth;
                if (g_input_replay[i].owner_pid != proc->pid)
                    continue;
                arch::SerialWrite("    msg=");
                arch::SerialWriteHex(g_input_replay[i].message);
                arch::SerialWrite(" hwnd=");
                arch::SerialWriteHex(g_input_replay[i].hwnd_biased);
                arch::SerialWrite(" wp=");
                arch::SerialWriteHex(g_input_replay[i].wparam);
                arch::SerialWrite(" lp=");
                arch::SerialWriteHex(g_input_replay[i].lparam);
                arch::SerialWrite("\n");
            }
        }
        frame->rax = 0;
        return;
    }
    case kOpGetErrorProvenance:
    {
        // rsi = user pointer to ErrorProvenance struct (32 bytes).
        // Copies the current record out. Returns 0 on success, -1
        // on bad user pointer or no provenance recorded.
        const auto* s = GetState(proc);
        if (s == nullptr || (s->policy & kPolicyErrorProvenance) == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        ErrorProvenance copy = s->error;
        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &copy, sizeof(copy)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 0;
        return;
    }
    case kOpDetectDeadlock:
    {
        // No args. Returns 1 if this thread is currently part of a
        // wait cycle, 0 otherwise. Useful as a self-check from a
        // watchdog thread.
        const u64 me_tid = sched::CurrentTaskId();
        arch::Cli();
        const bool cycle = DetectCycle(me_tid);
        arch::Sti();
        frame->rax = cycle ? 1 : 0;
        return;
    }
    case kOpGetSystemDefault:
    {
        frame->rax = GetSystemDefaultPolicy();
        return;
    }
    case kOpSetSystemDefault:
    {
        // rsi = new system-default mask. Affects every PROCESS
        // SPAWNED AFTER this call — already-running processes
        // keep whatever they were started with (unless they
        // call SetPolicy themselves). Privileged in spirit;
        // currently any process can flip it. A future revision
        // gates on a capability bit.
        const u64 old = GetSystemDefaultPolicy();
        SetSystemDefaultPolicy(frame->rsi);
        arch::SerialWrite("[w32-custom] system-default 0x");
        arch::SerialWriteHex(old);
        arch::SerialWrite(" -> 0x");
        arch::SerialWriteHex(GetSystemDefaultPolicy());
        arch::SerialWrite("\n");
        frame->rax = old;
        return;
    }
    default:
        frame->rax = static_cast<u64>(-1);
        return;
    }
}

} // namespace duetos::subsystems::win32::custom
