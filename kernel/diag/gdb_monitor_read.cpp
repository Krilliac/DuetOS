/*
 * DuetOS — GDB `monitor` read-introspection verbs
 * (ps/caps/threads/handles/vm/mods/win/win32/reg).
 *
 * Split out of gdb_monitor.cpp so the read-only subsystem-API
 * consumers live in ONE TU for the subsystem-isolation audit,
 * and each TU stays under the size threshold. Everything here is
 * READ-ONLY and routes through public kernel APIs — it never
 * mutates subsystem internals (see gdb_monitor.h contract).
 */

#include "diag/gdb_monitor.h"

#include "drivers/video/widget.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "loader/dll_loader.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "subsystems/win32/custom.h"
#include "subsystems/win32/registry.h"
#include "util/string.h"

namespace duetos::diag::mon_internal
{

namespace
{

const char* ThreadStateName(u8 s)
{
    switch (s)
    {
    case 0:
        return "ready";
    case 1:
        return "run";
    case 2:
        return "sleep";
    case 3:
        return "blocked";
    case 4:
        return "dead";
    default:
        return "?";
    }
}

void Unavailable(const char* verb, core::ErrorCode reason, MonitorWriter& out)
{
    out.Str(verb);
    out.Str(": unavailable at stop (lock ");
    out.Str(core::ErrorCodeName(reason));
    out.Str(")\n");
}

void NotFound(const char* verb, u64 pid, MonitorWriter& out)
{
    out.Str(verb);
    out.Str(": pid ");
    out.U64(pid);
    out.Str(" not found\n");
}

core::ErrorCode FindStoppedProc(u64 pid, core::Process** process_out, bool* vm_quiescent_out)
{
    const core::ErrorCode status = sched::SchedFindProcessByPidStopped(pid, process_out, vm_quiescent_out);
    if (status != core::ErrorCode::Ok)
        return status;
    if (*process_out == nullptr || core::ProcessLifecycleLoad(*process_out) != core::ProcessLifecycleState::Published)
    {
        *process_out = nullptr;
        *vm_quiescent_out = false;
        return core::ErrorCode::NotFound;
    }
    return core::ErrorCode::Ok;
}

} // namespace

void CmdPs(MonitorWriter& out)
{
    constexpr u32 kTaskCap = 128;
    sched::SchedTaskInfo tasks[kTaskCap]{};
    u32 total_tasks = 0;
    const core::ErrorCode status = sched::SchedSnapshotTasksStopped(tasks, kTaskCap, &total_tasks);
    if (status != core::ErrorCode::Ok)
    {
        Unavailable("ps", status, out);
        return;
    }

    struct ProcRow
    {
        u64 pid;
        const char* name;
        u64 ticks;
        bool all_dead;
    };
    ProcRow procs[64]{};
    u32 n = 0;
    const u32 shown_tasks = total_tasks < kTaskCap ? total_tasks : kTaskCap;
    for (u32 i = 0; i < shown_tasks; ++i)
    {
        const sched::SchedTaskInfo& task = tasks[i];
        if (!task.has_process || task.owner_pid == 0)
            continue;
        u32 row = 0;
        for (; row < n; ++row)
            if (procs[row].pid == task.owner_pid)
                break;
        if (row == n)
        {
            if (n == 64)
                continue;
            procs[n] = {task.owner_pid, task.name, 0, true};
            row = n++;
        }
        procs[row].ticks += task.ticks_run;
        if (task.state != 4)
            procs[row].all_dead = false;
    }
    out.Str("PID    STATE    TICKS       REGIONS  NAME\n");
    for (u32 i = 0; i < n; ++i)
    {
        out.U64(procs[i].pid);
        out.Str("\t");
        out.Str(procs[i].all_dead ? "zombie" : "run");
        out.Str("\t");
        out.U64(procs[i].ticks);
        out.Str("\t");
        out.Str("-");
        out.Str("\t");
        out.Str(procs[i].name != nullptr ? procs[i].name : "?");
        out.Line();
    }
    out.Str("(");
    out.U64(n);
    out.Str(" processes)\n");
}

void CmdCaps(u64 pid, MonitorWriter& out)
{
    core::Process* p = nullptr;
    bool vm_quiescent = false;
    const core::ErrorCode lookup = FindStoppedProc(pid, &p, &vm_quiescent);
    if (lookup == core::ErrorCode::NotFound)
    {
        NotFound("caps", pid, out);
        return;
    }
    if (lookup != core::ErrorCode::Ok)
    {
        Unavailable("caps", lookup, out);
        return;
    }
    (void)vm_quiescent;
    core::CapSet caps{};
    // No lease-expiry side effect in the stop loop: the bounded helper tries
    // the Process authority lock and publishes only a diagnostic view. Runtime
    // expiry resumes normally after continue.
    if (!core::ProcessCapsTrySnapshotNoExpire(p, &caps))
    {
        Unavailable("caps", core::ErrorCode::Busy, out);
        return;
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" caps=0x");
    out.Hex(caps.bits);
    out.Str("\n");
    for (u32 c = 1; c < static_cast<u32>(core::kCapCount); ++c)
    {
        const bool has = core::CapSetHas(caps, static_cast<core::Cap>(c));
        out.Str("  ");
        out.Str(has ? "[x] " : "[ ] ");
        // core::CapName is the single source of truth and is covered by
        // ProcessSelfTest's "every enumerator has a name" loop. This TU
        // used to carry its own hand-maintained name array; it had
        // already fallen a cap behind (kCapSchedPriority printed as
        // "cap10"), which is the whitelist-incompleteness shape
        // CLAUDE.md warns about. Deleted rather than extended.
        out.Str(core::CapName(static_cast<core::Cap>(c)));
        out.Line();
    }
}

void CmdThreads(MonitorWriter& out)
{
    const sched::SchedStats ov = sched::SchedStatsRead();
    out.Str("ctx-switches=");
    out.U64(ov.context_switches);
    out.Str(" live=");
    out.U64(ov.tasks_live);
    out.Str(" sleeping=");
    out.U64(ov.tasks_sleeping);
    out.Str(" blocked=");
    out.U64(ov.tasks_blocked);
    out.Line();

    sched::SchedTaskInfo th[128]{};
    u32 total = 0;
    const core::ErrorCode status = sched::SchedSnapshotTasksStopped(th, 128, &total);
    if (status != core::ErrorCode::Ok)
    {
        Unavailable("threads", status, out);
        return;
    }
    const u32 n = total < 128 ? total : 128;
    out.Str("TID    STATE   PRIO  TICKS       NAME\n");
    for (u32 i = 0; i < n; ++i)
    {
        out.U64(th[i].id);
        out.Str("\t");
        out.Str(ThreadStateName(th[i].state));
        out.Str("\t");
        out.U64(th[i].priority);
        out.Str("\t");
        out.U64(th[i].ticks_run);
        out.Str("\t");
        out.Str(th[i].name != nullptr ? th[i].name : "?");
        if (th[i].is_running)
        {
            out.Str(" *");
        }
        out.Line();
    }
    out.Str("(");
    out.U64(n);
    out.Str(" tasks)\n");
}

void CmdHandles(u64 pid, MonitorWriter& out)
{
    core::Process* p = nullptr;
    bool vm_quiescent = false;
    const core::ErrorCode lookup = FindStoppedProc(pid, &p, &vm_quiescent);
    if (lookup == core::ErrorCode::NotFound)
    {
        NotFound("handles", pid, out);
        return;
    }
    if (lookup != core::ErrorCode::Ok)
    {
        Unavailable("handles", lookup, out);
        return;
    }
    (void)vm_quiescent;

    ipc::HandleSnapshotEntry entries[ipc::kHandleTableCapacity]{};
    u32 total = 0;
    {
        sync::SpinLockTryGuard handle_guard(p->kobj_handles.lock);
        if (!handle_guard)
        {
            Unavailable("handles", handle_guard.reason(), out);
            return;
        }
        for (u32 slot_index = 1; slot_index < ipc::kHandleTableCapacity; ++slot_index)
        {
            const ipc::HandleSlot& slot = p->kobj_handles.slots[slot_index];
            if (slot.state != ipc::HandleSlotState::Live || slot.obj == nullptr)
                continue;
            entries[total++] = {ipc::HandleEncode(slot_index, slot.generation), slot.obj->type, slot.rights};
        }
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" live=");
    out.U64(total);
    out.Line();
    const u32 shown = total < ipc::kHandleTableCapacity ? total : ipc::kHandleTableCapacity;
    for (u32 i = 0; i < shown; ++i)
    {
        out.Str("  h=");
        out.U64(entries[i].handle);
        out.Str("  type=");
        out.Str(ipc::KObjectTypeName(entries[i].type));
        out.Str("  rights=0x");
        out.Hex(entries[i].rights, 16);
        out.Line();
    }
}

void CmdVm(u64 pid, MonitorWriter& out)
{
    core::Process* p = nullptr;
    bool vm_quiescent = false;
    const core::ErrorCode lookup = FindStoppedProc(pid, &p, &vm_quiescent);
    if (lookup == core::ErrorCode::NotFound)
    {
        NotFound("vm", pid, out);
        return;
    }
    if (lookup != core::ErrorCode::Ok)
    {
        Unavailable("vm", lookup, out);
        return;
    }
    if (!vm_quiescent)
    {
        out.Str("vm: unavailable at stop (VM transaction owned)\n");
        return;
    }
    const mm::AddressSpace* as = p->as;
    if (as == nullptr)
    {
        out.Str("vm: pid ");
        out.U64(pid);
        out.Str(" has no address space (kernel task)\n");
        return;
    }
    constexpr u32 kRowCap = 96;
    mm::AddressSpaceUserRegion rows[kRowCap]{};
    u32 total = 0;
    u32 shown = 0;
    {
        sync::SpinLockTryGuard region_guard(as->regions_lock);
        if (!region_guard)
        {
            Unavailable("vm", region_guard.reason(), out);
            return;
        }
        total = as->region_count;
        shown = (total < kRowCap) ? total : kRowCap;
        for (u32 i = 0; i < shown; ++i)
            rows[i] = as->regions[i];
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" regions=");
    out.U64(total);
    out.Line();
    for (u32 i = 0; i < shown; ++i)
    {
        out.Str("  va=0x");
        out.Hex(rows[i].vaddr, 12);
        out.Str("  frame=0x");
        out.Hex(static_cast<u64>(rows[i].frame), 9);
        out.Line();
    }
    if (shown < total)
    {
        out.Str("  ... (");
        out.U64(total - shown);
        out.Str(" more)\n");
    }
}

void CmdMods(u64 pid, MonitorWriter& out)
{
    core::Process* p = nullptr;
    bool vm_quiescent = false;
    const core::ErrorCode lookup = FindStoppedProc(pid, &p, &vm_quiescent);
    if (lookup == core::ErrorCode::NotFound)
    {
        NotFound("mods", pid, out);
        return;
    }
    if (lookup != core::ErrorCode::Ok)
    {
        Unavailable("mods", lookup, out);
        return;
    }
    if (!vm_quiescent)
    {
        out.Str("mods: unavailable at stop (VM transaction owned)\n");
        return;
    }
    core::DllImage images[core::Process::kDllImageCap]{};
    const u64 image_count =
        p->dll_image_count < core::Process::kDllImageCap ? p->dll_image_count : core::Process::kDllImageCap;
    for (u64 i = 0; i < image_count; ++i)
        images[i] = p->dll_images[i];
    out.Str("pid ");
    out.U64(pid);
    out.Str(" dll-images=");
    out.U64(image_count);
    out.Line();
    for (u64 i = 0; i < image_count; ++i)
    {
        const core::DllImage& d = images[i];
        out.Str("  [");
        out.U64(i);
        out.Str("] base=0x");
        out.Hex(d.base_va);
        out.Str(" size=0x");
        out.Hex(d.size);
        out.Str(" entry_rva=0x");
        out.Hex(d.entry_rva);
        out.Str(" file_len=");
        out.U64(d.file_len);
        out.Line();
    }
}

void CmdWin(MonitorWriter& out)
{
    using namespace duetos::drivers::video;
    const u32 count = WindowRegistryCount();
    out.Str("HWND  PID    VIS  BOUNDS            TITLE\n");
    u32 live = 0;
    for (u32 h = 0; h < count; ++h)
    {
        if (!WindowIsAlive(h))
        {
            continue;
        }
        ++live;
        u32 x = 0, y = 0, w = 0, ht = 0;
        WindowGetBounds(h, &x, &y, &w, &ht);
        out.U64(h);
        out.Str("\t");
        out.U64(WindowOwnerPid(h));
        out.Str("\t");
        out.Str(WindowIsVisible(h) ? "y" : "n");
        out.Str("\t");
        out.U64(x);
        out.Str(",");
        out.U64(y);
        out.Str(" ");
        out.U64(w);
        out.Str("x");
        out.U64(ht);
        out.Str("\t");
        out.Str(WindowTitle(h));
        out.Line();
    }
    out.Str("(");
    out.U64(live);
    out.Str(" live / ");
    out.U64(count);
    out.Str(" slots)\n");
}

void CmdWin32(u64 pid, MonitorWriter& out)
{
    core::Process* p = nullptr;
    bool vm_quiescent = false;
    const core::ErrorCode lookup = FindStoppedProc(pid, &p, &vm_quiescent);
    if (lookup == core::ErrorCode::NotFound)
    {
        NotFound("win32", pid, out);
        return;
    }
    if (lookup != core::ErrorCode::Ok)
    {
        Unavailable("win32", lookup, out);
        return;
    }
    if (!vm_quiescent)
    {
        out.Str("win32: unavailable at stop (VM transaction owned)\n");
        return;
    }
    subsystems::win32::custom::ProcessCustomState* st = subsystems::win32::custom::GetState(p);
    if (st == nullptr)
    {
        out.Str("pid ");
        out.U64(pid);
        out.Str(": no Win32 custom state (not a Win32 PE, or state never allocated)\n");
        return;
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" win32:\n  policy=0x");
    out.Hex(st->policy);
    out.Str("\n  flight_records=");
    out.U64(st->flight_count);
    out.Str("\n  handle_provenance=");
    out.U64(st->handles_count);
    out.Str("\n  quarantined=");
    out.U64(st->quarantine_count);
    out.Str("\n  cycle_reported=");
    out.Str(st->cycle_reported ? "yes" : "no");
    out.Line();
}

void CmdReg(const char* args, MonitorWriter& out)
{
    if (args == nullptr || args[0] == '\0')
    {
        out.Str("usage: duet reg <HKLM|HKCU> <Subkey\\Path>\n");
        return;
    }
    // First token = root; the remainder (which may contain spaces,
    // e.g. "Windows NT") = path. Forward slashes are accepted as a
    // convenience and normalised to backslashes.
    char root_tok[16];
    u32 ri = 0;
    u32 i = 0;
    while (args[i] == ' ' || args[i] == '\t')
    {
        ++i;
    }
    while (args[i] != '\0' && args[i] != ' ' && args[i] != '\t' && ri + 1 < sizeof(root_tok))
    {
        root_tok[ri++] = args[i++];
    }
    root_tok[ri] = '\0';
    while (args[i] == ' ' || args[i] == '\t')
    {
        ++i;
    }

    u64 root = 0;
    if (core::StrEqualCaseInsensitive(root_tok, "HKLM") ||
        core::StrEqualCaseInsensitive(root_tok, "HKEY_LOCAL_MACHINE"))
    {
        root = subsystems::win32::registry::kHkeyLocalMachine;
    }
    else if (core::StrEqualCaseInsensitive(root_tok, "HKCU") ||
             core::StrEqualCaseInsensitive(root_tok, "HKEY_CURRENT_USER"))
    {
        root = subsystems::win32::registry::kHkeyCurrentUser;
    }
    else
    {
        out.Str("reg: unknown root '");
        out.Str(root_tok);
        out.Str("' (use HKLM or HKCU)\n");
        return;
    }

    char path[160];
    u32 pp = 0;
    for (; args[i] != '\0' && pp + 1 < sizeof(path); ++i)
    {
        path[pp++] = (args[i] == '/') ? '\\' : args[i];
    }
    path[pp] = '\0';

    char rendered[1024];
    if (!subsystems::win32::registry::RegistryQuery(root, path, rendered, sizeof(rendered)))
    {
        out.Str("reg: key not found: ");
        out.Str(root_tok);
        out.Str("\\");
        out.Str(path);
        out.Line();
        return;
    }
    out.Str(root_tok);
    out.Str("\\");
    out.Str(path);
    out.Line();
    out.Str(rendered);
}

} // namespace duetos::diag::mon_internal
