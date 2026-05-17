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

#include "apps/dbg_core.h"
#include "drivers/video/widget.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "loader/dll_loader.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "subsystems/win32/custom.h"
#include "subsystems/win32/registry.h"
#include "util/string.h"

namespace duetos::diag::mon_internal
{

namespace
{

const char* ProcStateName(u8 s)
{
    switch (s)
    {
    case 0:
        return "run";
    case 1:
        return "ready";
    case 2:
        return "blocked";
    case 3:
        return "zombie";
    default:
        return "?";
    }
}

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

// enum Cap is dense [1, kCapCount); keep the names in index order.
const char* kCapNames[] = {
    "none", "serial-console", "fs-read", "debug", "fs-write", "spawn-thread", "net", "input", "net-admin", "diag",
};

core::Process* FindProc(u64 pid)
{
    return sched::SchedFindProcessByPid(pid);
}

void NotFound(const char* verb, u64 pid, MonitorWriter& out)
{
    out.Str(verb);
    out.Str(": pid ");
    out.U64(pid);
    out.Str(" not found\n");
}

} // namespace

void CmdPs(MonitorWriter& out)
{
    apps::dbg::core::ProcInfo procs[64];
    const usize n = apps::dbg::core::EnumerateProcesses(procs, 64);
    out.Str("PID    STATE    TICKS       REGIONS  NAME\n");
    for (usize i = 0; i < n; ++i)
    {
        out.U64(procs[i].pid);
        out.Str("\t");
        out.Str(ProcStateName(procs[i].state));
        out.Str("\t");
        out.U64(procs[i].ticks_used);
        out.Str("\t");
        out.U64(procs[i].region_count);
        out.Str("\t");
        out.Str(procs[i].name);
        out.Line();
    }
    out.Str("(");
    out.U64(n);
    out.Str(" processes)\n");
}

void CmdCaps(u64 pid, MonitorWriter& out)
{
    core::Process* p = FindProc(pid);
    if (p == nullptr)
    {
        NotFound("caps", pid, out);
        return;
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" caps=0x");
    out.Hex(p->caps.bits);
    out.Str("\n");
    for (u32 c = 1; c < static_cast<u32>(core::kCapCount); ++c)
    {
        const bool has = core::CapSetHas(p->caps, static_cast<core::Cap>(c));
        out.Str("  ");
        out.Str(has ? "[x] " : "[ ] ");
        if (c < (sizeof(kCapNames) / sizeof(kCapNames[0])))
        {
            out.Str(kCapNames[c]);
        }
        else
        {
            out.Str("cap");
            out.U64(c);
        }
        out.Line();
    }
}

void CmdThreads(MonitorWriter& out)
{
    apps::dbg::core::KernelOverview ov;
    apps::dbg::core::GetKernelOverview(&ov);
    out.Str("ctx-switches=");
    out.U64(ov.sched_context_switches);
    out.Str(" live=");
    out.U64(ov.sched_tasks_live);
    out.Str(" sleeping=");
    out.U64(ov.sched_tasks_sleeping);
    out.Str(" blocked=");
    out.U64(ov.sched_tasks_blocked);
    out.Line();

    apps::dbg::core::ThreadInfo th[128];
    const usize n = apps::dbg::core::EnumerateThreads(th, 128);
    out.Str("TID    STATE   PRIO  TICKS       NAME\n");
    for (usize i = 0; i < n; ++i)
    {
        out.U64(th[i].tid);
        out.Str("\t");
        out.Str(ThreadStateName(th[i].state));
        out.Str("\t");
        out.U64(th[i].priority);
        out.Str("\t");
        out.U64(th[i].ticks_run);
        out.Str("\t");
        out.Str(th[i].name);
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
    core::Process* p = FindProc(pid);
    if (p == nullptr)
    {
        NotFound("handles", pid, out);
        return;
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" live=");
    out.U64(ipc::HandleTableLiveCount(p->kobj_handles));
    out.Line();
    // Slot 0 is reserved for kHandleInvalid. Best-effort snapshot:
    // the stop loop is single-CPU with peers NMI-frozen, so an
    // unlocked read is a consistent debug view.
    for (u32 h = 1; h < ipc::kHandleTableCapacity; ++h)
    {
        const ipc::KObject* obj = p->kobj_handles.slots[h].obj;
        if (obj == nullptr)
        {
            continue;
        }
        out.Str("  h=");
        out.U64(h);
        out.Str("  type=");
        out.Str(ipc::KObjectTypeName(obj->type));
        out.Str("  refs=");
        out.U64(obj->refcount);
        out.Line();
    }
}

void CmdVm(u64 pid, MonitorWriter& out)
{
    core::Process* p = FindProc(pid);
    if (p == nullptr)
    {
        NotFound("vm", pid, out);
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
    const u32 total = as->region_count;
    constexpr u32 kRowCap = 96;
    const u32 shown = (total < kRowCap) ? total : kRowCap;
    out.Str("pid ");
    out.U64(pid);
    out.Str(" regions=");
    out.U64(total);
    out.Line();
    for (u32 i = 0; i < shown; ++i)
    {
        out.Str("  va=0x");
        out.Hex(as->regions[i].vaddr, 12);
        out.Str("  frame=0x");
        out.Hex(static_cast<u64>(as->regions[i].frame), 9);
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
    core::Process* p = FindProc(pid);
    if (p == nullptr)
    {
        NotFound("mods", pid, out);
        return;
    }
    out.Str("pid ");
    out.U64(pid);
    out.Str(" dll-images=");
    out.U64(p->dll_image_count);
    out.Line();
    for (u64 i = 0; i < p->dll_image_count && i < core::Process::kDllImageCap; ++i)
    {
        const core::DllImage& d = p->dll_images[i];
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
    core::Process* p = FindProc(pid);
    if (p == nullptr)
    {
        NotFound("win32", pid, out);
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
