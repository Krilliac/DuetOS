#include "process.h"

#include "../arch/x86_64/serial.h"
#include "log_names.h"
#include "../debug/probes.h"
#include "../drivers/video/theme.h"
#include "../drivers/video/widget.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"
#include "klog.h"
#include "panic.h"
#include "pe_loader.h"

namespace duetos::core
{

namespace
{

// Monotonic PID generator. Never reuses — matches the Task id
// discipline in the scheduler. PID 0 is reserved for "no process"
// (the kernel's implicit, never-allocated init-context), so the
// counter starts at 1.
constinit u64 g_next_pid = 1;
constinit u64 g_live_processes = 0;

} // namespace

Process* ProcessCreate(const char* name, mm::AddressSpace* as, CapSet caps, const fs::RamfsNode* root, u64 user_code_va,
                       u64 user_stack_va, u64 tick_budget)
{
    KLOG_TRACE_SCOPE("core/process", "ProcessCreate");
    KASSERT(name != nullptr, "core/process", "ProcessCreate null name");
    KASSERT(as != nullptr, "core/process", "ProcessCreate null as");
    KASSERT(root != nullptr, "core/process", "ProcessCreate null root");
    KASSERT(tick_budget > 0, "core/process", "ProcessCreate zero tick_budget");

    auto* p = static_cast<Process*>(mm::KMalloc(sizeof(Process)));
    if (p == nullptr)
    {
        return nullptr;
    }

    p->pid = g_next_pid++;
    p->name = name;
    p->as = as;
    p->caps = caps;
    p->root = root;
    p->user_code_va = user_code_va;
    p->user_stack_va = user_stack_va;
    p->user_rsp_init = 0; // loader overrides if it wants a custom rsp
    p->user_gs_base = 0;  // PE loader sets this to the TEB VA
    p->win32_iat_miss_count = 0;
    // DLL image table — every slot starts empty. `has_exports`
    // = false marks a free slot (matches DllLoad's post-state
    // on failure), and `ProcessRegisterDllImage` always writes
    // an image with has_exports = true. Walk condition in
    // `ProcessResolveDllExport` stops at `dll_image_count`,
    // so the intervening bytes only need to be zero-ish.
    for (u32 i = 0; i < Process::kDllImageCap; ++i)
    {
        p->dll_images[i].file = nullptr;
        p->dll_images[i].file_len = 0;
        p->dll_images[i].base_va = 0;
        p->dll_images[i].size = 0;
        p->dll_images[i].entry_rva = 0;
        p->dll_images[i].has_exports = false;
    }
    p->dll_image_count = 0;
    p->tick_budget = tick_budget;
    p->ticks_used = 0;
    p->sandbox_denials = 0;
    p->win32_last_error = 0; // ERROR_SUCCESS
    p->heap_base = 0;        // PeLoad fills these when the PE has
    p->heap_pages = 0;       // imports — see subsystems/win32/heap.cpp
    p->heap_free_head = 0;
    // Linux fd table: reserve stdin/stdout/stderr, mark rest unused.
    for (u32 i = 0; i < 16; ++i)
    {
        p->linux_fds[i].state = (i < 3) ? 1 /* reserved-tty */ : 0;
        p->linux_fds[i].first_cluster = 0;
        p->linux_fds[i].size = 0;
        p->linux_fds[i].offset = 0;
        for (u32 j = 0; j < sizeof(p->linux_fds[i]._pad); ++j)
            p->linux_fds[i]._pad[j] = 0;
        p->linux_fds[i]._pad2 = 0;
        for (u32 j = 0; j < sizeof(p->linux_fds[i].path); ++j)
            p->linux_fds[i].path[j] = 0;
    }
    p->linux_brk_base = 0; // loader fills when abi_flavor = kAbiLinux
    p->linux_brk_current = 0;
    p->linux_mmap_cursor = 0;
    p->abi_flavor = kAbiNative; // loaders flip to kAbiLinux if appropriate
    for (u32 i = 0; i < sizeof(p->_abi_pad); ++i)
        p->_abi_pad[i] = 0;
    // Win32 file-handle table — every slot starts unused. The
    // `kind == None` sentinel distinguishes free slots; the
    // ramfs / fat32 fields are valid only when kind matches.
    for (u32 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        p->win32_handles[i].kind = Process::FsBackingKind::None;
        p->win32_handles[i].ramfs_node = nullptr;
        p->win32_handles[i].fat32_volume_idx = 0;
        p->win32_handles[i].cursor = 0;
    }
    // Win32 VirtualAlloc arena — bump-only for v0. Starts at
    // Process::kWin32VmapBase with 0 pages consumed.
    p->vmap_base = Process::kWin32VmapBase;
    p->vmap_pages_used = 0;
    // Win32 mutex table — every slot starts free + unowned.
    for (u32 i = 0; i < Process::kWin32MutexCap; ++i)
    {
        p->win32_mutexes[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_mutexes[i]._pad); ++j)
            p->win32_mutexes[i]._pad[j] = 0;
        p->win32_mutexes[i].recursion = 0;
        p->win32_mutexes[i].owner = nullptr;
        p->win32_mutexes[i].waiters.head = nullptr;
        p->win32_mutexes[i].waiters.tail = nullptr;
    }
    // Win32 event table — every slot starts free + unsignaled.
    for (u32 i = 0; i < Process::kWin32EventCap; ++i)
    {
        p->win32_events[i].in_use = false;
        p->win32_events[i].manual_reset = false;
        p->win32_events[i].signaled = false;
        for (u32 j = 0; j < sizeof(p->win32_events[i]._pad); ++j)
            p->win32_events[i]._pad[j] = 0;
        p->win32_events[i].waiters.head = nullptr;
        p->win32_events[i].waiters.tail = nullptr;
    }
    // Win32 thread table — every slot starts free with exit_code
    // = STILL_ACTIVE (matches Win32 GetExitCodeThread semantics on
    // a running thread).
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        p->win32_threads[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_threads[i]._pad); ++j)
            p->win32_threads[i]._pad[j] = 0;
        p->win32_threads[i].exit_code = 0x103; // STILL_ACTIVE
        p->win32_threads[i].task = nullptr;
        p->win32_threads[i].user_stack_va = 0;
    }
    // Win32 semaphore table — every slot starts free.
    for (u32 i = 0; i < Process::kWin32SemaphoreCap; ++i)
    {
        p->win32_semaphores[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_semaphores[i]._pad); ++j)
            p->win32_semaphores[i]._pad[j] = 0;
        p->win32_semaphores[i].count = 0;
        p->win32_semaphores[i].max_count = 0;
        for (u32 j = 0; j < sizeof(p->win32_semaphores[i]._pad2); ++j)
            p->win32_semaphores[i]._pad2[j] = 0;
        p->win32_semaphores[i].waiters.head = nullptr;
        p->win32_semaphores[i].waiters.tail = nullptr;
    }
    p->thread_stack_cursor = Process::kV0ThreadStackArenaBase;
    // Win32 TLS — no slots allocated, all values zero.
    p->tls_slot_in_use = 0;
    for (u32 i = 0; i < Process::kWin32TlsCap; ++i)
        p->tls_slot_value[i] = 0;
    // Linux signal-handler table — every signal starts at SIG_DFL
    // (handler_va == 0), no flags, no mask.
    for (u32 i = 0; i < Process::kLinuxSignalCount; ++i)
    {
        p->linux_sigactions[i].handler_va = 0;
        p->linux_sigactions[i].flags = 0;
        p->linux_sigactions[i].restorer_va = 0;
        p->linux_sigactions[i].mask = 0;
    }
    p->linux_signal_mask = 0;
    // Default cwd is "/" — matches the value DoGetcwd hard-coded
    // before this field existed.
    for (u32 i = 0; i < Process::kLinuxCwdCap; ++i)
        p->linux_cwd[i] = 0;
    p->linux_cwd[0] = '/';
    p->refcount = 1;

    ++g_live_processes;

    arch::SerialWrite("[proc] create pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\" caps=");
    arch::SerialWriteHex(caps.bits);
    arch::SerialWrite("(");
    SerialWriteCapBits(caps.bits);
    arch::SerialWrite(") code_va=");
    arch::SerialWriteHex(user_code_va);
    arch::SerialWrite(" stack_va=");
    arch::SerialWriteHex(user_stack_va);
    arch::SerialWrite("\n");

    KBP_PROBE_V(::duetos::debug::ProbeId::kProcessCreate, p->pid);
    return p;
}

void ProcessRetain(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    ++p->refcount;
}

void ProcessRelease(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    if (p->refcount == 0)
    {
        PanicWithValue("core/process", "ProcessRelease on refcount==0", reinterpret_cast<u64>(p));
    }
    --p->refcount;
    if (p->refcount != 0)
    {
        return;
    }

    KBP_PROBE_V(::duetos::debug::ProbeId::kProcessDestroy, p->pid);

    // Reap any windows this process registered but never
    // DestroyWindow'd. Walks the compositor registry under the
    // compositor lock so it serialises cleanly with the input
    // threads + ui ticker that also draw. Triggered on the LAST
    // reference-drop, so multi-threaded processes reap exactly
    // once (when the final thread exits). `WindowReapByOwner`
    // refuses pid==0 (kernel-owned boot windows) as a safety
    // belt.
    {
        duetos::drivers::video::CompositorLock();
        const u32 reaped = duetos::drivers::video::WindowReapByOwner(p->pid);
        if (reaped > 0)
        {
            const duetos::drivers::video::Theme& theme = duetos::drivers::video::ThemeCurrent();
            duetos::drivers::video::DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            arch::SerialWrite("[proc] reap-windows pid=");
            arch::SerialWriteHex(p->pid);
            arch::SerialWrite(" count=");
            arch::SerialWriteHex(reaped);
            arch::SerialWrite("\n");
        }
        duetos::drivers::video::CompositorUnlock();
    }

    arch::SerialWrite("[proc] destroy pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(p->name);
    arch::SerialWrite("\"\n");

    // Drop the AS reference we took at create. If this was the last
    // process/task holding that AS (v0: always true — one task per
    // process, one process per AS), the AS destroy path runs inline:
    // user-half tables freed, backing frames returned, PML4 frame
    // returned.
    mm::AddressSpaceRelease(p->as);
    p->as = nullptr;

    mm::KFree(p);
    --g_live_processes;
}

Process* CurrentProcess()
{
    sched::Task* t = sched::CurrentTask();
    if (t == nullptr)
    {
        return nullptr;
    }
    return sched::TaskProcess(t);
}

void RecordSandboxDenial(Cap cap)
{
    sched::Task* t = sched::CurrentTask();
    if (t == nullptr)
    {
        return;
    }
    Process* p = sched::TaskProcess(t);
    if (p == nullptr)
    {
        return; // kernel-only task hit a cap-denial — shouldn't happen
    }
    ++p->sandbox_denials;

    // Fire the sandbox-denial probe at the same rate-limit the
    // existing denial logger uses (first hit + every 32nd). Same
    // motivation: a ring-3 hostile task can otherwise flood the
    // probe log with thousands of identical lines per boot.
    if (ShouldLogDenial(p->sandbox_denials))
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kSandboxDenialCap, static_cast<u64>(cap));
    }

    // Threshold-crossing: fire once at exactly kSandbox-
    // DenialKillThreshold and flag the task. Uses `==` so the
    // message doesn't repeat for denials that race past the
    // flag before Schedule picks them up.
    if (p->sandbox_denials == kSandboxDenialKillThreshold)
    {
        arch::SerialWrite("[sandbox] pid=");
        arch::SerialWriteHex(p->pid);
        arch::SerialWrite(" hit ");
        arch::SerialWriteHex(kSandboxDenialKillThreshold);
        arch::SerialWrite(" denials (last cap=");
        arch::SerialWrite(CapName(cap));
        arch::SerialWrite(") — terminating as malicious\n");
        sched::FlagCurrentForKill(sched::KillReason::SandboxDenialThreshold);
    }
}

bool ShouldLogDenial(u64 denial_index)
{
    // Rate-limit per-process denial log output. Always log the
    // first denial (so a bug in legitimate code surfaces
    // immediately), then log once every 32 thereafter. A burst
    // of 100 denials produces 1 + 3 = 4 log lines instead of
    // 100. The counter itself advances on every denial — only
    // the log is rate-limited — so the threshold-kill still
    // fires at the exact 100th attempt.
    //
    // 32 chosen because log2 is convenient and it produces ~4
    // lines at the threshold; tune if future workloads spam
    // the log at a different rate.
    return denial_index == 1 || (denial_index & 31) == 0;
}

const char* CapName(Cap c)
{
    switch (c)
    {
    case kCapNone:
        return "<none>";
    case kCapSerialConsole:
        return "SerialConsole";
    case kCapFsRead:
        return "FsRead";
    case kCapDebug:
        return "Debug";
    case kCapFsWrite:
        return "FsWrite";
    case kCapSpawnThread:
        return "SpawnThread";
    case kCapCount:
        return "<sentinel>";
    }
    return "<unknown>";
}

namespace
{

// ASCII to-lower. Kernel has no stdlib; this keeps DLL name
// matching case-insensitive without pulling in <cctype>.
inline char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c + ('a' - 'A'));
    return c;
}

// Case-insensitive strcmp for DLL names. Matches Win32
// convention — lld-link emits "CUSTOMDLL.dll" or
// "customdll.dll" inconsistently across toolchains.
bool DllNameEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return a == b;
    while (*a && *b)
    {
        if (AsciiToLower(*a) != AsciiToLower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

} // namespace

bool ProcessRegisterDllImage(Process* proc, const DllImage& image)
{
    if (proc == nullptr)
        return false;
    if (proc->dll_image_count >= Process::kDllImageCap)
    {
        arch::SerialWrite("[proc] dll-table FULL pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" cap=");
        arch::SerialWriteHex(Process::kDllImageCap);
        arch::SerialWrite("\n");
        return false;
    }
    proc->dll_images[proc->dll_image_count] = image;
    ++proc->dll_image_count;
    return true;
}

u64 ProcessResolveDllExport(const Process* proc, const char* dll_name, const char* func_name)
{
    if (proc == nullptr || func_name == nullptr)
        return 0;
    for (u64 i = 0; i < proc->dll_image_count; ++i)
    {
        const DllImage& img = proc->dll_images[i];
        if (!img.has_exports)
            continue;
        if (dll_name != nullptr)
        {
            const char* name = PeExportsDllName(img.exports);
            if (!DllNameEq(name, dll_name))
                continue;
        }
        PeExport e{};
        if (!PeExportLookupName(img.exports, func_name, e))
            continue;
        if (e.is_forwarder)
        {
            // Chase the forwarder through the rest of the process's
            // DLL table. The shared resolver handles both name- and
            // ordinal-form forwarders and bounds against cycles.
            const char* fwd_dll = PeExportsDllName(img.exports);
            u64 va = 0;
            if (PeResolveViaDlls(fwd_dll, func_name, proc->dll_images, proc->dll_image_count, &va))
                return va;
            return 0;
        }
        return img.base_va + static_cast<u64>(e.rva);
    }
    return 0;
}

u64 ProcessResolveDllExportByBase(const Process* proc, u64 base_va, const char* func_name)
{
    if (proc == nullptr || func_name == nullptr)
        return 0;
    for (u64 i = 0; i < proc->dll_image_count; ++i)
    {
        const DllImage& img = proc->dll_images[i];
        if (!img.has_exports)
            continue;
        if (base_va != 0 && img.base_va != base_va)
            continue;
        PeExport e{};
        if (!PeExportLookupName(img.exports, func_name, e))
            continue;
        if (e.is_forwarder)
        {
            const char* fwd_dll = PeExportsDllName(img.exports);
            u64 va = 0;
            if (PeResolveViaDlls(fwd_dll, func_name, proc->dll_images, proc->dll_image_count, &va))
                return va;
            return 0;
        }
        return img.base_va + static_cast<u64>(e.rva);
    }
    return 0;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    arch::SerialWrite("[process-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    Panic("core/process", "ProcessSelfTest assertion failed");
}

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return a == b;
    }
    while (*a && *b)
    {
        if (*a != *b)
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

} // namespace

void ProcessSelfTest()
{
    KLOG_TRACE_SCOPE("core/process", "ProcessSelfTest");

    // ----- CapSet bitmap basics -----
    {
        constexpr CapSet empty = CapSetEmpty();
        Expect(empty.bits == 0, "CapSetEmpty.bits == 0");
        Expect(!CapSetHas(empty, kCapSerialConsole), "empty has no SerialConsole");
        Expect(!CapSetHas(empty, kCapFsRead), "empty has no FsRead");
        Expect(!CapSetHas(empty, kCapFsWrite), "empty has no FsWrite");
        Expect(!CapSetHas(empty, kCapDebug), "empty has no Debug");
        Expect(!CapSetHas(empty, kCapSpawnThread), "empty has no SpawnThread");
    }
    {
        constexpr CapSet trusted = CapSetTrusted();
        Expect(trusted.bits != 0, "CapSetTrusted not empty");
        Expect(CapSetHas(trusted, kCapSerialConsole), "trusted has SerialConsole");
        Expect(CapSetHas(trusted, kCapFsRead), "trusted has FsRead");
        Expect(CapSetHas(trusted, kCapFsWrite), "trusted has FsWrite");
        Expect(CapSetHas(trusted, kCapDebug), "trusted has Debug");
        Expect(CapSetHas(trusted, kCapSpawnThread), "trusted has SpawnThread");
    }

    // ----- Boundary cases on the cap enum -----
    {
        CapSet s = CapSetEmpty();
        // kCapNone never enters the bitmap — it's the "no cap" sentinel.
        CapSetAdd(s, kCapNone);
        Expect(s.bits == 0, "CapSetAdd(kCapNone) is a no-op");
        Expect(!CapSetHas(s, kCapNone), "CapSetHas(kCapNone) is false");

        // kCapCount is the boundary marker, never live.
        CapSetAdd(s, kCapCount);
        Expect(s.bits == 0, "CapSetAdd(kCapCount) is a no-op");
        Expect(!CapSetHas(s, kCapCount), "CapSetHas(kCapCount) is false");
    }

    // ----- CapSetAdd accumulates without disturbing other bits -----
    {
        CapSet s = CapSetEmpty();
        CapSetAdd(s, kCapSerialConsole);
        Expect(CapSetHas(s, kCapSerialConsole), "after Add SerialConsole, set");
        Expect(!CapSetHas(s, kCapFsRead), "after Add SerialConsole, FsRead unset");
        CapSetAdd(s, kCapFsRead);
        Expect(CapSetHas(s, kCapSerialConsole), "after second Add, SerialConsole still set");
        Expect(CapSetHas(s, kCapFsRead), "after Add FsRead, set");
        // Adding the same cap twice is a no-op.
        const u64 before = s.bits;
        CapSetAdd(s, kCapSerialConsole);
        Expect(s.bits == before, "double-Add is idempotent");
    }

    // ----- CapName: every defined cap returns a real string -----
    Expect(StrEq(CapName(kCapNone), "<none>"), "CapName(kCapNone) == <none>");
    Expect(StrEq(CapName(kCapSerialConsole), "SerialConsole"), "CapName(SerialConsole)");
    Expect(StrEq(CapName(kCapFsRead), "FsRead"), "CapName(FsRead)");
    Expect(StrEq(CapName(kCapDebug), "Debug"), "CapName(Debug)");
    Expect(StrEq(CapName(kCapFsWrite), "FsWrite"), "CapName(FsWrite)");
    Expect(StrEq(CapName(kCapSpawnThread), "SpawnThread"), "CapName(SpawnThread)");
    Expect(StrEq(CapName(kCapCount), "<sentinel>"), "CapName(kCapCount) == <sentinel>");

    // Catches "added an enum value, forgot the switch arm" — every
    // entry from 1 to kCapCount must produce a non-fallback name.
    for (u32 c = 1; c < static_cast<u32>(kCapCount); ++c)
    {
        const char* name = CapName(static_cast<Cap>(c));
        Expect(name != nullptr, "CapName non-null");
        Expect(!StrEq(name, "<unknown>"), "CapName covers every enumerator");
    }

    // ----- ShouldLogDenial rate-limit (1st, then every 32nd) -----
    Expect(ShouldLogDenial(1), "denial #1 logs");
    Expect(!ShouldLogDenial(2), "denial #2 silent");
    Expect(!ShouldLogDenial(31), "denial #31 silent");
    Expect(ShouldLogDenial(32), "denial #32 logs");
    Expect(!ShouldLogDenial(33), "denial #33 silent");
    Expect(ShouldLogDenial(64), "denial #64 logs");
    Expect(ShouldLogDenial(96), "denial #96 logs");
    Expect(ShouldLogDenial(kSandboxDenialKillThreshold - 4), "denial near threshold logs (96)");

    arch::SerialWrite("[process-selftest] PASS (CapSet + CapName + ShouldLogDenial)\n");
}

} // namespace duetos::core
