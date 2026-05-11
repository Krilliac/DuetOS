#include "apps/dbg_core.h"

#include "arch/x86_64/traps.h"
#include "diag/hexdump.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/symbols.h"
#include "util/types.h"

// Kernel .text bounds, populated by the linker script. Used by
// the kernel-mode scan path (kKernelPid → ScanBytes walks
// [_text_start, _text_end) instead of an AddressSpace).
extern "C" duetos::u8 _text_start[];
extern "C" duetos::u8 _text_end[];

// Embedded symbol table — declared in util/symbols.cpp.
namespace duetos::core
{
extern "C" const SymbolEntry g_duetos_symtab_entries[];
extern "C" const u64 g_duetos_symtab_count;
} // namespace duetos::core

namespace duetos::apps::dbg::core
{

namespace
{

// File-scope watchlist. Single-app, single-table — protected by
// a small spinlock so the timer-driven Refresh and the operator-
// driven Add/Remove can't tear each other up.
sync::SpinLock g_watch_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};
WatchEntry g_watch[kWatchMax]{};

void StrCopyTrunc(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    while (src[i] != 0 && i + 1 < cap)
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = 0;
}

// Format `value` as "0xN" hex into dst (NUL-terminated).
void FormatHex(char* dst, u32 cap, u64 value)
{
    static const char kHex[] = "0123456789abcdef";
    if (cap < 4)
    {
        if (cap > 0)
            dst[0] = 0;
        return;
    }
    dst[0] = '0';
    dst[1] = 'x';
    if (value == 0)
    {
        dst[2] = '0';
        dst[3] = 0;
        return;
    }
    char tmp[18];
    u32 n = 0;
    while (value != 0 && n < 16)
    {
        tmp[n++] = kHex[value & 0xF];
        value >>= 4;
    }
    u32 w = 2;
    while (n > 0 && w + 1 < cap)
        dst[w++] = tmp[--n];
    dst[w] = 0;
}

void FormatBytesHex(char* dst, u32 cap, const u8* bytes, u8 n)
{
    static const char kHex[] = "0123456789abcdef";
    u32 w = 0;
    for (u8 i = 0; i < n && w + 3 < cap; ++i)
    {
        if (i != 0 && w + 1 < cap)
            dst[w++] = ' ';
        dst[w++] = kHex[(bytes[i] >> 4) & 0xF];
        dst[w++] = kHex[bytes[i] & 0xF];
    }
    if (w < cap)
        dst[w] = 0;
    else if (cap > 0)
        dst[cap - 1] = 0;
}

} // namespace

namespace
{

// Cookie for the SchedEnumerate-driven process walk. We collect
// distinct owner_pids (from process-backed tasks) into a small
// dedupe set, then materialise each as a ProcInfo row in a second
// pass. Avoids the wasteful PID 0..1023 iteration and finds
// processes whose pids fall outside any pre-baked range.
struct ProcCollector
{
    u64 seen_pids[64];
    usize seen_count;
};

void OnSchedEnumProc(const sched::SchedTaskInfo& info, void* cookie)
{
    auto* c = static_cast<ProcCollector*>(cookie);
    if (c == nullptr || !info.has_process || info.owner_pid == 0)
        return;
    if (c->seen_count >= sizeof(c->seen_pids) / sizeof(c->seen_pids[0]))
        return;
    for (usize i = 0; i < c->seen_count; ++i)
    {
        if (c->seen_pids[i] == info.owner_pid)
            return; // already seen via another thread of the same proc
    }
    c->seen_pids[c->seen_count++] = info.owner_pid;
}

} // namespace

usize EnumerateProcesses(ProcInfo* out, usize cap)
{
    if (out == nullptr || cap == 0)
        return 0;

    // Pass 1 — walk every task once, collect distinct owning pids.
    ProcCollector coll{};
    sched::SchedEnumerate(&OnSchedEnumProc, &coll);

    // Pass 2 — materialise each pid as a ProcInfo row. Dropping
    // the per-pid SchedFindProcessByPid call on the hot path
    // would let us populate from a single Task* during pass 1,
    // but exposing that requires a Task accessor — overkill for
    // a debug surface.
    usize count = 0;
    for (usize i = 0; i < coll.seen_count && count < cap; ++i)
    {
        ::duetos::core::Process* p = sched::SchedFindProcessByPid(coll.seen_pids[i]);
        if (p == nullptr)
            continue;
        ProcInfo& row = out[count];
        row.pid = p->pid;
        StrCopyTrunc(row.name, sizeof(row.name), p->name != nullptr ? p->name : "?");
        row.state = sched::SchedIsPidZombie(p->pid) ? 3 : 0;
        row.ticks_used = p->ticks_used;
        row.region_count = p->as != nullptr ? p->as->region_count : 0;
        ++count;
    }
    return count;
}

bool LookupProcess(u64 pid, ProcInfo* out)
{
    if (out == nullptr)
        return false;
    ::duetos::core::Process* p = sched::SchedFindProcessByPid(pid);
    if (p == nullptr)
        return false;
    out->pid = p->pid;
    StrCopyTrunc(out->name, sizeof(out->name), p->name != nullptr ? p->name : "?");
    out->state = sched::SchedIsPidZombie(pid) ? 3 : 0;
    out->ticks_used = p->ticks_used;
    out->region_count = p->as != nullptr ? p->as->region_count : 0;
    return true;
}

// ---- ReadMem / WriteMem -------------------------------------

namespace
{

// Cross-AS user memory access via the kernel direct-map alias of
// the backing frame. Returns nullptr if the page isn't mapped in
// `as`. Identical strategy to BpReadMem's helper, but parameterised
// on AddressSpace* so non-suspended targets work too.
const u8* ResolveUserByteRO(mm::AddressSpace* as, u64 user_va)
{
    if (as == nullptr)
        return nullptr;
    const u64 page_va = user_va & ~0xFFFULL;
    mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, page_va);
    if (frame == mm::kNullFrame)
        return nullptr;
    const u8* page = static_cast<const u8*>(mm::PhysToVirt(frame));
    return page + (user_va & 0xFFF);
}

u8* ResolveUserByteRW(mm::AddressSpace* as, u64 user_va)
{
    return const_cast<u8*>(ResolveUserByteRO(as, user_va));
}

} // namespace

u64 ReadMem(u64 pid, u64 va, u8* out, u64 len)
{
    if (out == nullptr || len == 0)
        return 0;

    // Kernel-mode read: walk the page directly via the higher-half
    // mapping, gated by PlausibleKernelAddress so a wild VA can't
    // nest a #PF inside the read. The plausibility check covers
    // the higher-half direct map + MMIO arena; anything else is
    // refused.
    if (pid == kKernelPid)
    {
        u64 copied = 0;
        while (copied < len)
        {
            const u64 page_va = (va + copied) & ~0xFFFULL;
            if (!::duetos::core::PlausibleKernelAddress(page_va))
                break;
            const u8* src = reinterpret_cast<const u8*>(va + copied);
            const u64 page_off = (va + copied) & 0xFFFULL;
            const u64 page_room = 0x1000 - page_off;
            u64 chunk = len - copied;
            if (chunk > page_room)
                chunk = page_room;
            for (u64 i = 0; i < chunk; ++i)
                out[copied + i] = src[i];
            copied += chunk;
        }
        return copied;
    }

    ::duetos::core::Process* p = sched::SchedFindProcessByPid(pid);
    if (p == nullptr || p->as == nullptr)
        return 0;
    u64 copied = 0;
    while (copied < len)
    {
        const u8* src = ResolveUserByteRO(p->as, va + copied);
        if (src == nullptr)
            break;
        const u64 page_off = (va + copied) & 0xFFFULL;
        const u64 page_room = 0x1000 - page_off;
        u64 chunk = len - copied;
        if (chunk > page_room)
            chunk = page_room;
        for (u64 i = 0; i < chunk; ++i)
            out[copied + i] = src[i];
        copied += chunk;
    }
    return copied;
}

u64 WriteMem(u64 pid, u64 va, const u8* in, u64 len)
{
    if (in == nullptr || len == 0)
        return 0;
    // Kernel-mode write is intentionally NOT supported through this
    // path — patching .text is the breakpoint subsystem's job (it
    // owns the W-window dance under spinlock); patching .data /
    // .bss arbitrarily is a footgun even with kCapDebug. If a
    // future operator workflow legitimately needs it, route it
    // through the breakpoint subsystem's PokeByte path.
    if (pid == kKernelPid)
        return 0;
    ::duetos::core::Process* p = sched::SchedFindProcessByPid(pid);
    if (p == nullptr || p->as == nullptr)
        return 0;
    u64 copied = 0;
    while (copied < len)
    {
        u8* dst = ResolveUserByteRW(p->as, va + copied);
        if (dst == nullptr)
            break;
        const u64 page_off = (va + copied) & 0xFFFULL;
        const u64 page_room = 0x1000 - page_off;
        u64 chunk = len - copied;
        if (chunk > page_room)
            chunk = page_room;
        for (u64 i = 0; i < chunk; ++i)
            dst[i] = in[copied + i];
        copied += chunk;
    }
    return copied;
}

// ---- Scan ---------------------------------------------------

usize ScanBytes(u64 pid, const u8* needle, usize nlen, u64* hits, usize cap)
{
    if (needle == nullptr || nlen == 0 || hits == nullptr || cap == 0)
        return 0;
    if (cap > kScanResultCap)
        cap = kScanResultCap;
    usize hit_count = 0;

    // Kernel-mode scan: sweep .text. The same bounds the breakpoint
    // subsystem uses for software-BP installs. Reads are linear
    // and direct — no AS walks.
    if (pid == kKernelPid)
    {
        const u8* lo = _text_start;
        const u8* hi = _text_end;
        if (hi <= lo)
            return 0;
        const u64 size = (u64)(hi - lo);
        for (u64 off = 0; off + nlen <= size && hit_count < cap; ++off)
        {
            bool match = true;
            for (usize k = 0; k < nlen; ++k)
            {
                if (lo[off + k] != needle[k])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                hits[hit_count++] = reinterpret_cast<u64>(lo + off);
        }
        return hit_count;
    }

    ::duetos::core::Process* p = sched::SchedFindProcessByPid(pid);
    if (p == nullptr || p->as == nullptr)
        return 0;
    mm::AddressSpace* as = p->as;
    // Walk the regions ledger. Each region is a 4 KiB page; we
    // scan within each page and across page boundaries within a
    // region by re-resolving every 4 KiB.
    for (u16 r = 0; r < as->region_count && hit_count < cap; ++r)
    {
        const u64 base = as->regions[r].vaddr;
        const u8* page = ResolveUserByteRO(as, base);
        if (page == nullptr)
            continue;
        // Scan the 4 KiB page; tail-spill match must fit before
        // the page end (we deliberately don't span pages here —
        // a needle straddling a page boundary won't match. That's
        // a known v0 GAP; documented in the Disasm wiki page.
        for (u64 off = 0; off + nlen <= 0x1000 && hit_count < cap; ++off)
        {
            bool match = true;
            for (usize k = 0; k < nlen; ++k)
            {
                if (page[off + k] != needle[k])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                hits[hit_count++] = base + off;
        }
    }
    return hit_count;
}

usize ScanNext(u64 pid, const u8* needle, usize nlen, const u64* prev_hits, usize prev_count, u64* out_hits, usize cap)
{
    if (needle == nullptr || nlen == 0 || prev_hits == nullptr || out_hits == nullptr || cap == 0)
        return 0;
    if (cap > kScanResultCap)
        cap = kScanResultCap;
    usize kept = 0;
    u8 buf[16];
    if (nlen > sizeof(buf))
        return 0;
    for (usize i = 0; i < prev_count && kept < cap; ++i)
    {
        const u64 got = ReadMem(pid, prev_hits[i], buf, nlen);
        if (got != nlen)
            continue;
        bool match = true;
        for (usize k = 0; k < nlen; ++k)
        {
            if (buf[k] != needle[k])
            {
                match = false;
                break;
            }
        }
        if (match)
            out_hits[kept++] = prev_hits[i];
    }
    return kept;
}

// ---- Disasm -------------------------------------------------

u64 DisasmRows(u64 pid, u64 va, debug::disasm::DecodedInsn* out, u64 row_cap)
{
    if (out == nullptr || row_cap == 0)
        return 0;
    // Pull a 256-byte window — enough for ~32 average-length
    // x86_64 instructions, well above the typical Disasm-tab
    // viewport. Capping the buffer keeps the decoder allocation-
    // free and bounded.
    static constexpr u64 kWindow = 256;
    u8 buf[kWindow];
    const u64 got = ReadMem(pid, va, buf, kWindow);
    if (got == 0)
        return 0;
    return debug::disasm::DecodeStream(buf, got, va, out, row_cap);
}

// ---- Breakpoints --------------------------------------------

debug::BreakpointId InstallBp(u64 va, debug::BpKind kind, debug::BpLen len, u64 owner_pid, bool suspend,
                              debug::BpError* err, debug::BpInstallFlags flags)
{
    if (kind == debug::BpKind::Software)
    {
        return debug::BpInstallSoftware(va, suspend, err, /*on_hit=*/nullptr, flags);
    }
    return debug::BpInstallHardware(va, kind, len, owner_pid, suspend, err, /*on_hit=*/nullptr, flags);
}

debug::BpError RemoveBp(debug::BreakpointId id, u64 requester_pid)
{
    return debug::BpRemove(id, requester_pid);
}

debug::BpError ResumeBp(debug::BreakpointId id)
{
    return debug::BpResume(id);
}

debug::BpError StepBp(debug::BreakpointId id)
{
    return debug::BpStep(id);
}

usize ListBp(debug::BpInfo* out, usize cap)
{
    return debug::BpList(out, cap);
}

// ---- Regs ---------------------------------------------------

bool RegsRead(debug::BreakpointId id, arch::TrapFrame* out)
{
    return debug::BpReadRegs(id, out);
}

debug::BpError RegsWrite(debug::BreakpointId id, const arch::TrapFrame* in)
{
    return debug::BpWriteRegs(id, in);
}

// ---- Watch --------------------------------------------------

u32 WatchAdd(u64 pid, u64 va, u8 len, WatchType type, const char* name)
{
    if (name == nullptr || name[0] == 0)
        return 0xFFFFFFFFu;
    if (len == 0 || len > 16)
        len = 4;
    sync::SpinLockGuard g(g_watch_lock);
    for (u32 i = 0; i < kWatchMax; ++i)
    {
        if (!g_watch[i].used)
        {
            g_watch[i].used = true;
            g_watch[i].pid = pid;
            g_watch[i].va = va;
            g_watch[i].len = len;
            g_watch[i].type = type;
            StrCopyTrunc(g_watch[i].name, sizeof(g_watch[i].name), name);
            StrCopyTrunc(g_watch[i].value, sizeof(g_watch[i].value), "n/a");
            return i;
        }
    }
    return 0xFFFFFFFFu;
}

bool WatchRemove(u32 slot)
{
    if (slot >= kWatchMax)
        return false;
    sync::SpinLockGuard g(g_watch_lock);
    if (!g_watch[slot].used)
        return false;
    g_watch[slot].used = false;
    return true;
}

void WatchRefresh()
{
    sync::SpinLockGuard g(g_watch_lock);
    for (u32 i = 0; i < kWatchMax; ++i)
    {
        if (!g_watch[i].used)
            continue;
        WatchEntry& e = g_watch[i];
        u8 raw[16];
        u8 want = e.len;
        switch (e.type)
        {
        case WatchType::U8:
            want = 1;
            break;
        case WatchType::U16:
            want = 2;
            break;
        case WatchType::U32:
        case WatchType::I32:
            want = 4;
            break;
        case WatchType::U64:
        case WatchType::I64:
            want = 8;
            break;
        case WatchType::Bytes:
            // already set
            break;
        }
        if (want > sizeof(raw))
            want = sizeof(raw);
        const u64 got = ReadMem(e.pid, e.va, raw, want);
        if (got != want)
        {
            StrCopyTrunc(e.value, sizeof(e.value), "n/a");
            continue;
        }
        u64 vu = 0;
        for (u8 b = 0; b < want; ++b)
            vu |= ((u64)raw[b]) << (b * 8);
        switch (e.type)
        {
        case WatchType::U8:
        case WatchType::U16:
        case WatchType::U32:
        case WatchType::U64:
            FormatHex(e.value, sizeof(e.value), vu);
            break;
        case WatchType::I32:
        case WatchType::I64:
        {
            // Reformat as signed if MSB set.
            i64 sv = (e.type == WatchType::I32) ? (i64)(i32)(u32)vu : (i64)vu;
            char tmp[32];
            // Tiny signed decimal formatter.
            u32 w = 0;
            if (sv < 0)
            {
                tmp[w++] = '-';
                sv = -sv;
            }
            char rev[24];
            u32 n = 0;
            if (sv == 0)
                rev[n++] = '0';
            while (sv != 0 && n < sizeof(rev))
            {
                rev[n++] = (char)('0' + (sv % 10));
                sv /= 10;
            }
            while (n > 0 && w + 1 < sizeof(tmp))
                tmp[w++] = rev[--n];
            tmp[w] = 0;
            StrCopyTrunc(e.value, sizeof(e.value), tmp);
            break;
        }
        case WatchType::Bytes:
            FormatBytesHex(e.value, sizeof(e.value), raw, want);
            break;
        }
    }
}

const WatchEntry* WatchSlot(u32 slot)
{
    if (slot >= kWatchMax)
        return nullptr;
    return &g_watch[slot];
}

usize WatchCount()
{
    usize n = 0;
    for (u32 i = 0; i < kWatchMax; ++i)
        if (g_watch[i].used)
            ++n;
    return n;
}

// ---- Threads / symbols / system overview --------------------

namespace
{

// Cookie passed to the SchedEnumerate callback while
// EnumerateThreads is running. We collect into a caller-supplied
// buffer; the cap+count protect against overflow when the system
// has more tasks than the GUI viewport can show.
struct ThreadsCollector
{
    ThreadInfo* out;
    usize cap;
    usize count;
};

void OnSchedEnumThread(const sched::SchedTaskInfo& info, void* cookie)
{
    auto* c = static_cast<ThreadsCollector*>(cookie);
    if (c == nullptr || c->count >= c->cap)
        return;
    ThreadInfo& row = c->out[c->count];
    row.tid = info.id;
    row.ticks_run = info.ticks_run;
    row.state = info.state;
    row.priority = info.priority;
    row.is_running = info.is_running;
    StrCopyTrunc(row.name, sizeof(row.name), info.name != nullptr ? info.name : "?");
    ++c->count;
}

// Case-sensitive substring match. Returns true iff `needle` is
// empty or appears anywhere in `hay`. Both must be NUL-terminated.
bool Contains(const char* hay, const char* needle)
{
    if (needle == nullptr || needle[0] == 0)
        return true;
    if (hay == nullptr)
        return false;
    for (u32 i = 0; hay[i] != 0; ++i)
    {
        u32 j = 0;
        while (needle[j] != 0 && hay[i + j] == needle[j])
            ++j;
        if (needle[j] == 0)
            return true;
    }
    return false;
}

} // namespace

usize EnumerateThreads(ThreadInfo* out, usize cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    ThreadsCollector c{out, cap, 0};
    sched::SchedEnumerate(&OnSchedEnumThread, &c);
    return c.count;
}

usize EnumerateSymbols(SymbolRow* out, usize cap, u64 start, const char* filter)
{
    if (out == nullptr || cap == 0)
        return 0;
    const u64 total = ::duetos::core::g_duetos_symtab_count;
    usize written = 0;
    u64 visited = 0;
    for (u64 i = 0; i < total && written < cap; ++i)
    {
        const auto& e = ::duetos::core::g_duetos_symtab_entries[i];
        if (filter != nullptr && filter[0] != 0 && !Contains(e.name, filter))
            continue;
        if (visited++ < start)
            continue;
        out[written].addr = e.addr;
        out[written].size = e.size;
        out[written].line = e.line;
        out[written].name = e.name;
        out[written].file = e.file;
        ++written;
    }
    return written;
}

u64 KernelSymbolCount()
{
    return ::duetos::core::g_duetos_symtab_count;
}

void GetKernelOverview(KernelOverview* out)
{
    if (out == nullptr)
        return;
    const auto h = mm::KernelHeapStatsRead();
    const auto s = sched::SchedStatsRead();
    out->heap_pool_bytes = h.pool_bytes;
    out->heap_used_bytes = h.used_bytes;
    out->heap_free_bytes = h.free_bytes;
    out->heap_alloc_count = h.alloc_count;
    out->heap_free_count = h.free_count;
    out->heap_largest_free_run = h.largest_free_run;
    out->sched_context_switches = s.context_switches;
    out->sched_tasks_live = s.tasks_live;
    out->sched_tasks_sleeping = s.tasks_sleeping;
    out->sched_tasks_blocked = s.tasks_blocked;
    out->sched_tasks_created = s.tasks_created;
    out->sched_tasks_exited = s.tasks_exited;
    out->sched_tasks_reaped = s.tasks_reaped;
    out->sched_total_ticks = s.total_ticks;
    out->sched_idle_ticks = s.idle_ticks;
    out->symbol_count = ::duetos::core::g_duetos_symtab_count;
    out->text_start = reinterpret_cast<u64>(_text_start);
    out->text_end = reinterpret_cast<u64>(_text_end);
}

} // namespace duetos::apps::dbg::core
