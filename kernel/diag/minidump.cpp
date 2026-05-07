#include "diag/minidump.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "core/panic.h"
#include "diag/debugcon.h"
#include "diag/fix_journal_persist.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/nvme.h"
#include "loader/dll_loader.h"
#include "loader/pe_exports.h"
#include "mm/address_space.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

/*
 * Microsoft minidump format implementation.
 *
 * On-wire structure (every offset/size known at write time):
 *
 *   +0x000  MINIDUMP_HEADER                  (32 bytes)
 *   +0x020  MINIDUMP_DIRECTORY × NumberOfStreams
 *   +0xXXX  stream bodies (in declaration order):
 *               SystemInfoStream
 *               ExceptionStream
 *               ThreadListStream
 *               ModuleListStream
 *               MemoryListStream
 *   +0xYYY  out-of-line blobs the streams point at:
 *               CONTEXT_X64
 *               module name strings (UTF-16LE, length-prefixed)
 *               raw memory bytes
 *
 * No padding rules to honour — everything is byte-aligned RVA
 * arithmetic. We hand-serialise field-by-field through
 * `Cursor::WriteU16/U32/U64/Bytes/Zero` so the layout is
 * grep-visible and not at the mercy of struct packing flags.
 */

namespace duetos::diag::minidump
{

namespace
{

// ---------- Format constants (Microsoft "minidumpapiset.h") ----------
constexpr u32 kMinidumpSignature = 0x504D444D; // 'PMDM' (LE 'MDMP')
constexpr u32 kMinidumpVersion = 0x0000A793;

// Stream type IDs (subset).
constexpr u32 kStreamThreadList = 3;
constexpr u32 kStreamModuleList = 4;
constexpr u32 kStreamMemoryList = 5;
constexpr u32 kStreamException = 6;
constexpr u32 kStreamSystemInfo = 7;

// CONTEXT flags (CONTEXT_AMD64 + INTEGER + CONTROL + SEGMENTS).
constexpr u32 kContextAmd64 = 0x00100000;
constexpr u32 kContextControl = kContextAmd64 | 0x1;
constexpr u32 kContextInteger = kContextAmd64 | 0x2;
constexpr u32 kContextSegments = kContextAmd64 | 0x4;
constexpr u32 kContextOurFlags = kContextControl | kContextInteger | kContextSegments;

// PROCESSOR_ARCHITECTURE_AMD64
constexpr u16 kProcArchAmd64 = 9;
// VER_PLATFORM_WIN32_NT
constexpr u32 kPlatformWin32Nt = 2;

// NTSTATUS-shaped fallback for non-trap panics.
constexpr u32 kStatusBreakpoint = 0x80000003;

// CONTEXT_X64 size per Windows ABI.
constexpr u64 kContextX64Bytes = 0x4D0; // 1232

// Stream count we always emit.
constexpr u32 kStreamCount = 5;

// Memory ranges we capture: stack (~16 KiB) + RIP page (~4 KiB).
constexpr u64 kStackBytesToCapture = 16 * 1024;
constexpr u64 kRipPageBytes = 4096;

// Module cap mirrors Process::kDllImageCap. Going over would
// be honoured by the writer (it just walks proc->dll_image_count)
// but capping the cursor reservations against the buffer size
// stays simpler with a known bound.
constexpr u64 kMaxModulesEmitted = 64;

// ---------- Static dump buffer ----------
constinit u8 g_buf[kMinidumpBufBytes] = {};
constinit u64 g_used = 0;

// Scratch buffers for the SafeReadInto stack + RIP-page captures.
// Living in .bss avoids a 16 KiB+4 KiB allocation against the
// kernel stack on the panic path (boot stack is finite, and a
// post-panic stack-overflow in the dumper would lose the whole
// artefact). Single-CPU access is fine — peer CPUs are NMI-halted
// by the time we get here.
constinit u8 g_stack_scratch[16 * 1024] = {};
constinit u8 g_rip_scratch[4096] = {};

class Cursor
{
  public:
    void Reset() { g_used = 0; }

    u32 Tell() const { return static_cast<u32>(g_used); }

    bool Reserve(u64 bytes) { return g_used + bytes <= kMinidumpBufBytes; }

    void Pad(u64 bytes)
    {
        if (!Reserve(bytes))
            return;
        for (u64 i = 0; i < bytes; ++i)
            g_buf[g_used++] = 0;
    }

    void WriteU8(u8 v)
    {
        if (!Reserve(1))
            return;
        g_buf[g_used++] = v;
    }

    void WriteU16(u16 v)
    {
        WriteU8(static_cast<u8>(v & 0xFF));
        WriteU8(static_cast<u8>((v >> 8) & 0xFF));
    }

    void WriteU32(u32 v)
    {
        WriteU16(static_cast<u16>(v & 0xFFFF));
        WriteU16(static_cast<u16>((v >> 16) & 0xFFFF));
    }

    void WriteU64(u64 v)
    {
        WriteU32(static_cast<u32>(v & 0xFFFFFFFFu));
        WriteU32(static_cast<u32>((v >> 32) & 0xFFFFFFFFu));
    }

    void WriteBytes(const u8* p, u64 n)
    {
        for (u64 i = 0; i < n; ++i)
            WriteU8(p[i]);
    }

    void Patch32(u32 at, u32 v)
    {
        if (at + 4 > g_used)
            return;
        g_buf[at + 0] = static_cast<u8>(v & 0xFF);
        g_buf[at + 1] = static_cast<u8>((v >> 8) & 0xFF);
        g_buf[at + 2] = static_cast<u8>((v >> 16) & 0xFF);
        g_buf[at + 3] = static_cast<u8>((v >> 24) & 0xFF);
    }
};

// ---------- Helpers ----------

// Conservative "is this a kernel address we can read without
// faulting?" check — same shape as the panic path's
// PlausibleStackPointer. Used for stack capture and the RIP
// page. The minidump is best-effort: if a captured range
// would deref into an unmapped page we emit zeroes instead so
// the writer never touches a region that could trip a
// secondary fault.
bool ReadableKernelAddr(u64 va)
{
    if (va == 0)
        return false;
    if (va >= 0xFFFF800000000000ULL)
        return true;
    if (va < 0x40000000ULL)
        return true;
    return false;
}

// Read up to `n` bytes from `va` into `dst`. Returns the count
// actually safe-to-read (probed via SnapshotPageWalk per page).
// Bytes that fall in unmapped pages are zero-filled in `dst`
// but still counted toward the length so the offset math in
// the dump stays predictable.
u64 SafeReadInto(u64 va, u8* dst, u64 n)
{
    u64 i = 0;
    while (i < n)
    {
        const u64 cur = va + i;
        const u64 page = cur & ~0xFFFULL;
        const auto walk = ::duetos::mm::SnapshotPageWalk(page);
        const bool present = walk.stop == ::duetos::mm::PageWalkStop::FourKiB ||
                             walk.stop == ::duetos::mm::PageWalkStop::TwoMiB ||
                             walk.stop == ::duetos::mm::PageWalkStop::OneGiB;
        const u64 in_page = 0x1000 - (cur & 0xFFFULL);
        const u64 chunk = (in_page < (n - i)) ? in_page : (n - i);
        if (present && ReadableKernelAddr(cur))
        {
            const u8* src = reinterpret_cast<const u8*>(cur);
            for (u64 j = 0; j < chunk; ++j)
                dst[i + j] = src[j];
        }
        else
        {
            for (u64 j = 0; j < chunk; ++j)
                dst[i + j] = 0;
        }
        i += chunk;
    }
    return i;
}

// Write a MINIDUMP_STRING (u32 byte-length + UTF-16LE buffer +
// NUL terminator) at the cursor and return its starting RVA.
u32 WriteString(Cursor& c, const char* s)
{
    const u32 rva = c.Tell();
    u32 char_count = 0;
    if (s != nullptr)
    {
        for (const char* p = s; *p != '\0'; ++p)
            ++char_count;
    }
    const u32 byte_len = char_count * 2;
    c.WriteU32(byte_len);
    if (s != nullptr)
    {
        for (u32 i = 0; i < char_count; ++i)
        {
            // ASCII passthrough — DuetOS DLL names are all ASCII
            // (kernel32.dll, ntdll.dll, …). Anything > 0x7F gets
            // truncated to a '?' so we never produce invalid UTF-16.
            const u8 ch = static_cast<u8>(s[i]);
            c.WriteU16(ch < 0x80 ? ch : '?');
        }
    }
    // NUL terminator (one UTF-16 code unit).
    c.WriteU16(0);
    return rva;
}

// Snapshot of the registers we want to put in CONTEXT_X64.
// Populated by callers from either a soft-panic call site
// (only rip/rsp/rbp known, rest defaulted to 0) or from a
// CPU-exception TrapFrame (every field meaningful).
struct ContextRegs
{
    u64 rax;
    u64 rcx;
    u64 rdx;
    u64 rbx;
    u64 rsp;
    u64 rbp;
    u64 rsi;
    u64 rdi;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 rip;
    u64 rflags;
    u16 cs;
    u16 ds;
    u16 es;
    u16 fs;
    u16 gs;
    u16 ss;
};

// Write a CONTEXT_X64 block (1232 bytes) for the faulting frame
// and return the RVA of its start. Layout follows the public
// Windows CONTEXT structure exactly. Only the bits we set in
// ContextFlags carry meaningful values; FP / vector regions
// stay zero (kernel runs `-mno-sse`).
u32 WriteContextX64(Cursor& c, const ContextRegs& r)
{
    const u32 rva = c.Tell();
    if (!c.Reserve(kContextX64Bytes))
        return rva;

    // 0x000..0x030: P{1..6}Home (6 × u64, zero-fill).
    c.Pad(0x30);
    // 0x030: ContextFlags
    c.WriteU32(kContextOurFlags);
    // 0x034: MxCsr
    c.WriteU32(0);
    // 0x038..0x044: CS / DS / ES / FS / GS / SS
    c.WriteU16(r.cs);
    c.WriteU16(r.ds);
    c.WriteU16(r.es);
    c.WriteU16(r.fs);
    c.WriteU16(r.gs);
    c.WriteU16(r.ss);
    // 0x044: EFlags
    c.WriteU32(static_cast<u32>(r.rflags & 0xFFFFFFFFu));
    // 0x048..0x078: Dr0..Dr7 (Dr4/Dr5 reserved → not in struct;
    // layout is Dr0,Dr1,Dr2,Dr3,Dr6,Dr7).
    for (u32 i = 0; i < 6; ++i)
        c.WriteU64(0);
    // 0x078..0x100: Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8..R15, Rip
    c.WriteU64(r.rax);
    c.WriteU64(r.rcx);
    c.WriteU64(r.rdx);
    c.WriteU64(r.rbx);
    c.WriteU64(r.rsp);
    c.WriteU64(r.rbp);
    c.WriteU64(r.rsi);
    c.WriteU64(r.rdi);
    c.WriteU64(r.r8);
    c.WriteU64(r.r9);
    c.WriteU64(r.r10);
    c.WriteU64(r.r11);
    c.WriteU64(r.r12);
    c.WriteU64(r.r13);
    c.WriteU64(r.r14);
    c.WriteU64(r.r15);
    c.WriteU64(r.rip);
    // 0x100..0x300: XMM_SAVE_AREA32 (FltSave) — zero-fill;
    // CONTEXT_FLOATING_POINT not set, so debugger ignores.
    c.Pad(0x200);
    // 0x300..0x4A0: VectorRegister[26] × 16 bytes
    c.Pad(26 * 16);
    // 0x4A0..0x4D0: VectorControl, DebugControl, LastBranchToRip,
    //                LastBranchFromRip, LastExceptionToRip,
    //                LastExceptionFromRip
    for (u32 i = 0; i < 6; ++i)
        c.WriteU64(0);

    // Sanity: cursor should have advanced by exactly kContextX64Bytes.
    return rva;
}

// Write SystemInfoStream body (56 bytes total).
u32 WriteSystemInfoStream(Cursor& c)
{
    const u32 rva = c.Tell();
    c.WriteU16(kProcArchAmd64);
    c.WriteU16(0);                // ProcessorLevel
    c.WriteU16(0);                // ProcessorRevision
    c.WriteU8(1);                 // NumberOfProcessors (BSP only for now)
    c.WriteU8(1);                 // ProductType (VER_NT_WORKSTATION)
    c.WriteU32(10);               // MajorVersion (Windows-10-shaped — VS doesn't care, just needs a number)
    c.WriteU32(0);                // MinorVersion
    c.WriteU32(0);                // BuildNumber
    c.WriteU32(kPlatformWin32Nt); // PlatformId
    c.WriteU32(0);                // CSDVersionRva — empty
    c.WriteU16(0);                // SuiteMask
    c.WriteU16(0);                // _reserved
    // CPU_INFORMATION (24 bytes). For AMD64 the union holds:
    //    DWORD VendorId[3];
    //    DWORD VersionInformation;
    //    DWORD FeatureInformation;
    //    DWORD AMDExtendedCpuFeatures; (or 0 for Intel)
    for (u32 i = 0; i < 6; ++i)
        c.WriteU32(0);
    return rva;
}

// Forward declarations for stream writers.
struct StreamLayout
{
    u32 system_info_rva;
    u32 system_info_size;
    u32 exception_rva;
    u32 exception_size;
    u32 thread_list_rva;
    u32 thread_list_size;
    u32 module_list_rva;
    u32 module_list_size;
    u32 memory_list_rva;
    u32 memory_list_size;
};

u32 WriteExceptionStream(Cursor& c, u32 thread_id, u64 rip, u32 code, u32 context_rva)
{
    const u32 rva = c.Tell();
    // MINIDUMP_EXCEPTION_STREAM
    c.WriteU32(thread_id);
    c.WriteU32(0); // _alignment
    // MINIDUMP_EXCEPTION
    c.WriteU32(code); // ExceptionCode
    c.WriteU32(0);    // ExceptionFlags
    c.WriteU64(0);    // ExceptionRecord (chained)
    c.WriteU64(rip);  // ExceptionAddress
    c.WriteU32(0);    // NumberParameters
    c.WriteU32(0);    // _unused
    for (u32 i = 0; i < 15; ++i)
        c.WriteU64(0); // ExceptionInformation[15]
    // MINIDUMP_LOCATION_DESCRIPTOR ThreadContext
    c.WriteU32(static_cast<u32>(kContextX64Bytes));
    c.WriteU32(context_rva);
    return rva;
}

// Write a MINIDUMP_THREAD_LIST containing one thread (the
// faulting one). Returns the stream-body RVA.
u32 WriteThreadListStream(Cursor& c, u32 thread_id, u64 stack_base, u32 stack_bytes, u32 stack_rva, u32 context_rva)
{
    const u32 rva = c.Tell();
    c.WriteU32(1); // NumberOfThreads
    // MINIDUMP_THREAD
    c.WriteU32(thread_id);
    c.WriteU32(0); // SuspendCount
    c.WriteU32(0); // PriorityClass
    c.WriteU32(0); // Priority
    c.WriteU64(0); // Teb
    // MINIDUMP_MEMORY_DESCRIPTOR Stack
    c.WriteU64(stack_base);  // StartOfMemoryRange
    c.WriteU32(stack_bytes); // DataSize
    c.WriteU32(stack_rva);   // Rva
    // MINIDUMP_LOCATION_DESCRIPTOR ThreadContext
    c.WriteU32(static_cast<u32>(kContextX64Bytes));
    c.WriteU32(context_rva);
    return rva;
}

struct ModuleEntry
{
    u64 base;
    u32 size;
    u32 name_rva;
};

u32 WriteModuleListStream(Cursor& c, const ModuleEntry* mods, u32 count)
{
    const u32 rva = c.Tell();
    c.WriteU32(count);
    for (u32 i = 0; i < count; ++i)
    {
        c.WriteU64(mods[i].base); // BaseOfImage
        c.WriteU32(mods[i].size); // SizeOfImage
        c.WriteU32(0);            // CheckSum
        c.WriteU32(0);            // TimeDateStamp
        c.WriteU32(mods[i].name_rva);
        // VS_FIXEDFILEINFO (52 bytes) — zero-fill.
        c.Pad(52);
        // CvRecord LocationDescriptor (8 bytes) — zero (no PDB info).
        c.WriteU32(0);
        c.WriteU32(0);
        // MiscRecord LocationDescriptor (8 bytes) — zero.
        c.WriteU32(0);
        c.WriteU32(0);
        // Reserved0/1
        c.WriteU64(0);
        c.WriteU64(0);
    }
    return rva;
}

struct MemoryEntry
{
    u64 base;
    u32 size;
    u32 rva;
};

u32 WriteMemoryListStream(Cursor& c, const MemoryEntry* mems, u32 count)
{
    const u32 rva = c.Tell();
    c.WriteU32(count);
    for (u32 i = 0; i < count; ++i)
    {
        c.WriteU64(mems[i].base);
        c.WriteU32(mems[i].size);
        c.WriteU32(mems[i].rva);
    }
    return rva;
}

} // namespace

// Build the dump into the static buffer without egressing it.
// Build a ContextRegs from a soft-panic call site: only rip/rsp/rbp
// are caller-known. Segment selectors are read live from the CPU
// (we're still on the same CPU as the panicking code, segments
// haven't moved). rflags is the live value too. All other GPRs
// stay zero — for the soft-panic path the calling function's
// locals would have to be reconstructed from the rbp chain anyway.
ContextRegs RegsFromSoftPanic(u64 rip, u64 rsp, u64 rbp)
{
    ContextRegs r{};
    r.rip = rip;
    r.rsp = rsp;
    r.rbp = rbp;
    r.rflags = arch::ReadRflags();
    // Read live segment selectors so the dump matches the actual
    // CPU state at panic time, not a guess.
    u16 cs = 0, ds = 0, es = 0, fs = 0, gs = 0, ss = 0;
    asm volatile("mov %%cs, %0" : "=r"(cs));
    asm volatile("mov %%ds, %0" : "=r"(ds));
    asm volatile("mov %%es, %0" : "=r"(es));
    asm volatile("mov %%fs, %0" : "=r"(fs));
    asm volatile("mov %%gs, %0" : "=r"(gs));
    asm volatile("mov %%ss, %0" : "=r"(ss));
    r.cs = cs;
    r.ds = ds;
    r.es = es;
    r.fs = fs;
    r.gs = gs;
    r.ss = ss;
    return r;
}

// Build a ContextRegs from a CPU-exception TrapFrame. Every GPR
// the hardware/exceptions.S preserved is real — `rax..r15` from
// the manual save sequence, `rip / cs / rflags / rsp / ss` from
// the CPU's own iretq frame.
ContextRegs RegsFromTrapFrame(const arch::TrapFrame* f)
{
    ContextRegs r{};
    r.rax = f->rax;
    r.rcx = f->rcx;
    r.rdx = f->rdx;
    r.rbx = f->rbx;
    r.rsp = f->rsp;
    r.rbp = f->rbp;
    r.rsi = f->rsi;
    r.rdi = f->rdi;
    r.r8 = f->r8;
    r.r9 = f->r9;
    r.r10 = f->r10;
    r.r11 = f->r11;
    r.r12 = f->r12;
    r.r13 = f->r13;
    r.r14 = f->r14;
    r.r15 = f->r15;
    r.rip = f->rip;
    r.rflags = f->rflags;
    r.cs = static_cast<u16>(f->cs);
    r.ss = static_cast<u16>(f->ss);
    // Data segments aren't on the trap frame (they're not pushed
    // by the CPU on an interrupt). Read them live — we're still
    // on the kernel's data-segment configuration.
    u16 ds = 0, es = 0, fs = 0, gs = 0;
    asm volatile("mov %%ds, %0" : "=r"(ds));
    asm volatile("mov %%es, %0" : "=r"(es));
    asm volatile("mov %%fs, %0" : "=r"(fs));
    asm volatile("mov %%gs, %0" : "=r"(gs));
    r.ds = ds;
    r.es = es;
    r.fs = fs;
    r.gs = gs;
    return r;
}

// Split out from EmitMinidump so the self-test can validate the
// shape without polluting the host's debugcon file (every byte
// pushed via outb 0xE9 is appended to that file by QEMU — an
// unfiltered self-test would make every clean boot look like a
// panic to the host extractor).
namespace
{
u64 BuildMinidumpInto(const ContextRegs& regs, u32 exception_code)
{
    const u64 rip = regs.rip;
    const u64 rsp = regs.rsp;
    Cursor c;
    c.Reset();

    // ---------- Phase 1: lay out the FILE HEADER + DIRECTORY ----------
    // We back-patch directory entries once each stream's size is known.
    // Header is 32 bytes at offset 0.
    const u32 header_rva = c.Tell();
    c.WriteU32(kMinidumpSignature);
    c.WriteU32(kMinidumpVersion);
    c.WriteU32(kStreamCount);
    const u32 dir_rva_field = c.Tell();
    c.WriteU32(0); // StreamDirectoryRva — patched below
    c.WriteU32(0); // CheckSum
    c.WriteU32(0); // TimeDateStamp
    c.WriteU64(0); // Flags
    (void)header_rva;

    // Directory immediately follows header: kStreamCount × 12 bytes.
    const u32 directory_rva = c.Tell();
    c.Patch32(dir_rva_field, directory_rva);
    // Reserve directory space; fill with zeroes, patch later.
    c.Pad(static_cast<u64>(kStreamCount) * 12);

    // ---------- Phase 2: emit stream bodies ----------
    StreamLayout layout{};

    layout.system_info_rva = c.Tell();
    (void)WriteSystemInfoStream(c);
    layout.system_info_size = c.Tell() - layout.system_info_rva;

    // Stream-body RVAs we'll patch after writing the variable-
    // length blobs that follow them. Streams whose entries
    // contain RVAs must be written AFTER the targets they
    // reference — so we lay out blobs first, streams second.

    // ---------- Phase 3: out-of-line blobs ----------

    // CONTEXT for the faulting thread.
    const u32 context_rva = WriteContextX64(c, regs);

    // Stack capture: ~16 KiB starting at rsp, snapped to page.
    // SafeReadInto handles unmapped pages.
    u64 stack_base = rsp & ~0xFFFULL;
    if (stack_base > rsp)
        stack_base = 0;
    u32 stack_rva = c.Tell();
    {
        const u64 read = SafeReadInto(stack_base, g_stack_scratch, kStackBytesToCapture);
        if (c.Reserve(read))
        {
            c.WriteBytes(g_stack_scratch, read);
        }
    }
    const u32 stack_size = c.Tell() - stack_rva;

    // RIP-page capture: 4 KiB starting at the page that contains rip.
    const u64 rip_page = rip & ~0xFFFULL;
    u32 rip_page_rva = c.Tell();
    {
        const u64 read = SafeReadInto(rip_page, g_rip_scratch, kRipPageBytes);
        if (c.Reserve(read))
        {
            c.WriteBytes(g_rip_scratch, read);
        }
    }
    const u32 rip_page_size = c.Tell() - rip_page_rva;

    // Module entries (collect into a stack array; emit names
    // first, then the ModuleListStream points at them).
    ModuleEntry mods[kMaxModulesEmitted];
    u32 mod_count = 0;
    if (auto* proc = duetos::core::CurrentProcess(); proc != nullptr)
    {
        const u64 limit = (proc->dll_image_count < kMaxModulesEmitted) ? proc->dll_image_count : kMaxModulesEmitted;
        for (u64 i = 0; i < limit; ++i)
        {
            const auto& dll = proc->dll_images[i];
            const char* name = dll.has_exports ? duetos::core::PeExportsDllName(dll.exports) : nullptr;
            mods[mod_count].base = dll.base_va;
            mods[mod_count].size = static_cast<u32>(dll.size);
            mods[mod_count].name_rva = WriteString(c, name != nullptr ? name : "<unnamed>");
            ++mod_count;
        }
    }

    // ---------- Phase 4: streams that reference the blobs above ----------
    layout.exception_rva = c.Tell();
    (void)WriteExceptionStream(c, /*thread_id=*/1, rip, exception_code != 0 ? exception_code : kStatusBreakpoint,
                               context_rva);
    layout.exception_size = c.Tell() - layout.exception_rva;

    layout.thread_list_rva = c.Tell();
    (void)WriteThreadListStream(c, /*thread_id=*/1, stack_base, stack_size, stack_rva, context_rva);
    layout.thread_list_size = c.Tell() - layout.thread_list_rva;

    layout.module_list_rva = c.Tell();
    (void)WriteModuleListStream(c, mods, mod_count);
    layout.module_list_size = c.Tell() - layout.module_list_rva;

    // Memory list: stack + RIP page (only entries we actually
    // captured non-zero bytes for).
    MemoryEntry mems[2];
    u32 mem_count = 0;
    if (stack_size > 0)
    {
        mems[mem_count++] = {stack_base, stack_size, stack_rva};
    }
    if (rip_page_size > 0)
    {
        mems[mem_count++] = {rip_page, rip_page_size, rip_page_rva};
    }
    layout.memory_list_rva = c.Tell();
    (void)WriteMemoryListStream(c, mems, mem_count);
    layout.memory_list_size = c.Tell() - layout.memory_list_rva;

    // ---------- Phase 5: back-patch the directory ----------
    {
        // Treat the directory as if we were rewriting from offset
        // `directory_rva`. The simplest approach: directly
        // mutate the static buffer at the pre-known offset.
        u64 off = directory_rva;
        auto put32 = [&](u32 v)
        {
            g_buf[off + 0] = static_cast<u8>(v & 0xFF);
            g_buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
            g_buf[off + 2] = static_cast<u8>((v >> 16) & 0xFF);
            g_buf[off + 3] = static_cast<u8>((v >> 24) & 0xFF);
            off += 4;
        };

        put32(kStreamSystemInfo);
        put32(layout.system_info_size);
        put32(layout.system_info_rva);

        put32(kStreamException);
        put32(layout.exception_size);
        put32(layout.exception_rva);

        put32(kStreamThreadList);
        put32(layout.thread_list_size);
        put32(layout.thread_list_rva);

        put32(kStreamModuleList);
        put32(layout.module_list_size);
        put32(layout.module_list_rva);

        put32(kStreamMemoryList);
        put32(layout.memory_list_size);
        put32(layout.memory_list_rva);
    }

    return g_used;
}
} // namespace

// Last successfully-built minidump's byte count. Reset to 0 by
// `BuildMinidumpInto` on entry; set to the final cursor on exit.
// Read-back via `AccessLastMinidump` so a panic-time disk
// persistence layer can grab the same bytes the debugcon path
// already pushed without re-running the build.
namespace
{
constinit u64 g_last_dump_bytes = 0;
} // namespace

// Persist the freshly-built minidump bytes to the reserved
// crash-dump LBA region. NVMe is the preferred backend; AHCI is
// the fallback when no NVMe namespace is online (real-hardware
// SATA-only boxes, QEMU configs without -device nvme). Best-
// effort — failure is logged on serial but doesn't block the
// panic flow. Called inline after the debugcon emit so an
// operator who only has access to the disk image still recovers
// the same .dmp file.
void PersistToDisk(u64 bytes)
{
    namespace stor = duetos::drivers::storage;
    if (stor::NvmeAvailable())
    {
        const u64 lba = stor::NvmeDumpReservedLba();
        arch::SerialWrite("[minidump] persisting to NVMe reserved LBA=");
        arch::SerialWriteHex(lba);
        arch::SerialWrite(" sectors=");
        arch::SerialWriteHex(stor::kNvmeDumpReservedSectors);
        arch::SerialWrite("\n");
        const bool ok = stor::NvmePanicWriteDump(g_buf, bytes);
        if (ok)
        {
            arch::SerialWrite("[minidump] disk persist OK (NVMe)\n");
        }
        else
        {
            arch::SerialWrite("[minidump] disk persist PARTIAL/FAILED bytes_written=");
            arch::SerialWriteHex(stor::NvmePanicLastWriteBytes());
            arch::SerialWrite("\n");
        }
        // Fix journal piggybacks on the same panic-write budget,
        // landing in the second half of the reserved region.
        // Fires for BOTH soft panics (core::Panic / PanicWithValue,
        // already wired in panic.cpp) AND hard crashes that take
        // the trap-fired EmitMinidumpFromTrapFrame path. Either
        // way the journal observed during the boot survives to
        // the next session.
        ::duetos::diag::FixJournalPanicWriteToNvme();
        return;
    }
    if (stor::AhciAvailable())
    {
        const u64 lba = stor::AhciDumpReservedLba();
        arch::SerialWrite("[minidump] persisting to AHCI reserved LBA=");
        arch::SerialWriteHex(lba);
        arch::SerialWrite(" sectors=");
        arch::SerialWriteHex(stor::kAhciDumpReservedSectors);
        arch::SerialWrite("\n");
        const bool ok = stor::AhciPanicWriteDump(g_buf, bytes);
        if (ok)
        {
            arch::SerialWrite("[minidump] disk persist OK (AHCI)\n");
        }
        else
        {
            arch::SerialWrite("[minidump] disk persist PARTIAL/FAILED bytes_written=");
            arch::SerialWriteHex(stor::AhciPanicLastWriteBytes());
            arch::SerialWrite("\n");
        }
        return;
    }
    arch::SerialWrite("[minidump] no NVMe / AHCI backend; disk persist skipped\n");
}

void EmitMinidump(u64 rip, u64 rsp, u64 rbp, u32 exception_code)
{
    const ContextRegs regs = RegsFromSoftPanic(rip, rsp, rbp);
    const u64 bytes = BuildMinidumpInto(regs, exception_code);
    g_last_dump_bytes = bytes;
    arch::SerialWrite("[minidump] emitting ");
    arch::SerialWriteHex(bytes);
    arch::SerialWrite(" bytes via debugcon (port 0xE9) [soft panic]\n");
    debugcon::Write(g_buf, bytes);
    PersistToDisk(bytes);
    arch::SerialWrite("[minidump] done\n");
}

void EmitMinidumpFromTrapFrame(const arch::TrapFrame* frame, u32 exception_code)
{
    if (frame == nullptr)
    {
        // Defensive: no frame to capture from. Fall back to a
        // soft-panic-shaped dump anchored at the panic call
        // site so the operator still gets *some* artefact.
        EmitMinidump(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(), arch::ReadRbp(),
                     exception_code);
        return;
    }
    const ContextRegs regs = RegsFromTrapFrame(frame);
    const u64 bytes = BuildMinidumpInto(regs, exception_code);
    g_last_dump_bytes = bytes;
    arch::SerialWrite("[minidump] emitting ");
    arch::SerialWriteHex(bytes);
    arch::SerialWrite(" bytes via debugcon (port 0xE9) [trap frame]\n");
    debugcon::Write(g_buf, bytes);
    PersistToDisk(bytes);
    arch::SerialWrite("[minidump] done\n");
}

bool AccessLastMinidump(const u8** out_bytes, u64* out_len)
{
    if (out_bytes == nullptr || out_len == nullptr)
    {
        return false;
    }
    if (g_last_dump_bytes == 0)
    {
        *out_bytes = nullptr;
        *out_len = 0;
        return false;
    }
    *out_bytes = g_buf;
    *out_len = g_last_dump_bytes;
    return true;
}

void MinidumpSelfTest()
{
    // Build into the buffer WITHOUT egressing — host-side
    // debugcon file stays empty for clean boots. Synthetic
    // ContextRegs covers every CONTEXT field so the writer's
    // full GPR + segment plumbing is exercised at boot.
    ContextRegs synth{};
    synth.rip = 0xFFFFFFFF80100000ULL;
    synth.rsp = 0xFFFFFFFFE0001000ULL;
    synth.rbp = 0xFFFFFFFFE0001008ULL;
    synth.rax = 0xDEADBEEFCAFEBABEULL;
    synth.rdi = 0x1111111111111111ULL;
    synth.rflags = 0x202;
    synth.cs = 0x08;
    synth.ds = 0x10;
    synth.ss = 0x10;
    (void)BuildMinidumpInto(synth, /*exception_code=*/0xC0000005);

    // Verify the magic bytes at offset 0..3.
    const u32 sig = static_cast<u32>(g_buf[0]) | (static_cast<u32>(g_buf[1]) << 8) |
                    (static_cast<u32>(g_buf[2]) << 16) | (static_cast<u32>(g_buf[3]) << 24);
    if (sig != kMinidumpSignature)
    {
        ::duetos::core::PanicWithValue("diag/minidump", "self-test: signature mismatch", sig);
    }
    const u32 ver = static_cast<u32>(g_buf[4]) | (static_cast<u32>(g_buf[5]) << 8) |
                    (static_cast<u32>(g_buf[6]) << 16) | (static_cast<u32>(g_buf[7]) << 24);
    if ((ver & 0xFFFF) != (kMinidumpVersion & 0xFFFF))
    {
        ::duetos::core::PanicWithValue("diag/minidump", "self-test: version mismatch", ver);
    }
    const u32 nstreams = static_cast<u32>(g_buf[8]) | (static_cast<u32>(g_buf[9]) << 8) |
                         (static_cast<u32>(g_buf[10]) << 16) | (static_cast<u32>(g_buf[11]) << 24);
    if (nstreams != kStreamCount)
    {
        ::duetos::core::PanicWithValue("diag/minidump", "self-test: stream count wrong", nstreams);
    }

    arch::SerialWrite("[minidump] self-test OK (signature + version + stream count)\n");

    // Reset so a subsequent real panic starts from an empty
    // buffer. The buffer is global; only one CPU panics at a
    // time so resetting here is safe.
    Cursor c;
    c.Reset();
}

void DiskPersistSelfTest()
{
    // Run AFTER NvmeInit (MinidumpSelfTest fires too early in boot
    // — the NVMe driver hasn't enumerated yet at that point).
    // Builds a synthetic dump, writes it to the reserved LBA
    // region, and reports the result. Surfaces a clean PASS/FAIL
    // line so a regression in the panic-write path doesn't slip
    // through silently.
    namespace stor = duetos::drivers::storage;
    const bool have_nvme = stor::NvmeAvailable();
    const bool have_ahci = stor::AhciAvailable();
    if (!have_nvme && !have_ahci)
    {
        arch::SerialWrite("[minidump] disk-persist self-test SKIP (no NVMe / AHCI backend)\n");
        return;
    }
    ContextRegs synth{};
    synth.rip = 0xFFFFFFFF80100000ULL;
    synth.rsp = 0xFFFFFFFFE0001000ULL;
    synth.rbp = 0xFFFFFFFFE0001008ULL;
    synth.cs = 0x08;
    synth.ds = 0x10;
    synth.ss = 0x10;
    synth.rflags = 0x202;
    const u64 disk_bytes = BuildMinidumpInto(synth, /*exception_code=*/0xC0000005);
    if (have_nvme)
    {
        const bool persisted = stor::NvmePanicWriteDump(g_buf, disk_bytes);
        if (!persisted)
        {
            arch::SerialWrite("[minidump] disk-persist self-test FAIL (NVMe) bytes_written=");
            arch::SerialWriteHex(stor::NvmePanicLastWriteBytes());
            arch::SerialWrite("\n");
        }
        else
        {
            arch::SerialWrite("[minidump] disk-persist self-test OK (NVMe); reserved LBA=");
            arch::SerialWriteHex(stor::NvmeDumpReservedLba());
            arch::SerialWrite(" bytes=");
            arch::SerialWriteHex(stor::NvmePanicLastWriteBytes());
            arch::SerialWrite("\n");
        }
    }
    if (have_ahci)
    {
        const bool persisted = stor::AhciPanicWriteDump(g_buf, disk_bytes);
        if (!persisted)
        {
            arch::SerialWrite("[minidump] disk-persist self-test FAIL (AHCI) bytes_written=");
            arch::SerialWriteHex(stor::AhciPanicLastWriteBytes());
            arch::SerialWrite("\n");
        }
        else
        {
            arch::SerialWrite("[minidump] disk-persist self-test OK (AHCI); reserved LBA=");
            arch::SerialWriteHex(stor::AhciDumpReservedLba());
            arch::SerialWrite(" bytes=");
            arch::SerialWriteHex(stor::AhciPanicLastWriteBytes());
            arch::SerialWrite("\n");
        }
    }
    // Clear the success flag + bytes so `lastdump` from the
    // shell doesn't claim a real panic landed when only the
    // self-test wrote.
    g_last_dump_bytes = 0;
    Cursor c;
    c.Reset();
}

} // namespace duetos::diag::minidump
