#include "diag/minidump.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/debugcon.h"
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

// Write a CONTEXT_X64 block (1232 bytes) for the faulting frame
// and return the RVA of its start. Layout follows the public
// Windows CONTEXT structure exactly. Only the bits we set in
// ContextFlags carry meaningful values; everything else is
// zero-padded.
u32 WriteContextX64(Cursor& c, u64 rip, u64 rsp, u64 rbp)
{
    const u32 rva = c.Tell();
    if (!c.Reserve(kContextX64Bytes))
        return rva;

    // Read the live trap-frame-equivalent registers so the dump
    // captures more than just RIP/RSP/RBP. The remaining GPRs
    // come from the live CPU state — for a Panic() call site
    // they're the values the panicking function had when it
    // called Panic; for a trap they'd already be on a TrapFrame
    // (which the trap dispatcher passes via a richer overload —
    // see EmitMinidump's signature).
    const u64 cr3 = arch::ReadCr3();
    (void)cr3; // not part of CONTEXT but useful elsewhere

    // 0x000..0x030: P{1..6}Home (6 × u64, zero-fill).
    c.Pad(0x30);
    // 0x030: ContextFlags
    c.WriteU32(kContextOurFlags);
    // 0x034: MxCsr
    c.WriteU32(0);
    // 0x038..0x044: CS / DS / ES / FS / GS / SS
    // Use kernel selectors as placeholders; debugger doesn't
    // strictly need real values for a stack-only walk.
    c.WriteU16(0x08); // CS
    c.WriteU16(0x10); // DS
    c.WriteU16(0x10); // ES
    c.WriteU16(0x10); // FS
    c.WriteU16(0x10); // GS
    c.WriteU16(0x10); // SS
    // 0x044: EFlags
    c.WriteU32(static_cast<u32>(arch::ReadRflags() & 0xFFFFFFFFu));
    // 0x048..0x078: Dr0..Dr7 (Dr4/Dr5 reserved → not in struct;
    // layout is Dr0,Dr1,Dr2,Dr3,Dr6,Dr7).
    for (u32 i = 0; i < 6; ++i)
        c.WriteU64(0);
    // 0x078..0x100: Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8..R15, Rip
    c.WriteU64(0);   // Rax
    c.WriteU64(0);   // Rcx
    c.WriteU64(0);   // Rdx
    c.WriteU64(0);   // Rbx
    c.WriteU64(rsp); // Rsp
    c.WriteU64(rbp); // Rbp
    c.WriteU64(0);   // Rsi
    c.WriteU64(0);   // Rdi
    c.WriteU64(0);   // R8
    c.WriteU64(0);   // R9
    c.WriteU64(0);   // R10
    c.WriteU64(0);   // R11
    c.WriteU64(0);   // R12
    c.WriteU64(0);   // R13
    c.WriteU64(0);   // R14
    c.WriteU64(0);   // R15
    c.WriteU64(rip); // Rip
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

// Write a MINIDUMP_DIRECTORY entry.
void WriteDirEntry(Cursor& c, u32 type, u32 size, u32 rva)
{
    c.WriteU32(type);
    c.WriteU32(size);
    c.WriteU32(rva);
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
// Split out from EmitMinidump so the self-test can validate the
// shape without polluting the host's debugcon file (every byte
// pushed via outb 0xE9 is appended to that file by QEMU — an
// unfiltered self-test would make every clean boot look like a
// panic to the host extractor).
namespace
{
u64 BuildMinidumpInto(u64 rip, u64 rsp, u64 rbp, u32 exception_code)
{
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
    const u32 context_rva = WriteContextX64(c, rip, rsp, rbp);

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
        Cursor d;
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

void EmitMinidump(u64 rip, u64 rsp, u64 rbp, u32 exception_code)
{
    const u64 bytes = BuildMinidumpInto(rip, rsp, rbp, exception_code);
    arch::SerialWrite("[minidump] emitting ");
    arch::SerialWriteHex(bytes);
    arch::SerialWrite(" bytes via debugcon (port 0xE9)\n");
    debugcon::Write(g_buf, bytes);
    arch::SerialWrite("[minidump] done\n");
}

void MinidumpSelfTest()
{
    // Build into the buffer WITHOUT egressing — host-side
    // debugcon file stays empty for clean boots.
    (void)BuildMinidumpInto(/*rip=*/0xFFFFFFFF80100000ULL,
                            /*rsp=*/0xFFFFFFFFE0001000ULL,
                            /*rbp=*/0xFFFFFFFFE0001008ULL,
                            /*exception_code=*/0xC0000005);

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

} // namespace duetos::diag::minidump
