#include "syscall_scan.h"

#include "../arch/x86_64/serial.h"
#include "../fs/fat32.h"
#include "../subsystems/linux/linux_syscall_table_generated.h"
#include "../subsystems/translation/translate.h"

namespace customos::debug
{

namespace
{

// Native CustomOS SYS_* table lookup — the translation unit owns
// the authoritative name table (for logging) but exposes only the
// Linux + NT lookups. Keep a small local mirror of the native
// names, indexed by number, so the scanner can classify `int 0x80`
// sites without pulling in translate.cpp's internals.
struct NativeName
{
    u32 nr;
    const char* name;
};
constexpr NativeName kNativeNames[] = {
    {0, "SYS_EXIT"},
    {1, "SYS_GETPID"},
    {2, "SYS_WRITE"},
    {3, "SYS_YIELD"},
    {4, "SYS_STAT"},
    {5, "SYS_READ"},
    {6, "SYS_DROPCAPS"},
    {7, "SYS_SPAWN"},
    {8, "SYS_GETPROCID"},
    {9, "SYS_GETLASTERROR"},
    {10, "SYS_SETLASTERROR"},
    {11, "SYS_HEAP_ALLOC"},
    {12, "SYS_HEAP_FREE"},
    {13, "SYS_PERF_COUNTER"},
    {14, "SYS_HEAP_SIZE"},
    {15, "SYS_HEAP_REALLOC"},
    {16, "SYS_WIN32_MISS_LOG"},
    {17, "SYS_GETTIME_FT"},
    {18, "SYS_NOW_NS"},
    {19, "SYS_SLEEP_MS"},
    {20, "SYS_FILE_OPEN"},
    {21, "SYS_FILE_READ"},
    {22, "SYS_FILE_CLOSE"},
    {23, "SYS_FILE_SEEK"},
    {24, "SYS_FILE_FSTAT"},
    {25, "SYS_MUTEX_CREATE"},
    {26, "SYS_MUTEX_WAIT"},
    {27, "SYS_MUTEX_RELEASE"},
    {28, "SYS_VMAP"},
    {29, "SYS_VUNMAP"},
    {30, "SYS_EVENT_CREATE"},
    {31, "SYS_EVENT_SET"},
    {32, "SYS_EVENT_RESET"},
    {33, "SYS_EVENT_WAIT"},
    {34, "SYS_TLS_ALLOC"},
    {35, "SYS_TLS_FREE"},
    {36, "SYS_TLS_GET"},
    {37, "SYS_TLS_SET"},
    {38, "SYS_BP_INSTALL"},
    {39, "SYS_BP_REMOVE"},
    {40, "SYS_GETTIME_ST"},
    {41, "SYS_ST_TO_FT"},
    {42, "SYS_FT_TO_ST"},
    {43, "SYS_FILE_WRITE"},
    {44, "SYS_FILE_CREATE"},
    {45, "SYS_THREAD_CREATE"},
    {46, "SYS_NT_INVOKE"},
};

const char* NativeNameLookup(u32 nr)
{
    for (const auto& e : kNativeNames)
    {
        if (e.nr == nr)
            return e.name;
    }
    return nullptr;
}

// How far back from a syscall-issuing opcode we'll walk looking
// for a `mov eax, imm32`. MSVC / gcc / clang all emit the
// immediate within a handful of bytes of the dispatch — 32 is
// generous. Going further inflates false positives.
constexpr u64 kMovEaxLookback = 32;

// Walk backward from `site_off` in `bytes` looking for the
// canonical `mov eax, imm32` encoding — opcode B8 followed by
// four little-endian bytes. Returns true on hit, writing the
// immediate to `*out_nr`. False positives are possible (we don't
// track REX / prefix boundaries); they surface as "number
// recovered but name lookup fails in all three tables" — useful
// data in its own right.
bool RecoverSyscallNumber(const u8* bytes, u64 size, u64 site_off, u32* out_nr)
{
    if (site_off == 0)
        return false;
    // A `mov eax, imm32` is 5 bytes: B8 ii ii ii ii. We need at
    // least 5 bytes of lookback room.
    const u64 lo = (site_off > kMovEaxLookback) ? (site_off - kMovEaxLookback) : 0;
    for (u64 i = site_off; i >= lo + 5; --i)
    {
        // Check for `B8 xx xx xx xx` at i-5 .. i-1.
        const u64 op_at = i - 5;
        if (op_at >= size)
            continue;
        if (bytes[op_at] != 0xB8)
        {
            if (i == lo + 5)
                break;
            continue;
        }
        const u32 imm = static_cast<u32>(bytes[op_at + 1]) | (static_cast<u32>(bytes[op_at + 2]) << 8) |
                        (static_cast<u32>(bytes[op_at + 3]) << 16) | (static_cast<u32>(bytes[op_at + 4]) << 24);
        *out_nr = imm;
        return true;
    }
    return false;
}

void ClassifySite(SyscallSite& site)
{
    if (!site.nr_recovered)
        return;
    auto& c = site.coverage;
    // Linux: only meaningful for `syscall` (shared with NT — we
    // look up both).
    c.linux_name = subsystems::translation::LinuxName(site.nr);
    if (c.linux_name != nullptr)
    {
        c.known_linux = true;
        // Did the primary Linux dispatcher pick up a handler?
        const auto* e = subsystems::linux::LinuxSyscallLookup(site.nr);
        if (e != nullptr && e->state == subsystems::linux::HandlerState::Implemented)
        {
            c.impl_linux = true;
        }
    }
    // NT: only meaningful for `syscall` / `int 0x2E`.
    if (site.kind == SyscallSiteKind::Syscall || site.kind == SyscallSiteKind::Int2E)
    {
        c.nt_name = subsystems::translation::NtName(site.nr);
        if (c.nt_name != nullptr)
            c.known_nt = true;
    }
    // Native: only meaningful for `int 0x80`.
    if (site.kind == SyscallSiteKind::Int80)
    {
        c.native_name = NativeNameLookup(site.nr);
        if (c.native_name != nullptr)
        {
            c.known_native = true;
            c.impl_native = true; // if it has a native name, it's dispatched
        }
    }
}

void LogSite(const SyscallSite& site)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[sysscan] site va=");
    SerialWriteHex(site.va);
    SerialWrite(" kind=");
    switch (site.kind)
    {
    case SyscallSiteKind::Syscall:
        SerialWrite("syscall");
        break;
    case SyscallSiteKind::Int80:
        SerialWrite("int80");
        break;
    case SyscallSiteKind::Int2E:
        SerialWrite("int2e");
        break;
    case SyscallSiteKind::Sysenter:
        SerialWrite("sysenter");
        break;
    default:
        SerialWrite("unknown");
        break;
    }
    if (site.nr_recovered)
    {
        SerialWrite(" nr=");
        SerialWriteHex(site.nr);
        const auto& c = site.coverage;
        if (c.linux_name != nullptr)
        {
            SerialWrite(" linux=\"");
            SerialWrite(c.linux_name);
            SerialWrite(c.impl_linux ? "\"(impl)" : "\"(unimpl)");
        }
        if (c.nt_name != nullptr)
        {
            SerialWrite(" nt=\"");
            SerialWrite(c.nt_name);
            SerialWrite("\"");
        }
        if (c.native_name != nullptr)
        {
            SerialWrite(" native=\"");
            SerialWrite(c.native_name);
            SerialWrite("\"");
        }
        if (!c.known_linux && !c.known_nt && !c.known_native)
        {
            SerialWrite(" <no-table-hit>");
        }
    }
    else
    {
        SerialWrite(" nr=<no mov eax,imm32 within 32B>");
    }
    SerialWrite("\n");
}

void UpdateTallies(const SyscallSite& site, SyscallScanReport& r)
{
    ++r.total_sites;
    switch (site.kind)
    {
    case SyscallSiteKind::Syscall:
        ++r.kind_syscall;
        break;
    case SyscallSiteKind::Int80:
        ++r.kind_int80;
        break;
    case SyscallSiteKind::Int2E:
        ++r.kind_int2e;
        break;
    case SyscallSiteKind::Sysenter:
        ++r.kind_sysenter;
        break;
    default:
        break;
    }
    if (site.nr_recovered)
    {
        ++r.recovered;
        const auto& c = site.coverage;
        if (c.known_linux)
            ++r.known_linux;
        if (c.known_nt)
            ++r.known_nt;
        if (c.known_native)
            ++r.known_native;
        if (c.impl_linux)
            ++r.impl_linux;
        if (c.impl_native)
            ++r.impl_native;
        if (!c.known_linux && !c.known_nt && !c.known_native)
            ++r.unknown;
    }
}

void LogSummary(const SyscallScanReport& r)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[sysscan] summary base=");
    SerialWriteHex(r.region_base_va);
    SerialWrite(" size=");
    SerialWriteHex(r.region_size);
    SerialWrite(" sites=");
    SerialWriteHex(r.total_sites);
    SerialWrite(" recovered=");
    SerialWriteHex(r.recovered);
    SerialWrite(" linux_known=");
    SerialWriteHex(r.known_linux);
    SerialWrite(" (impl=");
    SerialWriteHex(r.impl_linux);
    SerialWrite(") nt_known=");
    SerialWriteHex(r.known_nt);
    SerialWrite(" native_known=");
    SerialWriteHex(r.known_native);
    SerialWrite(" (impl=");
    SerialWriteHex(r.impl_native);
    SerialWrite(") unknown=");
    SerialWriteHex(r.unknown);
    SerialWrite("\n[sysscan] summary kinds: syscall=");
    SerialWriteHex(r.kind_syscall);
    SerialWrite(" int80=");
    SerialWriteHex(r.kind_int80);
    SerialWrite(" int2e=");
    SerialWriteHex(r.kind_int2e);
    SerialWrite(" sysenter=");
    SerialWriteHex(r.kind_sysenter);
    if (r.sites_dropped > 0)
    {
        SerialWrite(" dropped=");
        SerialWriteHex(r.sites_dropped);
    }
    SerialWrite("\n");
}

} // namespace

SyscallScanReport SyscallScanRegion(const u8* bytes, u64 size, u64 base_va)
{
    SyscallScanReport r{};
    r.region_base_va = base_va;
    r.region_size = size;
    if (bytes == nullptr || size < 2)
        return r;

    arch::SerialWrite("[sysscan] begin base=");
    arch::SerialWriteHex(base_va);
    arch::SerialWrite(" size=");
    arch::SerialWriteHex(size);
    arch::SerialWrite("\n");

    u32 emitted = 0;
    // Walk byte-by-byte. Classifier looks at bytes[i] + bytes[i+1]
    // to decide whether this position is a syscall idiom. No state
    // between iterations — false positives (a `0F 05` inside a
    // longer instruction's operand) are rare enough that the
    // caller can eyeball the log and discount them.
    for (u64 i = 0; i + 1 < size; ++i)
    {
        const u8 b0 = bytes[i];
        const u8 b1 = bytes[i + 1];
        SyscallSiteKind kind = SyscallSiteKind::Unknown;
        if (b0 == 0x0F && b1 == 0x05)
            kind = SyscallSiteKind::Syscall;
        else if (b0 == 0xCD && b1 == 0x80)
            kind = SyscallSiteKind::Int80;
        else if (b0 == 0xCD && b1 == 0x2E)
            kind = SyscallSiteKind::Int2E;
        else if (b0 == 0x0F && b1 == 0x34)
            kind = SyscallSiteKind::Sysenter;
        if (kind == SyscallSiteKind::Unknown)
            continue;

        SyscallSite site{};
        site.va = base_va + i;
        site.kind = kind;
        site.nr_recovered = RecoverSyscallNumber(bytes, size, i, &site.nr);
        ClassifySite(site);
        UpdateTallies(site, r);
        if (emitted < kMaxSitesLogged)
        {
            LogSite(site);
            ++emitted;
        }
        else
        {
            ++r.sites_dropped;
        }
        // Skip ahead by the opcode length so we don't double-count
        // the second byte of a two-byte match as the start of a new
        // one. All four recognized idioms are 2 bytes.
        ++i;
    }

    LogSummary(r);
    return r;
}

// Emitted by the linker script. Addresses of the kernel .text
// section boundaries.
extern "C" const u8 _text_start[];
extern "C" const u8 _text_end[];

SyscallScanReport SyscallScanKernelText()
{
    const u64 base = reinterpret_cast<u64>(_text_start);
    const u64 end = reinterpret_cast<u64>(_text_end);
    if (end <= base)
    {
        arch::SerialWrite("[sysscan] kernel text region invalid\n");
        return SyscallScanReport{};
    }
    return SyscallScanRegion(_text_start, end - base, base);
}

namespace
{

// Trivial little-endian readers for PE / ELF header parsing.
u16 Rd16(const u8* p)
{
    return static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8);
}
u32 Rd32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}
u64 Rd64(const u8* p)
{
    return static_cast<u64>(Rd32(p)) | (static_cast<u64>(Rd32(p + 4)) << 32);
}

// Strip a leading /fat/ mount prefix or a bare leading slash so
// the raw FAT32 lookup path is volume-relative.
const char* StripFatPrefix(const char* p)
{
    while (*p == '/')
        ++p;
    if (p[0] == 'f' && p[1] == 'a' && p[2] == 't' && p[3] == '/')
        return p + 4;
    return p;
}

// Scratch buffer for file contents. Sized to fit a small PE or
// ELF — real programs can exceed this, and bytes past the cap
// are truncated with a log note (short scan is still better than
// no scan).
constexpr u64 kFileScratchCap = 128 * 1024;
u8 g_file_scratch[kFileScratchCap];

// Try to locate a PE's executable .text section inside the loaded
// buffer. Returns {offset, size} on success, zeros on failure.
// Because we're scanning the on-disk layout (not the in-memory
// image), VA ↔ file-offset translation needs care: we use the
// section's PointerToRawData as the file offset, and return the
// image-base + VirtualAddress as the reported base_va so log
// lines match where the code would actually land.
struct SectionSpan
{
    u64 file_off;
    u64 size;
    u64 base_va;
};
bool FindPeTextSection(const u8* file, u64 len, SectionSpan* out)
{
    if (len < 0x40)
        return false;
    if (file[0] != 'M' || file[1] != 'Z')
        return false;
    const u32 pe_off = Rd32(file + 0x3C);
    if (pe_off + 4 >= len)
        return false;
    if (file[pe_off] != 'P' || file[pe_off + 1] != 'E' || file[pe_off + 2] != 0 || file[pe_off + 3] != 0)
        return false;
    const u8* coff = file + pe_off + 4;
    if (pe_off + 24 >= len)
        return false;
    const u16 num_sections = Rd16(coff + 2);
    const u16 opt_size = Rd16(coff + 16);
    const u8* opt = coff + 20;
    if ((opt + opt_size) >= (file + len))
        return false;
    u64 image_base = 0;
    if (opt_size >= 24)
    {
        // PE32+ (magic 0x20B) stores ImageBase at offset 24 as u64;
        // PE32 (magic 0x10B) at offset 28 as u32.
        const u16 magic = Rd16(opt);
        if (magic == 0x20B && opt_size >= 32)
        {
            image_base = Rd64(opt + 24);
        }
        else if (magic == 0x10B && opt_size >= 32)
        {
            image_base = Rd32(opt + 28);
        }
    }
    const u8* sections = opt + opt_size;
    for (u16 i = 0; i < num_sections; ++i)
    {
        const u8* s = sections + i * 40;
        if (s + 40 > file + len)
            break;
        const u32 virt_size = Rd32(s + 8);
        const u32 virt_addr = Rd32(s + 12);
        const u32 raw_size = Rd32(s + 16);
        const u32 raw_ptr = Rd32(s + 20);
        const u32 chars = Rd32(s + 36);
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000.
        if ((chars & 0x20000000u) == 0)
            continue;
        const u64 size_on_disk = (raw_size < virt_size) ? raw_size : virt_size;
        if (raw_ptr + size_on_disk > len)
            continue;
        out->file_off = raw_ptr;
        out->size = size_on_disk;
        out->base_va = image_base + virt_addr;
        return true;
    }
    return false;
}

// Find the first executable PT_LOAD in a 64-bit ELF. Returns
// {file_off, size, p_vaddr} on success.
bool FindElfTextSegment(const u8* file, u64 len, SectionSpan* out)
{
    if (len < 64)
        return false;
    if (file[0] != 0x7F || file[1] != 'E' || file[2] != 'L' || file[3] != 'F')
        return false;
    if (file[4] != 2) // must be 64-bit
        return false;
    const u64 e_phoff = Rd64(file + 32);
    const u16 e_phentsize = Rd16(file + 54);
    const u16 e_phnum = Rd16(file + 56);
    if (e_phoff + static_cast<u64>(e_phentsize) * e_phnum > len)
        return false;
    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u8* ph = file + e_phoff + static_cast<u64>(e_phentsize) * i;
        const u32 p_type = Rd32(ph);
        if (p_type != 1) // PT_LOAD
            continue;
        const u32 p_flags = Rd32(ph + 4);
        if ((p_flags & 0x1) == 0) // PF_X
            continue;
        const u64 p_offset = Rd64(ph + 8);
        const u64 p_vaddr = Rd64(ph + 16);
        const u64 p_filesz = Rd64(ph + 32);
        if (p_offset + p_filesz > len)
            continue;
        out->file_off = p_offset;
        out->size = p_filesz;
        out->base_va = p_vaddr;
        return true;
    }
    return false;
}

} // namespace

SyscallScanReport SyscallScanFile(const char* path)
{
    using arch::SerialWrite;
    SyscallScanReport r{};
    if (path == nullptr || path[0] == 0)
    {
        SerialWrite("[sysscan] file: empty path\n");
        return r;
    }
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[sysscan] file: no fat32 volume 0\n");
        return r;
    }
    fs::fat32::DirEntry entry;
    const char* leaf = StripFatPrefix(path);
    if (!fs::fat32::Fat32LookupPath(v, leaf, &entry))
    {
        SerialWrite("[sysscan] file: lookup failed: ");
        SerialWrite(path);
        SerialWrite("\n");
        return r;
    }
    const i64 rc = fs::fat32::Fat32ReadFile(v, &entry, g_file_scratch, kFileScratchCap);
    if (rc <= 0)
    {
        SerialWrite("[sysscan] file: read failed\n");
        return r;
    }
    const u64 len = static_cast<u64>(rc);
    if (len == kFileScratchCap && entry.size_bytes > kFileScratchCap)
    {
        SerialWrite("[sysscan] file: truncated at scratch cap (");
        arch::SerialWriteHex(kFileScratchCap);
        SerialWrite(" bytes); scanning prefix only\n");
    }
    // Auto-detect.
    SectionSpan sec{};
    if (FindPeTextSection(g_file_scratch, len, &sec))
    {
        SerialWrite("[sysscan] file: PE, scanning .text rva+=");
        arch::SerialWriteHex(sec.base_va);
        SerialWrite("\n");
        return SyscallScanRegion(g_file_scratch + sec.file_off, sec.size, sec.base_va);
    }
    if (FindElfTextSegment(g_file_scratch, len, &sec))
    {
        SerialWrite("[sysscan] file: ELF, scanning PT_LOAD (X) vaddr=");
        arch::SerialWriteHex(sec.base_va);
        SerialWrite("\n");
        return SyscallScanRegion(g_file_scratch + sec.file_off, sec.size, sec.base_va);
    }
    // Raw bytes — scan the whole file with base_va=0.
    SerialWrite("[sysscan] file: no PE/ELF header, scanning raw bytes\n");
    return SyscallScanRegion(g_file_scratch, len, 0);
}

} // namespace customos::debug
