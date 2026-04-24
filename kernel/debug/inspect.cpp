#include "inspect.h"

#include "../arch/x86_64/serial.h"
#include "../fs/fat32.h"

namespace duetos::debug
{

// ---------- Shared loader helpers ----------

namespace
{

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

const char* StripFatPrefix(const char* p)
{
    while (*p == '/')
        ++p;
    if (p[0] == 'f' && p[1] == 'a' && p[2] == 't' && p[3] == '/')
        return p + 4;
    return p;
}

// Single scratch buffer shared across the inspect subcommands.
// Sized to hold a small PE / ELF — larger inputs are truncated
// with a log note. Sitting in BSS keeps the scan cost-free
// when no inspect command is issued.
u8 g_file_scratch[kInspectFileScratchCap];

// Freestanding kernel — no libc memset. A `OpcodeScanReport r{}`
// value-init would lower to a memset call for the big 2 KiB
// histograms (first_byte[256] + esc_0f[256]), which the kernel
// can't resolve. Zero-fill the report explicitly.
void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

} // namespace

bool InspectReadFatFile(const char* path, const u8** out_bytes, u64* out_len)
{
    using arch::SerialWrite;
    if (path == nullptr || path[0] == 0)
    {
        SerialWrite("[inspect] file: empty path\n");
        return false;
    }
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[inspect] file: no fat32 volume 0\n");
        return false;
    }
    fs::fat32::DirEntry entry;
    const char* leaf = StripFatPrefix(path);
    if (!fs::fat32::Fat32LookupPath(v, leaf, &entry))
    {
        SerialWrite("[inspect] file: lookup failed: ");
        SerialWrite(path);
        SerialWrite("\n");
        return false;
    }
    const i64 rc = fs::fat32::Fat32ReadFile(v, &entry, g_file_scratch, kInspectFileScratchCap);
    if (rc <= 0)
    {
        SerialWrite("[inspect] file: read failed\n");
        return false;
    }
    const u64 len = static_cast<u64>(rc);
    if (len == kInspectFileScratchCap && entry.size_bytes > kInspectFileScratchCap)
    {
        SerialWrite("[inspect] file: truncated at scratch cap (");
        arch::SerialWriteHex(kInspectFileScratchCap);
        SerialWrite(" bytes); scanning prefix only\n");
    }
    *out_bytes = g_file_scratch;
    *out_len = len;
    return true;
}

bool InspectFindPeText(const u8* file, u64 len, InspectSection* out)
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
        // PE32+ (magic 0x20B) stores ImageBase at offset 24 as
        // u64; PE32 (magic 0x10B) at offset 28 as u32.
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

bool InspectFindElfText(const u8* file, u64 len, InspectSection* out)
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

// ---------- Opcodes scanner ----------

namespace
{

// File-scope report buffer. Single instance, overwritten on
// each scan. Operator-triggered scans are single-threaded by
// construction (shell serializes) and the spawn-path call is
// also single-threaded at the point of interest; no locking
// needed.
OpcodeScanReport g_op_report;

// Rank the full 256-entry first_byte histogram into the
// top-N slots. Uses a simple selection pass — N is fixed at
// kOpcodeHistogramTopN (16), so this is O(256*16) = trivial.
void BuildTopN(OpcodeScanReport& r)
{
    static bool taken[256];
    // Manual reset — `bool taken[256] = {}` on a local would
    // be lowered to a memset call the freestanding kernel
    // can't link.
    for (u32 b = 0; b < 256; ++b)
        taken[b] = false;
    r.top_n_valid = 0;
    for (u32 slot = 0; slot < kOpcodeHistogramTopN; ++slot)
    {
        u32 best_count = 0;
        i32 best_byte = -1;
        for (u32 b = 0; b < 256; ++b)
        {
            if (taken[b])
                continue;
            if (r.first_byte[b] > best_count)
            {
                best_count = r.first_byte[b];
                best_byte = static_cast<i32>(b);
            }
        }
        if (best_byte < 0 || best_count == 0)
            break;
        taken[best_byte] = true;
        r.top_n_byte[slot] = static_cast<u8>(best_byte);
        r.top_n_count[slot] = best_count;
        ++r.top_n_valid;
    }
}

// Classify a byte position into the "interesting instruction
// class" buckets. Returns how many bytes to advance past
// this position (1 for prefixes / single-byte opcodes,
// 2 for 0F-escape + CD xx forms). A classification of "no
// class" still returns 1 so the caller just walks on.
//
// We deliberately don't parse ModRM / SIB / displacement. A
// two-byte JE rel32 looks like 0F 84 …; we count the 0F 84
// and move on, which undercounts nothing the operator cares
// about at triage time.
u32 ClassifyAndAdvance(const u8* p, u64 remaining, OpcodeScanReport& r)
{
    const u8 b0 = p[0];
    // Two-byte escapes.
    if (b0 == 0x0F && remaining >= 2)
    {
        const u8 b1 = p[1];
        ++r.esc_0f[b1];
        if (b1 == 0x05)
        {
            ++r.syscall_idiom;
        }
        else if (b1 == 0x34)
        {
            ++r.syscall_idiom;
        }
        else if (b1 >= 0x80 && b1 <= 0x8F)
        {
            ++r.jump_near;
        }
        else if (b1 == 0x1F)
        {
            ++r.nop;
        }
        return 2;
    }
    // INT imm8.
    if (b0 == 0xCD && remaining >= 2)
    {
        const u8 b1 = p[1];
        if (b1 == 0x80 || b1 == 0x2E)
        {
            ++r.syscall_idiom;
        }
        else
        {
            ++r.int_imm;
        }
        return 2;
    }
    // Single-byte control flow.
    if (b0 == 0xE8)
    {
        ++r.call_near;
        return 1;
    }
    if (b0 == 0xE9 || b0 == 0xEB)
    {
        ++r.jump_near;
        return 1;
    }
    if (b0 == 0xC2 || b0 == 0xC3 || b0 == 0xCA || b0 == 0xCB)
    {
        ++r.ret_near;
        return 1;
    }
    if (b0 == 0x90)
    {
        ++r.nop;
        return 1;
    }
    // Prefixes. We count the lone byte then fall through —
    // the next iteration will classify whatever primary
    // opcode follows it.
    if (b0 >= 0x40 && b0 <= 0x4F)
    {
        ++r.rex_prefix;
        return 1;
    }
    if (b0 == 0xF0)
    {
        ++r.lock_prefix;
        return 1;
    }
    if (b0 == 0xF2 || b0 == 0xF3)
    {
        ++r.rep_prefix;
        return 1;
    }
    if (b0 == 0x26 || b0 == 0x2E || b0 == 0x36 || b0 == 0x3E || b0 == 0x64 || b0 == 0x65)
    {
        ++r.seg_prefix;
        return 1;
    }
    if (b0 == 0x66 || b0 == 0x67)
    {
        ++r.osz_prefix;
        return 1;
    }
    return 1;
}

void LogHistogram(const OpcodeScanReport& r)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[inspect-op] top-");
    SerialWriteHex(r.top_n_valid);
    SerialWrite(" first-byte opcodes:\n");
    for (u32 i = 0; i < r.top_n_valid; ++i)
    {
        SerialWrite("[inspect-op]   0x");
        SerialWriteHex(r.top_n_byte[i]);
        SerialWrite(" count=");
        SerialWriteHex(r.top_n_count[i]);
        SerialWrite("\n");
    }
}

void LogClassCounters(const OpcodeScanReport& r)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[inspect-op] class: jump=");
    SerialWriteHex(r.jump_near);
    SerialWrite(" call=");
    SerialWriteHex(r.call_near);
    SerialWrite(" ret=");
    SerialWriteHex(r.ret_near);
    SerialWrite(" int=");
    SerialWriteHex(r.int_imm);
    SerialWrite(" nop=");
    SerialWriteHex(r.nop);
    SerialWrite(" syscall=");
    SerialWriteHex(r.syscall_idiom);
    SerialWrite("\n[inspect-op] prefix: rex=");
    SerialWriteHex(r.rex_prefix);
    SerialWrite(" lock=");
    SerialWriteHex(r.lock_prefix);
    SerialWrite(" rep=");
    SerialWriteHex(r.rep_prefix);
    SerialWrite(" seg=");
    SerialWriteHex(r.seg_prefix);
    SerialWrite(" osz=");
    SerialWriteHex(r.osz_prefix);
    SerialWrite("\n");
}

} // namespace

void OpcodeScanRegion(const u8* bytes, u64 size, u64 base_va)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    OpcodeScanReport& r = g_op_report;
    ByteZero(&r, sizeof(r));
    r.region_base_va = base_va;
    r.region_size = size;
    if (bytes == nullptr || size == 0)
        return;

    SerialWrite("[inspect-op] begin base=");
    SerialWriteHex(base_va);
    SerialWrite(" size=");
    SerialWriteHex(size);
    SerialWrite("\n");

    // First pass: raw byte histogram. Every byte counts toward
    // the first-byte frequency table — that's the "top 16
    // opcodes in this blob" signal, even though many of those
    // bytes are actually operand / displacement bytes of
    // multi-byte instructions. Ordinary code distributions
    // still make the meaningful opcodes (0x48 REX.W, 0xE8 CALL,
    // 0x89 MOV r/m,r) float to the top.
    for (u64 i = 0; i < size; ++i)
    {
        ++r.first_byte[bytes[i]];
    }

    // Second pass: classification walk with opcode advance.
    // This is the "how many jumps/calls/etc" signal — decoupled
    // from the raw histogram so false positives in the histogram
    // don't leak into the class counters.
    u64 i = 0;
    while (i < size)
    {
        const u64 remaining = size - i;
        const u32 step = ClassifyAndAdvance(bytes + i, remaining, r);
        i += step;
    }

    BuildTopN(r);
    LogHistogram(r);
    LogClassCounters(r);
}

void OpcodeScanFile(const char* path)
{
    using arch::SerialWrite;

    const u8* bytes = nullptr;
    u64 len = 0;
    if (!InspectReadFatFile(path, &bytes, &len))
        return;

    InspectSection sec;
    ByteZero(&sec, sizeof(sec));
    if (InspectFindPeText(bytes, len, &sec))
    {
        SerialWrite("[inspect-op] file: PE, scanning .text va=");
        arch::SerialWriteHex(sec.base_va);
        SerialWrite("\n");
        OpcodeScanRegion(bytes + sec.file_off, sec.size, sec.base_va);
        return;
    }
    if (InspectFindElfText(bytes, len, &sec))
    {
        SerialWrite("[inspect-op] file: ELF, scanning PT_LOAD (X) vaddr=");
        arch::SerialWriteHex(sec.base_va);
        SerialWrite("\n");
        OpcodeScanRegion(bytes + sec.file_off, sec.size, sec.base_va);
        return;
    }
    SerialWrite("[inspect-op] file: no PE/ELF header, scanning raw bytes\n");
    OpcodeScanRegion(bytes, len, 0);
}

// ---------- Arm latch ----------
//
// Single boolean, written from shell-thread context (`inspect
// arm on/off`) and read from spawn-path context. Aligned u8
// loads/stores on x86_64 are atomic at the hardware level; no
// locking needed. The arm latch is one-shot by design — a
// single `on` fires on the next spawn and then clears itself,
// matching the "I'm about to run foo.exe, tell me about it"
// workflow the operator actually wants.
namespace
{
volatile bool g_inspect_armed = false;
}

bool InspectArmActive()
{
    return g_inspect_armed;
}

void InspectArmSet(bool on)
{
    g_inspect_armed = on;
}

void InspectOnSpawn(const char* name, const u8* bytes, u64 size)
{
    if (!g_inspect_armed)
        return;
    // Disarm first so a reentrant spawn (e.g. a driver thread
    // that spawns during our log output) doesn't re-fire.
    g_inspect_armed = false;

    using arch::SerialWrite;
    SerialWrite("[inspect] arm fired on spawn: name=\"");
    SerialWrite(name != nullptr ? name : "<anon>");
    SerialWrite("\"\n");

    if (bytes == nullptr || size == 0)
    {
        SerialWrite("[inspect] arm: empty image, skipping\n");
        return;
    }

    // Auto-detect the executable section inside the in-memory
    // image. Ring-3 spawn hands us the file-on-disk bytes (not
    // the mapped image), so the PE/ELF locators work.
    InspectSection sec;
    ByteZero(&sec, sizeof(sec));
    if (InspectFindPeText(bytes, size, &sec))
    {
        OpcodeScanRegion(bytes + sec.file_off, sec.size, sec.base_va);
        return;
    }
    if (InspectFindElfText(bytes, size, &sec))
    {
        OpcodeScanRegion(bytes + sec.file_off, sec.size, sec.base_va);
        return;
    }
    // Raw: scan the whole buffer.
    OpcodeScanRegion(bytes, size, 0);
}

} // namespace duetos::debug
