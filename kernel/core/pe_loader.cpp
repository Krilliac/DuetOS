#include "pe_loader.h"

#include "../arch/x86_64/serial.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/page.h"
#include "../mm/paging.h"

namespace customos::core
{

namespace
{

// Little-endian readers — same contract as the ELF loader's:
// the buffer is byte-addressed and headers may sit at offsets
// with no natural alignment, so we never dereference through a
// (T*) cast.
inline u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
inline u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
inline u64 LeU64(const u8* p)
{
    return static_cast<u64>(LeU32(p)) | (static_cast<u64>(LeU32(p + 4)) << 32);
}

// ---- PE constants (the handful the v0 loader cares about) ----
constexpr u16 kDosMagic = 0x5A4D;        // 'M','Z' in LE
constexpr u32 kPeSignature = 0x00004550; // 'P','E',0,0 in LE
constexpr u16 kMachineAmd64 = 0x8664;
constexpr u16 kOptMagicPe32Plus = 0x020B;
constexpr u32 kPageAlign = 4096;

// Offsets inside the IMAGE_FILE_HEADER (20 bytes) and the
// PE32+ IMAGE_OPTIONAL_HEADER. Hand-coded rather than pulled
// from <winnt.h> so the kernel stays self-contained — we never
// include Windows SDK headers, and PE layout is an ABI-stable
// part of the PE spec anyway.
constexpr u64 kFileHeaderSize = 20;
constexpr u64 kOptHeaderAddressOfEntryPoint = 16;
constexpr u64 kOptHeaderImageBase = 24;
constexpr u64 kOptHeaderSectionAlignment = 32;
constexpr u64 kOptHeaderFileAlignment = 36;
constexpr u64 kOptHeaderSizeOfImage = 56;
constexpr u64 kOptHeaderSizeOfHeaders = 60;
constexpr u64 kOptHeaderNumberOfRvaAndSizes = 108;
constexpr u64 kOptHeaderDataDirectories = 112;
constexpr u64 kDataDirEntrySize = 8; // RVA + Size
constexpr u64 kSectionHeaderSize = 40;
constexpr u64 kSectionHeaderVirtualSize = 8;
constexpr u64 kSectionHeaderVirtualAddress = 12;
constexpr u64 kSectionHeaderSizeOfRawData = 16;
constexpr u64 kSectionHeaderPointerToRawData = 20;
constexpr u64 kSectionHeaderCharacteristics = 36;

// Data directory indices we specifically gate.
constexpr u64 kDirEntryImport = 1;
constexpr u64 kDirEntryBaseReloc = 5;
constexpr u64 kDirEntryTls = 9;

constexpr u64 kV0StackVa = 0x7FFFE000ULL;
constexpr u64 kPageMask = kPageAlign - 1;

struct PeHeaders
{
    u64 nt_base;      // file offset of "PE\0\0"
    u64 opt_base;     // file offset of Optional Header
    u64 section_base; // file offset of first section header
    u16 section_count;
    u16 opt_header_size;
    u64 image_base;
    u64 image_size;
    u64 entry_rva;
};

// Parse and validate. PeHeaders is populated iff status is Ok.
PeStatus ParseHeaders(const u8* file, u64 file_len, PeHeaders& out)
{
    // DOS stub: need at least e_lfanew (offset 0x3C + 4 bytes).
    if (file == nullptr || file_len < 0x40)
        return PeStatus::TooSmall;
    if (LeU16(file) != kDosMagic)
        return PeStatus::BadDosMagic;

    const u32 e_lfanew = LeU32(file + 0x3C);
    // NT header = 4 bytes sig + 20 FileHeader + 240 PE32+ OptHeader.
    // Demand at least sig + FileHeader; OptHeader size is read
    // from FileHeader and bounds-checked below.
    if (u64(e_lfanew) + 4 + kFileHeaderSize > file_len)
        return PeStatus::BadLfanewBounds;
    out.nt_base = e_lfanew;

    if (LeU32(file + out.nt_base) != kPeSignature)
        return PeStatus::BadNtSignature;

    const u8* file_hdr = file + out.nt_base + 4;
    const u16 machine = LeU16(file_hdr + 0);
    if (machine != kMachineAmd64)
        return PeStatus::BadMachine;
    out.section_count = LeU16(file_hdr + 2);
    if (out.section_count == 0)
        return PeStatus::SectionCountZero;
    out.opt_header_size = LeU16(file_hdr + 16);

    out.opt_base = out.nt_base + 4 + kFileHeaderSize;
    // Need enough optional header bytes to reach our
    // last-read field (NumberOfRvaAndSizes + data dirs).
    const u64 min_opt = kOptHeaderNumberOfRvaAndSizes + 4;
    if (out.opt_header_size < min_opt)
        return PeStatus::OptHeaderOutOfBounds;
    if (out.opt_base + out.opt_header_size > file_len)
        return PeStatus::OptHeaderOutOfBounds;

    const u8* opt = file + out.opt_base;
    if (LeU16(opt) != kOptMagicPe32Plus)
        return PeStatus::NotPe32Plus;

    const u32 section_alignment = LeU32(opt + kOptHeaderSectionAlignment);
    const u32 file_alignment = LeU32(opt + kOptHeaderFileAlignment);
    // SectionAlignment must equal our page size — the loader
    // maps each section at (ImageBase + VirtualAddress), and a
    // sub-page SectionAlignment would mean two sections could
    // share a page with conflicting protections. Refuse.
    if (section_alignment != kPageAlign)
        return PeStatus::SectionAlignUnsup;
    // FileAlignment: the MS spec allows any power-of-2 in the
    // range [512, SectionAlignment]. Real-world PEs (Chrome,
    // ripgrep, the MS UCRT DLLs) use 512; our own toolchain
    // uses 4096 for v0's hello.exe. MapSection already copies
    // on a per-page intersection, so any FileAlignment works
    // for the copy itself. Gate only on "is it a legal value".
    if (file_alignment != 512 && file_alignment != 1024 && file_alignment != 2048 && file_alignment != 4096)
        return PeStatus::FileAlignUnsup;

    out.image_base = LeU64(opt + kOptHeaderImageBase);
    out.entry_rva = LeU32(opt + kOptHeaderAddressOfEntryPoint);
    out.image_size = LeU32(opt + kOptHeaderSizeOfImage);

    // Section headers follow the optional header. Populate
    // `out.section_base` BEFORE any rejection check so PeReport
    // can walk the section table even on "rejected" PEs — the
    // diagnostic path has to work on exactly the PEs we can't
    // load yet.
    out.section_base = out.opt_base + out.opt_header_size;
    const u64 section_table_bytes = u64(out.section_count) * kSectionHeaderSize;
    if (out.section_base + section_table_bytes > file_len)
        return PeStatus::SectionOutOfBounds;

    // Cross-check every section's raw extent fits in the file.
    for (u16 i = 0; i < out.section_count; ++i)
    {
        const u8* sec = file + out.section_base + u64(i) * kSectionHeaderSize;
        const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
        const u32 raw_sz = LeU32(sec + kSectionHeaderSizeOfRawData);
        if (u64(raw_off) + u64(raw_sz) > file_len)
            return PeStatus::SectionOutOfBounds;
    }

    // Data Directories: v0 rejects any image with a non-empty
    // Import, BaseReloc, or TLS directory. These are the three
    // user-mode-loader features a real Win32 subsystem provides;
    // parsing them is done separately by PeReport, which runs
    // BEFORE this function on the spawn path so the log
    // carries a full picture even when we reject.
    const u32 num_dirs = LeU32(opt + kOptHeaderNumberOfRvaAndSizes);
    const u64 dir_bytes = u64(num_dirs) * kDataDirEntrySize;
    if (kOptHeaderDataDirectories + dir_bytes > out.opt_header_size)
        return PeStatus::OptHeaderOutOfBounds;
    auto dir_rva = [&](u64 idx) -> u32
    {
        if (idx >= num_dirs)
            return 0;
        return LeU32(opt + kOptHeaderDataDirectories + idx * kDataDirEntrySize + 0);
    };
    auto dir_size = [&](u64 idx) -> u32
    {
        if (idx >= num_dirs)
            return 0;
        return LeU32(opt + kOptHeaderDataDirectories + idx * kDataDirEntrySize + 4);
    };
    if (dir_rva(kDirEntryImport) != 0 || dir_size(kDirEntryImport) != 0)
        return PeStatus::ImportsPresent;
    if (dir_rva(kDirEntryBaseReloc) != 0 || dir_size(kDirEntryBaseReloc) != 0)
        return PeStatus::RelocsNonEmpty;
    if (dir_rva(kDirEntryTls) != 0 || dir_size(kDirEntryTls) != 0)
        return PeStatus::TlsPresent;

    return PeStatus::Ok;
}

// Map one section. Mirror of the ELF LoadSegment, adapted for
// the PE contract:
//   - VirtualSize is the in-memory footprint (may exceed
//     SizeOfRawData; the tail is .bss-equivalent, zero-init).
//   - SizeOfRawData bytes are copied from
//     file[PointerToRawData..] into memory at
//     ImageBase + VirtualAddress.
//   - Characteristics bits pick the mapping flags.
bool MapSection(const u8* file, const u8* sec, u64 image_base, customos::mm::AddressSpace* as)
{
    using namespace customos::mm;
    const u32 virt_addr = LeU32(sec + kSectionHeaderVirtualAddress);
    const u32 virt_size = LeU32(sec + kSectionHeaderVirtualSize);
    const u32 raw_size = LeU32(sec + kSectionHeaderSizeOfRawData);
    const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
    const u32 chars = LeU32(sec + kSectionHeaderCharacteristics);

    // PE spec: in-memory footprint is max(VirtualSize, RawSize)
    // rounded up to SectionAlignment. Our toolchain config gives
    // us SectionAlignment == FileAlignment == 4096, so:
    u64 in_mem = virt_size > raw_size ? virt_size : raw_size;
    if (in_mem == 0)
        return true; // empty section — skip.

    const u64 seg_va = image_base + virt_addr;
    const u64 start = seg_va & ~kPageMask;
    const u64 end = (seg_va + in_mem + kPageMask) & ~kPageMask;

    u64 flags = kPagePresent | kPageUser;
    if (chars & kScnMemWrite)
        flags |= kPageWritable;
    if (!(chars & kScnMemExecute))
        flags |= kPageNoExecute;
    // Note: kScnMemRead is implied on x86_64 — every mapped
    // page is readable to ring 3 if the U bit is set. PE bit
    // is advisory here.

    for (u64 page_va = start; page_va < end; page_va += kPageSize)
    {
        const PhysAddr frame = AllocateFrame();
        if (frame == kNullFrame)
            return false;
        auto* frame_direct = static_cast<u8*>(PhysToVirt(frame));
        // AllocateFrame hands out zeroed frames; the bytes we
        // don't overwrite below stay zero, which serves as
        // both the PE "BSS" tail and any raw-size < virt-size
        // padding.

        // Intersect this page with the section's raw (file)
        // bytes. Only the intersection is copied.
        const u64 page_end = page_va + kPageSize;
        const u64 raw_mem_end = seg_va + raw_size;
        const u64 copy_lo = (seg_va > page_va) ? seg_va : page_va;
        const u64 copy_hi = (raw_mem_end < page_end) ? raw_mem_end : page_end;
        if (copy_hi > copy_lo)
        {
            const u64 page_off = copy_lo - page_va;
            const u64 file_off = raw_off + (copy_lo - seg_va);
            const u64 n = copy_hi - copy_lo;
            for (u64 i = 0; i < n; ++i)
                frame_direct[page_off + i] = file[file_off + i];
        }
        AddressSpaceMapUserPage(as, page_va, frame, flags);
    }
    return true;
}

// Map the PE headers themselves as a read-only user page. The
// Windows loader conventionally makes the image's first
// SizeOfHeaders bytes visible to the process so code that asks
// `__ImageBase` can walk its own headers. Cheap to do, and
// keeps the image layout at runtime isomorphic to the on-disk
// layout — important for a future slice that runs a DLL
// resolver.
bool MapHeaders(const u8* file, u64 sizeof_headers, u64 image_base, customos::mm::AddressSpace* as)
{
    using namespace customos::mm;
    const u64 start = image_base & ~kPageMask;
    const u64 end = (image_base + sizeof_headers + kPageMask) & ~kPageMask;
    if (end <= start)
        return true;

    for (u64 page_va = start; page_va < end; page_va += kPageSize)
    {
        const PhysAddr frame = AllocateFrame();
        if (frame == kNullFrame)
            return false;
        auto* direct = static_cast<u8*>(PhysToVirt(frame));
        const u64 file_off = page_va - image_base;
        const u64 remain = (file_off < sizeof_headers) ? (sizeof_headers - file_off) : 0;
        const u64 n = remain < kPageSize ? remain : kPageSize;
        for (u64 i = 0; i < n; ++i)
            direct[i] = file[file_off + i];
        AddressSpaceMapUserPage(as, page_va, frame, kPagePresent | kPageUser | kPageNoExecute);
    }
    return true;
}

} // namespace

const char* PeStatusName(PeStatus s)
{
    switch (s)
    {
    case PeStatus::Ok:
        return "Ok";
    case PeStatus::TooSmall:
        return "TooSmall";
    case PeStatus::BadDosMagic:
        return "BadDosMagic";
    case PeStatus::BadLfanewBounds:
        return "BadLfanewBounds";
    case PeStatus::BadNtSignature:
        return "BadNtSignature";
    case PeStatus::BadMachine:
        return "BadMachine";
    case PeStatus::NotPe32Plus:
        return "NotPe32Plus";
    case PeStatus::SectionAlignUnsup:
        return "SectionAlignUnsup";
    case PeStatus::FileAlignUnsup:
        return "FileAlignUnsup";
    case PeStatus::SectionCountZero:
        return "SectionCountZero";
    case PeStatus::OptHeaderOutOfBounds:
        return "OptHeaderOutOfBounds";
    case PeStatus::SectionOutOfBounds:
        return "SectionOutOfBounds";
    case PeStatus::ImportsPresent:
        return "ImportsPresent";
    case PeStatus::RelocsNonEmpty:
        return "RelocsNonEmpty";
    case PeStatus::TlsPresent:
        return "TlsPresent";
    }
    return "?";
}

PeStatus PeValidate(const u8* file, u64 file_len)
{
    PeHeaders h{};
    return ParseHeaders(file, file_len, h);
}

PeLoadResult PeLoad(const u8* file, u64 file_len, customos::mm::AddressSpace* as)
{
    PeLoadResult r{};
    r.ok = false;
    if (as == nullptr)
        return r;

    PeHeaders h{};
    if (ParseHeaders(file, file_len, h) != PeStatus::Ok)
        return r;

    using namespace customos::mm;
    // 1. Map PE headers (RO, NX) at ImageBase. Loader
    //    convention — makes __ImageBase usable from ring 3.
    const u64 sizeof_headers = LeU32(file + h.opt_base + kOptHeaderSizeOfHeaders);
    if (!MapHeaders(file, sizeof_headers, h.image_base, as))
        return r;

    // 2. Map every section.
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        if (!MapSection(file, sec, h.image_base, as))
            return r;
    }

    // 3. One stack page, writable + NX, same VA the ELF
    //    loader uses so the rest of the ring3 plumbing does
    //    not need to know which loader produced the image.
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
        return r;
    AddressSpaceMapUserPage(as, kV0StackVa, stack_frame, kPagePresent | kPageUser | kPageWritable | kPageNoExecute);

    r.ok = true;
    r.entry_va = h.image_base + h.entry_rva;
    r.stack_va = kV0StackVa;
    r.stack_top = kV0StackVa + kPageSize;
    r.image_base = h.image_base;
    r.image_size = h.image_size;
    return r;
}

// ---------------------------------------------------------------
// PeReport — diagnostic dump of DOS + NT + sections + imports +
// relocs + TLS.
//
// Called from SpawnPeFile BEFORE PeValidate so the serial log
// carries a full picture of any PE we touched, even if the
// loader then rejects it. When `hello.exe` (freestanding, no
// imports) goes through this, the import/reloc/TLS sections
// report "empty". When a real Windows PE like windows-kill.exe
// or a Chrome DLL goes through, the same function lists every
// imported DLL + function, base-reloc block count, and TLS
// callback count — giving a concrete measure of the Win32
// subsystem gap.
// ---------------------------------------------------------------

namespace
{

// Read a NUL-terminated ASCII string at `file[off..]` with
// bounds checks. Returns nullptr if we can't prove there's a
// NUL before the buffer ends — callers treat that as "skip,
// malformed". Cap at 256 chars so a hostile image can't dangle
// the serial log forever.
const char* BoundedCString(const u8* file, u64 file_len, u64 off)
{
    if (off >= file_len)
        return nullptr;
    constexpr u64 kMaxLen = 256;
    const u64 cap = (file_len - off) < kMaxLen ? (file_len - off) : kMaxLen;
    for (u64 i = 0; i < cap; ++i)
    {
        if (file[off + i] == 0)
            return reinterpret_cast<const char*>(file + off);
    }
    return nullptr;
}

// RVA -> file offset using the section table. Returns u64(-1)
// if the RVA lies outside every section's virtual extent.
// PE directories (Import, BaseReloc, TLS) point to RVAs, and
// those RVAs must land inside one of the sections we've
// already bounds-checked.
u64 RvaToFile(const u8* file, const PeHeaders& h, u32 rva)
{
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        const u32 va = LeU32(sec + kSectionHeaderVirtualAddress);
        const u32 raw_size = LeU32(sec + kSectionHeaderSizeOfRawData);
        const u32 virt_size = LeU32(sec + kSectionHeaderVirtualSize);
        const u32 extent = raw_size > virt_size ? raw_size : virt_size;
        if (rva >= va && rva < va + extent)
        {
            const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
            return u64(raw_off) + u64(rva - va);
        }
    }
    return ~u64(0);
}

// Read directory [rva, size] from the Optional Header's data
// directory table. Returns {rva=0, size=0} if the index is
// past NumberOfRvaAndSizes.
struct PeDataDir
{
    u32 rva;
    u32 size;
};
PeDataDir ReadDataDir(const u8* file, const PeHeaders& h, u64 idx)
{
    const u8* opt = file + h.opt_base;
    const u32 num_dirs = LeU32(opt + kOptHeaderNumberOfRvaAndSizes);
    if (idx >= num_dirs)
        return {0, 0};
    const u8* e = opt + kOptHeaderDataDirectories + idx * kDataDirEntrySize;
    return {LeU32(e + 0), LeU32(e + 4)};
}

void ReportSections(const u8* file, const PeHeaders& h)
{
    using arch::SerialWrite;
    using arch::SerialWriteByte;
    using arch::SerialWriteHex;
    SerialWrite("  sections (");
    SerialWriteHex(h.section_count);
    SerialWrite(")\n");
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        SerialWrite("    [");
        // Section name is 8 bytes, NOT NUL-terminated when full.
        // Emit char-by-char until first zero byte.
        for (u64 j = 0; j < 8; ++j)
        {
            const u8 c = sec[j];
            if (c == 0)
                break;
            SerialWriteByte(c);
        }
        SerialWrite("] rva=");
        SerialWriteHex(LeU32(sec + kSectionHeaderVirtualAddress));
        SerialWrite(" vsz=");
        SerialWriteHex(LeU32(sec + kSectionHeaderVirtualSize));
        SerialWrite(" rsz=");
        SerialWriteHex(LeU32(sec + kSectionHeaderSizeOfRawData));
        SerialWrite(" flags=");
        SerialWriteHex(LeU32(sec + kSectionHeaderCharacteristics));
        SerialWrite("\n");
    }
}

void ReportImports(const u8* file, u64 file_len, const PeHeaders& h)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    const PeDataDir imp = ReadDataDir(file, h, kDirEntryImport);
    if (imp.rva == 0 || imp.size == 0)
    {
        SerialWrite("  imports: (empty)\n");
        return;
    }
    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes:
    //   u32 OriginalFirstThunk  (RVA of INT, 0-terminated u64 array)
    //   u32 TimeDateStamp
    //   u32 ForwarderChain
    //   u32 Name                 (RVA of NUL-terminated DLL name)
    //   u32 FirstThunk           (RVA of IAT)
    // Terminated by an all-zero descriptor.
    const u64 tbl_off = RvaToFile(file, h, imp.rva);
    if (tbl_off == ~u64(0) || tbl_off + imp.size > file_len)
    {
        SerialWrite("  imports: <bad rva>\n");
        return;
    }
    SerialWrite("  imports: rva=");
    SerialWriteHex(imp.rva);
    SerialWrite(" size=");
    SerialWriteHex(imp.size);
    SerialWrite("\n");

    u32 dll_count = 0;
    u32 fn_count = 0;
    constexpr u32 kMaxDll = 64;
    constexpr u32 kMaxFnPerDll = 64;

    for (u32 d = 0; d < kMaxDll; ++d)
    {
        const u64 desc_off = tbl_off + u64(d) * 20;
        if (desc_off + 20 > file_len)
            break;
        const u8* desc = file + desc_off;
        const u32 orig_thunk = LeU32(desc + 0);
        const u32 name_rva = LeU32(desc + 12);
        const u32 first_thunk = LeU32(desc + 16);
        if (orig_thunk == 0 && name_rva == 0 && first_thunk == 0)
            break; // terminator

        ++dll_count;
        SerialWrite("    needs ");
        const u64 name_off = RvaToFile(file, h, name_rva);
        const char* dll_name = (name_off == ~u64(0)) ? nullptr : BoundedCString(file, file_len, name_off);
        SerialWrite(dll_name ? dll_name : "<bad dll name>");
        SerialWrite(":\n");

        // Walk the INT (Import Name Table). Each entry is a
        // u64: MSB set -> import by ordinal (low 16 bits);
        // else entry is an RVA to an IMAGE_IMPORT_BY_NAME
        // (u16 hint + NUL-terminated name).
        const u32 int_rva = orig_thunk ? orig_thunk : first_thunk;
        if (int_rva == 0)
            continue;
        const u64 int_off = RvaToFile(file, h, int_rva);
        if (int_off == ~u64(0))
        {
            SerialWrite("      <bad INT rva>\n");
            continue;
        }
        for (u32 f = 0; f < kMaxFnPerDll; ++f)
        {
            const u64 ent_off = int_off + u64(f) * 8;
            if (ent_off + 8 > file_len)
                break;
            const u64 ent = LeU64(file + ent_off);
            if (ent == 0)
                break;
            ++fn_count;
            SerialWrite("      ");
            if (ent & (u64(1) << 63))
            {
                SerialWrite("<ord ");
                SerialWriteHex(ent & 0xFFFF);
                SerialWrite(">\n");
                continue;
            }
            const u32 ibn_rva = static_cast<u32>(ent & 0x7FFFFFFF);
            const u64 ibn_off = RvaToFile(file, h, ibn_rva);
            if (ibn_off == ~u64(0) || ibn_off + 2 >= file_len)
            {
                SerialWrite("<bad name rva>\n");
                continue;
            }
            const char* fn_name = BoundedCString(file, file_len, ibn_off + 2);
            SerialWrite(fn_name ? fn_name : "<bad fn name>");
            SerialWrite("\n");
        }
    }
    SerialWrite("  imports total: dlls=");
    SerialWriteHex(dll_count);
    SerialWrite(" functions=");
    SerialWriteHex(fn_count);
    SerialWrite("\n");
}

void ReportRelocs(const u8* file, u64 file_len, const PeHeaders& h)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    const PeDataDir br = ReadDataDir(file, h, kDirEntryBaseReloc);
    if (br.rva == 0 || br.size == 0)
    {
        SerialWrite("  relocs: (empty)\n");
        return;
    }
    const u64 tbl_off = RvaToFile(file, h, br.rva);
    if (tbl_off == ~u64(0) || tbl_off + br.size > file_len)
    {
        SerialWrite("  relocs: <bad rva>\n");
        return;
    }
    // Each block: u32 PageRVA, u32 BlockSize (includes the 8-byte
    // header), then (BlockSize-8)/2 u16 entries. Walk blocks
    // and accumulate totals.
    u32 blocks = 0;
    u32 entries = 0;
    u64 cursor = tbl_off;
    const u64 end = tbl_off + br.size;
    while (cursor + 8 <= end)
    {
        const u32 page_rva = LeU32(file + cursor + 0);
        const u32 block_sz = LeU32(file + cursor + 4);
        if (block_sz < 8 || cursor + block_sz > end)
            break;
        if (page_rva == 0 && block_sz == 0)
            break;
        ++blocks;
        entries += (block_sz - 8) / 2;
        cursor += block_sz;
    }
    SerialWrite("  relocs: blocks=");
    SerialWriteHex(blocks);
    SerialWrite(" entries=");
    SerialWriteHex(entries);
    SerialWrite(" dir_size=");
    SerialWriteHex(br.size);
    SerialWrite("\n");
}

void ReportTls(const u8* file, u64 file_len, const PeHeaders& h)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    const PeDataDir tls = ReadDataDir(file, h, kDirEntryTls);
    if (tls.rva == 0 || tls.size == 0)
    {
        SerialWrite("  tls: (empty)\n");
        return;
    }
    const u64 tls_off = RvaToFile(file, h, tls.rva);
    // PE32+ TLS directory layout:
    //   u64 StartAddressOfRawData
    //   u64 EndAddressOfRawData
    //   u64 AddressOfIndex
    //   u64 AddressOfCallBacks   (VA of 0-terminated array of callback VAs)
    //   u32 SizeOfZeroFill
    //   u32 Characteristics
    if (tls_off == ~u64(0) || tls_off + 40 > file_len)
    {
        SerialWrite("  tls: <bad rva>\n");
        return;
    }
    const u64 raw_start = LeU64(file + tls_off + 0);
    const u64 raw_end = LeU64(file + tls_off + 8);
    const u64 cb_va = LeU64(file + tls_off + 24);
    SerialWrite("  tls: raw=[");
    SerialWriteHex(raw_start);
    SerialWrite("..");
    SerialWriteHex(raw_end);
    SerialWrite("] callbacks_va=");
    SerialWriteHex(cb_va);

    // Count callbacks. AddressOfCallBacks is a VA pointing at a
    // 0-terminated array of VAs in the image's mapped address
    // space. On disk we convert (VA - ImageBase) -> RVA -> file
    // offset.
    u32 cb_count = 0;
    if (cb_va != 0 && cb_va >= h.image_base)
    {
        const u32 cb_rva = static_cast<u32>(cb_va - h.image_base);
        const u64 cb_off = RvaToFile(file, h, cb_rva);
        if (cb_off != ~u64(0))
        {
            constexpr u32 kMaxCb = 16;
            for (u32 i = 0; i < kMaxCb; ++i)
            {
                const u64 ent_off = cb_off + u64(i) * 8;
                if (ent_off + 8 > file_len)
                    break;
                const u64 ent = LeU64(file + ent_off);
                if (ent == 0)
                    break;
                ++cb_count;
            }
        }
    }
    SerialWrite(" callbacks=");
    SerialWriteHex(cb_count);
    SerialWrite("\n");
}

} // namespace

void PeReport(const u8* file, u64 file_len)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    if (file == nullptr || file_len == 0)
        return;
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    // ParseHeaders populates h through BadDosMagic; if we get
    // past the signature+machine checks we can report. If it
    // fails earlier we still want to say so briefly.
    SerialWrite("[pe-report] bytes=");
    SerialWriteHex(file_len);
    SerialWrite(" parse_status=");
    SerialWrite(PeStatusName(s));
    SerialWrite("\n");
    if (s == PeStatus::TooSmall || s == PeStatus::BadDosMagic || s == PeStatus::BadLfanewBounds ||
        s == PeStatus::BadNtSignature || s == PeStatus::BadMachine || s == PeStatus::NotPe32Plus)
    {
        return;
    }
    SerialWrite("  image_base=");
    SerialWriteHex(h.image_base);
    SerialWrite(" entry_rva=");
    SerialWriteHex(h.entry_rva);
    SerialWrite(" image_size=");
    SerialWriteHex(h.image_size);
    SerialWrite("\n");
    ReportSections(file, h);
    ReportImports(file, file_len, h);
    ReportRelocs(file, file_len, h);
    ReportTls(file, file_len, h);
}

} // namespace customos::core
