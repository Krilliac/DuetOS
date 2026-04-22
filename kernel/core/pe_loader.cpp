#include "pe_loader.h"

#include "../arch/x86_64/serial.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/page.h"
#include "klog.h"
#include "../mm/paging.h"
#include "../security/guard.h"
#include "../subsystems/win32/stubs.h"

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

// Stack layout: kV0StackTop is the one-past-last byte (initial rsp
// is kV0StackTop - 8), kV0StackPages is how many 4 KiB pages we
// actually map ending just below it. One page is enough for the
// freestanding hello_pe and hello_winapi tests but not for a real
// MSVC PE — the CRT's __chkstk walks the stack a page at a time
// during startup and a cold PE like windows-kill.exe needs ~tens
// of KiB of it mapped up front. 16 pages (64 KiB) is the committed
// v0 default; workloads that want more get a larger budget via an
// explicit override at spawn time (path not wired yet).
constexpr u64 kV0StackTop = 0x80000000ULL;
constexpr u64 kV0StackPages = 16;
constexpr u64 kV0StackVa = kV0StackTop - kV0StackPages * customos::mm::kPageSize;
constexpr u64 kPageMask = kPageAlign - 1;

// Minimal TEB (Thread Environment Block) page for Win32 PEs.
// Placed between the Win32 stubs (0x60000000) and the user stack
// (0x7FFF0000) so it doesn't collide with anything the loader
// already maps. Populated with NT_TIB.Self at offset 0x30 so MSVC
// CRT startup code that reads gs:[0x30] (the classic x64 TEB
// self-pointer dereference) gets a valid VA back. All other TEB
// fields stay zero — good enough to progress past the CRT's
// earliest TEB reads; anything later (TLS slot lookup, PEB
// traversal) will fault visibly so we can fill it in incrementally.
constexpr u64 kV0TebVa = 0x70000000ULL;
constexpr u64 kTebOffSelf = 0x30;

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
    // Base-reloc directory is accepted as of the base-reloc slice
    // — PeLoad walks the table in ApplyRelocations below. In v0
    // we always map the image at its preferred ImageBase so the
    // effective delta is zero; the walk still runs to validate
    // the table shape and catch malformed .reloc sections early.
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
    case PeStatus::StubsPageAllocFail:
        return "StubsPageAllocFail";
    }
    return "?";
}

PeStatus PeValidate(const u8* file, u64 file_len)
{
    PeHeaders h{};
    return ParseHeaders(file, file_len, h);
}

// Resolve every entry in the import table by patching the IAT
// in place. For each import descriptor:
//   1. Read the DLL name from its Name RVA.
//   2. For each function entry (by-name; ordinal imports get
//      rejected in v0), read the hint/name from the IBN, look
//      up the stub VA in win32::Win32StubsLookup.
//   3. Write the stub VA to the corresponding IAT slot by
//      finding the user page's physical frame and poking
//      through the kernel's direct map (the user-level
//      mapping is read-only; the kernel's mapping isn't).
//
// Returns true only if EVERY import resolves. The caller must
// treat `false` as a fatal load failure — a half-resolved IAT
// leaves null slots that would #PF on the first call.
//
// Separate namespace{} block from the parsing/reporting
// helpers above: that earlier block is closed before PeLoad,
// so a fresh anon namespace is the cheapest place to put this
// helper without forcing a forward-declare.
namespace
{

// Walk the base-relocation directory and apply each entry to
// the in-memory image. `delta = actual_base - preferred_base`;
// in v0 we always load at the preferred base so delta == 0 and
// the inner patch is a no-op, but the walk still runs to catch
// a malformed .reloc section (bad block size, unsupported
// relocation type, out-of-bounds page RVA).
//
// Each block patches entries within one 4 KiB virtual page:
//   u32 PageRVA
//   u32 BlockSize  (includes the 8-byte header)
//   u16 entries[]  (top 4 bits = type, bottom 12 bits = page offset)
//
// v0 supports:
//   type 0  IMAGE_REL_BASED_ABSOLUTE  — padding, skip.
//   type 10 IMAGE_REL_BASED_DIR64     — add delta to the u64 at
//                                        ImageBase + PageRVA + offset.
// Any other type is rejected — PE32+ images produced by MSVC /
// lld-link use only these two.
//
// When delta != 0, a DIR64 patch whose 8 bytes straddle a page
// boundary needs two `AddressSpaceLookupUserFrame` lookups. The
// apply path handles that correctly; the zero-delta pass never
// touches memory so the split case is invisible there.
bool ApplyRelocations(const u8* file, u64 file_len, const PeHeaders& h, customos::mm::AddressSpace* as, u64 delta)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    const PeDataDir br = ReadDataDir(file, h, kDirEntryBaseReloc);
    if (br.rva == 0 || br.size == 0)
        return true;

    const u64 tbl_off = RvaToFile(file, h, br.rva);
    if (tbl_off == ~u64(0) || tbl_off + br.size > file_len)
    {
        SerialWrite("[pe-reloc] reloc table rva out of bounds\n");
        return false;
    }

    const u64 end = tbl_off + br.size;
    u64 cursor = tbl_off;
    u32 blocks_seen = 0;
    u32 entries_applied = 0;

    while (cursor + 8 <= end)
    {
        const u32 page_rva = LeU32(file + cursor + 0);
        const u32 block_sz = LeU32(file + cursor + 4);
        if (block_sz < 8 || cursor + block_sz > end)
        {
            SerialWrite("[pe-reloc] malformed block size\n");
            return false;
        }
        // Terminator: an all-zero block ends the directory even if
        // br.size covers trailing padding.
        if (page_rva == 0 && block_sz == 0)
            break;

        const u32 entry_count = (block_sz - 8) / 2;
        for (u32 i = 0; i < entry_count; ++i)
        {
            const u16 entry = LeU16(file + cursor + 8 + u64(i) * 2);
            const u16 type = entry >> 12;
            const u16 offset = entry & 0x0FFF;

            if (type == 0) // IMAGE_REL_BASED_ABSOLUTE — pad entry.
                continue;
            if (type != 10) // IMAGE_REL_BASED_DIR64 is the only other type we expect.
            {
                SerialWrite("[pe-reloc] unsupported reloc type=");
                SerialWriteHex(type);
                SerialWrite("\n");
                return false;
            }

            if (delta == 0)
                continue; // no-op apply — still validated the entry shape.

            const u64 patch_va = h.image_base + u64(page_rva) + u64(offset);
            // Read current 8 bytes, add delta, write back. Split
            // across two frames if the write straddles a page.
            u64 orig = 0;
            for (u64 b = 0; b < 8; ++b)
            {
                const u64 va = patch_va + b;
                const u64 page_va = va & ~0xFFFULL;
                const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, page_va);
                if (frame == mm::kNullFrame)
                {
                    SerialWrite("[pe-reloc] patch va unmapped rva=");
                    SerialWriteHex(page_rva);
                    SerialWrite(" off=");
                    SerialWriteHex(offset);
                    SerialWrite("\n");
                    return false;
                }
                const auto* direct = static_cast<const u8*>(mm::PhysToVirt(frame));
                orig |= u64(direct[va & 0xFFFULL]) << (b * 8);
            }
            const u64 fixed = orig + delta;
            for (u64 b = 0; b < 8; ++b)
            {
                const u64 va = patch_va + b;
                const u64 page_va = va & ~0xFFFULL;
                const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, page_va);
                if (frame == mm::kNullFrame)
                    return false; // can't happen — just read this frame.
                auto* direct = static_cast<u8*>(mm::PhysToVirt(frame));
                direct[va & 0xFFFULL] = u8((fixed >> (b * 8)) & 0xFF);
            }
            ++entries_applied;
        }
        ++blocks_seen;
        cursor += block_sz;
    }

    SerialWrite("[pe-reloc] blocks=");
    SerialWriteHex(blocks_seen);
    SerialWrite(" applied=");
    SerialWriteHex(entries_applied);
    SerialWrite(" delta=");
    SerialWriteHex(delta);
    SerialWrite("\n");
    return true;
}

bool ResolveImports(const u8* file, u64 file_len, const PeHeaders& h, customos::mm::AddressSpace* as)
{
    KLOG_TRACE_SCOPE("pe-resolve", "ResolveImports");
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    const PeDataDir imp = ReadDataDir(file, h, kDirEntryImport);
    if (imp.rva == 0 || imp.size == 0)
        return true; // no imports, nothing to do

    const u64 tbl_off = RvaToFile(file, h, imp.rva);
    if (tbl_off == ~u64(0) || tbl_off + imp.size > file_len)
    {
        SerialWrite("[pe-resolve] import table rva out of bounds\n");
        return false;
    }

    constexpr u32 kMaxDll = 64;
    constexpr u32 kMaxFnPerDll = 256;
    u32 resolved = 0;

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

        const u64 name_off = RvaToFile(file, h, name_rva);
        const char* dll_name = (name_off == ~u64(0)) ? nullptr : BoundedCString(file, file_len, name_off);
        if (dll_name == nullptr)
        {
            SerialWrite("[pe-resolve] descriptor ");
            SerialWriteHex(d);
            SerialWrite(": bad dll name rva\n");
            return false;
        }

        // Walk the INT (which sits in .rdata and is stable
        // across load) to get function names. The IAT might
        // already have been patched by the OS in a real
        // Windows load, but on disk INT == IAT until the
        // loader runs, so OriginalFirstThunk and FirstThunk
        // are interchangeable as the name table source. We
        // prefer OriginalFirstThunk (present on every
        // non-bound import) and fall back to FirstThunk.
        const u32 int_rva = orig_thunk ? orig_thunk : first_thunk;
        if (int_rva == 0 || first_thunk == 0)
        {
            SerialWrite("[pe-resolve] ");
            SerialWrite(dll_name);
            SerialWrite(": descriptor missing IAT or INT\n");
            return false;
        }
        const u64 int_off = RvaToFile(file, h, int_rva);
        if (int_off == ~u64(0))
        {
            SerialWrite("[pe-resolve] ");
            SerialWrite(dll_name);
            SerialWrite(": INT rva out of bounds\n");
            return false;
        }

        for (u32 fn_idx = 0; fn_idx < kMaxFnPerDll; ++fn_idx)
        {
            const u64 int_ent_off = int_off + u64(fn_idx) * 8;
            if (int_ent_off + 8 > file_len)
                break;
            const u64 ent = LeU64(file + int_ent_off);
            if (ent == 0)
                break;
            if (ent & (u64(1) << 63))
            {
                SerialWrite("[pe-resolve] ");
                SerialWrite(dll_name);
                SerialWrite(": ordinal import #");
                SerialWriteHex(ent & 0xFFFF);
                SerialWrite(" — v0 only resolves by-name imports\n");
                return false;
            }
            const u32 ibn_rva = static_cast<u32>(ent & 0x7FFFFFFF);
            const u64 ibn_off = RvaToFile(file, h, ibn_rva);
            if (ibn_off == ~u64(0) || ibn_off + 2 >= file_len)
            {
                SerialWrite("[pe-resolve] ");
                SerialWrite(dll_name);
                SerialWrite(": IBN rva out of bounds\n");
                return false;
            }
            const char* fn_name = BoundedCString(file, file_len, ibn_off + 2);
            if (fn_name == nullptr)
            {
                SerialWrite("[pe-resolve] ");
                SerialWrite(dll_name);
                SerialWrite(": IBN name unterminated\n");
                return false;
            }

            u64 stub_va = 0;
            bool is_noop_stub = false;
            if (!win32::Win32StubsLookupKind(dll_name, fn_name, &stub_va, &is_noop_stub))
            {
                // Unresolved import — the PE calls (or imports as
                // data) a symbol not in the stub table. Historically
                // this was a hard load failure; to let real-world
                // PEs like windows-kill.exe actually run far enough
                // to exercise what IS stubbed, we fall back to the
                // shared "return 0" stub and flag it prominently.
                // Two consequences if the binary really uses it:
                //   - Called as a function -> returns 0, call site
                //     either tolerates it or crashes visibly.
                //   - Dereferenced as a data global -> reads the
                //     3-byte "xor eax,eax; ret" opcode (the page is
                //     present R-X), which is garbage but not a #PF.
                // Either outcome is louder than "loader silently
                // refuses the entire image."
                if (!win32::Win32StubsLookupCatchAll(&stub_va))
                {
                    core::LogWithString(core::LogLevel::Error, "pe-resolve", "UNRESOLVED import (no catch-all)", "fn",
                                        fn_name);
                    core::LogWithString(core::LogLevel::Error, "pe-resolve", "  from", "dll", dll_name);
                    return false;
                }
                is_noop_stub = true;
                core::LogWithString(core::LogLevel::Warn, "pe-resolve", "unknown import -> catch-all NO-OP", "fn",
                                    fn_name);
                core::LogWithString(core::LogLevel::Warn, "pe-resolve", "  from", "dll", dll_name);
            }

            // Patch the IAT slot. Slot VA = image_base +
            // first_thunk + fn_idx * 8. Find backing frame,
            // write via direct map.
            const u64 iat_slot_va = h.image_base + u64(first_thunk) + u64(fn_idx) * 8;
            const mm::PhysAddr iat_frame = mm::AddressSpaceLookupUserFrame(as, iat_slot_va);
            if (iat_frame == mm::kNullFrame)
            {
                SerialWrite("[pe-resolve] ");
                SerialWrite(dll_name);
                SerialWrite("!");
                SerialWrite(fn_name);
                SerialWrite(": IAT slot VA not mapped\n");
                return false;
            }
            auto* iat_direct = static_cast<u8*>(mm::PhysToVirt(iat_frame));
            const u64 page_off = iat_slot_va & 0xFFFULL;
            // Store little-endian u64 byte-by-byte; avoids any
            // alignment assumption on the direct-map pointer.
            for (u64 b = 0; b < 8; ++b)
                iat_direct[page_off + b] = static_cast<u8>((stub_va >> (b * 8)) & 0xFF);
            ++resolved;

            // Structured klog: Info for real stubs, Warn for no-op
            // "safe-ignore" shims. The Warn colour (yellow) makes it
            // obvious at boot-log skim which imports will silently
            // misbehave if the PE actually relies on them.
            const core::LogLevel lvl = is_noop_stub ? core::LogLevel::Warn : core::LogLevel::Info;
            const char* msg = is_noop_stub ? "import resolved to NO-OP stub" : "import resolved";
            core::LogWithString(lvl, "pe-resolve", msg, "fn", fn_name);
        }
    }

    core::LogWithValue(core::LogLevel::Info, "pe-resolve", "total imports resolved", resolved);
    return true;
}

} // namespace

PeLoadResult PeLoad(const u8* file, u64 file_len, customos::mm::AddressSpace* as)
{
    KLOG_TRACE_SCOPE("pe-loader", "PeLoad");
    PeLoadResult r{};
    r.ok = false;
    if (as == nullptr)
        return r;

    // Security guard. Catches the classic process-injection combo
    // (CreateRemoteThread + WriteProcessMemory), the suspicious-API
    // multi-match, and packed/no-import PEs. Advisory mode (default)
    // always allows; Enforce mode prompts the user.
    customos::security::ImageDescriptor gd{customos::security::ImageKind::WindowsPE, "(pe)", file, file_len};
    if (!customos::security::Gate(gd))
    {
        arch::SerialWrite("[pe-loader] security guard blocked PE load\n");
        return r;
    }

    PeHeaders h{};
    const PeStatus ps = ParseHeaders(file, file_len, h);
    // Two parse outcomes are tractable for v0:
    //   Ok             — freestanding PE, no imports, load
    //                    directly (hello_pe path).
    //   ImportsPresent — imports exist; resolve them through
    //                    the Win32 stubs table below. Returned
    //                    by ParseHeaders before it checks
    //                    Relocs/TLS, so we know the reject
    //                    reason IS imports (not something we
    //                    don't handle at all yet).
    // Everything else is still a hard reject for v0.
    // Accept TlsPresent alongside Ok + ImportsPresent — TLS
    // callbacks aren't wired (the PE will not have _tls_index
    // or TEB.ThreadLocalStoragePointer populated), but many
    // real-world PEs carry a near-empty .tls section that the
    // program itself doesn't actually read at runtime (e.g.
    // MSVC's default CRT stubs). Rejecting on TLS presence
    // alone keeps us from even ATTEMPTING to run binaries like
    // windows-kill.exe; accepting + logging lets us see how
    // far they get before the first real gap.
    if (ps != PeStatus::Ok && ps != PeStatus::ImportsPresent && ps != PeStatus::TlsPresent)
        return r;

    using namespace customos::mm;
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    // Step-trace breadcrumbs. PeLoad has several paths that can
    // silently return false (frame-alloc OOMs, bad section RVA,
    // ResolveImports internals). Logging each gate gives us a
    // "last breadcrumb wins" view of where a real-world PE like
    // windows-kill.exe drops out, without having to instrument
    // every helper.
    SerialWrite("[pe-load] begin status=");
    SerialWrite(PeStatusName(ps));
    SerialWrite(" image_base=");
    SerialWriteHex(h.image_base);
    SerialWrite(" sections=");
    SerialWriteHex(h.section_count);
    SerialWrite("\n");

    // 1. Map PE headers (RO, NX) at ImageBase. Loader
    //    convention — makes __ImageBase usable from ring 3.
    const u64 sizeof_headers = LeU32(file + h.opt_base + kOptHeaderSizeOfHeaders);
    if (!MapHeaders(file, sizeof_headers, h.image_base, as))
    {
        SerialWrite("[pe-load] FAIL MapHeaders\n");
        return r;
    }
    SerialWrite("[pe-load] step1 headers mapped\n");

    // 2. Map every section.
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        if (!MapSection(file, sec, h.image_base, as))
        {
            SerialWrite("[pe-load] FAIL MapSection idx=");
            SerialWriteHex(i);
            SerialWrite("\n");
            return r;
        }
    }
    SerialWrite("[pe-load] step2 sections mapped\n");

    // 3. Apply base relocations. v0 always loads at the preferred
    //    ImageBase (no ASLR, no DLL collision handling), so delta
    //    is 0 and the apply path is a no-op — the walk still runs
    //    to reject a malformed .reloc section before ring-3 entry.
    //    When ASLR lands, compute the actual_base delta here.
    const u64 reloc_delta = 0;
    if (!ApplyRelocations(file, file_len, h, as, reloc_delta))
    {
        SerialWrite("[pe-load] FAIL ApplyRelocations\n");
        return r;
    }
    SerialWrite("[pe-load] step3 relocs applied\n");

    // 4. Stack: kV0StackPages pages, writable + NX, mapped
    //    ending at kV0StackTop. MSVC's __chkstk probes the
    //    stack a page at a time during CRT startup, so a real
    //    PE needs several pages up front (1 page was enough
    //    for hello_winapi but not for windows-kill.exe, which
    //    blew out at rsp+0x1000 inside the CRT).
    for (u64 p = 0; p < kV0StackPages; ++p)
    {
        const PhysAddr stack_frame = AllocateFrame();
        if (stack_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL stack frame alloc idx=");
            SerialWriteHex(p);
            SerialWrite("\n");
            return r;
        }
        const u64 page_va = kV0StackVa + p * kPageSize;
        AddressSpaceMapUserPage(as, page_va, stack_frame, kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
    }
    SerialWrite("[pe-load] step4 stack mapped pages=");
    SerialWriteHex(kV0StackPages);
    SerialWrite("\n");

    // 4b. TEB page (Win32 PEs only). MSVC CRT startup reads
    //     gs:[0x30] for the self-pointer during __security_init
    //     _cookie / __scrt_common_main_seh; without this page it
    //     faults at linear 0x30. One page, RW+NX. Self-pointer
    //     stored at offset 0x30.
    u64 teb_va = 0;
    if (ps == PeStatus::ImportsPresent)
    {
        const PhysAddr teb_frame = AllocateFrame();
        if (teb_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL teb frame alloc\n");
            return r;
        }
        auto* teb_direct = static_cast<u8*>(PhysToVirt(teb_frame));
        for (u64 i = 0; i < kPageSize; ++i)
            teb_direct[i] = 0;
        // Write self-pointer (little-endian u64).
        for (u64 b = 0; b < 8; ++b)
            teb_direct[kTebOffSelf + b] = static_cast<u8>((kV0TebVa >> (b * 8)) & 0xFF);
        AddressSpaceMapUserPage(as, kV0TebVa, teb_frame, kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
        teb_va = kV0TebVa;
        SerialWrite("[pe-load] step4b teb mapped va=");
        SerialWriteHex(teb_va);
        SerialWrite("\n");
    }

    // 5. If imports are present, stand up the per-process
    //    Win32 stubs page + resolve every IAT entry.
    if (ps == PeStatus::ImportsPresent)
    {
        const PhysAddr stubs_frame = AllocateFrame();
        if (stubs_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL stubs frame alloc\n");
            return r;
        }
        auto* stubs_direct = static_cast<u8*>(PhysToVirt(stubs_frame));
        for (u64 i = 0; i < kPageSize; ++i)
            stubs_direct[i] = 0;
        win32::Win32StubsPopulate(stubs_direct);
        // R-X: no kPageWritable (W^X), no kPageNoExecute. The
        // AS layer enforces W^X and will panic if both are set.
        AddressSpaceMapUserPage(as, win32::kWin32StubsVa, stubs_frame, kPagePresent | kPageUser);

        if (!ResolveImports(file, file_len, h, as))
        {
            SerialWrite("[pe-load] FAIL ResolveImports\n");
            return r;
        }
        SerialWrite("[pe-load] step5 imports resolved\n");
    }
    SerialWrite("[pe-load] OK\n");

    r.ok = true;
    r.imports_resolved = (ps == PeStatus::ImportsPresent);
    r.entry_va = h.image_base + h.entry_rva;
    r.stack_va = kV0StackVa;
    r.stack_top = kV0StackTop;
    r.image_base = h.image_base;
    r.image_size = h.image_size;
    r.teb_va = teb_va;
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
