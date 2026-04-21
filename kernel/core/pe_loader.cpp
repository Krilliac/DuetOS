#include "pe_loader.h"

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
    if (section_alignment != kPageAlign)
        return PeStatus::SectionAlignUnsup;
    if (file_alignment != kPageAlign)
        return PeStatus::FileAlignUnsup;

    out.image_base = LeU64(opt + kOptHeaderImageBase);
    out.entry_rva = LeU32(opt + kOptHeaderAddressOfEntryPoint);
    out.image_size = LeU32(opt + kOptHeaderSizeOfImage);

    // Data Directories: we only require Import, BaseReloc, TLS
    // to be empty. A PE that imports nothing and isn't
    // relocation-aware is exactly the freestanding binary our
    // toolchain emits.
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

    // Section headers follow the optional header.
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

} // namespace customos::core
