#include "loader/dll_loader.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"

namespace duetos::core
{

namespace
{

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

// ---- minimal PE constants (kept local; see pe_loader.cpp) -----
constexpr u16 kDosMagic = 0x5A4D;
constexpr u32 kPeSignature = 0x00004550;
constexpr u16 kMachineAmd64 = 0x8664;
constexpr u16 kOptMagicPe32Plus = 0x020B;
constexpr u16 kCharacteristicsDll = 0x2000;
constexpr u64 kFileHeaderSize = 20;
constexpr u64 kFileHeaderCharacteristics = 18;

constexpr u64 kOptHeaderAddressOfEntryPoint = 16;
constexpr u64 kOptHeaderImageBase = 24;
constexpr u64 kOptHeaderSectionAlignment = 32;
constexpr u64 kOptHeaderFileAlignment = 36;
constexpr u64 kOptHeaderSizeOfImage = 56;
constexpr u64 kOptHeaderSizeOfHeaders = 60;
constexpr u64 kOptHeaderNumberOfRvaAndSizes = 108;
constexpr u64 kOptHeaderDataDirectories = 112;
constexpr u64 kDataDirEntrySize = 8;
constexpr u64 kSectionHeaderSize = 40;
constexpr u64 kSectionHeaderVirtualSize = 8;
constexpr u64 kSectionHeaderVirtualAddress = 12;
constexpr u64 kSectionHeaderSizeOfRawData = 16;
constexpr u64 kSectionHeaderPointerToRawData = 20;
constexpr u64 kSectionHeaderCharacteristics = 36;

constexpr u64 kDirEntryBaseReloc = 5;

constexpr u32 kPageAlign = 4096;
constexpr u64 kPageMask = kPageAlign - 1;

constexpr u32 kScnMemExecute = 0x20000000;
constexpr u32 kScnMemWrite = 0x80000000;

struct DllHeaders
{
    u64 opt_base;
    u16 opt_header_size;
    u64 section_base;
    u16 section_count;
    u16 characteristics;
    u32 num_rva_and_sizes;

    u64 image_base;
    u64 image_size;
    u64 sizeof_headers;
    u32 entry_rva;
};

bool ParseHeaders(const u8* file, u64 file_len, DllHeaders& out)
{
    if (file == nullptr || file_len < 0x40)
        return false;
    if (LeU16(file) != kDosMagic)
        return false;
    const u32 e_lfanew = LeU32(file + 0x3C);
    // Overflow-safe: e_lfanew is a u32, the addends are small constants,
    // but we still phrase the bound subtractively in case file_len is
    // smaller than the constant prefix on a truncated header.
    if (file_len < u64(4) + kFileHeaderSize)
        return false;
    if (u64(e_lfanew) > file_len - 4 - kFileHeaderSize)
        return false;
    if (LeU32(file + e_lfanew) != kPeSignature)
        return false;
    const u8* fh = file + e_lfanew + 4;
    if (LeU16(fh + 0) != kMachineAmd64)
        return false;
    out.section_count = LeU16(fh + 2);
    out.opt_header_size = LeU16(fh + 16);
    out.characteristics = LeU16(fh + kFileHeaderCharacteristics);
    out.opt_base = u64(e_lfanew) + 4 + kFileHeaderSize;
    if (out.opt_base > file_len || out.opt_header_size > file_len - out.opt_base)
        return false;
    const u8* opt = file + out.opt_base;
    if (LeU16(opt) != kOptMagicPe32Plus)
        return false;
    if (out.opt_header_size < kOptHeaderNumberOfRvaAndSizes + 4)
        return false;
    out.num_rva_and_sizes = LeU32(opt + kOptHeaderNumberOfRvaAndSizes);
    out.image_base = LeU64(opt + kOptHeaderImageBase);
    out.image_size = LeU32(opt + kOptHeaderSizeOfImage);
    out.sizeof_headers = LeU32(opt + kOptHeaderSizeOfHeaders);
    out.entry_rva = LeU32(opt + kOptHeaderAddressOfEntryPoint);
    // ImageBase must be page-aligned per the PE/COFF spec; an unaligned
    // base added to a page-aligned section RVA would map the section
    // bytes shifted relative to their declared file offsets.
    if ((out.image_base & u64(kPageMask)) != 0)
        return false;
    // sizeof_headers must fit inside the file or the per-page header
    // copy below would walk past the buffer end.
    if (out.sizeof_headers > file_len)
        return false;
    // Reject DLLs whose preferred ImageBase + SizeOfImage extends out of
    // the canonical user low half. Same DoS path as the PE loader: a
    // hostile DLL would otherwise reach AddressSpaceMapUserPage with a
    // kernel-half VA and PanicAs the kernel.
    constexpr u64 kDllUserMax = 0x00007FFFFFFFFFFFULL;
    if (out.image_base > kDllUserMax)
        return false;
    if (out.image_size > 0 && (u64(out.image_size) - 1) > (kDllUserMax - out.image_base))
        return false;
    out.section_base = out.opt_base + out.opt_header_size;
    // Bound section_count BEFORE the multiplication so a u16 max
    // (~65535) × kSectionHeaderSize (40) cannot overflow into a small
    // value that re-passes the file-size check on the line below.
    const u64 sect_bytes = u64(out.section_count) * kSectionHeaderSize;
    if (out.section_base > file_len || sect_bytes > file_len - out.section_base)
        return false;
    // Cross-check every section's raw extent fits in the file.
    for (u16 i = 0; i < out.section_count; ++i)
    {
        const u8* sec = file + out.section_base + u64(i) * kSectionHeaderSize;
        const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
        const u32 raw_sz = LeU32(sec + kSectionHeaderSizeOfRawData);
        // Subtractive bound — u32 + u32 can overflow into a small u64
        // that passes a naive `<` check while raw_off itself is past
        // the file end.
        if (u64(raw_off) > file_len || u64(raw_sz) > file_len - u64(raw_off))
            return false;
    }
    return true;
}

u64 RvaToFile(const u8* file, const DllHeaders& h, u32 rva)
{
    if (file == nullptr)
        return ~u64(0);
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        const u32 va = LeU32(sec + kSectionHeaderVirtualAddress);
        const u32 raw_size = LeU32(sec + kSectionHeaderSizeOfRawData);
        const u32 virt_size = LeU32(sec + kSectionHeaderVirtualSize);
        const u32 extent = raw_size > virt_size ? raw_size : virt_size;
        // Phrase the upper bound subtractively so a (va == UINT32_MAX
        // intentional) hostile DLL can't wrap `va + extent` into a
        // small number that brackets every RVA.
        if (rva >= va && (extent > 0 && rva - va < extent))
        {
            const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
            return u64(raw_off) + u64(rva - va);
        }
    }
    return ~u64(0);
}

bool MapHeadersPage(const u8* file, u64 sizeof_headers, u64 base_va, duetos::mm::AddressSpace* as)
{
    using namespace duetos::mm;
    if (file == nullptr || as == nullptr)
        return false;
    const u64 start = base_va & ~kPageMask;
    const u64 end = (base_va + sizeof_headers + kPageMask) & ~kPageMask;
    if (end <= start)
        return true;
    for (u64 page_va = start; page_va < end; page_va += kPageSize)
    {
        const PhysAddr frame = AllocateFrame();
        if (frame == kNullFrame)
            return false;
        auto* direct = static_cast<u8*>(PhysToVirt(frame));
        const u64 file_off = page_va - base_va;
        const u64 remain = (file_off < sizeof_headers) ? (sizeof_headers - file_off) : 0;
        const u64 n = remain < kPageSize ? remain : kPageSize;
        for (u64 i = 0; i < n; ++i)
            direct[i] = file[file_off + i];
        for (u64 i = n; i < kPageSize; ++i)
            direct[i] = 0;
        AddressSpaceMapUserPage(as, page_va, frame, kPagePresent | kPageUser | kPageNoExecute);
    }
    return true;
}

bool MapSection(const u8* file, const u8* sec, u64 base_va, duetos::mm::AddressSpace* as)
{
    using namespace duetos::mm;
    if (file == nullptr || sec == nullptr || as == nullptr)
        return false;
    const u32 virt_addr = LeU32(sec + kSectionHeaderVirtualAddress);
    const u32 virt_size = LeU32(sec + kSectionHeaderVirtualSize);
    const u32 raw_size = LeU32(sec + kSectionHeaderSizeOfRawData);
    const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
    const u32 chars = LeU32(sec + kSectionHeaderCharacteristics);

    const u64 in_mem = virt_size > raw_size ? virt_size : raw_size;
    if (in_mem == 0)
        return true;

    const u64 seg_va = base_va + virt_addr;
    const u64 start = seg_va & ~kPageMask;
    const u64 end = (seg_va + in_mem + kPageMask) & ~kPageMask;

    u64 flags = kPagePresent | kPageUser;
    if (chars & kScnMemWrite)
        flags |= kPageWritable;
    if (!(chars & kScnMemExecute))
        flags |= kPageNoExecute;

    for (u64 page_va = start; page_va < end; page_va += kPageSize)
    {
        const PhysAddr frame = AllocateFrame();
        if (frame == kNullFrame)
            return false;
        auto* frame_direct = static_cast<u8*>(PhysToVirt(frame));
        for (u64 i = 0; i < kPageSize; ++i)
            frame_direct[i] = 0;
        const u64 copy_lo = page_va > seg_va ? page_va : seg_va;
        const u64 src_end = seg_va + raw_size;
        const u64 copy_hi_raw = page_va + kPageSize < src_end ? page_va + kPageSize : src_end;
        const u64 copy_hi = copy_hi_raw > copy_lo ? copy_hi_raw : copy_lo;
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

// Apply IMAGE_REL_BASED_DIR64 relocations. Simplified twin of
// pe_loader.cpp::ApplyRelocations — kept local to keep DLL and
// EXE loaders independent until a shared helper is justified.
bool ApplyRelocations(const u8* file, u64 file_len, const DllHeaders& h, duetos::mm::AddressSpace* as, u64 base_va,
                      u64 delta)
{
    using namespace duetos::mm;
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u8* opt = file + h.opt_base;
    const u64 dir_bytes = u64(h.num_rva_and_sizes) * kDataDirEntrySize;
    if (kOptHeaderDataDirectories + dir_bytes > h.opt_header_size)
        return true; // no reloc dir in header — treat as empty
    if (kDirEntryBaseReloc >= h.num_rva_and_sizes)
        return true;
    const u32 br_rva = LeU32(opt + kOptHeaderDataDirectories + kDirEntryBaseReloc * kDataDirEntrySize + 0);
    const u32 br_sz = LeU32(opt + kOptHeaderDataDirectories + kDirEntryBaseReloc * kDataDirEntrySize + 4);
    if (br_rva == 0 || br_sz == 0)
        return true;

    const u64 tbl_off = RvaToFile(file, h, br_rva);
    if (tbl_off == ~u64(0) || tbl_off + br_sz > file_len)
    {
        SerialWrite("[dll-load] reloc rva out of bounds\n");
        return false;
    }
    const u64 end = tbl_off + br_sz;
    u64 cursor = tbl_off;
    u32 blocks = 0;
    u32 applied = 0;
    while (cursor + 8 <= end)
    {
        const u32 page_rva = LeU32(file + cursor + 0);
        const u32 block_sz = LeU32(file + cursor + 4);
        if (block_sz < 8 || cursor + block_sz > end)
        {
            SerialWrite("[dll-load] malformed reloc block\n");
            return false;
        }
        if (page_rva == 0 && block_sz == 0)
            break;
        const u32 entry_count = (block_sz - 8) / 2;
        for (u32 i = 0; i < entry_count; ++i)
        {
            const u16 entry = LeU16(file + cursor + 8 + u64(i) * 2);
            const u16 type = entry >> 12;
            const u16 offset = entry & 0x0FFF;
            if (type == 0)
                continue;   // padding
            if (type != 10) // IMAGE_REL_BASED_DIR64
            {
                SerialWrite("[dll-load] unsupported reloc type=");
                SerialWriteHex(type);
                SerialWrite("\n");
                return false;
            }
            if (delta == 0)
                continue;
            const u64 patch_va = base_va + u64(page_rva) + u64(offset);
            u64 orig = 0;
            for (u64 b = 0; b < 8; ++b)
            {
                const u64 va = patch_va + b;
                const u64 page_va = va & ~0xFFFULL;
                const PhysAddr frame = AddressSpaceLookupUserFrame(as, page_va);
                if (frame == kNullFrame)
                {
                    SerialWrite("[dll-load] reloc patch va unmapped\n");
                    return false;
                }
                const auto* direct = static_cast<const u8*>(PhysToVirt(frame));
                orig |= u64(direct[va & 0xFFFULL]) << (b * 8);
            }
            const u64 fixed = orig + delta;
            for (u64 b = 0; b < 8; ++b)
            {
                const u64 va = patch_va + b;
                const u64 page_va = va & ~0xFFFULL;
                const PhysAddr frame = AddressSpaceLookupUserFrame(as, page_va);
                if (frame == kNullFrame)
                    return false;
                auto* direct = static_cast<u8*>(PhysToVirt(frame));
                direct[va & 0xFFFULL] = u8((fixed >> (b * 8)) & 0xFF);
            }
            ++applied;
        }
        ++blocks;
        cursor += block_sz;
    }
    SerialWrite("[dll-load] relocs blocks=");
    SerialWriteHex(blocks);
    SerialWrite(" applied=");
    SerialWriteHex(applied);
    SerialWrite(" delta=");
    SerialWriteHex(delta);
    SerialWrite("\n");
    return true;
}

} // namespace

const char* DllLoadStatusName(DllLoadStatus s)
{
    switch (s)
    {
    case DllLoadStatus::Ok:
        return "Ok";
    case DllLoadStatus::HeaderParseFailed:
        return "HeaderParseFailed";
    case DllLoadStatus::NotADll:
        return "NotADll";
    case DllLoadStatus::BadMachine:
        return "BadMachine";
    case DllLoadStatus::SectionAlignUnsup:
        return "SectionAlignUnsup";
    case DllLoadStatus::SectionOutOfBounds:
        return "SectionOutOfBounds";
    case DllLoadStatus::MapFailed:
        return "MapFailed";
    case DllLoadStatus::RelocFailed:
        return "RelocFailed";
    case DllLoadStatus::ExportParseFailed:
        return "ExportParseFailed";
    default:
        KLOG_ONCE_WARN("loader/dll", "DllLoadStatusName: unrecognised status");
        return "?";
    }
}

DllLoadResult DllLoad(const u8* file, u64 file_len, duetos::mm::AddressSpace* as, u64 aslr_delta)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    DllLoadResult r{};
    r.status = DllLoadStatus::HeaderParseFailed;

    DllHeaders h{};
    if (!ParseHeaders(file, file_len, h))
        return r;
    if ((h.characteristics & kCharacteristicsDll) == 0)
    {
        r.status = DllLoadStatus::NotADll;
        return r;
    }

    // SectionAlignment gate mirrors PeLoad: sub-page alignment
    // would let two sections share a page with conflicting flags.
    const u8* opt = file + h.opt_base;
    if (LeU32(opt + kOptHeaderSectionAlignment) != kPageAlign)
    {
        r.status = DllLoadStatus::SectionAlignUnsup;
        return r;
    }
    // FileAlignment: accept any power-of-2 in [512, 4096] — same
    // range as PeLoad tolerates.
    const u32 file_align = LeU32(opt + kOptHeaderFileAlignment);
    if (file_align != 512 && file_align != 1024 && file_align != 2048 && file_align != 4096)
    {
        r.status = DllLoadStatus::SectionAlignUnsup; // reuse the same gate — file-align failures are rare
        return r;
    }

    const u64 base_va = h.image_base + aslr_delta;
    // Re-validate after ASLR shift: the parser checked the preferred
    // base, but the caller-supplied delta could push us across the
    // user/kernel boundary.
    {
        constexpr u64 kDllUserMax = 0x00007FFFFFFFFFFFULL;
        if (base_va > kDllUserMax || (h.image_size > 0 && (u64(h.image_size) - 1) > (kDllUserMax - base_va)))
        {
            r.status = DllLoadStatus::MapFailed;
            return r;
        }
    }

    KLOG_INFO_2V("loader/dll", "DLL load BEGIN", "base_va", base_va, "size", h.image_size);
    KLOG_DEBUG_V("loader/dll", "DLL sections+chars; sections", static_cast<u64>(h.section_count));
    SerialWrite("[dll-load] begin base_va=");
    SerialWriteHex(base_va);
    SerialWrite(" size=");
    SerialWriteHex(h.image_size);
    SerialWrite(" sections=");
    SerialWriteHex(h.section_count);
    SerialWrite(" chars=");
    SerialWriteHex(h.characteristics);
    SerialWrite("\n");

    if (!MapHeadersPage(file, h.sizeof_headers, base_va, as))
    {
        r.status = DllLoadStatus::MapFailed;
        return r;
    }
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        if (!MapSection(file, sec, base_va, as))
        {
            SerialWrite("[dll-load] MapSection fail idx=");
            SerialWriteHex(i);
            SerialWrite("\n");
            r.status = DllLoadStatus::MapFailed;
            return r;
        }
    }

    if (!ApplyRelocations(file, file_len, h, as, base_va, aslr_delta))
    {
        KLOG_ERROR_V("loader/dll", "RelocFailed at base_va", base_va);
        r.status = DllLoadStatus::RelocFailed;
        return r;
    }

    // Parse EAT. An empty export directory is legal (DLL with
    // no exports is useless but well-formed); anything else
    // failing is a hard fault.
    PeExports exp{};
    const PeExportStatus pes = PeParseExports(file, file_len, exp);
    if (pes != PeExportStatus::Ok && pes != PeExportStatus::NoExportDirectory)
    {
        KLOG_ERROR_S("loader/dll", "export parse FAILED", "pes", PeExportStatusName(pes));
        SerialWrite("[dll-load] export parse fail: ");
        SerialWrite(PeExportStatusName(pes));
        SerialWrite("\n");
        r.status = DllLoadStatus::ExportParseFailed;
        return r;
    }

    r.image.file = file;
    r.image.file_len = file_len;
    r.image.base_va = base_va;
    r.image.size = h.image_size;
    r.image.entry_rva = h.entry_rva;
    r.image.has_exports = (pes == PeExportStatus::Ok);
    if (r.image.has_exports)
        r.image.exports = exp;
    r.status = DllLoadStatus::Ok;

    KLOG_INFO_2V("loader/dll", "DLL load OK", "entry_rva", static_cast<u64>(h.entry_rva), "has_exports",
                 static_cast<u64>(r.image.has_exports ? 1 : 0));
    SerialWrite("[dll-load] OK entry_rva=");
    SerialWriteHex(h.entry_rva);
    SerialWrite(" has_exports=");
    SerialWriteHex(r.image.has_exports ? 1 : 0);
    SerialWrite("\n");
    return r;
}

u64 DllResolveExport(const DllImage& dll, const char* name)
{
    if (!dll.has_exports || name == nullptr)
    {
        KLOG_DEBUG("loader/dll", "ResolveExport: DLL has no exports or null name");
        return 0;
    }
    PeExport e{};
    if (!PeExportLookupName(dll.exports, name, e))
    {
        KLOG_DEBUG_S("loader/dll", "ResolveExport: name MISS (export not in EAT)", "name", name);
        return 0;
    }
    if (e.is_forwarder)
    {
        // Forwarder: function is re-exported from another DLL. v0
        // doesn't chase, but logging the fact reveals the import
        // chain a debugger would otherwise have to discover by
        // walking strings in the DLL image.
        KLOG_WARN_S("loader/dll", "ResolveExport: forwarder NOT chased (returns 0)", "name", name);
        return 0;
    }
    const u64 va = dll.base_va + u64(e.rva);
    KLOG_TRACE_V("loader/dll", "ResolveExport hit; va", va);
    return va;
}

u64 DllResolveOrdinal(const DllImage& dll, u32 ordinal)
{
    if (!dll.has_exports)
    {
        KLOG_DEBUG("loader/dll", "ResolveOrdinal: DLL has no exports");
        return 0;
    }
    PeExport e{};
    if (!PeExportLookupOrdinal(dll.exports, ordinal, e))
    {
        KLOG_DEBUG_V("loader/dll", "ResolveOrdinal: ordinal MISS", static_cast<u64>(ordinal));
        return 0;
    }
    if (e.is_forwarder)
    {
        KLOG_WARN_V("loader/dll", "ResolveOrdinal: forwarder NOT chased (returns 0); ordinal",
                    static_cast<u64>(ordinal));
        return 0;
    }
    const u64 va = dll.base_va + u64(e.rva);
    KLOG_TRACE_V("loader/dll", "ResolveOrdinal hit; va", va);
    return va;
}

} // namespace duetos::core
