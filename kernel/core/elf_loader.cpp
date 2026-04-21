#include "elf_loader.h"

namespace customos::core
{

namespace
{

// Little-endian readers — the buffer is byte-addressed and may
// not be naturally aligned at the offsets we need.
inline u16 LeU16(const u8* p) { return u16(p[0]) | (u16(p[1]) << 8); }
inline u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
inline u64 LeU64(const u8* p)
{
    return static_cast<u64>(LeU32(p)) | (static_cast<u64>(LeU32(p + 4)) << 32);
}

constexpr u32 kPtLoad = 1;
constexpr u16 kEmX86_64 = 0x3E;

} // namespace

const char* ElfStatusName(ElfStatus s)
{
    switch (s)
    {
    case ElfStatus::Ok:
        return "Ok";
    case ElfStatus::TooSmall:
        return "TooSmall";
    case ElfStatus::BadMagic:
        return "BadMagic";
    case ElfStatus::NotElf64:
        return "NotElf64";
    case ElfStatus::NotLittleEndian:
        return "NotLittleEndian";
    case ElfStatus::BadVersion:
        return "BadVersion";
    case ElfStatus::BadMachine:
        return "BadMachine";
    case ElfStatus::NoProgramHeaders:
        return "NoProgramHeaders";
    case ElfStatus::HeaderOutOfBounds:
        return "HeaderOutOfBounds";
    case ElfStatus::SegmentOutOfBounds:
        return "SegmentOutOfBounds";
    case ElfStatus::UnalignedSegment:
        return "UnalignedSegment";
    }
    return "<unknown>";
}

ElfStatus ElfValidate(const u8* file, u64 file_len)
{
    if (file == nullptr || file_len < 64)
    {
        return ElfStatus::TooSmall;
    }
    if (!(file[0] == 0x7F && file[1] == 'E' && file[2] == 'L' && file[3] == 'F'))
    {
        return ElfStatus::BadMagic;
    }
    if (file[4] != 2)
    {
        return ElfStatus::NotElf64;
    }
    if (file[5] != 1)
    {
        return ElfStatus::NotLittleEndian;
    }
    if (file[6] != 1)
    {
        return ElfStatus::BadVersion;
    }
    const u16 e_machine = LeU16(file + 18);
    if (e_machine != kEmX86_64)
    {
        return ElfStatus::BadMachine;
    }
    const u64 e_phoff = LeU64(file + 32);
    const u16 e_phentsize = LeU16(file + 54);
    const u16 e_phnum = LeU16(file + 56);
    if (e_phoff == 0 || e_phnum == 0 || e_phentsize < 56)
    {
        return ElfStatus::NoProgramHeaders;
    }
    // All program headers must fit inside the file.
    const u64 phtbl_end = e_phoff + static_cast<u64>(e_phnum) * e_phentsize;
    if (phtbl_end > file_len)
    {
        return ElfStatus::HeaderOutOfBounds;
    }
    // For each PT_LOAD, the file bytes it declares must fit.
    // Also check the classic alignment invariant:
    //   p_offset % p_align == p_vaddr % p_align
    // A violation means the file wasn't built for page-at-a-time
    // loading without shuffling bytes around.
    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u64 off = e_phoff + static_cast<u64>(i) * e_phentsize;
        const u8* p = file + off;
        const u32 p_type = LeU32(p);
        if (p_type != kPtLoad)
            continue;
        const u64 p_offset = LeU64(p + 8);
        const u64 p_vaddr = LeU64(p + 16);
        const u64 p_filesz = LeU64(p + 32);
        const u64 p_align = LeU64(p + 48);
        if (p_offset + p_filesz > file_len)
        {
            return ElfStatus::SegmentOutOfBounds;
        }
        if (p_align > 1 && ((p_offset % p_align) != (p_vaddr % p_align)))
        {
            return ElfStatus::UnalignedSegment;
        }
    }
    return ElfStatus::Ok;
}

u64 ElfEntry(const u8* file) { return LeU64(file + 24); }

void ElfProgramHeaderInfo(const u8* file, u64* phoff_out, u16* phnum_out, u16* phentsize_out)
{
    if (phoff_out != nullptr)
        *phoff_out = LeU64(file + 32);
    if (phentsize_out != nullptr)
        *phentsize_out = LeU16(file + 54);
    if (phnum_out != nullptr)
        *phnum_out = LeU16(file + 56);
}

u32 ElfForEachPtLoad(const u8* file, u64 /*file_len*/, ElfSegmentCb cb, void* cookie)
{
    if (cb == nullptr)
        return 0;
    const u64 e_phoff = LeU64(file + 32);
    const u16 e_phentsize = LeU16(file + 54);
    const u16 e_phnum = LeU16(file + 56);
    u32 visited = 0;
    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u64 off = e_phoff + static_cast<u64>(i) * e_phentsize;
        const u8* p = file + off;
        if (LeU32(p) != kPtLoad)
            continue;
        ElfSegment seg;
        seg.flags = static_cast<u8>(LeU32(p + 4) & 0x7);
        seg.file_offset = LeU64(p + 8);
        seg.vaddr = LeU64(p + 16);
        // p_paddr at offset 24, skipped
        seg.filesz = LeU64(p + 32);
        seg.memsz = LeU64(p + 40);
        seg.align = LeU64(p + 48);
        for (u32 k = 0; k < sizeof(seg._pad); ++k)
            seg._pad[k] = 0;
        cb(seg, cookie);
        ++visited;
    }
    return visited;
}

} // namespace customos::core
