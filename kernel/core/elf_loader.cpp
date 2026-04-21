#include "elf_loader.h"

#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/page.h"
#include "../mm/paging.h"

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
    // All program headers must fit inside the file. Do every addition
    // as an overflow-checked step: a malicious ELF with e_phoff near
    // UINT64_MAX and a non-zero phtbl size would otherwise wrap and
    // pass the file-length check while indexing far past `file`.
    const u64 phtbl_bytes = static_cast<u64>(e_phnum) * e_phentsize;
    if (e_phoff > file_len || phtbl_bytes > file_len - e_phoff)
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
        const u64 p_memsz = LeU64(p + 40);
        const u64 p_align = LeU64(p + 48);
        // Overflow-safe bounds: a crafted ELF with p_offset = UINT64_MAX
        // and p_filesz = 0x10 would pass `p_offset + p_filesz > file_len`
        // after wrapping unless we compare subtractively.
        if (p_offset > file_len || p_filesz > file_len - p_offset)
        {
            return ElfStatus::SegmentOutOfBounds;
        }
        // memsz >= filesz is required by the spec.
        if (p_memsz < p_filesz)
        {
            return ElfStatus::SegmentOutOfBounds;
        }
        // User VAs must live in the canonical low half. Checking against
        // kUserMax subtractively keeps the arithmetic overflow-safe and
        // stops a malformed ELF from tripping the kernel-half panic
        // inside AddressSpaceMapUserPage.
        constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
        if (p_vaddr > kUserMax)
        {
            return ElfStatus::SegmentOutOfBounds;
        }
        if (p_memsz > 0 && (p_memsz - 1) > (kUserMax - p_vaddr))
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

// ---------------------------------------------------------------
// ElfLoad implementation
//
// Stack VA is fixed at 0x7FFFE000 for v0 — a page below the top of
// the 32-bit low-canonical range. Well clear of any PT_LOAD we'd
// see (Intel convention is 0x400000, which is 256 MiB below this).
// When a real toolchain ships that grows stacks or uses TLS, this
// picks out of a per-process stack arena instead.
// ---------------------------------------------------------------

namespace
{

constexpr u64 kV0StackVa = 0x7FFFE000ULL;

// Context struct passed through ElfForEachPtLoad via the void*
// cookie so we can plumb state into the lambda.
struct LoadCtx
{
    const u8* file;
    customos::mm::AddressSpace* as;
    bool ok;
};

// Walk the pages covering one segment's [vaddr, vaddr+memsz) and
// install them. Separate from the dispatcher so the OOM / partial-
// failure path is one clear bail-out instead of nested loops.
void LoadSegment(LoadCtx& ctx, const ElfSegment& seg)
{
    using namespace customos::mm;
    if (!ctx.ok)
        return; // a prior segment already failed; fall through

    // Page-aligned bounds. memsz can exceed filesz: the tail is
    // zero-init (.bss in practice). We copy [file[p_offset],
    // file[p_offset + filesz]) and leave the rest at 0 — frames
    // from AllocateFrame are zeroed-on-alloc already (see frame
    // allocator zero-frame path), so the .bss half is free.
    const u64 page_mask = kPageSize - 1;
    const u64 start = seg.vaddr & ~page_mask;
    const u64 end = (seg.vaddr + seg.memsz + page_mask) & ~page_mask;
    if (end <= start)
        return; // zero-length memsz: nothing to do

    // Derive page-level flags from the ELF PF_* bits. Always set
    // Present + User. Writable iff PF_W. Non-exec iff !PF_X — EFER.NXE
    // is on so the bit is honoured.
    u64 flags = kPagePresent | kPageUser;
    if (seg.flags & kElfPfW)
        flags |= kPageWritable;
    if (!(seg.flags & kElfPfX))
        flags |= kPageNoExecute;

    for (u64 page_va = start; page_va < end; page_va += kPageSize)
    {
        const PhysAddr frame = AllocateFrame();
        if (frame == kNullFrame)
        {
            ctx.ok = false;
            return;
        }
        // AllocateFrame zeroes the page for us (frame allocator
        // contract for frames under the direct map). Still safe to
        // rely on: the ELF bytes we copy below overwrite the
        // filesz region; the tail stays zero.
        auto* frame_direct = static_cast<u8*>(PhysToVirt(frame));

        // Intersect [seg.vaddr, seg.vaddr + seg.filesz) with this
        // page. Only the bytes inside the intersection are copied
        // from the file; everything else in the page remains zero.
        const u64 page_end = page_va + kPageSize;
        const u64 seg_file_end = seg.vaddr + seg.filesz;
        const u64 copy_lo = (seg.vaddr > page_va) ? seg.vaddr : page_va;
        const u64 copy_hi = (seg_file_end < page_end) ? seg_file_end : page_end;
        if (copy_hi > copy_lo)
        {
            const u64 page_off = copy_lo - page_va;
            const u64 file_off = seg.file_offset + (copy_lo - seg.vaddr);
            const u64 n = copy_hi - copy_lo;
            for (u64 i = 0; i < n; ++i)
            {
                frame_direct[page_off + i] = ctx.file[file_off + i];
            }
        }

        AddressSpaceMapUserPage(ctx.as, page_va, frame, flags);
    }
}

} // namespace

ElfLoadResult ElfLoad(const u8* file, u64 file_len, customos::mm::AddressSpace* as)
{
    ElfLoadResult r;
    r.ok = false;
    r.entry_va = 0;
    r.stack_va = 0;
    r.stack_top = 0;
    if (as == nullptr)
        return r;
    if (ElfValidate(file, file_len) != ElfStatus::Ok)
        return r;

    LoadCtx ctx{file, as, true};
    ElfForEachPtLoad(file, file_len,
                     [](const ElfSegment& seg, void* cookie) {
                         LoadSegment(*static_cast<LoadCtx*>(cookie), seg);
                     },
                     &ctx);
    if (!ctx.ok)
        return r;

    // Stack page. Writable + NX + User. Caller has already populated
    // the code segment(s); the stack goes at the fixed v0 VA.
    using namespace customos::mm;
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
        return r;
    AddressSpaceMapUserPage(as, kV0StackVa, stack_frame,
                            kPagePresent | kPageUser | kPageWritable | kPageNoExecute);

    r.ok = true;
    r.entry_va = ElfEntry(file);
    r.stack_va = kV0StackVa;
    r.stack_top = kV0StackVa + kPageSize;
    return r;
}

} // namespace customos::core
