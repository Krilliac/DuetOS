#include "loader/elf_loader.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "security/guard.h"
#include "log/klog.h"

namespace duetos::core
{

namespace
{

// Little-endian readers — the buffer is byte-addressed and may
// not be naturally aligned at the offsets we need.
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
    default:
        KLOG_ONCE_WARN("elf-loader", "ElfStatusName: unrecognised ElfStatus enumerator");
        return "<unknown>";
    }
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

u64 ElfEntry(const u8* file)
{
    // ElfValidate guarantees a 64-byte ehdr exists; defensively
    // refuse a null caller rather than dereferencing into low memory.
    if (file == nullptr)
        return 0;
    return LeU64(file + 24);
}

void ElfProgramHeaderInfo(const u8* file, u64* phoff_out, u16* phnum_out, u16* phentsize_out)
{
    if (file == nullptr)
        return;
    if (phoff_out != nullptr)
        *phoff_out = LeU64(file + 32);
    if (phentsize_out != nullptr)
        *phentsize_out = LeU16(file + 54);
    if (phnum_out != nullptr)
        *phnum_out = LeU16(file + 56);
}

u32 ElfForEachPtLoad(const u8* file, u64 /*file_len*/, ElfSegmentCb cb, void* cookie)
{
    if (file == nullptr || cb == nullptr)
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

// Allocation-ladder unwind for ElfLoad. PT_LOAD segments and the
// stack page each AllocateFrame + map; a partial failure leaves the
// pages mapped before the failing leg leaked. Track every successful
// map and unmap+free on early-return. Disarmed on full success.
//
// Cap: typical small ELFs map a handful of pages; large statically-
// linked binaries can run into the hundreds. 1024 covers the v0
// workloads with headroom; if a future binary blows past it the log
// line in Track flags the leak hazard at the boundary.
struct LoaderUnwindGuard
{
    static constexpr u64 kMaxTrackedVas = 1024;
    duetos::mm::AddressSpace* as = nullptr;
    u64 vas[kMaxTrackedVas] = {};
    u32 count = 0;
    bool armed = true;

    void Track(u64 va)
    {
        // Same shape as the PE loader — a silent return here used
        // to leak frames mapped after the cap if a later step then
        // failed. 1024 entries is 4 MiB of mappings; an ELF that
        // legitimately exceeds it is structurally beyond v0 scope
        // and should crash loudly, not leak.
        KASSERT(count < kMaxTrackedVas, "loader/elf", "LoaderUnwindGuard cap exceeded");
        vas[count++] = va;
    }

    void Disarm() { armed = false; }

    ~LoaderUnwindGuard()
    {
        if (!armed || as == nullptr)
            return;
        for (u32 i = count; i > 0; --i)
            duetos::mm::AddressSpaceUnmapUserPage(as, vas[i - 1]);
    }
};

// Context struct passed through ElfForEachPtLoad via the void*
// cookie so we can plumb state into the lambda.
struct LoadCtx
{
    const u8* file;
    duetos::mm::AddressSpace* as;
    LoaderUnwindGuard* guard;
    bool ok;
};

// Walk the pages covering one segment's [vaddr, vaddr+memsz) and
// install them. Separate from the dispatcher so the OOM / partial-
// failure path is one clear bail-out instead of nested loops.
void LoadSegment(LoadCtx& ctx, const ElfSegment& seg)
{
    using namespace duetos::mm;
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
            KBP_PROBE_V(::duetos::debug::ProbeId::kElfLoaderOom, page_va);
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
        if (ctx.guard != nullptr)
            ctx.guard->Track(page_va);
    }
}

} // namespace

ElfLoadResult ElfLoad(const u8* file, u64 file_len, duetos::mm::AddressSpace* as)
{
    KLOG_TRACE_SCOPE("elf-loader", "ElfLoad");
    ElfLoadResult r;
    r.ok = false;
    r.entry_va = 0;
    r.stack_va = 0;
    r.stack_top = 0;
    if (as == nullptr)
    {
        KLOG_WARN("elf-loader", "ElfLoad called with null AddressSpace");
        return r;
    }
    // Security guard. Every image goes through the guard before
    // mapping a single page. In Advisory mode (the default) the
    // gate always returns true but the scan + log lines run so
    // operators can spot heuristic fires before flipping Enforce.
    duetos::security::ImageDescriptor gd{duetos::security::ImageKind::NativeElf, "(elf)", file, file_len};
    if (!duetos::security::Gate(gd))
    {
        KLOG_WARN("elf-loader", "security guard blocked ELF load");
        return r;
    }
    const ElfStatus vs = ElfValidate(file, file_len);
    if (vs != ElfStatus::Ok)
    {
        KLOG_WARN_S("elf-loader", "ElfValidate rejected file", "status", ElfStatusName(vs));
        return r;
    }

    LoaderUnwindGuard guard;
    guard.as = as;
    LoadCtx ctx{file, as, &guard, true};
    ElfForEachPtLoad(
        file, file_len, [](const ElfSegment& seg, void* cookie) { LoadSegment(*static_cast<LoadCtx*>(cookie), seg); },
        &ctx);
    if (!ctx.ok)
    {
        KLOG_ERROR("elf-loader", "PT_LOAD segment mapping failed mid-load");
        return r;
    }

    // Stack page. Writable + NX + User. Caller has already populated
    // the code segment(s); the stack goes at the fixed v0 VA.
    using namespace duetos::mm;
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        KLOG_ERROR("elf-loader", "stack frame allocation failed (OOM)");
        KBP_PROBE(::duetos::debug::ProbeId::kElfLoaderOom);
        return r;
    }
    AddressSpaceMapUserPage(as, kV0StackVa, stack_frame, kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
    guard.Track(kV0StackVa);

    r.ok = true;
    r.entry_va = ElfEntry(file);
    r.stack_va = kV0StackVa;
    r.stack_top = kV0StackVa + kPageSize;
    // Image now owned by the AddressSpace; suppress the unwind so
    // the destructor doesn't roll back what's now legitimately mapped.
    guard.Disarm();
    KBP_PROBE_V(::duetos::debug::ProbeId::kElfLoadOk, r.entry_va);
    return r;
}

// ---------------------------------------------------------------
// LoaderUnwindGuard self-test
//
// Builds a minimal in-memory ELF64 image with one PT_LOAD segment
// covering a few pages, primes FrameAllocatorSetFailAfter to fail
// partway through the segment loop, and asserts that ElfLoad's
// LoaderUnwindGuard rolled back every prior page so the global
// free-frame count matches the pre-test baseline.
// ---------------------------------------------------------------

void ElfLoaderUnwindSelfTest()
{
    using arch::SerialWrite;
    using namespace duetos::mm;

    // Build a minimal valid ELF64 buffer on the heap (well, the
    // bss-resident static): one PT_LOAD covering 4 pages of memsz so
    // the OOM injection has multiple successful Track() calls to
    // unwind. ElfValidate is strict; getting through it requires:
    // - "\x7FELF" magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT
    // - e_machine = EM_X86_64
    // - e_phoff in bounds, e_phentsize >= 56, e_phnum > 0
    // - PT_LOAD p_offset + p_filesz in bounds; p_memsz >= p_filesz
    // - p_vaddr in canonical low half
    // - p_offset % p_align == p_vaddr % p_align (we use align=0x1000
    //   and place the segment at offset 0x1000 → page-aligned)
    constexpr u64 kFileLen = 0x2000; // 8 KiB: 1 page header + 4 pages payload
    static u8 file[kFileLen];
    for (u64 i = 0; i < kFileLen; ++i)
        file[i] = 0;

    // ELF identification.
    file[0] = 0x7F;
    file[1] = 'E';
    file[2] = 'L';
    file[3] = 'F';
    file[4] = 2; // ELFCLASS64
    file[5] = 1; // ELFDATA2LSB
    file[6] = 1; // EV_CURRENT

    auto write_u16 = [](u8* p, u16 v)
    {
        p[0] = static_cast<u8>(v);
        p[1] = static_cast<u8>(v >> 8);
    };
    auto write_u32 = [](u8* p, u32 v)
    {
        p[0] = static_cast<u8>(v);
        p[1] = static_cast<u8>(v >> 8);
        p[2] = static_cast<u8>(v >> 16);
        p[3] = static_cast<u8>(v >> 24);
    };
    auto write_u64 = [](u8* p, u64 v)
    {
        for (int i = 0; i < 8; ++i)
            p[i] = static_cast<u8>(v >> (i * 8));
    };

    write_u16(file + 16, 2);        // e_type = ET_EXEC
    write_u16(file + 18, 0x3E);     // e_machine = EM_X86_64
    write_u32(file + 20, 1);        // e_version
    write_u64(file + 24, 0x400000); // e_entry
    write_u64(file + 32, 64);       // e_phoff (right after Ehdr)
    write_u16(file + 54, 56);       // e_phentsize
    write_u16(file + 56, 1);        // e_phnum

    // Program header at offset 64.
    u8* ph = file + 64;
    write_u32(ph, 1);           // p_type = PT_LOAD
    write_u32(ph + 4, 0x4);     // p_flags = PF_R
    write_u64(ph + 8, 0x1000);  // p_offset (page-aligned)
    write_u64(ph + 16, 0x1000); // p_vaddr (also page-aligned → same residue)
    // p_paddr at +24 (zero ok)
    write_u64(ph + 32, 0x1000); // p_filesz: 4 KiB
    write_u64(ph + 40, 0x4000); // p_memsz: 16 KiB → 4 mapped pages
    write_u64(ph + 48, 0x1000); // p_align

    AddressSpace* as = AddressSpaceCreate(/*frame_budget=*/64);
    if (as == nullptr)
    {
        SerialWrite("[elf-test] FAIL AddressSpaceCreate\n");
        core::Panic("elf-loader", "ElfLoaderUnwindSelfTest: AddressSpaceCreate returned null");
    }

    const u64 free_before = FreeFramesCount();

    // Inject failure on the third successful AllocateFrame inside
    // LoadSegment. With memsz=0x4000 the loop maps four pages; the
    // first two succeed, the third returns kNullFrame, the guard
    // unwinds those two on early-return.
    FrameAllocatorSetFailAfter(2);

    ElfLoadResult r = ElfLoad(file, kFileLen, as);

    // Make sure injection actually fired and is now disabled.
    if (FrameAllocatorGetFailAfter() != 0)
    {
        SerialWrite("[elf-test] FAIL injection counter not consumed\n");
        core::Panic("elf-loader", "ElfLoaderUnwindSelfTest: FrameAllocatorSetFailAfter didn't fire");
    }
    if (r.ok)
    {
        SerialWrite("[elf-test] FAIL ElfLoad returned ok despite OOM injection\n");
        core::Panic("elf-loader", "ElfLoaderUnwindSelfTest: ElfLoad ignored OOM");
    }

    // The guard should have unwound the two pages it tracked. The
    // address space itself still owns its PML4/PDPT/PD frames; tear
    // it down before sampling FreeFramesCount.
    AddressSpaceRelease(as);

    const u64 free_after = FreeFramesCount();
    if (free_after != free_before)
    {
        SerialWrite("[elf-test] FAIL frame count drifted: before=");
        for (int i = 60; i >= 0; i -= 4)
        {
            const u64 nibble = (free_before >> i) & 0xF;
            char c = static_cast<char>(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);
            char buf[2] = {c, 0};
            SerialWrite(buf);
        }
        SerialWrite(" after=");
        for (int i = 60; i >= 0; i -= 4)
        {
            const u64 nibble = (free_after >> i) & 0xF;
            char c = static_cast<char>(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);
            char buf[2] = {c, 0};
            SerialWrite(buf);
        }
        SerialWrite("\n");
        core::Panic("elf-loader", "ElfLoaderUnwindSelfTest: frame leak detected");
    }

    SerialWrite("[elf-test] unwind-guard PASS\n");
}

} // namespace duetos::core
