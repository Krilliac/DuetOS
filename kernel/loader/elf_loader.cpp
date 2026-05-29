#include "loader/elf_loader.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "exec_meta_rust.h"
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
    // Validation lives in the Rust crate `duetos_exec_meta` —
    // bounds-checked slice traversal of the ELF64 header + every
    // PT_LOAD segment, with overflow-safe arithmetic against
    // attacker-crafted file offsets near U64_MAX. The status
    // enumerators are byte-identical to ElfStatus so the FFI
    // round-trips cleanly through a u32 cast.
    const u32 raw = ::duetos::loader::exec_meta::duetos_exec_meta_elf_validate(file, static_cast<usize>(file_len));
    return static_cast<ElfStatus>(raw);
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

u32 ElfForEachPtLoad(const u8* file, u64 file_len, ElfSegmentCb cb, void* cookie)
{
    if (file == nullptr || cb == nullptr)
        return 0;
    // file_len was previously ignored and the header / program
    // headers were read unconditionally — a caller that invokes
    // this directly (the public signature takes file_len, and
    // `readelf` / `exec` can) on a short or empty buffer drove
    // LeU64 off the end. The fuzz harness hits this on a 0-byte
    // input. Honour the length: need the full 64-byte ELF64 ehdr
    // before touching e_phoff/e_phentsize/e_phnum, and 56 readable
    // bytes per program header (the largest field read is
    // p_align at p+48..p+55).
    constexpr u64 kElf64EhdrSize = 64;
    constexpr u64 kPhdrReadSpan = 56;
    if (file_len < kElf64EhdrSize)
        return 0;
    const u64 e_phoff = LeU64(file + 32);
    const u16 e_phentsize = LeU16(file + 54);
    const u16 e_phnum = LeU16(file + 56);
    if (e_phoff > file_len)
        return 0;
    u32 visited = 0;
    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u64 off = e_phoff + static_cast<u64>(i) * e_phentsize;
        // No u64 wrap: e_phoff <= file_len and i*e_phentsize is
        // bounded by 2^32, so off stays well below U64_MAX for any
        // sane file_len. A header whose 56-byte read would run
        // past EOF ends the walk (entries only move outward when
        // e_phentsize > 0; when it is 0 every entry shares this
        // out-of-bounds offset).
        if (off > file_len - kPhdrReadSpan)
            break;
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
        return; // zero-length memsz: nothing to do (also catches
                // a vaddr+memsz wrap that drove end below start)

    // Defensive span bound. ElfValidate (the Rust crate) checks
    // p_filesz against the file but a *valid* ELF may still declare
    // an enormous p_memsz (legitimate .bss is small; a malformed or
    // hostile header is not). Without this guard the loop below
    // calls AllocateFrame per page until the physical pool is dry,
    // and the AS walker then hard-PANICS (PanicAs "AllocateFrame
    // returned null inside AS walker") instead of failing the load.
    // 256 MiB is orders of magnitude above any real test/userland
    // image yet far below the frame pool, so a pathological segment
    // now takes the graceful ctx.ok=false bail the rest of the
    // loader already handles.
    constexpr u64 kMaxSegmentSpanBytes = 256ULL * 1024 * 1024;
    if (end - start > kMaxSegmentSpanBytes)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Loader, "elf-loader",
                     "segment span exceeds sanity bound — rejecting load", end - start);
        KBP_PROBE_V(::duetos::debug::ProbeId::kElfLoaderOom, end - start);
        ctx.ok = false;
        return;
    }

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
        auto frame_r = TryAllocateFrame();
        if (!frame_r)
        {
            KBP_PROBE_V(::duetos::debug::ProbeId::kElfLoaderOom, page_va);
            ctx.ok = false;
            return;
        }
        const PhysAddr frame = frame_r.value();
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
    auto stack_frame_r = TryAllocateFrame();
    if (!stack_frame_r)
    {
        KLOG_ERROR("elf-loader", "stack frame allocation failed (OOM)");
        KBP_PROBE(::duetos::debug::ProbeId::kElfLoaderOom);
        return r;
    }
    const PhysAddr stack_frame = stack_frame_r.value();
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

    // Sample free-frame count BEFORE AddressSpaceCreate so the post-
    // release balance includes the PML4 frame returned by Release.
    // Otherwise free_after would be +1 vs free_before because Release
    // returns a frame Create allocated outside the test's window.
    //
    // Drain per-CPU warm pools first. `FreeFramesCount` reports
    // bitmap-free frames only; pool-resident frames count as USED.
    // Without draining, the pre/post diff is dominated by frames
    // that drift in and out of the pool (AS create may pop from
    // pool; AS release pushes back into pool), making the balance
    // non-deterministic. Draining BOTH before sampling AND before
    // the final sample collapses pool state into the bitmap so the
    // diff reflects real allocation drift.
    FrameAllocatorDrainPools();
    const u64 free_before = FreeFramesCount();

    auto as_r = AddressSpaceCreate(/*frame_budget=*/64);
    if (!as_r)
    {
        SerialWrite("[elf-test] FAIL AddressSpaceCreate\n");
        core::Panic("elf-loader", "ElfLoaderUnwindSelfTest: AddressSpaceCreate returned null");
    }
    AddressSpace* as = as_r.value();

    // Inject OOM mid-load so the unwind guard has work to do.
    //
    // The `FailAfter(N)` injection decrements on every successful
    // AllocateFrame and trips on the Nth call. The test's LoadSegment
    // loop maps four 4 KiB pages, but each call to
    // `AddressSpaceMapUserPage` may consume additional frames for
    // intermediate page tables (PDPT / PD / PT) when the walker
    // creates a new branch. On a freshly-created AS, the FIRST
    // mapping at va=0x1000 allocates three page-table frames before
    // installing the leaf PTE, then each subsequent mapping at
    // va=0x2000, 0x3000, ... uses only the user-page allocation
    // because the page-table branch is already in place.
    //
    // Total successful allocations to map 2 of 4 pages = 3 (tables)
    // + 1 (page 0) + 1 (page 1) = 5. Setting FailAfter to 6 means
    // the 6th call — page 2's user-page allocation — returns
    // kNullFrame. The guard tracks the two successfully-mapped user
    // pages and unwinds them; the page tables remain in the AS and
    // are freed by AddressSpaceRelease via FreeUserHalfTables.
    FrameAllocatorSetFailAfter(6);

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

    // Drain pools again so any frames Release pushed into the warm
    // pool (instead of the bitmap) show up in the free count.
    FrameAllocatorDrainPools();
    const u64 free_after = FreeFramesCount();
    // The unwind guard's invariant is "no frames go missing": a
    // real leak would leave `free_after < free_before` (some user
    // page or page-table frame stayed allocated forever). A
    // POSITIVE drift just means background activity (the timer
    // tick's wake path, the reaper consuming a zombie's stack)
    // freed more frames than it allocated during the test window.
    // That's not a leak — it's bookkeeping noise from the
    // running kernel. Enforce direction-only: fail loudly on
    // missing frames, tolerate background gains.
    if (free_after < free_before)
    {
        SerialWrite("[elf-test] FAIL frame leak: before=");
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
