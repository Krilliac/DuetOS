/*
 * DuetOS — PE/COFF loader: implementation.
 *
 * Companion to pe_loader.h — see there for the v0 scope statement
 * (which PE features are supported, which are intentionally cut)
 * and the caller-facing API (PeLoad, PeReport).
 *
 * WHAT
 *   Maps a PE32+ image into a fresh address space, applies base
 *   relocations, resolves IAT entries (chasing forwarders through
 *   the per-process DLL table; falling back to the Win32 thunks
 *   page for unresolved imports), and returns the entry point VA
 *   for the spawn path to start a Task on.
 *
 * HOW
 *   Top-down inside `PeLoad`. Numbered phases match the section
 *   banners (`// 1. Validate headers`, `// 2. Reserve image`,
 *   etc.). Each phase reads from the byte buffer via the
 *   `LeU16/32/64` helpers — never via casts to packed structs —
 *   so the loader survives unaligned headers without UB.
 *
 *   IAT resolution priority (onward):
 *     loaded DLL EATs (chase forwarders)
 *       -> Win32ThunksLookupKind          (in-kernel thunks page)
 *         -> IsLikelyDataImport ? data-miss landing pad
 *                               : miss-logger thunk
 *
 *   Companion files:
 *     pe_exports.cpp   — EAT parsing + name-table binary search
 *     dll_loader.cpp   — preload table for kernel32 / ntdll / etc.
 *     win32/thunks.cpp — kernel-resident IAT thunk page
 *     win32/proc_env.cpp — proc-env page (argv, cmdline, etc.)
 *
 * WHY THIS FILE IS LARGE
 *   PE has many directories (imports, exports, base relocs, TLS,
 *   resources, exception, debug). Each gets its own walker. A
 *   real-world MSVC PE exercises most of them; the v0 PE we ship
 *   only the bare minimum, but the diagnostic path (`PeReport`)
 *   walks every directory and emits a coverage table on boot —
 *   that diagnostic surface is what pushes line count up.
 */

#include "loader/pe_loader.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "exec_meta_rust.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "security/guard.h"
#include "subsystems/win32/proc_env.h"
#include "subsystems/win32/thunks.h"
#include "diag/cleanroom_trace.h"
#include "diag/fix_journal.h"
#include "diag/kdbg.h"
#include "log/klog.h"
#include "loader/pe_exports.h"
#include "proc/process.h"
#include "util/random.h"

namespace duetos::core
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

// ---- PE constants (the handful the v0 loader still uses) ----
// The PE-prefix + image-validation constants (DosMagic, PeSig,
// MachineAmd64, OptMagicPe32Plus, FileHeaderSize,
// OptHeaderAddressOfEntryPoint / ImageBase / SectionAlignment /
// FileAlignment / SizeOfImage) all moved to the Rust crate
// `duetos_exec_meta`. What stays here is the C++-side data-
// directory + section-mapping shape used by ParseHeaders'
// post-validation tail and by MapSection.
constexpr u32 kPageAlign = 4096;

// Offsets inside the IMAGE_OPTIONAL_HEADER + IMAGE_SECTION_HEADER
// that the C++ code still reaches into. Hand-coded so the kernel
// stays self-contained.
constexpr u64 kOptHeaderSizeOfHeaders = 60;
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
constexpr u64 kDirEntryLoadConfig = 10;

// IMAGE_LOAD_CONFIG_DIRECTORY64 field offsets used by the
// /GS cookie-randomisation slice. The LoadConfig struct grows
// over MSVC versions; we only touch fields whose offsets have
// been stable since the SecurityCookie field was added.
constexpr u64 kLoadConfigSizeOffset = 0;        // u32 — Size of struct
constexpr u64 kLoadConfigSecurityCookie = 0x58; // u64 — VA of __security_cookie

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
constexpr u64 kV0StackVa = kV0StackTop - kV0StackPages * duetos::mm::kPageSize;
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

// Static-TLS region (T6-01). A PE with an IMAGE_DIRECTORY_ENTRY_TLS
// gets:
//   - kV0TlsArrayVa : one page holding the ThreadLocalStoragePointer
//     array. TEB+0x58 points here; slot[_tls_index] -> the data
//     block. MSVC __declspec(thread) access is
//     `mov rax, gs:[0x58]; mov ecx,[_tls_index]; mov rax,[rax+rcx*8]`.
//   - kV0TlsBlockVa : the per-process main-thread TLS data block —
//     a copy of the .tls template (Start..End) plus SizeOfZeroFill
//     zero bytes. Sized up to kV0TlsBlockMaxPages.
//   - kV0TlsTrampVa : an R-X page holding a generated trampoline
//     that invokes each TLS callback (rcx=base, rdx=DLL_PROCESS_
//     ATTACH, r8=0) before jumping to the real entry point.
constexpr u64 kV0TlsArrayVa = 0x71000000ULL;
constexpr u64 kV0TlsBlockVa = 0x72000000ULL;
constexpr u64 kV0TlsTrampVa = 0x73000000ULL;
constexpr u64 kV0TlsBlockMaxPages = 64; // 256 KiB template+zerofill cap
constexpr u64 kTebOffTlsPointer = 0x58; // TEB.ThreadLocalStoragePointer (x64)
constexpr u32 kDllProcessAttach = 1;
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
    // Bitness picked up from the optional-header magic. PE32 (i386)
    // images parse cleanly but are rejected before MapAndRun until
    // the 32-bit user-CS + syscall-ABI layers land — see
    // PeStatus::NotPe32PlusYet emitted in PeLoad.
    bool is_pe32;
    u32 data_dir_offset;
    u32 number_of_rva_and_sizes;
};

// Allocation-ladder unwind for PeLoad. PE startup maps headers,
// every section, a stack, a TEB, a proc-env page, and the Win32
// stubs region — five+ allocation phases that each can fail
// independently. Without an unwind, a partial-failure leaks every
// frame mapped before the failing leg (~20+ frames + VA mappings).
//
// Contract: every successful AddressSpaceMapUserPage inside PeLoad
// (and the helpers it delegates to) is followed by a Track(va)
// call. The destructor walks the tracked VAs in reverse order and
// calls AddressSpaceUnmapUserPage, which both clears the PTE and
// frees the underlying frame (see kernel/mm/address_space.cpp:446).
// PeLoad disarms the guard on success — the destructor then no-ops.
//
// Cap sized for the v0 worst case: kV0StackPages (16) + 1 TEB + 1
// env + 2 stubs + sections (~16 pages typical, ~256 worst case for
// large images) + headers (1-2 pages). 1024 leaves comfortable
// headroom; if a future PE legitimately exceeds it, the KASSERT in
// Track fires at the boundary so the leak doesn't go silent.
struct LoaderUnwindGuard
{
    static constexpr u64 kMaxTrackedVas = 1024;
    duetos::mm::AddressSpace* as = nullptr;
    u64 vas[kMaxTrackedVas] = {};
    u32 count = 0;
    bool armed = true;

    void Track(u64 va)
    {
        // Cap exhaustion used to silently no-op, leaving frames
        // mapped after a failing later step with no record for
        // the destructor to unmap — a guaranteed leak. The cap is
        // 4 MiB of mappings; hitting it on a normal PE means the
        // image is structurally beyond what v0 supports, and
        // continuing with a half-tracked unwind is worse than a
        // panic.
        KASSERT(count < kMaxTrackedVas, "loader/pe", "LoaderUnwindGuard cap exceeded");
        vas[count++] = va;
    }

    void Disarm() { armed = false; }

    ~LoaderUnwindGuard()
    {
        if (!armed || as == nullptr)
            return;
        // Walk in reverse so paging table levels are torn down in
        // the same order they were built up.
        for (u32 i = count; i > 0; --i)
            duetos::mm::AddressSpaceUnmapUserPage(as, vas[i - 1]);
    }
};

// Read a NUL-terminated ASCII string at `file[off..]` with
// bounds checks. Returns nullptr if we can't prove there's a
// NUL before the buffer ends — callers treat that as "skip,
// malformed". Cap at 256 chars so a hostile image can't dangle
// the serial log forever.
const char* BoundedCString(const u8* file, u64 file_len, u64 off)
{
    if (file == nullptr || off >= file_len)
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
    if (file == nullptr)
        return ~u64(0);
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        const u32 va = LeU32(sec + kSectionHeaderVirtualAddress);
        const u32 raw_size = LeU32(sec + kSectionHeaderSizeOfRawData);
        const u32 virt_size = LeU32(sec + kSectionHeaderVirtualSize);
        const u32 extent = raw_size > virt_size ? raw_size : virt_size;
        // Subtractive bound: a hostile section with va near UINT32_MAX
        // and a non-zero extent would otherwise wrap `va + extent` past
        // zero and bracket every RVA. Guard `extent > 0` because a
        // zero-length section legitimately covers no RVAs.
        if (rva >= va && extent > 0 && rva - va < extent)
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
    if (file == nullptr)
        return {0, 0};
    // PE32 vs PE32+: the data-directory array sits at a different
    // offset in the two layouts (96 vs 112) because the four
    // stack/heap reserve/commit slots are u32 in PE32 and u64 in
    // PE32+. ParseHeaders precomputes the correct offset and count
    // via the Rust validator; use those instead of the hardcoded
    // PE32+ constants which only work for AMD64 images.
    const u8* opt = file + h.opt_base;
    if (idx >= h.number_of_rva_and_sizes)
        return {0, 0};
    const u8* e = opt + h.data_dir_offset + idx * kDataDirEntrySize;
    return {LeU32(e + 0), LeU32(e + 4)};
}

// Parse and validate. PeHeaders is populated iff status is Ok.
PeStatus ParseHeaders(const u8* file, u64 file_len, PeHeaders& out)
{
    // Image validation (DOS stub, PE signature, AMD64 machine,
    // optional-header magic, section/file alignment, image-base
    // low-half bound, section-table bounds, per-section raw
    // extent) lives in the Rust crate `duetos_exec_meta`. The
    // first 12 PeStatus enumerators plus `ImageBaseOutOfRange`
    // (17) are byte-identical to the Rust crate's image-status
    // enum so the FFI round-trips cleanly through a u32 cast.
    //
    // The Rust validator populates `out_image` AS IT GOES (even
    // on failure return), mirroring the diagnostic-friendly
    // behaviour the C++ inline code had — `PeReport` needs the
    // partially-filled `out` to walk a rejected PE's section
    // table. The wrapper copies every field unconditionally so
    // that contract holds whether the call succeeded or not.
    using ::duetos::loader::exec_meta::duetos_exec_meta_pe_validate_image;
    using ::duetos::loader::exec_meta::DuetosPeImage;
    DuetosPeImage image{};
    u32 status = 0;
    duetos_exec_meta_pe_validate_image(file, static_cast<usize>(file_len), &image, &status);
    out.nt_base = image.nt_base;
    out.section_count = image.section_count;
    out.opt_header_size = image.opt_header_size;
    out.opt_base = image.opt_base;
    out.image_size = image.image_size;
    out.entry_rva = image.entry_rva;
    out.image_base = image.image_base;
    out.section_base = image.section_base;
    out.is_pe32 = (image.is_pe32 != 0);
    out.data_dir_offset = image.data_dir_offset;
    out.number_of_rva_and_sizes = image.number_of_rva_and_sizes;
    if (status != static_cast<u32>(PeStatus::Ok))
        return static_cast<PeStatus>(status);

    // Data Directories: v0 rejects any image with a non-empty
    // Import, BaseReloc, or TLS directory. These are the three
    // user-mode-loader features a real Win32 subsystem provides;
    // parsing them is done separately by PeReport, which runs
    // BEFORE this function on the spawn path so the log
    // carries a full picture even when we reject.
    //
    // PE32 (i386) vs PE32+ (AMD64): the data-directory array sits
    // at offset 96 in PE32 and 112 in PE32+ (the four stack/heap
    // Reserve/Commit slots are u32 in PE32, u64 in PE32+). The
    // Rust validator pre-computes the correct offset; we use it
    // verbatim here.
    const u8* opt = file + out.opt_base;
    const u32 num_dirs = out.number_of_rva_and_sizes;
    const u64 dd_off = out.data_dir_offset;
    const u64 dir_bytes = u64(num_dirs) * kDataDirEntrySize;
    if (dd_off + dir_bytes > out.opt_header_size)
        return PeStatus::OptHeaderOutOfBounds;
    auto dir_rva = [&](u64 idx) -> u32
    {
        if (idx >= num_dirs)
            return 0;
        return LeU32(opt + dd_off + idx * kDataDirEntrySize + 0);
    };
    auto dir_size = [&](u64 idx) -> u32
    {
        if (idx >= num_dirs)
            return 0;
        return LeU32(opt + dd_off + idx * kDataDirEntrySize + 4);
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
bool MapSection(const u8* file, const u8* sec, u64 image_base, duetos::mm::AddressSpace* as, LoaderUnwindGuard& guard)
{
    using namespace duetos::mm;
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
        // PE sections occasionally share a 4 KiB page with their neighbour
        // (small SectionAlignment, or one section's BSS tail spilling
        // into the next section's first page). Reuse the existing
        // mapping on conflict — copy the bytes into the existing frame
        // and skip a duplicate AddressSpaceMapUserPage call.
        const PhysAddr existing = AddressSpaceLookupUserFrame(as, page_va);
        const bool reusing = existing != kNullFrame;
        const PhysAddr frame = reusing ? existing : AllocateFrame();
        if (frame == kNullFrame)
            return false;
        auto* frame_direct = static_cast<u8*>(PhysToVirt(frame));
        // AllocateFrame hands out zeroed frames; the bytes we
        // don't overwrite below stay zero, which serves as
        // both the PE "BSS" tail and any raw-size < virt-size
        // padding. On the reuse path, the previous section's
        // bytes already live there — leave them alone.

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
        if (!reusing)
        {
            AddressSpaceMapUserPage(as, page_va, frame, flags);
            guard.Track(page_va);
        }
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
bool MapHeaders(const u8* file, u64 sizeof_headers, u64 image_base, duetos::mm::AddressSpace* as,
                LoaderUnwindGuard& guard)
{
    using namespace duetos::mm;
    const u64 start = image_base & ~kPageMask;
    const u64 end = (image_base + sizeof_headers + kPageMask) & ~kPageMask;
    if (end <= start)
        return true;

    for (u64 page_va = start; page_va < end; page_va += kPageSize)
    {
        // Headers and the first section can share a page when the
        // optional header's SizeOfHeaders + sections fit in fewer
        // bytes than SectionAlignment. Reuse the existing mapping.
        const PhysAddr existing = AddressSpaceLookupUserFrame(as, page_va);
        const bool reusing = existing != kNullFrame;
        const PhysAddr frame = reusing ? existing : AllocateFrame();
        if (frame == kNullFrame)
            return false;
        auto* direct = static_cast<u8*>(PhysToVirt(frame));
        const u64 file_off = page_va - image_base;
        const u64 remain = (file_off < sizeof_headers) ? (sizeof_headers - file_off) : 0;
        const u64 n = remain < kPageSize ? remain : kPageSize;
        for (u64 i = 0; i < n; ++i)
            direct[i] = file[file_off + i];
        if (!reusing)
        {
            AddressSpaceMapUserPage(as, page_va, frame, kPagePresent | kPageUser | kPageNoExecute);
            guard.Track(page_va);
        }
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
    case PeStatus::TlsCallbacksUnsupported:
        return "TlsCallbacksUnsupported";
    case PeStatus::StubsPageAllocFail:
        return "StubsPageAllocFail";
    case PeStatus::ImageBaseOutOfRange:
        return "ImageBaseOutOfRange";
    case PeStatus::Pe32ExecutionNotReady:
        return "Pe32ExecutionNotReady";
    default:
        KLOG_ONCE_WARN("loader/pe", "PeStatusName: unrecognised PeStatus enumerator");
        return "?";
    }
}

PeStatus PeValidate(const u8* file, u64 file_len)
{
    PeHeaders h{};
    return ParseHeaders(file, file_len, h);
}

// IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040 (per the PE
// spec). DllCharacteristics is a u16 at offset 70 in the
// PE32+ Optional Header (right after Subsystem at 68).
bool PeIsDynamicBase(const u8* file, u64 file_len)
{
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    if (s != PeStatus::Ok && s != PeStatus::ImportsPresent && s != PeStatus::TlsPresent)
        return false;
    constexpr u64 kOptHeaderDllCharacteristics = 70;
    if (file_len < h.opt_base + kOptHeaderDllCharacteristics + 2)
        return false;
    const u16 chars = LeU16(file + h.opt_base + kOptHeaderDllCharacteristics);
    constexpr u16 kDynamicBase = 0x0040;
    return (chars & kDynamicBase) != 0;
}

bool PeIsPe32(const u8* file, u64 file_len)
{
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    // PE32 images come back with status Ok / ImportsPresent / TlsPresent
    // and h.is_pe32 set; everything else (malformed magic, out-of-bounds
    // section table, etc.) is "no".
    if (s != PeStatus::Ok && s != PeStatus::ImportsPresent && s != PeStatus::TlsPresent)
        return false;
    return h.is_pe32;
}

u64 PePreferredBaseOf(const u8* file, u64 file_len)
{
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    if (s != PeStatus::Ok && s != PeStatus::ImportsPresent && s != PeStatus::TlsPresent)
        return 0;
    return h.image_base;
}

u64 PeImageSizeOf(const u8* file, u64 file_len)
{
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    if (s != PeStatus::Ok && s != PeStatus::ImportsPresent && s != PeStatus::TlsPresent)
        return 0;
    return h.image_size;
}

// Resolve every entry in the import table by patching the IAT
// in place. For each import descriptor:
//   1. Read the DLL name from its Name RVA.
//   2. For each function entry (by-name; ordinal imports get
//      rejected in v0), read the hint/name from the IBN, look
//      up the stub VA in win32::Win32ThunksLookup.
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

// Staging buffer for Win32 catch-all misses recorded during the
// current PeLoad. Drained by PeLoadDrainIatMisses() after the
// Process is created — Process doesn't exist while PeLoad runs,
// so the catch-all path queues entries here and SpawnPeFile
// transfers them once it has a proc to attach them to. Single
// PE load at a time (kernel has one boot-time loader worker),
// so no concurrency guard needed.
struct StagedMiss
{
    u64 slot_va;
    const char* name;
};
constexpr u64 kStagedMissCap = 128;
StagedMiss g_staged_misses[kStagedMissCap];
u64 g_staged_miss_count = 0;
// Dropped imports past the cap. Surfaced as one WARN per
// PeLoad in PeLoadDrainIatMisses so an operator can see the
// PE legitimately exceeded the staging buffer rather than
// just guess from the IAT-miss count being suspiciously round.
u64 g_staged_miss_dropped = 0;

void StagedMissReset()
{
    g_staged_miss_count = 0;
    g_staged_miss_dropped = 0;
}

// Build a fix-journal source-pin into pin_out. Format: "<dll>!<fn>\0".
// Total pin buffer is 40 bytes (one record-field width). Drops the
// redundant trailing ".dll" suffix so longer DLL names like
// "api-ms-win-crt-runtime-l1-1-0.dll" fit; prefers preserving the
// function name (the more diagnostic half) when truncation is forced.
void BuildFixJournalPin(const char* dll_name, const char* fn_name, char (&pin_out)[40])
{
    constexpr u64 kPinCap = 40;
    constexpr u64 kPinContent = kPinCap - 1; // leave room for '\0'

    auto str_len = [](const char* s) -> u64
    {
        if (s == nullptr)
            return 0;
        u64 n = 0;
        while (s[n] != '\0')
            ++n;
        return n;
    };

    u64 dll_len = str_len(dll_name);
    if (dll_len >= 4)
    {
        const char* tail = dll_name + (dll_len - 4);
        const bool ends_dll = (tail[0] == '.') && ((tail[1] == 'd') || (tail[1] == 'D')) &&
                              ((tail[2] == 'l') || (tail[2] == 'L')) && ((tail[3] == 'l') || (tail[3] == 'L'));
        if (ends_dll)
            dll_len -= 4;
    }
    const u64 fn_len = str_len(fn_name);

    // 1 char for '!' separator. Cap the function half first
    // (it's the more diagnostic part), then give the rest to dll.
    const u64 fn_avail = (kPinContent >= 1) ? (kPinContent - 1) : 0;
    const u64 fn_take = fn_len < fn_avail ? fn_len : fn_avail;
    const u64 dll_avail = fn_avail - fn_take;
    const u64 dll_take = dll_len < dll_avail ? dll_len : dll_avail;

    u64 p = 0;
    for (u64 i = 0; i < dll_take; ++i)
        pin_out[p++] = dll_name[i];
    if (p < kPinContent)
        pin_out[p++] = '!';
    for (u64 i = 0; i < fn_take; ++i)
        pin_out[p++] = fn_name[i];
    pin_out[p] = '\0';
}

void StagedMissAppend(u64 slot_va, const char* name)
{
    if (g_staged_miss_count >= kStagedMissCap)
    {
        ++g_staged_miss_dropped;
        return;
    }
    g_staged_misses[g_staged_miss_count].slot_va = slot_va;
    g_staged_misses[g_staged_miss_count].name = name;
    ++g_staged_miss_count;
}

// Byte-wise read/write through an inactive AddressSpace's user
// mappings (same frame-lookup + PhysToVirt round-trip
// ApplyRelocations uses). Returns false if any page is unmapped.
bool AsRead(duetos::mm::AddressSpace* as, u64 va, void* dst, u64 len)
{
    auto* d = static_cast<u8*>(dst);
    for (u64 i = 0; i < len; ++i)
    {
        const u64 cur = va + i;
        const duetos::mm::PhysAddr fr = duetos::mm::AddressSpaceLookupUserFrame(as, cur & ~0xFFFULL);
        if (fr == duetos::mm::kNullFrame)
            return false;
        d[i] = static_cast<const u8*>(duetos::mm::PhysToVirt(fr))[cur & 0xFFFULL];
    }
    return true;
}
bool AsWrite(duetos::mm::AddressSpace* as, u64 va, const void* src, u64 len)
{
    const auto* s = static_cast<const u8*>(src);
    for (u64 i = 0; i < len; ++i)
    {
        const u64 cur = va + i;
        const duetos::mm::PhysAddr fr = duetos::mm::AddressSpaceLookupUserFrame(as, cur & ~0xFFFULL);
        if (fr == duetos::mm::kNullFrame)
            return false;
        static_cast<u8*>(duetos::mm::PhysToVirt(fr))[cur & 0xFFFULL] = s[i];
    }
    return true;
}

struct TlsSetupResult
{
    bool ok = false;           // false => hard failure, fail the load
    bool present = false;      // a TLS directory was present
    u64 entry_override_va = 0; // non-zero => jump here first (callback trampoline)
    // Template descriptor for per-thread replication (T6-01
    // per-thread half). Mapped/relocated VAs.
    u64 tmpl_src_va = 0;
    u64 tmpl_raw = 0;
    u64 tmpl_zerofill = 0;
    u64 index_va = 0;
    u32 cb_count = 0;
    u64 callbacks[16] = {};
};

// T6-01: static TLS + TLS-callback support.
//
// Builds the per-process main-thread TLS data block (a copy of the
// .tls template Start..End plus SizeOfZeroFill zero bytes), points
// TEB.ThreadLocalStoragePointer (gs:[0x58]) at a slot array whose
// slot 0 is that block, writes the module's _tls_index (0), and —
// if the image registers TLS callbacks — generates an R-X
// trampoline that invokes each callback with the Win64
// (rcx=image_base, rdx=DLL_PROCESS_ATTACH, r8=0) ABI before
// jumping to the real entry point. Returns ok=false only on a
// structural failure (malformed dir / OOM / unmapped template);
// a PE with no TLS directory returns ok=true, present=false.
TlsSetupResult SetupStaticTls(const u8* file, u64 file_len, const PeHeaders& h, duetos::mm::AddressSpace* as,
                              u64 teb_va, LoaderUnwindGuard& guard)
{
    TlsSetupResult res;
    const PeDataDir tls_dir = ReadDataDir(file, h, kDirEntryTls);
    if (tls_dir.rva == 0 || tls_dir.size == 0)
    {
        res.ok = true; // no TLS — nothing to do
        return res;
    }
    res.present = true;
    (void)file;
    (void)file_len;
    // Read the IMAGE_TLS_DIRECTORY64 from the MAPPED image, not the
    // file. The data-directory RVA is base-independent, but the
    // dir's Start/End/Index/Callbacks fields are absolute VAs that
    // base-relocation already fixed up in the mapped image (this
    // runs after ApplyRelocations). Reading the file copy would
    // yield preferred-base VAs and be wrong whenever the spawn
    // applied an ASLR delta (it does — h.image_base = load base).
    const u64 dir_va = h.image_base + tls_dir.rva;
    u8 dir[40];
    if (!AsRead(as, dir_va, dir, sizeof(dir)))
    {
        arch::SerialWrite("[pe-tls] FAIL TLS directory unmapped va=");
        arch::SerialWriteHex(dir_va);
        arch::SerialWrite("\n");
        return res;
    }
    const u64 start_va = LeU64(dir + 0x00);
    const u64 end_va = LeU64(dir + 0x08);
    const u64 idx_va = LeU64(dir + 0x10);
    const u64 cb_arr_va = LeU64(dir + 0x18);
    const u32 zerofill = LeU32(dir + 0x20);
    if (end_va < start_va)
    {
        arch::SerialWrite("[pe-tls] FAIL End<Start\n");
        return res;
    }
    const u64 raw = end_va - start_va;
    const u64 total = raw + zerofill;
    if (total > kV0TlsBlockMaxPages * duetos::mm::kPageSize)
    {
        arch::SerialWrite("[pe-tls] FAIL TLS block too large size=");
        arch::SerialWriteHex(total);
        arch::SerialWrite("\n");
        return res;
    }

    // 1. Map a zeroed TLS data block, then copy the template.
    const u64 npages = total == 0 ? 1 : ((total + duetos::mm::kPageSize - 1) / duetos::mm::kPageSize);
    for (u64 p = 0; p < npages; ++p)
    {
        const mm::PhysAddr f = mm::AllocateFrame();
        if (f == mm::kNullFrame)
        {
            arch::SerialWrite("[pe-tls] FAIL block frame alloc\n");
            return res;
        }
        auto* d = static_cast<u8*>(duetos::mm::PhysToVirt(f));
        for (u64 i = 0; i < duetos::mm::kPageSize; ++i)
            d[i] = 0;
        const u64 va = kV0TlsBlockVa + p * duetos::mm::kPageSize;
        duetos::mm::AddressSpaceMapUserPage(as, va, f,
                                            mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
        guard.Track(va);
    }
    if (raw != 0)
    {
        u8 buf[256];
        u64 done = 0;
        while (done < raw)
        {
            u64 chunk = raw - done;
            if (chunk > sizeof(buf))
                chunk = sizeof(buf);
            if (!AsRead(as, start_va + done, buf, chunk))
            {
                arch::SerialWrite("[pe-tls] FAIL template read (unmapped .tls)\n");
                return res;
            }
            if (!AsWrite(as, kV0TlsBlockVa + done, buf, chunk))
            {
                arch::SerialWrite("[pe-tls] FAIL block write\n");
                return res;
            }
            done += chunk;
        }
    }

    // 2. Slot array page; slot[0] -> block.
    {
        const mm::PhysAddr f = mm::AllocateFrame();
        if (f == mm::kNullFrame)
        {
            arch::SerialWrite("[pe-tls] FAIL array frame alloc\n");
            return res;
        }
        auto* d = static_cast<u8*>(duetos::mm::PhysToVirt(f));
        for (u64 i = 0; i < duetos::mm::kPageSize; ++i)
            d[i] = 0;
        for (u64 b = 0; b < 8; ++b)
            d[b] = static_cast<u8>((kV0TlsBlockVa >> (b * 8)) & 0xFF);
        duetos::mm::AddressSpaceMapUserPage(as, kV0TlsArrayVa, f,
                                            mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
        guard.Track(kV0TlsArrayVa);
    }

    // 3. TEB.ThreadLocalStoragePointer = array VA.
    {
        const u64 ptr = kV0TlsArrayVa;
        if (!AsWrite(as, teb_va + kTebOffTlsPointer, &ptr, 8))
        {
            arch::SerialWrite("[pe-tls] FAIL TEB+0x58 write\n");
            return res;
        }
    }

    // 4. *_tls_index = 0 (single module). Best-effort: a stripped
    //    image may point this outside a writable section.
    if (idx_va != 0)
    {
        const u32 zero = 0;
        if (!AsWrite(as, idx_va, &zero, 4))
            arch::SerialWrite("[pe-tls] WARN _tls_index VA unmapped — skipped\n");
    }

    // 5. Callbacks -> generated R-X trampoline. The callback array
    //    is a NULL-terminated list of absolute VAs; read it from
    //    the mapped image (relocated) at cb_arr_va. Cap the walk so
    //    a missing terminator can't spin the loader.
    u64 cbs[16];
    u32 ncb = 0;
    if (cb_arr_va != 0)
    {
        for (u32 i = 0; i < 16; ++i)
        {
            u64 ent = 0;
            if (!AsRead(as, cb_arr_va + u64(i) * 8, &ent, 8) || ent == 0)
                break;
            cbs[ncb++] = ent;
        }
    }
    if (ncb != 0)
    {
        const mm::PhysAddr f = mm::AllocateFrame();
        if (f == mm::kNullFrame)
        {
            arch::SerialWrite("[pe-tls] FAIL trampoline frame alloc\n");
            return res;
        }
        auto* code = static_cast<u8*>(duetos::mm::PhysToVirt(f));
        for (u64 i = 0; i < duetos::mm::kPageSize; ++i)
            code[i] = 0;
        u64 n = 0;
        auto emit = [&](u8 b) { code[n++] = b; };
        auto emit_u64 = [&](u64 v)
        {
            for (int i = 0; i < 8; ++i)
                emit(static_cast<u8>((v >> (i * 8)) & 0xFF));
        };
        // sub rsp,0x28  (32B shadow + 8 to keep 16-byte alignment
        // across the calls; entry rsp is 16-aligned per the kernel).
        emit(0x48);
        emit(0x81);
        emit(0xEC);
        emit(0x28);
        emit(0x00);
        emit(0x00);
        emit(0x00);
        for (u32 i = 0; i < ncb; ++i)
        {
            emit(0x48); // mov rcx, image_base
            emit(0xB9);
            emit_u64(h.image_base);
            emit(0x31); // xor edx,edx
            emit(0xD2);
            emit(0xB2); // mov dl,1  (DLL_PROCESS_ATTACH)
            emit(static_cast<u8>(kDllProcessAttach));
            emit(0x45); // xor r8d,r8d
            emit(0x31);
            emit(0xC0);
            emit(0x48); // mov rax, cb
            emit(0xB8);
            emit_u64(cbs[i]);
            emit(0xFF); // call rax
            emit(0xD0);
        }
        emit(0x48); // add rsp,0x28
        emit(0x81);
        emit(0xC4);
        emit(0x28);
        emit(0x00);
        emit(0x00);
        emit(0x00);
        emit(0x48); // mov rax, real_entry
        emit(0xB8);
        emit_u64(h.image_base + h.entry_rva);
        emit(0xFF); // jmp rax
        emit(0xE0);
        // R-X (no writable, no NX) — W^X for generated code.
        duetos::mm::AddressSpaceMapUserPage(as, kV0TlsTrampVa, f, mm::kPagePresent | mm::kPageUser);
        guard.Track(kV0TlsTrampVa);
        res.entry_override_va = kV0TlsTrampVa;
        arch::SerialWrite("[pe-tls] callbacks=");
        arch::SerialWriteHex(ncb);
        arch::SerialWrite(" trampoline armed va=");
        arch::SerialWriteHex(kV0TlsTrampVa);
        arch::SerialWrite("\n");
    }
    arch::SerialWrite("[pe-tls] static TLS ready raw=");
    arch::SerialWriteHex(raw);
    arch::SerialWrite(" zerofill=");
    arch::SerialWriteHex(zerofill);
    arch::SerialWrite(" idx_va=");
    arch::SerialWriteHex(idx_va);
    arch::SerialWrite("\n");
    // Hand the template out so SYS_THREAD_CREATE can replicate it
    // per-thread (the source bytes are the same mapped, relocated
    // template region the main-thread copy was taken from).
    res.tmpl_src_va = start_va;
    res.tmpl_raw = raw;
    res.tmpl_zerofill = zerofill;
    res.index_va = idx_va;
    res.cb_count = ncb;
    for (u32 i = 0; i < ncb && i < 16; ++i)
        res.callbacks[i] = cbs[i];
    res.ok = true;
    return res;
}

// Seed the per-image /GS stack cookie (T9-02 follow-on).
//
// MSVC `/GS`-protected functions emit a save/check pair around
// the stack frame that compares against `__security_cookie`,
// a per-image global. Without per-image randomisation, every
// process's cookie is the documented MSVC default value
// (vcruntime140 ships exactly that default), which makes the
// check trivial to bypass with a known overflow.
//
// MSVC's CRT publishes the address of `__security_cookie` via
// IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie. We read that
// field, generate a fresh u64 from the kernel RNG, and write
// it directly into the loaded image's data section before
// ring-3 entry.
//
// On PEs without a load config (older / freestanding builds)
// or whose load config is too small to include SecurityCookie,
// we silently skip — the compiler-emitted check still works
// because it compares the cookie value to itself across one
// function call.
//
// On the v0 happy path the cookie variable lives in a single
// page, so a one-frame lookup + 8-byte write is enough. We
// still handle the page-straddle case using the same pattern
// as ApplyRelocations.
bool SeedSecurityCookie(const u8* file, u64 file_len, const PeHeaders& h, duetos::mm::AddressSpace* as)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    const PeDataDir lc = ReadDataDir(file, h, kDirEntryLoadConfig);
    if (lc.rva == 0 || lc.size == 0)
        return true; // No load config — nothing to seed.
    const u64 lc_off = RvaToFile(file, h, lc.rva);
    if (lc_off == ~u64(0) || lc_off + 4 > file_len)
        return true; // Malformed — silently skip.
    const u32 cfg_size = LeU32(file + lc_off + kLoadConfigSizeOffset);
    // Need at least Size + everything up through SecurityCookie.
    if (cfg_size < kLoadConfigSecurityCookie + 8)
        return true; // Pre-/GS load config layout — skip.
    if (lc_off + kLoadConfigSecurityCookie + 8 > file_len)
        return true; // Truncated — skip.
    const u64 cookie_va = LeU64(file + lc_off + kLoadConfigSecurityCookie);
    if (cookie_va == 0)
        return true; // /GS disabled at compile time.
    // Generate a random cookie. Avoid all-zero (the "uninitialised"
    // sentinel MSVC checks for) and the documented default.
    u64 cookie = duetos::core::RandomU64();
    constexpr u64 kMsvcDefault = 0x00002B992DDFA232ULL;
    if (cookie == 0 || cookie == kMsvcDefault)
        cookie ^= 0x0123456789ABCDEFULL;
    // Only the low 48 bits are kept on x64 (MSVC zeroes the high
    // 16 to keep the cookie usable as a SEH key) — match that.
    cookie &= 0x0000FFFFFFFFFFFFULL;
    // Write the cookie 8 bytes via the same per-page lookup the
    // relocation walker uses, so a page-straddle works correctly.
    for (u64 b = 0; b < 8; ++b)
    {
        const u64 va = cookie_va + b;
        const u64 page_va = va & ~0xFFFULL;
        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, page_va);
        if (frame == mm::kNullFrame)
        {
            SerialWrite("[pe-load] /GS cookie va unmapped — skipping seed\n");
            return true; // best-effort; keep loading.
        }
        auto* direct = static_cast<u8*>(mm::PhysToVirt(frame));
        direct[va & 0xFFFULL] = u8((cookie >> (b * 8)) & 0xFF);
    }
    SerialWrite("[pe-load] step3c /GS cookie seeded va=");
    SerialWriteHex(cookie_va);
    SerialWrite("\n");
    return true;
}

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
bool ApplyRelocations(const u8* file, u64 file_len, const PeHeaders& h, duetos::mm::AddressSpace* as, u64 delta)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    KDBG_2V(PeReloc, "pe-reloc", "ApplyRelocations enter", "delta", delta, "file_len", file_len);
    const PeDataDir br = ReadDataDir(file, h, kDirEntryBaseReloc);
    if (br.rva == 0 || br.size == 0)
    {
        KDBG(PeReloc, "pe-reloc", "no reloc table — nothing to do");
        return true;
    }

    const u64 tbl_off = RvaToFile(file, h, br.rva);
    if (tbl_off == ~u64(0) || tbl_off + br.size > file_len)
    {
        // Either the data dir's reloc-table RVA didn't resolve to a
        // file offset (truncated section table) or the claimed
        // size walks past the end of the on-disk image. Could be a
        // malformed PE or a deliberate fuzz attempt; route through
        // klog so the panic-time replay shows the offending values.
        KLOG_ERROR_2V("loader/pe-reloc", "reloc table rva out of bounds", "tbl_off", tbl_off, "size", br.size);
        return false;
    }
    KDBG_2V(PeReloc, "pe-reloc", "reloc table mapped", "tbl_off", tbl_off, "size", br.size);

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
            // Block header smaller than the fixed 8-byte preamble
            // OR its claimed size walks past the table end. Pin
            // both the page_rva (locates the block in the image)
            // and block_sz so a post-mortem can correlate against
            // the offending image's reloc table.
            KLOG_ERROR_2V("loader/pe-reloc", "malformed reloc block size", "page_rva", page_rva, "block_sz", block_sz);
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
            // Two real types we apply:
            //   3  IMAGE_REL_BASED_HIGHLOW — PE32 (i386), patches 4 bytes
            //   10 IMAGE_REL_BASED_DIR64   — PE32+ (AMD64), patches 8 bytes
            // PE32 images use HIGHLOW exclusively; PE32+ images use DIR64
            // exclusively. Mixing within one image is malformed.
            const bool is_highlow = (type == 3);
            const bool is_dir64 = (type == 10);
            if (!is_highlow && !is_dir64)
            {
                // Surface the IMAGE_REL_BASED_* name so a reader doesn't
                // have to look up `type=3` against the PE spec table.
                const char* name = "unknown";
                switch (type)
                {
                case 0:
                    name = "ABSOLUTE";
                    break;
                case 1:
                    name = "HIGH";
                    break;
                case 2:
                    name = "LOW";
                    break;
                case 3:
                    name = "HIGHLOW";
                    break;
                case 4:
                    name = "HIGHADJ";
                    break;
                case 5:
                    name = "MIPS_JMPADDR/ARM_MOV32";
                    break;
                case 7:
                    name = "ARM_MOV32T";
                    break;
                case 9:
                    name = "MIPS_JMPADDR16";
                    break;
                case 10:
                    name = "DIR64";
                    break;
                default:
                    name = "unknown";
                    break;
                }
                SerialWrite("[pe-reloc] unsupported reloc type=");
                SerialWriteHex(type);
                SerialWrite(" (IMAGE_REL_BASED_");
                SerialWrite(name);
                SerialWrite(")\n");
                return false;
            }

            if (delta == 0)
                continue; // no-op apply — still validated the entry shape.

            const u64 patch_va = h.image_base + u64(page_rva) + u64(offset);
            // HIGHLOW = 4 bytes, DIR64 = 8 bytes. Read, add delta, write
            // back. Split across two frames if the write straddles a page.
            const u64 patch_bytes = is_highlow ? 4 : 8;
            u64 orig = 0;
            for (u64 b = 0; b < patch_bytes; ++b)
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
            // HIGHLOW only patches the low 32 bits; the delta itself for
            // a 32-bit image lives in the low 32 bits too (ImageBase is
            // u32). Truncating after the add matches what a 32-bit
            // Windows loader does.
            const u64 fixed = orig + delta;
            for (u64 b = 0; b < patch_bytes; ++b)
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

// ASCII to-lower. Duplicated locally from process.cpp to keep
// pe_loader.cpp standalone — no cross-translation-unit coupling
// for a 5-line helper.
inline char AsciiToLower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

// Case-insensitive strcmp for DLL names (Win32 convention —
// lld-link capitalises inconsistently across toolchains).
bool DllNameEqCI(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return a == b;
    while (*a && *b)
    {
        if (AsciiToLower(*a) != AsciiToLower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

// Parse a PE-style forwarder string ("DllBase.TargetFunc" or
// "DllBase.#Ordinal") into its components.
//
// On success, writes the pre-'.' substring into `out_dll`
// (appending ".dll" if not already present — PE forwarders
// conventionally omit the extension) and fills `out`:
//   - is_ordinal=false + func points just past '.' for name form
//   - is_ordinal=true  + ordinal holds the parsed decimal ordinal
//                        for "#N" form
// `out_dll` must have room for at least kMaxForwarderDllLen
// bytes. Returns false on malformed strings (no '.', empty
// target, missing/overflowed ordinal digits).
constexpr u64 kMaxForwarderDllLen = 64;

struct ParsedForwarder
{
    bool is_ordinal;
    u32 ordinal;      // valid when is_ordinal
    const char* func; // valid when !is_ordinal (borrowed into fwd)
};

bool ParseForwarder(const char* fwd, char* out_dll, ParsedForwarder& out)
{
    if (fwd == nullptr || out_dll == nullptr)
        return false;
    out = {};
    // Locate the '.' separator — first occurrence is the split.
    const char* dot = nullptr;
    for (const char* p = fwd; *p; ++p)
    {
        if (*p == '.')
        {
            dot = p;
            break;
        }
    }
    if (dot == nullptr || dot == fwd)
        return false;
    if (*(dot + 1) == '\0')
        return false; // empty target after '.'

    // Copy the DLL name segment, append ".dll" if caller didn't.
    const u64 dll_chars = static_cast<u64>(dot - fwd);
    // Leave room for ".dll\0" (5 bytes) on top of the segment.
    if (dll_chars + 5 > kMaxForwarderDllLen)
        return false;
    for (u64 i = 0; i < dll_chars; ++i)
        out_dll[i] = fwd[i];
    out_dll[dll_chars] = '\0';

    // Detect a pre-existing ".dll" / ".DLL" suffix.
    bool has_dll_suffix = false;
    if (dll_chars >= 4)
    {
        const char* tail = out_dll + (dll_chars - 4);
        if (AsciiToLower(tail[0]) == '.' && AsciiToLower(tail[1]) == 'd' && AsciiToLower(tail[2]) == 'l' &&
            AsciiToLower(tail[3]) == 'l')
            has_dll_suffix = true;
    }
    if (!has_dll_suffix)
    {
        out_dll[dll_chars + 0] = '.';
        out_dll[dll_chars + 1] = 'd';
        out_dll[dll_chars + 2] = 'l';
        out_dll[dll_chars + 3] = 'l';
        out_dll[dll_chars + 4] = '\0';
    }

    // Ordinal form: "Dll.#N" — N is decimal, fits in u32. Reject
    // empty digit run (just '#'), non-digit chars, and any value
    // that overflows u32.
    if (*(dot + 1) == '#')
    {
        const char* digits = dot + 2;
        if (*digits < '0' || *digits > '9')
            return false;
        u64 acc = 0;
        for (const char* p = digits; *p; ++p)
        {
            if (*p < '0' || *p > '9')
                return false;
            acc = acc * 10 + u64(*p - '0');
            if (acc > 0xFFFFFFFFULL)
                return false;
        }
        out.is_ordinal = true;
        out.ordinal = static_cast<u32>(acc);
        out.func = nullptr;
        return true;
    }

    out.is_ordinal = false;
    out.ordinal = 0;
    out.func = dot + 1;
    return true;
}

// Try the caller's preloaded DLL array (with forwarder chase) before
// falling through to the flat stubs table. Returns true and
// writes *out_va on hit; returns false on miss so ResolveImports
// falls through to Win32ThunksLookupKind unchanged.
//
// Forwarder exports (where the EAT RVA points inside the export
// directory to a "Dll.Target" string rather than to a real code
// RVA) are chased recursively: we parse the forwarder, look up
// the target in the same preloaded-DLL array. `depth` bounds the
// recursion against pathological forwarder cycles (depth ~4 is
// enough for real-world multi-hop redirects like
// kernel32→kernelbase→ntdll). Both name-form ("Dll.Func") and
// ordinal-form ("Dll.#N") forwarders are handled.
constexpr u32 kMaxForwarderDepth = 4;

bool TryResolveViaPreloadedDllsByOrdinalImpl(const char* dll_name, u32 ordinal, const DllImage* dlls, u64 count,
                                             u32 depth, u64* out_va);

bool TryResolveViaPreloadedDllsImpl(const char* dll_name, const char* fn_name, const DllImage* dlls, u64 count,
                                    u32 depth, u64* out_va)
{
    if (depth > kMaxForwarderDepth)
        return false;
    if (dll_name == nullptr || fn_name == nullptr || dlls == nullptr || count == 0 || out_va == nullptr)
        return false;
    for (u64 i = 0; i < count; ++i)
    {
        const DllImage& img = dlls[i];
        if (!img.has_exports)
            continue;
        const char* img_dll_name = PeExportsDllName(img.exports);
        if (!DllNameEqCI(img_dll_name, dll_name))
            continue;
        PeExport e{};
        if (!PeExportLookupName(img.exports, fn_name, e))
            continue;
        if (e.is_forwarder)
        {
            char fwd_dll[kMaxForwarderDllLen];
            ParsedForwarder parsed{};
            if (!ParseForwarder(e.forwarder, fwd_dll, parsed))
            {
                arch::SerialWrite("[pe-resolve] forwarder unparseable: \"");
                arch::SerialWrite(e.forwarder ? e.forwarder : "<null>");
                arch::SerialWrite("\"\n");
                continue; // fall through to next DLL match / flat stubs
            }
            u64 target_va = 0;
            const bool ok = parsed.is_ordinal ? TryResolveViaPreloadedDllsByOrdinalImpl(fwd_dll, parsed.ordinal, dlls,
                                                                                        count, depth + 1, &target_va)
                                              : TryResolveViaPreloadedDllsImpl(fwd_dll, parsed.func, dlls, count,
                                                                               depth + 1, &target_va);
            if (!ok)
                continue; // target unknown; fall through
            arch::SerialWrite("[pe-resolve] via-dll-fwd ");
            arch::SerialWrite(dll_name);
            arch::SerialWrite("!");
            arch::SerialWrite(fn_name);
            arch::SerialWrite(" -> ");
            arch::SerialWrite(e.forwarder);
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(target_va);
            arch::SerialWrite("\n");
            *out_va = target_va;
            return true;
        }
        *out_va = img.base_va + static_cast<u64>(e.rva);
        return true;
    }
    return false;
}

// Ordinal-keyed twin of the recursive resolver above. Used when a
// forwarder string is "Dll.#N" — the chained target is identified
// by its absolute ordinal, not by name. Forwarder exports reached
// via ordinal are themselves chased through the same recursion
// (with depth incremented), so a "kernel32.#100 -> ntdll.RtlFoo"
// chain resolves cleanly.
bool TryResolveViaPreloadedDllsByOrdinalImpl(const char* dll_name, u32 ordinal, const DllImage* dlls, u64 count,
                                             u32 depth, u64* out_va)
{
    if (depth > kMaxForwarderDepth)
        return false;
    if (dll_name == nullptr || dlls == nullptr || count == 0 || out_va == nullptr)
        return false;
    for (u64 i = 0; i < count; ++i)
    {
        const DllImage& img = dlls[i];
        if (!img.has_exports)
            continue;
        const char* img_dll_name = PeExportsDllName(img.exports);
        if (!DllNameEqCI(img_dll_name, dll_name))
            continue;
        PeExport e{};
        if (!PeExportLookupOrdinal(img.exports, ordinal, e))
            continue;
        if (e.is_forwarder)
        {
            char fwd_dll[kMaxForwarderDllLen];
            ParsedForwarder parsed{};
            if (!ParseForwarder(e.forwarder, fwd_dll, parsed))
            {
                arch::SerialWrite("[pe-resolve] forwarder unparseable: \"");
                arch::SerialWrite(e.forwarder ? e.forwarder : "<null>");
                arch::SerialWrite("\"\n");
                continue;
            }
            u64 target_va = 0;
            const bool ok = parsed.is_ordinal ? TryResolveViaPreloadedDllsByOrdinalImpl(fwd_dll, parsed.ordinal, dlls,
                                                                                        count, depth + 1, &target_va)
                                              : TryResolveViaPreloadedDllsImpl(fwd_dll, parsed.func, dlls, count,
                                                                               depth + 1, &target_va);
            if (!ok)
                continue;
            arch::SerialWrite("[pe-resolve] via-dll-fwd ");
            arch::SerialWrite(dll_name);
            arch::SerialWrite("!#");
            arch::SerialWriteHex(ordinal);
            arch::SerialWrite(" -> ");
            arch::SerialWrite(e.forwarder);
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(target_va);
            arch::SerialWrite("\n");
            *out_va = target_va;
            return true;
        }
        *out_va = img.base_va + static_cast<u64>(e.rva);
        return true;
    }
    return false;
}

bool TryResolveViaPreloadedDlls(const char* dll_name, const char* fn_name, const DllImage* dlls, u64 count, u64* out_va)
{
    return TryResolveViaPreloadedDllsImpl(dll_name, fn_name, dlls, count, /*depth=*/0, out_va);
}

bool TryResolveViaPreloadedDllsByOrdinal(const char* dll_name, u32 ordinal, const DllImage* dlls, u64 count,
                                         u64* out_va)
{
    return TryResolveViaPreloadedDllsByOrdinalImpl(dll_name, ordinal, dlls, count, /*depth=*/0, out_va);
}

// True if `dll_name` is a Windows API-set contract name —
// "api-ms-win-..." or "ext-ms-win-..." (case-insensitive). These
// are not real DLLs: they are name contracts whose implementation
// lives in one of the base DLLs the loader already preloads
// (kernel32 / kernelbase / ntdll / ...). mingw's import libs
// (e.g. -lsynchronization) emit imports against these contract
// names for modern APIs (WaitOnAddress, condition variables, …),
// and Chrome links the same way.
bool IsApiSetContract(const char* dll_name)
{
    if (dll_name == nullptr)
        return false;
    auto lc = [](char c) -> char { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
    const char* a = "api-ms-win-";
    const char* e = "ext-ms-win-";
    bool ma = true, me = true;
    for (u64 i = 0; a[i] != '\0'; ++i)
    {
        if (lc(dll_name[i]) != a[i])
        {
            ma = false;
            break;
        }
    }
    if (ma)
        return true;
    for (u64 i = 0; e[i] != '\0'; ++i)
    {
        if (lc(dll_name[i]) != e[i])
        {
            me = false;
            break;
        }
    }
    return me;
}

// Resolve `fn_name` by NAME across every preloaded DLL, ignoring
// the (contract) DLL name. This is the api-set host-resolution
// model: the contract names a function, the host is whichever
// preloaded base DLL exports it. First match wins — for the
// api-set surface that is unambiguous in practice (a given
// contract function is exported by exactly one base DLL we
// preload). Forwarders are chased through the normal path.
//
// GAP: "first preloaded export by name" is a heuristic, not a
// real api-set schema. If two preloaded base DLLs ever export the
// same name with different semantics this could mis-host;
// revisit with a real api-set map if that collision shows up.
bool TryResolveViaPreloadedDllsAnyName(const char* fn_name, const DllImage* dlls, u64 count, u64* out_va)
{
    if (fn_name == nullptr || dlls == nullptr || count == 0 || out_va == nullptr)
        return false;
    for (u64 i = 0; i < count; ++i)
    {
        const DllImage& img = dlls[i];
        if (!img.has_exports)
            continue;
        const char* host = PeExportsDllName(img.exports);
        if (host == nullptr)
            continue;
        if (TryResolveViaPreloadedDllsImpl(host, fn_name, dlls, count, /*depth=*/0, out_va))
            return true;
    }
    return false;
}

bool ResolveImports(const u8* file, u64 file_len, const PeHeaders& h, duetos::mm::AddressSpace* as,
                    const DllImage* preloaded_dlls, u64 preloaded_dll_count)
{
    KLOG_TRACE_SCOPE("pe-resolve", "ResolveImports");
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    KDBG_V(PeImport, "pe-resolve", "ResolveImports enter; preloaded_dll_count", preloaded_dll_count);
    const PeDataDir imp = ReadDataDir(file, h, kDirEntryImport);
    if (imp.rva == 0 || imp.size == 0)
    {
        KDBG(PeImport, "pe-resolve", "no import directory — skipping");
        return true; // no imports, nothing to do
    }

    const u64 tbl_off = RvaToFile(file, h, imp.rva);
    // Subtractive bound: `tbl_off + imp.size > file_len` wraps on
    // hostile inputs where tbl_off is near UINT64_MAX. Compare via
    // subtraction so wraparound can't bracket the buffer end.
    if (tbl_off == ~u64(0) || tbl_off > file_len || imp.size > file_len - tbl_off)
    {
        SerialWrite("[pe-resolve] import table rva out of bounds\n");
        return false;
    }
    KDBG_2V(PeImport, "pe-resolve", "import table mapped", "tbl_off", tbl_off, "size", imp.size);

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

        // IAT entry size depends on PE32+ (8 bytes) vs PE32 (4 bytes).
        // Ordinal flag is bit 63 in PE32+, bit 31 in PE32. The low 31
        // bits carry the IBN RVA in both formats; the low 16 bits
        // carry the ordinal value when the flag is set.
        const u64 ent_bytes = h.is_pe32 ? u64(4) : u64(8);
        const u64 ordinal_flag = h.is_pe32 ? (u64(1) << 31) : (u64(1) << 63);
        for (u32 fn_idx = 0; fn_idx < kMaxFnPerDll; ++fn_idx)
        {
            const u64 int_ent_off = int_off + u64(fn_idx) * ent_bytes;
            if (int_ent_off + ent_bytes > file_len)
                break;
            const u64 ent = h.is_pe32 ? u64(LeU32(file + int_ent_off)) : LeU64(file + int_ent_off);
            if (ent == 0)
                break;

            // Ordinal vs by-name: the ordinal flag bit gates which
            // shape the low bits carry.
            const bool is_ordinal_import = (ent & ordinal_flag) != 0;
            const u32 import_ordinal = static_cast<u32>(ent & 0xFFFF);

            const char* fn_name = nullptr;
            char ordinal_name_buf[32];
            if (is_ordinal_import)
            {
                // Synthesize a printable "#N" name for log lines and
                // catch-all path. The buffer is on the stack — the
                // by-name fall-through never persists this pointer.
                ordinal_name_buf[0] = '#';
                u32 v = import_ordinal;
                u32 digits = 0;
                char tmp[10];
                if (v == 0)
                {
                    tmp[digits++] = '0';
                }
                while (v > 0 && digits < sizeof(tmp))
                {
                    tmp[digits++] = static_cast<char>('0' + (v % 10));
                    v /= 10;
                }
                u32 out_idx = 1;
                for (u32 i = digits; i > 0 && out_idx + 1 < sizeof(ordinal_name_buf); --i)
                    ordinal_name_buf[out_idx++] = tmp[i - 1];
                ordinal_name_buf[out_idx] = '\0';
                fn_name = ordinal_name_buf;
            }
            else
            {
                const u32 ibn_rva = static_cast<u32>(ent & 0x7FFFFFFF);
                const u64 ibn_off = RvaToFile(file, h, ibn_rva);
                if (ibn_off == ~u64(0) || ibn_off + 2 >= file_len)
                {
                    SerialWrite("[pe-resolve] ");
                    SerialWrite(dll_name);
                    SerialWrite(": IBN rva out of bounds\n");
                    return false;
                }
                fn_name = BoundedCString(file, file_len, ibn_off + 2);
                if (fn_name == nullptr)
                {
                    SerialWrite("[pe-resolve] ");
                    SerialWrite(dll_name);
                    SerialWrite(": IBN name unterminated\n");
                    return false;
                }
            }

            u64 stub_va = 0;
            bool is_noop_stub = false;
            // Consult the caller's preloaded DLL table first.
            // On hit, the IAT slot is patched with
            // the DLL's export VA directly — no trampoline page,
            // no syscall round-trip — the PE's indirect call
            // lands straight in the DLL's code. Misses fall
            // through to Win32ThunksLookupKind, preserving all
            // existing stub-table behaviour.
            //
            // For ordinal imports we ask the EAT directly; the
            // flat stub table is name-keyed and won't match.
            bool resolved_via_dll =
                is_ordinal_import
                    ? TryResolveViaPreloadedDllsByOrdinal(dll_name, import_ordinal, preloaded_dlls, preloaded_dll_count,
                                                          &stub_va)
                    : TryResolveViaPreloadedDlls(dll_name, fn_name, preloaded_dlls, preloaded_dll_count, &stub_va);
            // API-set fallback: an "api-ms-win-*" / "ext-ms-win-*"
            // import names a contract, not a real DLL, so the exact
            // (dll,fn) match above misses. Resolve the function by
            // name against whichever preloaded base DLL hosts it
            // (kernel32 / kernelbase / ntdll / …). This is how
            // modern APIs (WaitOnAddress, condition variables, …)
            // — and Chrome — bind.
            if (!resolved_via_dll && !is_ordinal_import && IsApiSetContract(dll_name))
            {
                if (TryResolveViaPreloadedDllsAnyName(fn_name, preloaded_dlls, preloaded_dll_count, &stub_va))
                {
                    resolved_via_dll = true;
                    SerialWrite("[pe-resolve] via-apiset ");
                    SerialWrite(dll_name);
                    SerialWrite("!");
                    SerialWrite(fn_name);
                    SerialWrite("\n");
                }
            }
            if (resolved_via_dll)
            {
                SerialWrite("[pe-resolve] via-dll ");
                SerialWrite(dll_name);
                SerialWrite("!");
                SerialWrite(fn_name);
                SerialWrite(" -> ");
                SerialWriteHex(stub_va);
                SerialWrite("\n");
            }
            else if (h.is_pe32)
            {
                // PE32: via-DLL miss → 32-bit unresolved-import
                // stub. The Win32ThunksLookupKind path is skipped
                // because the bytes in the PE32+ thunks page are
                // 64-bit instructions; decoding them in compat
                // mode would trap immediately. The 32-bit stub
                // does SYS_EXIT(0xDEAD0042) so any call to an
                // unresolved import cleanly terminates the
                // process with a readable signature.
                stub_va = win32::kWin32Thunks32UnresolvedVa;
                is_noop_stub = true;
            }
            else if (!win32::Win32ThunksLookupKind(dll_name, fn_name, &stub_va, &is_noop_stub))
            {
                // Unresolved import. Two flavours land here:
                //   - Functions -> miss-logger thunk (R-X). Called,
                //     logs a `[win32-miss]` line + returns 0.
                //   - Data (e.g. `?cout@std@@3V...`) -> data-miss
                //     landing pad in the proc-env page (RW, zeros).
                //     Dereferenced as a pointer, reads 0 cleanly.
                // Picking the right bucket is a name-mangling
                // heuristic (`?...@@3...` == MSVC global data).
                const bool is_data = win32::IsLikelyDataImport(fn_name);
                // Per-name override for the well-known CRT data
                // globals (`__argv`, `__argc`, `_acmdln`, `_wcmdln`)
                // takes precedence over the all-zeros catch-all.
                // The IAT then holds the proc-env slot VA holding
                // the populated value, so the CRT's argv-walk
                // pattern reads a real argv pointer instead of zero.
                const bool data_named = is_data && win32::Win32ThunksLookupDataNamed(fn_name, &stub_va);
                const bool ok = data_named ? true
                                : is_data  ? win32::Win32ThunksLookupDataCatchAll(&stub_va)
                                           : win32::Win32ThunksLookupCatchAll(&stub_va);
                if (!ok)
                {
                    core::CleanroomTraceRecord("pe-loader", "import-unresolved-fatal", h.image_base, first_thunk,
                                               fn_idx);
                    core::LogWithString(core::LogLevel::Error, "pe-resolve", "UNRESOLVED import (no catch-all)", "fn",
                                        fn_name);
                    core::LogWithString(core::LogLevel::Error, "pe-resolve", "  from", "dll", dll_name);
                    return false;
                }
                // Only the catch-all branches resolved to a generic
                // noop. data_named pointed the IAT slot at a real
                // proc-env-backed location; treating it as a noop
                // would re-journal it on every boot via the
                // noop-stub path below, defeating the dedup the
                // data-named lookup provides.
                is_noop_stub = !data_named;
                const char* msg = data_named ? "data import -> proc-env named slot"
                                  : is_data  ? "unknown import -> data-miss zero pad"
                                             : "unknown import -> catch-all NO-OP";
                core::LogWithString(core::LogLevel::Warn, "pe-resolve", msg, "fn", fn_name);
                core::LogWithString(core::LogLevel::Warn, "pe-resolve", "  from", "dll", dll_name);
                // Record the gap. Build "<dll>!<fn>" into a 40-byte
                // source_pin so the reviewer can grep the journal
                // for "ntdll!Nt..." or "kernel32!Csr...". `data_named`
                // is excluded — those resolved to a real proc-env slot
                // and aren't a gap. Skipped when the journal isn't
                // initialised (very early boot, before kernel_main
                // has called FixJournalInit; static allocator
                // ordering should make that unreachable in practice).
                if (!data_named)
                {
                    char pin[40];
                    BuildFixJournalPin(dll_name, fn_name, pin);
                    (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::UnmappedThunk, pin,
                                                           is_data ? "implement data import" : "implement Win32 thunk",
                                                           h.image_base, 0);
                }
                // Only FUNCTION catch-alls need an IAT-slot-name
                // mapping in the miss-logger table — data imports
                // aren't called, just dereferenced, and will never
                // hit SYS_WIN32_MISS_LOG.
                if (!is_data)
                {
                    const u64 iat_slot_va_for_miss = h.image_base + u64(first_thunk) + u64(fn_idx) * ent_bytes;
                    StagedMissAppend(iat_slot_va_for_miss, fn_name);
                }
                core::CleanroomTraceRecord("pe-loader", is_data ? "import-data-catchall" : "import-fn-catchall",
                                           h.image_base, first_thunk, fn_idx);
            }

            // Patch the IAT slot. Slot size is bitness-dependent
            // (8 bytes for PE32+, 4 for PE32) — the same as the INT
            // entry size we just read. For PE32 the resolved VA
            // must fit in 32 bits; we asserted this implicitly by
            // mapping the 32-bit DLL set into the low 4 GiB.
            const u64 iat_slot_va = h.image_base + u64(first_thunk) + u64(fn_idx) * ent_bytes;
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
            // Store little-endian byte-by-byte; avoids any
            // alignment assumption on the direct-map pointer.
            for (u64 b = 0; b < ent_bytes; ++b)
                iat_direct[page_off + b] = static_cast<u8>((stub_va >> (b * 8)) & 0xFF);
            ++resolved;

            // Structured klog: Info for real stubs, Warn for no-op
            // "safe-ignore" shims. The Warn colour (yellow) makes it
            // obvious at boot-log skim which imports will silently
            // misbehave if the PE actually relies on them.
            const core::LogLevel lvl = is_noop_stub ? core::LogLevel::Warn : core::LogLevel::Info;
            const char* msg = is_noop_stub ? "import resolved to NO-OP stub" : "import resolved";
            core::LogWithString(lvl, "pe-resolve", msg, "fn", fn_name);

            // Journal the resolved-to-NO-OP path too: the catch-all
            // earlier in this function only caught imports with no
            // table entry at all. A function that DOES have a thunk
            // entry but resolves to `kOffReturnZero` / `kOffReturnOne`
            // / `kOffMissLogger` / `kOffCritSecNop` is still a gap —
            // the call returns a constant rather than doing the real
            // work. Dedup by (UnmappedThunk, "<dll>!<fn>") collapses
            // repeats, so a PE that calls the same noop 1000 times
            // shows up once with repeat_count=1000.
            if (is_noop_stub)
            {
                char pin[40];
                BuildFixJournalPin(dll_name, fn_name, pin);
                (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::UnmappedThunk, pin,
                                                       "implement Win32 thunk (currently noop-stub)", h.image_base, 1);
            }
        }
    }

    core::LogWithValue(core::LogLevel::Info, "pe-resolve", "total imports resolved", resolved);
    core::CleanroomTraceRecord("pe-loader", "imports-resolved", h.image_base, resolved, 0);
    return true;
}

} // namespace

bool PeResolveImportsForLoadedImage(const u8* file, u64 file_len, duetos::mm::AddressSpace* as,
                                    const DllImage* preloaded_dlls, u64 preloaded_dll_count)
{
    if (file == nullptr || as == nullptr || file_len == 0)
        return false;
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    // ImportsPresent is the only status that still warrants
    // walking; Ok means no imports (we're done), anything
    // else is a header problem the caller already knows about.
    if (s != PeStatus::Ok && s != PeStatus::ImportsPresent && s != PeStatus::TlsPresent)
        return false;
    if (s == PeStatus::Ok)
        return true; // no imports to resolve
    return ResolveImports(file, file_len, h, as, preloaded_dlls, preloaded_dll_count);
}

PeLoadResult PeLoad(const u8* file, u64 file_len, duetos::mm::AddressSpace* as, const char* program_name,
                    u64 aslr_delta, const DllImage* preloaded_dlls, u64 preloaded_dll_count)
{
    KLOG_TRACE_SCOPE("pe-loader", "PeLoad");
    KDBG_S(PeLoad, "pe-loader", "PeLoad enter", "name", program_name != nullptr ? program_name : "(anon)");
    KDBG_3V(PeLoad, "pe-loader", "PeLoad sizes", "file_len", file_len, "aslr_delta", aslr_delta, "preloaded_dlls",
            preloaded_dll_count);
    PeLoadResult r{};
    r.ok = false;
    if (as == nullptr || file == nullptr || file_len == 0)
        return r;
    // Reject preloaded_dlls inconsistencies: a non-zero count with a
    // null table would deref garbage when the import resolver
    // chases forwarders. Either both populated or both empty.
    if (preloaded_dll_count != 0 && preloaded_dlls == nullptr)
        return r;

    // Security guard. Catches the classic process-injection combo
    // (CreateRemoteThread + WriteProcessMemory), the suspicious-API
    // multi-match, and packed/no-import PEs. Advisory mode (default)
    // always allows; Enforce mode prompts the user.
    duetos::security::ImageDescriptor gd{duetos::security::ImageKind::WindowsPE, "(pe)", file, file_len};
    if (!duetos::security::Gate(gd))
    {
        arch::SerialWrite("[pe-loader] security guard blocked PE load\n");
        return r;
    }

    // Clear staged miss buffer before walking imports — previous
    // PeLoad's drain may have left it populated if a caller
    // skipped PeLoadDrainIatMisses (e.g. PeLoad failed mid-way).
    StagedMissReset();

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
    // PE32 (i386) is now executable end-to-end for self-contained
    // images whose import surface is never actually called — the
    // pe32_smoke fixture exits via int 0x80 directly. PE32 images
    // that DO call their imports will faceplant at the first call
    // until the i386 DLL set lands (Layer 4 follow-up); the
    // Pe32ExecutionNotReady status is retained so a future
    // policy gate can flip it back on if we want to reject such
    // PEs preemptively.
    PeStatus effective_ps = ps;
    if (effective_ps != PeStatus::Ok && effective_ps != PeStatus::ImportsPresent &&
        effective_ps != PeStatus::TlsPresent)
    {
        // Journal the rejection so the reviewer sees which PE
        // characteristics our v0 loader can't handle yet, even
        // when the rejection is silent on the boot log. Pin
        // format `loader/pe:<status>` groups by reject reason.
        char pin[40];
        const char* tag = "loader/pe:";
        u64 p = 0;
        while (p < 39 && tag[p] != '\0')
        {
            pin[p] = tag[p];
            ++p;
        }
        const char* sn = PeStatusName(effective_ps);
        u64 i = 0;
        while (p < 39 && sn[i] != '\0')
        {
            pin[p++] = sn[i++];
        }
        pin[p] = '\0';
        (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::LoaderReject, pin,
                                               "implement PE feature or improve loader policy",
                                               static_cast<u64>(effective_ps), file_len);
        // Surface the reject reason on serial so the boot transcript
        // carries the specific status name (e.g. Pe32ExecutionNotReady)
        // rather than the generic "PeLoad failed" line emitted by the
        // caller. WARN level so it shows under any sensible loglevel.
        KLOG_WARN_S("loader/pe", "PE rejected", "status", PeStatusName(effective_ps));
        return r;
    }

    using namespace duetos::mm;
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    // Step-trace breadcrumbs. PeLoad has several paths that can
    // silently return false (frame-alloc OOMs, bad section RVA,
    // ResolveImports internals). Logging each gate gives us a
    // "last breadcrumb wins" view of where a real-world PE like
    // windows-kill.exe drops out, without having to instrument
    // every helper.
    // ASLR: shift the preferred ImageBase by the caller-supplied
    // delta. All subsequent section mapping + relocation pointer
    // fixups happen at the shifted VA. Must be 64 KiB aligned.
    // Zero delta is the v0 path (no ASLR).
    const u64 preferred_base = h.image_base;
    h.image_base += aslr_delta;

    // ParseHeaders validated image_base+image_size against the user
    // canonical low half, but the ASLR shift here can push the final
    // base back across the boundary if the caller passes a wide delta.
    // Re-validate so we never reach AddressSpaceMapUserPage with a
    // kernel-half VA — that would PanicAs and DoS the kernel.
    {
        constexpr u64 kPeUserMax = 0x00007FFFFFFFFFFFULL;
        if (h.image_base > kPeUserMax || (h.image_size > 0 && (u64(h.image_size) - 1) > (kPeUserMax - h.image_base)))
        {
            SerialWrite("[pe-load] FAIL ImageBase out of user range after ASLR\n");
            return r;
        }
    }

    SerialWrite("[pe-load] begin status=");
    SerialWrite(PeStatusName(ps));
    SerialWrite(" preferred_base=");
    SerialWriteHex(preferred_base);
    SerialWrite(" aslr_delta=");
    SerialWriteHex(aslr_delta);
    SerialWrite(" image_base=");
    SerialWriteHex(h.image_base);
    SerialWrite(" sections=");
    SerialWriteHex(h.section_count);
    SerialWrite("\n");

    // Allocation-ladder unwind. Every successful frame map is
    // tracked in `guard`; if PeLoad early-returns from any of the
    // failure legs below, the destructor walks the tracked VAs and
    // unmaps + frees each one. Disarmed at the bottom on success.
    LoaderUnwindGuard guard;
    guard.as = as;

    // 1. Map PE headers (RO, NX) at ImageBase. Loader
    //    convention — makes __ImageBase usable from ring 3.
    const u64 sizeof_headers = LeU32(file + h.opt_base + kOptHeaderSizeOfHeaders);
    if (!MapHeaders(file, sizeof_headers, h.image_base, as, guard))
    {
        SerialWrite("[pe-load] FAIL MapHeaders\n");
        KBP_PROBE(::duetos::debug::ProbeId::kPeLoaderOom);
        return r;
    }
    SerialWrite("[pe-load] step1 headers mapped\n");

    // 2. Map every section.
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        if (!MapSection(file, sec, h.image_base, as, guard))
        {
            SerialWrite("[pe-load] FAIL MapSection idx=");
            SerialWriteHex(i);
            SerialWrite("\n");
            KBP_PROBE(::duetos::debug::ProbeId::kPeLoaderOom);
            return r;
        }
    }
    SerialWrite("[pe-load] step2 sections mapped\n");

    // 3. Apply base relocations. The delta is the ASLR shift
    //    from the preferred base. When delta == 0 the walk still
    //    runs (to reject a malformed .reloc section before ring-3
    //    entry) but the patch body is a no-op.
    const u64 reloc_delta = aslr_delta;
    if (!ApplyRelocations(file, file_len, h, as, reloc_delta))
    {
        SerialWrite("[pe-load] FAIL ApplyRelocations\n");
        return r;
    }
    SerialWrite("[pe-load] step3 relocs applied\n");

    // 3a. /GS cookie randomisation (T9-02 follow-on). Best-effort:
    //     SeedSecurityCookie always returns true (silently skips on
    //     no-load-config / pre-/GS layout / unmapped cookie VA).
    (void)SeedSecurityCookie(file, file_len, h, as);

    // 3b. TLS (T6-01) is now fully supported: static-TLS template
    //     copy, TEB.ThreadLocalStoragePointer wiring, and a
    //     generated R-X trampoline that invokes any registered TLS
    //     callbacks before entry. The actual setup runs at step
    //     4b' (after the TEB page exists and imports are resolved,
    //     since a callback may call into an imported DLL). No
    //     pre-gate / reject here any more.

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
            KBP_PROBE_V(::duetos::debug::ProbeId::kPeLoaderOom, p);
            return r;
        }
        const u64 page_va = kV0StackVa + p * kPageSize;
        AddressSpaceMapUserPage(as, page_va, stack_frame, kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
        guard.Track(page_va);
    }
    SerialWrite("[pe-load] step4 stack mapped pages=");
    SerialWriteHex(kV0StackPages);
    SerialWrite("\n");

    // 4b. TEB page. PE32+ (64-bit) reads via gs:[0x30] (self),
    //     PE32 (32-bit) via fs:[0x18] (self) and fs:[0x30] (PEB).
    //     Both variants land in the same allocated frame at
    //     kV0TebVa with the appropriate offsets populated. The
    //     32-bit task's FSBASE gets pointed at this VA by
    //     EnterUserMode32 (via wrmsr) so the fs-relative reads
    //     land here rather than at linear 0x18 / 0x30.
    u64 teb_va = 0;
    if (ps == PeStatus::ImportsPresent)
    {
        const PhysAddr teb_frame = AllocateFrame();
        if (teb_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL teb frame alloc\n");
            KBP_PROBE(::duetos::debug::ProbeId::kPeLoaderOom);
            return r;
        }
        auto* teb_direct = static_cast<u8*>(PhysToVirt(teb_frame));
        for (u64 i = 0; i < kPageSize; ++i)
            teb_direct[i] = 0;
        if (!h.is_pe32)
        {
            // 64-bit TEB: NT_TIB.Self at offset 0x30 (u64). MSVC
            // x64 CRT reads gs:[0x30] for the self-pointer.
            for (u64 b = 0; b < 8; ++b)
                teb_direct[kTebOffSelf + b] = static_cast<u8>((kV0TebVa >> (b * 8)) & 0xFF);

            // PEB / PEB_LDR_DATA minimal v0 scaffolding. The MSVC
            // x64 CRT bootstrap (and any of the Image / loader-walk
            // helpers stamped by the toolchain) reads:
            //   gs:[0x60]            -> PEB
            //   PEB[0x20]            -> PEB.Ldr
            //   PEB.Ldr[0x08]        -> SsHandle (compared, jl exit)
            //   PEB.Ldr[0x10..0x37]  -> three LIST_ENTRY heads
            // Without these pre-populated, the bootstrap reads NULL
            // and faults at cr2=0x20 (Unity launcher orig.) or 0x08
            // (post-PEB-set).
            //
            // Layout inside the 4 KiB TEB page so we don't burn a
            // second frame for v0:
            //   0x000..0x05F  NT_TIB + the few fields above
            //   0x060        PEB pointer  -> TEB+0x100
            //   0x100..0x17F PEB (128 B). Only Ldr (PEB+0x20) is set;
            //                ImageBaseAddress / ProcessParameters /
            //                etc. stay NULL until a future slice.
            //   0x200..0x257 PEB_LDR_DATA (0x58 bytes). Length +
            //                Initialized populated; all three module
            //                lists are circular-empty (Flink=Blink=
            //                &ListHead), the documented "loader has
            //                no modules" state. CRT walkers wrap
            //                straight back without dereferencing
            //                anything outside this struct.
            constexpr u64 kTeb64OffPeb = 0x60;
            constexpr u64 kPebOffsetInTeb = 0x100;
            constexpr u64 kLdrOffsetInTeb = 0x200;
            constexpr u64 kPebVa = kV0TebVa + kPebOffsetInTeb;
            constexpr u64 kLdrVa = kV0TebVa + kLdrOffsetInTeb;

            auto write_u64 = [&](u64 page_off, u64 value)
            {
                for (u64 b = 0; b < 8; ++b)
                    teb_direct[page_off + b] = static_cast<u8>((value >> (b * 8)) & 0xFF);
            };
            auto write_u32 = [&](u64 page_off, u32 value)
            {
                for (u64 b = 0; b < 4; ++b)
                    teb_direct[page_off + b] = static_cast<u8>((value >> (b * 8)) & 0xFF);
            };

            // TEB.ProcessEnvironmentBlock -> PEB
            write_u64(kTeb64OffPeb, kPebVa);

            // PEB.Ldr (offset 0x20 in PEB) -> PEB_LDR_DATA
            write_u64(kPebOffsetInTeb + 0x20, kLdrVa);

            // PEB_LDR_DATA.Length = 0x58, .Initialized = TRUE.
            // SsHandle (offset 0x08) stays 0 — the comparison
            // `cmp ebx, 0x8(rcx)` in the Unity launcher then sees
            // 0 vs 0 (equal) and falls through to the list-walk.
            write_u32(kLdrOffsetInTeb + 0x00, 0x58);
            write_u32(kLdrOffsetInTeb + 0x04, 1);

            // Three module lists, each circular-empty: Flink and
            // Blink point at the list head itself. CRT iteration
            // (`while (entry->Flink != head) entry = entry->Flink`)
            // wraps on the first read.
            constexpr u64 kLdrOffInLoad = 0x10;
            constexpr u64 kLdrOffInMem = 0x20;
            constexpr u64 kLdrOffInInit = 0x30;
            const u64 in_load_va = kLdrVa + kLdrOffInLoad;
            const u64 in_mem_va = kLdrVa + kLdrOffInMem;
            const u64 in_init_va = kLdrVa + kLdrOffInInit;
            write_u64(kLdrOffsetInTeb + kLdrOffInLoad + 0, in_load_va);
            write_u64(kLdrOffsetInTeb + kLdrOffInLoad + 8, in_load_va);
            write_u64(kLdrOffsetInTeb + kLdrOffInMem + 0, in_mem_va);
            write_u64(kLdrOffsetInTeb + kLdrOffInMem + 8, in_mem_va);
            write_u64(kLdrOffsetInTeb + kLdrOffInInit + 0, in_init_va);
            write_u64(kLdrOffsetInTeb + kLdrOffInInit + 8, in_init_va);
        }
        else
        {
            // 32-bit TEB layout differs from x64. Key fields the
            // MSVC i386 CRT touches:
            //   fs:[0x00]  ExceptionList (head of SEH chain). Set
            //              to 0xFFFFFFFF (no handler) per the v0
            //              "no SEH" stance.
            //   fs:[0x04]  StackBase (high address). Top of the
            //              user stack we just mapped.
            //   fs:[0x08]  StackLimit (low address). Bottom of the
            //              user stack.
            //   fs:[0x18]  Self (TEB self-pointer, u32).
            //   fs:[0x20]  ClientId.UniqueProcess (pid).
            //   fs:[0x24]  ClientId.UniqueThread (tid).
            //   fs:[0x30]  PEB pointer. v0 stores the TEB VA itself
            //              so dereferences read zero (process-wide
            //              PEB structure is a separate slice).
            constexpr u64 kTeb32OffSelf = 0x18;
            constexpr u64 kTeb32OffPeb = 0x30;
            constexpr u64 kTeb32OffStackBase = 0x04;
            constexpr u64 kTeb32OffStackLimit = 0x08;
            constexpr u32 kSehSentinel = 0xFFFFFFFFu;
            // ExceptionList = 0xFFFFFFFF
            for (u64 b = 0; b < 4; ++b)
                teb_direct[0x00 + b] = static_cast<u8>((kSehSentinel >> (b * 8)) & 0xFF);
            // StackBase / StackLimit (low 32 bits of the user VAs).
            const u32 stack_top32 = static_cast<u32>(kV0StackTop);
            const u32 stack_va32 = static_cast<u32>(kV0StackVa);
            for (u64 b = 0; b < 4; ++b)
            {
                teb_direct[kTeb32OffStackBase + b] = static_cast<u8>((stack_top32 >> (b * 8)) & 0xFF);
                teb_direct[kTeb32OffStackLimit + b] = static_cast<u8>((stack_va32 >> (b * 8)) & 0xFF);
            }
            // Self pointer (u32) — TEB VA, low 32 bits.
            const u32 teb_va32 = static_cast<u32>(kV0TebVa);
            for (u64 b = 0; b < 4; ++b)
                teb_direct[kTeb32OffSelf + b] = static_cast<u8>((teb_va32 >> (b * 8)) & 0xFF);
            // PEB pointer (u32) — for v0 we point at the TEB itself
            // so `fs:[0x30]` is non-NULL and dereferences land in
            // the (mostly zero) TEB page rather than #PFing.
            for (u64 b = 0; b < 4; ++b)
                teb_direct[kTeb32OffPeb + b] = static_cast<u8>((teb_va32 >> (b * 8)) & 0xFF);
        }
        AddressSpaceMapUserPage(as, kV0TebVa, teb_frame, kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
        guard.Track(kV0TebVa);
        teb_va = kV0TebVa;
        SerialWrite("[pe-load] step4b teb mapped va=");
        SerialWriteHex(teb_va);
        if (h.is_pe32)
            SerialWrite(" (pe32 fs-base)");
        SerialWrite("\n");
    }

    // 4c. Proc-env page (64-bit Win32 PEs only). MSVC CRT startup
    //     reads argc/argv via `__p___argc()` / `__p___argv()`
    //     accessor functions; their stubs return addresses inside
    //     this page. One page, R-W + NX. Populated with argc=1,
    //     argv=[program_name, NULL], program_name="a.exe". PE32
    //     accessors live in a 32-bit kernel32 — gated alongside
    //     Layer 4.
    if (!h.is_pe32 && ps == PeStatus::ImportsPresent)
    {
        const PhysAddr env_frame = AllocateFrame();
        if (env_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL proc-env frame alloc\n");
            KBP_PROBE(::duetos::debug::ProbeId::kPeLoaderOom);
            return r;
        }
        auto* env_direct = static_cast<u8*>(PhysToVirt(env_frame));
        for (u64 i = 0; i < kPageSize; ++i)
            env_direct[i] = 0;
        win32::Win32ProcEnvPopulate(env_direct, program_name, h.image_base);
        AddressSpaceMapUserPage(as, win32::kProcEnvVa, env_frame,
                                kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
        guard.Track(win32::kProcEnvVa);
        SerialWrite("[pe-load] step4c proc-env mapped va=");
        SerialWriteHex(win32::kProcEnvVa);
        SerialWrite("\n");
    }

    // 5. If imports are present, stand up the per-process
    //    Win32 stubs region (PE32+ only — the bytes are 64-bit) +
    //    resolve every IAT entry. PE32 (i386) images skip the
    //    thunks page (64-bit code) but DO run ResolveImports,
    //    which now branches its slot-size + ordinal-bit reads on
    //    h.is_pe32. Pe32 IAT entries that resolve cleanly point
    //    at the kernel32_32.dll preload set's exports.
    //
    // The stub byte table has outgrown a single 4 KiB page (render
    // work: filled Rectangle/Ellipse + UTF-16 paint + message loop
    // etc.), so we now allocate two contiguous frames and map both
    // R-X. `Win32ThunksPopulate` writes the full `sizeof(kThunksBytes)`
    // into the direct-map window; any trailing bytes in the second
    // page beyond the stub table stay zeroed from the pre-clear.
    if (!h.is_pe32 && ps == PeStatus::ImportsPresent)
    {
        const PhysAddr stubs_frame = AllocateContiguousFrames(2);
        if (stubs_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL stubs frames alloc (need 2)\n");
            KBP_PROBE(::duetos::debug::ProbeId::kPeLoaderOom);
            return r;
        }
        auto* stubs_direct = static_cast<u8*>(PhysToVirt(stubs_frame));
        for (u64 i = 0; i < 2 * kPageSize; ++i)
            stubs_direct[i] = 0;
        win32::Win32ThunksPopulate(stubs_direct);
        // R-X on both pages: no kPageWritable (W^X), no kPageNoExecute.
        // Tracked individually — AddressSpaceUnmapUserPage frees one
        // frame at a time, matching the bitmap-per-frame shape of the
        // contiguous run (see kernel/mm/dma.h:99).
        AddressSpaceMapUserPage(as, win32::kWin32ThunksVa, stubs_frame, kPagePresent | kPageUser);
        guard.Track(win32::kWin32ThunksVa);
        AddressSpaceMapUserPage(as, win32::kWin32ThunksVa + kPageSize, stubs_frame + kPageSize,
                                kPagePresent | kPageUser);
        guard.Track(win32::kWin32ThunksVa + kPageSize);

        if (!ResolveImports(file, file_len, h, as, preloaded_dlls, preloaded_dll_count))
        {
            SerialWrite("[pe-load] FAIL ResolveImports\n");
            return r;
        }
        SerialWrite("[pe-load] step5 imports resolved\n");
    }
    else if (h.is_pe32 && ps == PeStatus::ImportsPresent)
    {
        // PE32 IAT walk + 32-bit Win32 thunks page. Unresolved
        // imports get pointed at the i386 "SYS_EXIT(0xDEAD0042)"
        // stub at kWin32Thunks32Va, so calling an unresolved
        // import cleanly terminates the process instead of #PFing
        // at the 64-bit catch-all VA (which isn't mapped for PE32).
        const PhysAddr thunks32_frame = AllocateFrame();
        if (thunks32_frame == kNullFrame)
        {
            SerialWrite("[pe-load] FAIL pe32 thunks page alloc\n");
            KBP_PROBE(::duetos::debug::ProbeId::kPeLoaderOom);
            return r;
        }
        auto* thunks32_direct = static_cast<u8*>(PhysToVirt(thunks32_frame));
        for (u64 i = 0; i < kPageSize; ++i)
            thunks32_direct[i] = 0;
        win32::Win32Thunks32Populate(thunks32_direct);
        // R-X — same W^X discipline as the 64-bit thunks page.
        AddressSpaceMapUserPage(as, win32::kWin32Thunks32Va, thunks32_frame, kPagePresent | kPageUser);
        guard.Track(win32::kWin32Thunks32Va);

        if (!ResolveImports(file, file_len, h, as, preloaded_dlls, preloaded_dll_count))
        {
            SerialWrite("[pe-load] FAIL ResolveImports (pe32)\n");
            return r;
        }
        SerialWrite("[pe-load] step5 pe32 imports resolved\n");
    }

    // 4b'. Static TLS + TLS callbacks (T6-01). 64-bit Win32 PEs
    //      only — the 32-bit TLS array lives at a different TEB
    //      offset and the i386 user path isn't executable yet.
    //      Runs after the TEB exists and imports are resolved
    //      (a callback may call an imported DLL).
    u64 tls_entry_override = 0;
    if (!h.is_pe32 && teb_va != 0)
    {
        const TlsSetupResult tls = SetupStaticTls(file, file_len, h, as, teb_va, guard);
        if (!tls.ok)
        {
            // present-but-failed is a hard error: the PE would run
            // with uninitialised thread-locals. guard unwinds the
            // partial mappings.
            SerialWrite("[pe-load] FAIL static-TLS setup\n");
            return r;
        }
        tls_entry_override = tls.entry_override_va;
        if (tls.present && tls.ok)
        {
            r.tls_present = true;
            r.tls_tmpl_src_va = tls.tmpl_src_va;
            r.tls_tmpl_raw = tls.tmpl_raw;
            r.tls_tmpl_zerofill = tls.tmpl_zerofill;
            r.tls_index_va = tls.index_va;
            r.tls_cb_count = tls.cb_count;
            for (u32 i = 0; i < tls.cb_count && i < 16; ++i)
                r.tls_callbacks[i] = tls.callbacks[i];
        }
    }

    SerialWrite("[pe-load] OK\n");

    r.ok = true;
    r.imports_resolved = (ps == PeStatus::ImportsPresent);
    r.is_pe32 = h.is_pe32;
    r.entry_va = tls_entry_override != 0 ? tls_entry_override : (h.image_base + h.entry_rva);
    r.stack_va = kV0StackVa;
    r.stack_top = kV0StackTop;
    r.image_base = h.image_base;
    r.image_size = h.image_size;
    r.teb_va = teb_va;
    // Image now owned by the AddressSpace; the unwind guard's
    // destructor must NOT roll back what's now legitimately mapped.
    guard.Disarm();
    KBP_PROBE_V(::duetos::debug::ProbeId::kPeLoadOk, h.image_base);
    return r;
}

void PeLoadDrainIatMisses(Process* proc)
{
    if (proc == nullptr)
        return;
    const u64 n = g_staged_miss_count < Process::kWin32IatMissCap ? g_staged_miss_count : Process::kWin32IatMissCap;
    for (u64 i = 0; i < n; ++i)
    {
        proc->win32_iat_misses[i].slot_va = g_staged_misses[i].slot_va;
        proc->win32_iat_misses[i].name = g_staged_misses[i].name;
    }
    proc->win32_iat_miss_count = n;
    if (g_staged_miss_dropped != 0)
        KLOG_WARN_V("loader/pe", "IAT miss staging buffer overflowed; entries dropped",
                    static_cast<u64>(g_staged_miss_dropped));
    g_staged_miss_count = 0;
    g_staged_miss_dropped = 0;
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

    // Stage 2: also dump the Export Address Table if present.
    // Executables routinely ship with no exports, in which case
    // PeParseExports returns NoExportDirectory and we stay
    // silent. DLLs (and some oddball EXEs that re-export) get
    // the full dump.
    PeExports exp{};
    const PeExportStatus pes = PeParseExports(file, file_len, exp);
    if (pes == PeExportStatus::Ok)
    {
        PeExportsReport(exp);
    }
    else if (pes != PeExportStatus::NoExportDirectory)
    {
        SerialWrite("  exports: <bad> status=");
        SerialWrite(PeExportStatusName(pes));
        SerialWrite("\n");
    }
}

bool PeResolveViaDlls(const char* dll_name, const char* fn_name, const DllImage* dlls, u64 count, u64* out_va)
{
    return TryResolveViaPreloadedDlls(dll_name, fn_name, dlls, count, out_va);
}

namespace
{
// Hex emit (no "0x" prefix, lowercase, no leading zeros except
// for v == 0). Local to PeQuickSummaryTo so it doesn't affect
// the broader serial path.
void EmitHexTo(PeReportFn writer, u64 v)
{
    if (v == 0)
    {
        writer("0");
        return;
    }
    char buf[17] = {};
    int i = 0;
    while (v != 0)
    {
        const u8 nyb = static_cast<u8>(v & 0xF);
        buf[i++] = static_cast<char>(nyb < 10 ? '0' + nyb : 'a' + (nyb - 10));
        v >>= 4;
    }
    char out[18] = {};
    int o = 0;
    while (i > 0)
        out[o++] = buf[--i];
    writer(out);
}

void EmitDecTo(PeReportFn writer, u64 v)
{
    if (v == 0)
    {
        writer("0");
        return;
    }
    char buf[24] = {};
    int i = 0;
    while (v != 0)
    {
        buf[i++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    char out[25] = {};
    int o = 0;
    while (i > 0)
        out[o++] = buf[--i];
    writer(out);
}
} // namespace

void PeQuickSummaryTo(PeReportFn writer, const u8* file, u64 file_len)
{
    if (writer == nullptr)
        return;
    if (file == nullptr || file_len == 0)
    {
        writer("# PE inspect: empty / nullptr file\n");
        return;
    }
    PeHeaders h{};
    const PeStatus s = ParseHeaders(file, file_len, h);
    writer("# PE inspect summary\n");
    writer("file_bytes 0x");
    EmitHexTo(writer, file_len);
    writer("\n");
    writer("parse_status ");
    writer(PeStatusName(s));
    writer("\n");
    if (s == PeStatus::TooSmall || s == PeStatus::BadDosMagic || s == PeStatus::BadLfanewBounds ||
        s == PeStatus::BadNtSignature || s == PeStatus::BadMachine || s == PeStatus::NotPe32Plus)
    {
        // Headers couldn't be trusted past the magic — bail
        // before reading h.
        return;
    }
    writer("image_base 0x");
    EmitHexTo(writer, h.image_base);
    writer("\n");
    writer("entry_rva 0x");
    EmitHexTo(writer, h.entry_rva);
    writer("\n");
    writer("image_size 0x");
    EmitHexTo(writer, h.image_size);
    writer("\n");
    writer("section_count ");
    EmitDecTo(writer, h.section_count);
    writer("\n");
    // Export directory: present iff the PE acts as a DLL or
    // re-exporting EXE. PeParseExports is cheap on absent
    // exports (returns NoExportDirectory immediately).
    PeExports exp{};
    const PeExportStatus pes = PeParseExports(file, file_len, exp);
    if (pes == PeExportStatus::Ok)
    {
        writer("exports_status ok\n");
        writer("exports_named ");
        EmitDecTo(writer, exp.num_names);
        writer("\n");
        writer("exports_funcs ");
        EmitDecTo(writer, exp.num_funcs);
        writer("\n");
    }
    else if (pes == PeExportStatus::NoExportDirectory)
    {
        writer("exports_status none\n");
    }
    else
    {
        writer("exports_status ");
        writer(PeExportStatusName(pes));
        writer("\n");
    }
}

} // namespace duetos::core
