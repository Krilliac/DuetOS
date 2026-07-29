#pragma once

// Delay-load import directory (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
// index 13) — the pure, allocation-free parsing half.
//
// A delay-load import looks exactly like an ordinary import at the
// call site: `call [__imp_Foo]` through a slot in the image's
// delay IAT. The difference is who fills the slot. On Windows the
// linker seeds each slot with the address of a `__tailMerge` stub
// it emitted into the image; the stub calls the image's OWN
// `__delayLoadHelper2` (statically linked in from `delayimp.lib`),
// which does LoadLibrary + GetProcAddress and overwrites the slot.
// The OS loader is not involved.
//
// DuetOS binds these slots eagerly at load instead — see
// `ResolveDelayImports` in pe_loader.cpp and the trade-off recorded
// in wiki/reference/Design-Decisions.md. Doing so needs the same
// descriptor walk the helper would have done, over bytes that come
// straight from an untrusted image.
//
// This header holds ONLY that walk: no allocation, no address
// space, no kernel state, so it is drivable from a hosted unit test
// (tests/host/test_pe_delay_import.cpp) and from the PE fuzzer via
// PeReport. Everything that touches the guest — name reads, symbol
// resolution, IAT writes — stays in pe_loader.cpp.
//
// Reference layout (`ImgDelayDescr`, winnt.h / delayimp.h), 32
// bytes, identical for PE32 and PE32+ because every field is an
// RVA when the `dlattrRva` attribute bit is set:
//
//   +0x00  u32 grAttrs         bit 0 (dlattrRva) => fields below are RVAs
//   +0x04  u32 rvaDLLName      -> NUL-terminated ASCII DLL name
//   +0x08  u32 rvaHmod         -> HMODULE storage slot (helper-owned)
//   +0x0C  u32 rvaIAT          -> delay import address table
//   +0x10  u32 rvaINT          -> delay import name table (IMAGE_THUNK_DATA)
//   +0x14  u32 rvaBoundIAT     -> prebind cache (advisory; ignored)
//   +0x18  u32 rvaUnloadIAT    -> original slot values for unload (ignored)
//   +0x1C  u32 dwTimeStamp     -> bind timestamp (ignored)
//
// Context: any. Pure functions over a caller-owned byte buffer.

#include "util/types.h"

namespace duetos::loader::delayimp
{

/// Size of one `ImgDelayDescr` on disk.
inline constexpr u64 kDelayDescriptorSize = 32;

/// `dlattrRva` — set by every linker since VC7. When clear, the
/// descriptor's fields are absolute virtual addresses (the VC6
/// form), which needs a different fixup path we do not implement.
inline constexpr u32 kDelayAttrRva = 0x1;

/// Descriptor-walk cap. Mirrors ResolveImports' `kMaxDll` so the
/// two walks agree on how much of a malformed table they will read.
inline constexpr u32 kMaxDelayDescriptors = 64;

struct DelayDescriptor
{
    u32 attributes;
    u32 name_rva;
    u32 hmod_rva;
    u32 iat_rva;
    u32 int_rva;
    u32 bound_iat_rva;
    u32 unload_iat_rva;
    u32 timestamp;
};

enum class DelayDescStatus : u8
{
    Ok = 0,        ///< Well-formed, RVA-form, has both tables. Bindable.
    Terminator,    ///< All-zero descriptor: end of table. Stop walking.
    Incomplete,    ///< The 32 bytes do not fit inside the file. Stop walking.
    NotRvaForm,    ///< `dlattrRva` clear (VC6 absolute-VA form). Skip.
    MissingTable,  ///< Name, IAT or INT RVA is zero. Skip.
    IndexOverflow, ///< Index past `kMaxDelayDescriptors`. Stop walking.
};

/// Little-endian u32 read. Local so the header stays dependency-free.
inline u32 DelayLeU32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

/// True iff a directory of `dir_size` bytes starting at file offset
/// `tbl_off` lies wholly inside a `file_len`-byte buffer, and is at
/// least one descriptor long.
///
/// Written subtractively on purpose: `tbl_off + dir_size > file_len`
/// wraps for a hostile RVA that translates near UINT64_MAX and would
/// then bracket the whole buffer. Same shape as the guard in
/// ResolveImports.
inline bool DelayTableInBounds(u64 tbl_off, u64 dir_size, u64 file_len)
{
    if (tbl_off == ~u64(0) || tbl_off > file_len)
        return false;
    if (dir_size < kDelayDescriptorSize)
        return false;
    return dir_size <= file_len - tbl_off;
}

/// Read descriptor `index` out of the table at file offset
/// `tbl_off`. `out` is populated only when the return is `Ok` or
/// `NotRvaForm` / `MissingTable` (so a caller can log what it
/// refused); on every other status `out` is left untouched.
///
/// The caller must have validated `tbl_off` with `DelayTableInBounds`
/// first — this function re-bounds each 32-byte descriptor against
/// `file_len` regardless, because the descriptor array is walked to
/// its terminator rather than to the directory's declared Size (the
/// Windows loader does the same, and some linkers under-report Size).
inline DelayDescStatus ReadDelayDescriptor(const u8* file, u64 file_len, u64 tbl_off, u32 index, DelayDescriptor& out)
{
    if (file == nullptr)
        return DelayDescStatus::Incomplete;
    if (index >= kMaxDelayDescriptors)
        return DelayDescStatus::IndexOverflow;

    // Every bound below is subtractive so nothing can wrap. Doing
    // this as `tbl_off + index * 32 + 32 > file_len` is wrong twice
    // over: a `tbl_off` of UINT64_MAX with index 1 folds back to
    // offset 31 and passes, handing the caller a descriptor
    // assembled from unrelated bytes inside the image.
    if (tbl_off > file_len)
        return DelayDescStatus::Incomplete;
    const u64 span = u64(index) * kDelayDescriptorSize;
    if (span > file_len - tbl_off)
        return DelayDescStatus::Incomplete;
    const u64 off = tbl_off + span;
    if (kDelayDescriptorSize > file_len - off)
        return DelayDescStatus::Incomplete;

    const u8* d = file + off;
    DelayDescriptor desc{};
    desc.attributes = DelayLeU32(d + 0x00);
    desc.name_rva = DelayLeU32(d + 0x04);
    desc.hmod_rva = DelayLeU32(d + 0x08);
    desc.iat_rva = DelayLeU32(d + 0x0C);
    desc.int_rva = DelayLeU32(d + 0x10);
    desc.bound_iat_rva = DelayLeU32(d + 0x14);
    desc.unload_iat_rva = DelayLeU32(d + 0x18);
    desc.timestamp = DelayLeU32(d + 0x1C);

    if (desc.attributes == 0 && desc.name_rva == 0 && desc.hmod_rva == 0 && desc.iat_rva == 0 && desc.int_rva == 0 &&
        desc.bound_iat_rva == 0 && desc.unload_iat_rva == 0 && desc.timestamp == 0)
    {
        return DelayDescStatus::Terminator;
    }

    out = desc;
    if ((desc.attributes & kDelayAttrRva) == 0)
        return DelayDescStatus::NotRvaForm;
    if (desc.name_rva == 0 || desc.iat_rva == 0 || desc.int_rva == 0)
        return DelayDescStatus::MissingTable;
    return DelayDescStatus::Ok;
}

/// Grep-able name for a walk status. Used by the loader's boot-log
/// lines and by the hosted test's failure messages.
inline const char* DelayDescStatusName(DelayDescStatus s)
{
    switch (s)
    {
    case DelayDescStatus::Ok:
        return "Ok";
    case DelayDescStatus::Terminator:
        return "Terminator";
    case DelayDescStatus::Incomplete:
        return "Incomplete";
    case DelayDescStatus::NotRvaForm:
        return "NotRvaForm";
    case DelayDescStatus::MissingTable:
        return "MissingTable";
    case DelayDescStatus::IndexOverflow:
        return "IndexOverflow";
    }
    return "?";
}

} // namespace duetos::loader::delayimp
