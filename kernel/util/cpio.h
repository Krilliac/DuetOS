#pragma once

#include "util/types.h"

/*
 * DuetOS — CPIO "newc" archive walker (clean room).
 *
 * Spec:
 *   - SVR4 portable / "newc" format (magic `070701`) — 110-byte
 *     ASCII-hex header + filename (NUL-terminated, 4-byte aligned)
 *     + file data (4-byte aligned). Trailer entry named exactly
 *     `TRAILER!!!` with size 0 ends the archive.
 *   - SVR4 portable with CRC (magic `070702`) — same byte layout
 *     as newc but the header records a 32-bit checksum across
 *     the file data; we accept this magic but do not currently
 *     verify the CRC (the spec says it's optional).
 *
 * The original "old binary" (070707) and "old ASCII" (070707
 * 76-byte header) variants are deliberately rejected — Linux
 * initramfs has shipped newc-only since the early 2.6 era and
 * making downstream code distinguish three formats buys nothing.
 *
 * Eventual consumer: `kernel/loader/initramfs.{h,cpp}` (when
 * landed). Today the parser stands alone with a boot KAT — the
 * initramfs unpacker is its own bounded slice and would route
 * through `CpioForEach` without re-deriving the format.
 *
 * No allocation, no global state — every routine operates on
 * a caller-provided byte buffer.
 */

namespace duetos::util
{

/// Length of one newc / newc-CRC header (ASCII-hex).
inline constexpr u32 kCpioHeaderBytes = 110;

/// Trailer entry name. Producers always emit `TRAILER!!!` with
/// `c_filesize == 0`; the walker stops on first sight.
inline constexpr const char* kCpioTrailerName = "TRAILER!!!";

/// Parsed entry record. `name` and `data` are pointers into the
/// caller's archive buffer — valid only while that buffer lives.
struct CpioEntry
{
    const char* name; // NUL-terminated, points into archive buffer
    u32 name_len;     // c_namesize - 1 (excludes terminator)
    const u8* data;   // first byte of file payload
    u32 data_len;     // c_filesize
    u32 mode;         // c_mode (file type + permissions)
    u32 ino;
    u32 uid;
    u32 gid;
    u32 nlink;
    u32 mtime;
    u32 dev_major;
    u32 dev_minor;
    u32 rdev_major;
    u32 rdev_minor;
};

/// Callback signature for `CpioForEach`. Return false to stop
/// the walk early without an error; return true to continue.
using CpioVisitor = bool (*)(const CpioEntry& entry, void* ctx);

/// Walk every entry in a newc / newc-CRC archive. Stops on the
/// trailer entry, on a truncated header, or when `visit` returns
/// false. Returns true iff the walk reached the trailer cleanly;
/// false on truncation, bad magic, or an out-of-range field.
///
/// `archive` points at the first byte of the first header. The
/// pointer must remain valid for the full call.
bool CpioForEach(const u8* archive, u32 archive_len, CpioVisitor visit, void* ctx);

void CpioSelfTest();

} // namespace duetos::util
