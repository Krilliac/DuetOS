#pragma once

#include "util/types.h"

/*
 * DuetOS — POSIX.1-2001 ustar (TAR) archive walker (clean room).
 *
 * Spec: POSIX.1-2001 §ustar, mirrored in libarchive's docs and
 * the original USTAR/IEEE-1003.1 published reference.
 *
 * Each entry has a 512-byte ASCII header followed by the file
 * payload, padded to the next 512-byte boundary. Two consecutive
 * 512-byte zero blocks mark end-of-archive.
 *
 * Eventual consumers:
 *   - Distribution tarball extraction (when DuetOS gains a
 *     "first-boot install seed" model — for now it's not the
 *     critical path).
 *   - Linux ABI thunks for `tar -x` semantics that someone might
 *     port — same shape as the CPIO walker.
 *
 * Out of scope (deliberate):
 *   - GNU TAR extensions (long-link, sparse files).
 *   - PAX extended headers (typeflag 'x' / 'g'). Tolerated as
 *     unknown typeflags — we walk past them; their payload is
 *     ignored.
 *   - Splitting / multi-volume archives.
 *
 * No allocation, no global state.
 */

namespace duetos::util
{

inline constexpr u32 kTarBlockBytes = 512;

/// Per-entry record exposed to the visitor. `name` and `data`
/// point into the caller's archive buffer — valid only while
/// that buffer lives. `name` is NUL-terminated.
struct TarEntry
{
    char name[100 + 155 + 2]; // POSIX prefix + name + '/' + NUL
    const u8* data;
    u64 data_len;
    u32 mode;
    u32 uid;
    u32 gid;
    u64 mtime;
    char typeflag; // '0' / '\0' = regular, '5' = directory, ...
    char linkname[100];
};

/// Visitor signature. Return false to short-circuit the walk
/// without an error.
using TarVisitor = bool (*)(const TarEntry& entry, void* ctx);

/// Walk a tar archive. Stops on the dual-zero-block trailer or
/// when the visitor returns false. Returns true iff the walk
/// reached the trailer cleanly.
bool TarForEach(const u8* archive, u32 archive_len, TarVisitor visit, void* ctx);

void TarSelfTest();

} // namespace duetos::util
