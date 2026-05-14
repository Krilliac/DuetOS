#pragma once

#include "util/types.h"

/*
 * DuetOS — ZIP archive reader (read-only, deflate + stored).
 *
 * Walks the central-directory of a ZIP archive held entirely in
 * memory and decompresses individual entries on demand. The
 * inflater is the kernel's existing RFC 1951 implementation
 * (`util/deflate.h`); the ZIP layer adds central-directory
 * parsing and local-file-header chasing.
 *
 * Supported entry compression methods:
 *   - 0 (Stored)   — copy compressed_size bytes verbatim.
 *   - 8 (Deflate)  — run through DeflateInflate.
 * Every other method (Bzip2, LZMA, Zstd, ...) is rejected with
 * `BadMethod`; callers can detect them via ZipEntryInfo.method.
 *
 * Not supported (deliberate):
 *   - ZIP64 (4 GiB+ archives / >65535 entries). Detected and
 *     rejected at EOCD parse — the size fields are u32 / u16 in
 *     the v0 record and a real ZIP64 archive carries an extra
 *     EOCD64 we don't read.
 *   - Encryption (any flag bit). Rejected.
 *   - Spanned / split archives.
 *
 * Memory model: caller owns the archive bytes. All ZipReader
 * accessors borrow into that buffer; copy out before freeing.
 * Decompression writes into a caller-provided output buffer.
 *
 * Threading: every function is pure — no global state, no
 * locks. The shared inflater scratch is on the inflater's own
 * stack frame.
 */

namespace duetos::util
{

enum class ZipStatus : u8
{
    Ok = 0,
    TooSmall,          // archive < EOCD minimum (22 bytes)
    NoEocd,            // can't find end-of-central-directory record
    Zip64NotSupported, // ZIP64 archive (size_or_count fields all 0xFFFF*)
    CentralOutOfRange, // CD offset / size points past EOF
    BadCentralMagic,   // central-directory entry magic != 0x02014b50
    NameTooLong,       // filename longer than internal name buffer
    EncryptedFlag,     // entry has encryption / strong-encryption bit set
    BadLocalMagic,     // local-file-header magic != 0x04034b50
    BadMethod,         // compression method != 0 and != 8
    DataOutOfRange,    // local-data offset+size past EOF
    InflateFailed,     // DeflateInflate refused the entry
    DstTooSmall,       // caller's output buffer < entry.uncompressed_size
    BadIndex,          // entry index out of range
};

const char* ZipStatusName(ZipStatus s);

/// Per-entry metadata, populated by `ZipReadEntry`.
struct ZipEntryInfo
{
    u32 compressed_size;
    u32 uncompressed_size;
    u16 method;       // 0 = stored, 8 = deflate, other = unsupported
    u32 local_offset; // offset of local-file-header in archive
    u32 crc32;        // RFC 1952 CRC; not verified by ZipReader v0
    char name[256];   // NUL-terminated, slash-separated; "/" suffix = directory
    u16 name_len;     // length excluding NUL
};

/// Cursor over a ZIP archive in memory. Populated by `ZipOpen`;
/// every method below is read-only.
struct ZipReader
{
    const u8* file;
    u32 file_len;
    u32 entry_count;
    u32 central_offset;
    u32 central_size;
};

/// Parse the EOCD + central-directory header. Does NOT walk the
/// individual entries — that happens lazily through
/// `ZipReadEntry` / `ZipExtractEntry` indexed by 0..entry_count-1.
ZipStatus ZipOpen(const u8* file, u32 file_len, ZipReader* out);

/// Read entry `index`'s central-directory record into `out`.
/// Index range: 0 .. reader.entry_count - 1.
ZipStatus ZipReadEntry(const ZipReader& reader, u32 index, ZipEntryInfo* out);

/// Decompress entry `index` into `dst` (capacity `dst_cap`).
/// `*out_bytes` receives the number of decompressed bytes
/// written (== entry.uncompressed_size on success).
///
/// Stored entries are memcpy'd; deflated entries route through
/// the kernel inflater. Directories (entry name ending in '/')
/// produce 0 bytes and OK status.
ZipStatus ZipExtractEntry(const ZipReader& reader, u32 index, u8* dst, u32 dst_cap, u32* out_bytes);

/// Boot-time self-test: builds a tiny in-memory ZIP (one
/// stored entry + one deflate entry), parses it back, and
/// verifies the round-trip. Emits `[zip-st] PASS` / `[zip-st]
/// FAIL <step>` on serial. Does not panic on failure.
void ZipReaderSelfTest();

} // namespace duetos::util
