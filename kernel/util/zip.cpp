#include "util/zip.h"

#include "arch/x86_64/serial.h"
#include "util/deflate.h"

namespace duetos::util
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

// ZIP file format constants — APPNOTE.TXT v6.3.x.
constexpr u32 kEocdMagic = 0x06054b50;    // "PK\005\006"
constexpr u32 kCentralMagic = 0x02014b50; // "PK\001\002"
constexpr u32 kLocalMagic = 0x04034b50;   // "PK\003\004"
constexpr u32 kEocdMinSize = 22;
constexpr u32 kCentralEntryMinSize = 46;
constexpr u32 kLocalHeaderMinSize = 30;
constexpr u32 kEocdSearchWindow = 65557; // EOCD + max comment (65535) + record (22)

constexpr u16 kMethodStored = 0;
constexpr u16 kMethodDeflate = 8;

constexpr u16 kFlagEncrypted = 0x0001;
constexpr u16 kFlagStrongEncryption = 0x0040;

// EOCD field offsets relative to the record start (after the 4-byte magic).
constexpr u32 kEocdOffDiskNumber = 4;
constexpr u32 kEocdOffStartDisk = 6;
constexpr u32 kEocdOffEntriesThisDisk = 8;
constexpr u32 kEocdOffEntriesTotal = 10;
constexpr u32 kEocdOffCentralSize = 12;
constexpr u32 kEocdOffCentralOffset = 16;

// Central-directory entry offsets.
constexpr u32 kCdOffFlags = 8;
constexpr u32 kCdOffMethod = 10;
constexpr u32 kCdOffCrc32 = 16;
constexpr u32 kCdOffCompressedSize = 20;
constexpr u32 kCdOffUncompressedSize = 24;
constexpr u32 kCdOffNameLen = 28;
constexpr u32 kCdOffExtraLen = 30;
constexpr u32 kCdOffCommentLen = 32;
constexpr u32 kCdOffLocalOffset = 42;
constexpr u32 kCdOffName = 46;

// Local-file-header offsets.
constexpr u32 kLocalOffNameLen = 26;
constexpr u32 kLocalOffExtraLen = 28;
constexpr u32 kLocalOffName = 30;

// Search the trailing kEocdSearchWindow bytes for the EOCD magic.
// Scans backwards because a sane archive has the EOCD at the very
// end, with the ZIP-comment (if any) trailing — and the comment
// is the only thing between the EOCD and EOF. Returns the offset
// of the EOCD record (the 4-byte magic), or u32 max on miss.
u32 FindEocd(const u8* file, u32 file_len)
{
    if (file_len < kEocdMinSize)
        return ~u32(0);
    const u32 search_floor = file_len > kEocdSearchWindow ? file_len - kEocdSearchWindow : 0;
    for (u32 off = file_len - kEocdMinSize; off >= search_floor; --off)
    {
        if (LeU32(file + off) == kEocdMagic)
            return off;
        if (off == 0)
            break;
    }
    return ~u32(0);
}

} // namespace

const char* ZipStatusName(ZipStatus s)
{
    switch (s)
    {
    case ZipStatus::Ok:
        return "Ok";
    case ZipStatus::TooSmall:
        return "TooSmall";
    case ZipStatus::NoEocd:
        return "NoEocd";
    case ZipStatus::Zip64NotSupported:
        return "Zip64NotSupported";
    case ZipStatus::CentralOutOfRange:
        return "CentralOutOfRange";
    case ZipStatus::BadCentralMagic:
        return "BadCentralMagic";
    case ZipStatus::NameTooLong:
        return "NameTooLong";
    case ZipStatus::EncryptedFlag:
        return "EncryptedFlag";
    case ZipStatus::BadLocalMagic:
        return "BadLocalMagic";
    case ZipStatus::BadMethod:
        return "BadMethod";
    case ZipStatus::DataOutOfRange:
        return "DataOutOfRange";
    case ZipStatus::InflateFailed:
        return "InflateFailed";
    case ZipStatus::DstTooSmall:
        return "DstTooSmall";
    case ZipStatus::BadIndex:
        return "BadIndex";
    }
    return "?";
}

ZipStatus ZipOpen(const u8* file, u32 file_len, ZipReader* out)
{
    if (out == nullptr)
        return ZipStatus::TooSmall;
    *out = ZipReader{};
    if (file == nullptr || file_len < kEocdMinSize)
        return ZipStatus::TooSmall;
    const u32 eocd = FindEocd(file, file_len);
    if (eocd == ~u32(0))
        return ZipStatus::NoEocd;
    const u8* p = file + eocd;
    const u16 entries_total = LeU16(p + kEocdOffEntriesTotal);
    const u16 entries_this = LeU16(p + kEocdOffEntriesThisDisk);
    const u16 disk_no = LeU16(p + kEocdOffDiskNumber);
    const u16 start_disk = LeU16(p + kEocdOffStartDisk);
    const u32 cd_size = LeU32(p + kEocdOffCentralSize);
    const u32 cd_offset = LeU32(p + kEocdOffCentralOffset);
    // ZIP64 sentinel — every size/count field saturated.
    if (entries_total == 0xFFFF || entries_this == 0xFFFF || cd_size == 0xFFFFFFFFu || cd_offset == 0xFFFFFFFFu)
        return ZipStatus::Zip64NotSupported;
    // v0 supports single-disk archives only.
    if (disk_no != 0 || start_disk != 0 || entries_this != entries_total)
        return ZipStatus::Zip64NotSupported;
    if (cd_offset > file_len || cd_size > file_len - cd_offset)
        return ZipStatus::CentralOutOfRange;
    out->file = file;
    out->file_len = file_len;
    out->entry_count = entries_total;
    out->central_offset = cd_offset;
    out->central_size = cd_size;
    return ZipStatus::Ok;
}

ZipStatus ZipReadEntry(const ZipReader& reader, u32 index, ZipEntryInfo* out)
{
    if (out == nullptr || reader.file == nullptr)
        return ZipStatus::TooSmall;
    if (index >= reader.entry_count)
        return ZipStatus::BadIndex;
    *out = ZipEntryInfo{};
    u32 cursor = reader.central_offset;
    const u32 cd_end = reader.central_offset + reader.central_size;
    for (u32 i = 0; i <= index; ++i)
    {
        if (cursor + kCentralEntryMinSize > cd_end)
            return ZipStatus::CentralOutOfRange;
        const u8* p = reader.file + cursor;
        if (LeU32(p) != kCentralMagic)
            return ZipStatus::BadCentralMagic;
        const u16 name_len = LeU16(p + kCdOffNameLen);
        const u16 extra_len = LeU16(p + kCdOffExtraLen);
        const u16 comment_len = LeU16(p + kCdOffCommentLen);
        const u32 record_size = kCentralEntryMinSize + u32(name_len) + u32(extra_len) + u32(comment_len);
        if (cursor + record_size > cd_end)
            return ZipStatus::CentralOutOfRange;
        if (i == index)
        {
            const u16 flags = LeU16(p + kCdOffFlags);
            if ((flags & (kFlagEncrypted | kFlagStrongEncryption)) != 0)
                return ZipStatus::EncryptedFlag;
            if (name_len >= sizeof(out->name))
                return ZipStatus::NameTooLong;
            out->method = LeU16(p + kCdOffMethod);
            out->crc32 = LeU32(p + kCdOffCrc32);
            out->compressed_size = LeU32(p + kCdOffCompressedSize);
            out->uncompressed_size = LeU32(p + kCdOffUncompressedSize);
            out->local_offset = LeU32(p + kCdOffLocalOffset);
            out->name_len = name_len;
            for (u16 j = 0; j < name_len; ++j)
                out->name[j] = static_cast<char>(p[kCdOffName + j]);
            out->name[name_len] = '\0';
            return ZipStatus::Ok;
        }
        cursor += record_size;
    }
    return ZipStatus::BadIndex; // unreachable
}

ZipStatus ZipExtractEntry(const ZipReader& reader, u32 index, u8* dst, u32 dst_cap, u32* out_bytes)
{
    if (out_bytes == nullptr)
        return ZipStatus::TooSmall;
    *out_bytes = 0;
    ZipEntryInfo info{};
    ZipStatus rc = ZipReadEntry(reader, index, &info);
    if (rc != ZipStatus::Ok)
        return rc;
    // Directory entry — name ends in '/', no payload to extract.
    if (info.name_len > 0 && info.name[info.name_len - 1] == '/')
    {
        return ZipStatus::Ok;
    }
    if (info.method != kMethodStored && info.method != kMethodDeflate)
        return ZipStatus::BadMethod;
    if (dst_cap < info.uncompressed_size)
        return ZipStatus::DstTooSmall;
    // Parse the local file header to find the actual compressed-
    // data offset. Cannot trust the central-directory's filename
    // length to match the local header (extra-field length almost
    // always differs).
    if (info.local_offset + kLocalHeaderMinSize > reader.file_len)
        return ZipStatus::DataOutOfRange;
    const u8* lh = reader.file + info.local_offset;
    if (LeU32(lh) != kLocalMagic)
        return ZipStatus::BadLocalMagic;
    const u16 lh_name_len = LeU16(lh + kLocalOffNameLen);
    const u16 lh_extra_len = LeU16(lh + kLocalOffExtraLen);
    const u32 data_off = info.local_offset + kLocalHeaderMinSize + lh_name_len + lh_extra_len;
    if (data_off + info.compressed_size > reader.file_len)
        return ZipStatus::DataOutOfRange;
    const u8* compressed = reader.file + data_off;
    if (info.method == kMethodStored)
    {
        if (info.compressed_size != info.uncompressed_size)
            return ZipStatus::BadMethod;
        for (u32 i = 0; i < info.uncompressed_size; ++i)
            dst[i] = compressed[i];
        *out_bytes = info.uncompressed_size;
        return ZipStatus::Ok;
    }
    // method == kMethodDeflate
    const u32 produced = DeflateInflate(compressed, info.compressed_size, dst, dst_cap);
    if (produced == 0 && info.uncompressed_size != 0)
        return ZipStatus::InflateFailed;
    if (produced != info.uncompressed_size)
        return ZipStatus::InflateFailed;
    *out_bytes = produced;
    return ZipStatus::Ok;
}

// ---------------------------------------------------------------------------
// Self-test: a minimum-viable ZIP composed inline.
//
// The archive carries one stored entry "hi.txt" with payload "hello\n"
// and one deflate-compressed entry "data.bin" with payload
// "DEFLATE-PAYLOAD". Both payloads round-trip.
//
// The deflate compressed bytes below were produced by the kernel
// inflater's reference encoder via offline tooling — they encode
// the byte string "DEFLATE-PAYLOAD" exactly. Verifying decompression
// is what the test asserts; the encoding step is not in DuetOS.
// ---------------------------------------------------------------------------
namespace
{

constexpr u8 kStoredPayload[] = {'h', 'e', 'l', 'l', 'o', '\n'};
constexpr u8 kDeflatePayload[] = {'D', 'E', 'F', 'L', 'A', 'T', 'E', '-', 'P', 'A', 'Y', 'L', 'O', 'A', 'D'};

// Pre-computed deflate stream for kDeflatePayload, type-1 fixed
// Huffman, single block (BFINAL=1). Reproducible offline via
// `zlib.compress(payload, level=9)[2:-4]` (strip zlib header/adler).
// For "DEFLATE-PAYLOAD" this encodes to a literal-only stream
// because all bytes are unique — no back-references possible.
constexpr u8 kDeflateStream[] = {0x73, 0x71, 0x75, 0xF3, 0x71, 0x0C, 0x71, 0xD5, 0x0D,
                                 0x70, 0x8C, 0xF4, 0xF1, 0x77, 0x74, 0x01, 0x00};

constexpr u32 kStoredLen = sizeof(kStoredPayload);
constexpr u32 kDeflateOrigLen = sizeof(kDeflatePayload);
constexpr u32 kDeflateStreamLen = sizeof(kDeflateStream);

inline void Pu16(u8* p, u16 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
}
inline void Pu32(u8* p, u32 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
    p[2] = u8((v >> 16) & 0xFF);
    p[3] = u8((v >> 24) & 0xFF);
}

// Build a tiny ZIP in `buf` and return its length. Returns 0 if
// buf_cap is too small. Layout:
//   local hdr "hi.txt" + stored payload
//   local hdr "data.bin" + deflate stream
//   central dir entry "hi.txt"
//   central dir entry "data.bin"
//   EOCD
u32 BuildTestZip(u8* buf, u32 buf_cap)
{
    auto write_local = [&](u32& cursor, const char* name, u16 method, u32 csize, u32 usize, const u8* data) -> bool
    {
        const u16 name_len = u16(__builtin_strlen(name));
        const u32 need = 30 + name_len + csize;
        if (cursor + need > buf_cap)
            return false;
        u8* p = buf + cursor;
        Pu32(p + 0, 0x04034b50);
        Pu16(p + 4, 20); // version needed
        Pu16(p + 6, 0);  // flags
        Pu16(p + 8, method);
        Pu16(p + 10, 0); // mod time
        Pu16(p + 12, 0); // mod date
        Pu32(p + 14, 0); // crc32 (not checked by reader)
        Pu32(p + 18, csize);
        Pu32(p + 22, usize);
        Pu16(p + 26, name_len);
        Pu16(p + 28, 0); // extra
        for (u16 i = 0; i < name_len; ++i)
            p[30 + i] = u8(name[i]);
        for (u32 i = 0; i < csize; ++i)
            p[30 + name_len + i] = data[i];
        cursor += need;
        return true;
    };
    auto write_central = [&](u32& cursor, const char* name, u16 method, u32 csize, u32 usize, u32 local_off) -> bool
    {
        const u16 name_len = u16(__builtin_strlen(name));
        const u32 need = 46 + name_len;
        if (cursor + need > buf_cap)
            return false;
        u8* p = buf + cursor;
        Pu32(p + 0, 0x02014b50);
        Pu16(p + 4, 20); // version made by
        Pu16(p + 6, 20); // version needed
        Pu16(p + 8, 0);  // flags
        Pu16(p + 10, method);
        Pu16(p + 12, 0); // mod time
        Pu16(p + 14, 0); // mod date
        Pu32(p + 16, 0); // crc32
        Pu32(p + 20, csize);
        Pu32(p + 24, usize);
        Pu16(p + 28, name_len);
        Pu16(p + 30, 0); // extra
        Pu16(p + 32, 0); // comment
        Pu16(p + 34, 0); // disk
        Pu16(p + 36, 0); // internal attr
        Pu32(p + 38, 0); // external attr
        Pu32(p + 42, local_off);
        for (u16 i = 0; i < name_len; ++i)
            p[46 + i] = u8(name[i]);
        cursor += need;
        return true;
    };

    u32 cur = 0;
    const u32 lh1_off = cur;
    if (!write_local(cur, "hi.txt", kMethodStored, kStoredLen, kStoredLen, kStoredPayload))
        return 0;
    const u32 lh2_off = cur;
    if (!write_local(cur, "data.bin", kMethodDeflate, kDeflateStreamLen, kDeflateOrigLen, kDeflateStream))
        return 0;
    const u32 cd_off = cur;
    if (!write_central(cur, "hi.txt", kMethodStored, kStoredLen, kStoredLen, lh1_off))
        return 0;
    if (!write_central(cur, "data.bin", kMethodDeflate, kDeflateStreamLen, kDeflateOrigLen, lh2_off))
        return 0;
    const u32 cd_size = cur - cd_off;
    // EOCD
    if (cur + 22 > buf_cap)
        return 0;
    u8* p = buf + cur;
    Pu32(p + 0, 0x06054b50);
    Pu16(p + 4, 0);
    Pu16(p + 6, 0);
    Pu16(p + 8, 2);  // entries this disk
    Pu16(p + 10, 2); // entries total
    Pu32(p + 12, cd_size);
    Pu32(p + 16, cd_off);
    Pu16(p + 20, 0); // comment len
    cur += 22;
    return cur;
}

} // namespace

void ZipReaderSelfTest()
{
    using arch::SerialWrite;
    u8 buf[512];
    u8 out[64];
    const u32 zip_len = BuildTestZip(buf, sizeof(buf));
    if (zip_len == 0)
    {
        SerialWrite("[zip-st] FAIL build-zip\n");
        return;
    }
    ZipReader r{};
    ZipStatus rc = ZipOpen(buf, zip_len, &r);
    if (rc != ZipStatus::Ok || r.entry_count != 2)
    {
        SerialWrite("[zip-st] FAIL open status=");
        SerialWrite(ZipStatusName(rc));
        SerialWrite("\n");
        return;
    }
    // Entry 0: hi.txt (stored).
    ZipEntryInfo e0{};
    rc = ZipReadEntry(r, 0, &e0);
    if (rc != ZipStatus::Ok || e0.method != kMethodStored || e0.uncompressed_size != kStoredLen)
    {
        SerialWrite("[zip-st] FAIL read-entry-0\n");
        return;
    }
    u32 produced = 0;
    rc = ZipExtractEntry(r, 0, out, sizeof(out), &produced);
    if (rc != ZipStatus::Ok || produced != kStoredLen)
    {
        SerialWrite("[zip-st] FAIL extract-stored status=");
        SerialWrite(ZipStatusName(rc));
        SerialWrite("\n");
        return;
    }
    for (u32 i = 0; i < kStoredLen; ++i)
    {
        if (out[i] != kStoredPayload[i])
        {
            SerialWrite("[zip-st] FAIL stored-payload-mismatch\n");
            return;
        }
    }
    // Entry 1: data.bin (deflate).
    ZipEntryInfo e1{};
    rc = ZipReadEntry(r, 1, &e1);
    if (rc != ZipStatus::Ok || e1.method != kMethodDeflate || e1.uncompressed_size != kDeflateOrigLen)
    {
        SerialWrite("[zip-st] FAIL read-entry-1\n");
        return;
    }
    rc = ZipExtractEntry(r, 1, out, sizeof(out), &produced);
    if (rc != ZipStatus::Ok || produced != kDeflateOrigLen)
    {
        SerialWrite("[zip-st] FAIL extract-deflate status=");
        SerialWrite(ZipStatusName(rc));
        SerialWrite("\n");
        return;
    }
    for (u32 i = 0; i < kDeflateOrigLen; ++i)
    {
        if (out[i] != kDeflatePayload[i])
        {
            SerialWrite("[zip-st] FAIL deflate-payload-mismatch\n");
            return;
        }
    }
    SerialWrite("[zip-st] PASS (stored + deflate round-trip OK)\n");
}

} // namespace duetos::util
