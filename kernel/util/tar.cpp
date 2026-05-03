#include "util/tar.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

// Header field offsets per the POSIX ustar layout.
constexpr u32 kFieldName = 0;     // 100 bytes
constexpr u32 kFieldMode = 100;   // 8 bytes octal
constexpr u32 kFieldUid = 108;    // 8 bytes octal
constexpr u32 kFieldGid = 116;    // 8 bytes octal
constexpr u32 kFieldSize = 124;   // 12 bytes octal
constexpr u32 kFieldMtime = 136;  // 12 bytes octal
constexpr u32 kFieldChksum = 148; // 8 bytes octal
constexpr u32 kFieldTypeflag = 156;
constexpr u32 kFieldLinkname = 157; // 100 bytes
constexpr u32 kFieldMagic = 257;    // 6 bytes ("ustar\0" or "ustar ")
constexpr u32 kFieldVersion = 263;  // 2 bytes
constexpr u32 kFieldUname = 265;    // 32 bytes
constexpr u32 kFieldGname = 297;    // 32 bytes
constexpr u32 kFieldPrefix = 345;   // 155 bytes

// Read an N-byte ASCII-octal field. Spaces and NUL terminate.
// Returns false if the field contains non-octal bytes.
bool ReadOctal(const u8* p, u32 n, u64& out)
{
    u64 v = 0;
    bool any = false;
    for (u32 i = 0; i < n; ++i)
    {
        const u8 c = p[i];
        if (c == 0 || c == ' ')
        {
            if (any)
                return true;
            continue;
        }
        if (c < '0' || c > '7')
            return false;
        v = (v << 3) | u64(c - '0');
        any = true;
    }
    if (!any)
        return false;
    out = v;
    return true;
}

bool MagicValid(const u8* hdr)
{
    // ustar trailing NUL or ustar trailing space (GNU). POSIX ustar
    // requires "ustar\0" + version "00"; GNU's older non-strict form
    // emits "ustar  \0". Accept both.
    if (hdr[kFieldMagic + 0] != 'u' || hdr[kFieldMagic + 1] != 's' || hdr[kFieldMagic + 2] != 't' ||
        hdr[kFieldMagic + 3] != 'a' || hdr[kFieldMagic + 4] != 'r')
        return false;
    return true;
}

bool IsZeroBlock(const u8* hdr)
{
    for (u32 i = 0; i < kTarBlockBytes; ++i)
        if (hdr[i] != 0)
            return false;
    return true;
}

void CopyName(const u8* hdr, char* out)
{
    // POSIX prefix + '/' + name. Either may be empty; we drop the
    // separator when prefix is empty.
    u32 dst = 0;
    for (u32 i = 0; i < 155; ++i)
    {
        if (hdr[kFieldPrefix + i] == 0)
            break;
        out[dst++] = char(hdr[kFieldPrefix + i]);
    }
    if (dst > 0)
        out[dst++] = '/';
    for (u32 i = 0; i < 100; ++i)
    {
        if (hdr[kFieldName + i] == 0)
            break;
        out[dst++] = char(hdr[kFieldName + i]);
    }
    out[dst] = '\0';
}

void CopyLink(const u8* hdr, char* out)
{
    u32 i = 0;
    for (; i < 100; ++i)
    {
        if (hdr[kFieldLinkname + i] == 0)
            break;
        out[i] = char(hdr[kFieldLinkname + i]);
    }
    out[i] = '\0';
}

u32 RoundUp512(u64 n)
{
    return u32((n + 511u) & ~u64(511u));
}

} // namespace

bool TarForEach(const u8* archive, u32 archive_len, TarVisitor visit, void* ctx)
{
    u32 off = 0;
    while (off + kTarBlockBytes <= archive_len)
    {
        const u8* hdr = archive + off;
        if (IsZeroBlock(hdr))
        {
            // Spec requires two consecutive zero blocks for the
            // trailer; one zero block alone is malformed but tolerant
            // readers stop on the first. We require two.
            if (off + 2 * kTarBlockBytes <= archive_len && IsZeroBlock(archive + off + kTarBlockBytes))
                return true;
            return false;
        }
        if (!MagicValid(hdr))
            return false;

        TarEntry entry = {};
        u64 mode = 0, uid = 0, gid = 0, size = 0, mtime = 0;
        if (!ReadOctal(hdr + kFieldMode, 8, mode) || !ReadOctal(hdr + kFieldUid, 8, uid) ||
            !ReadOctal(hdr + kFieldGid, 8, gid) || !ReadOctal(hdr + kFieldSize, 12, size) ||
            !ReadOctal(hdr + kFieldMtime, 12, mtime))
            return false;

        const u32 padded = RoundUp512(size);
        if (u64(off) + kTarBlockBytes + size > u64(archive_len))
            return false;
        if (u64(off) + kTarBlockBytes + padded > u64(archive_len))
        {
            // Tolerant: padding may be elided at EOF if file size is
            // already 512-aligned. If not aligned, hard fail.
            if (padded != size)
                return false;
        }

        CopyName(hdr, entry.name);
        CopyLink(hdr, entry.linkname);
        entry.mode = u32(mode);
        entry.uid = u32(uid);
        entry.gid = u32(gid);
        entry.mtime = mtime;
        entry.typeflag = char(hdr[kFieldTypeflag]);
        entry.data = archive + off + kTarBlockBytes;
        entry.data_len = size;

        if (!visit(entry, ctx))
            return true;

        off += kTarBlockBytes + padded;
    }
    return false; // ran off without seeing the trailer
}

namespace
{

// Self-test helpers.
void WriteOctal(u8* p, u32 n, u64 v)
{
    // Right-justified, zero-padded, NUL-terminated (n-1 digits + NUL).
    for (u32 i = 0; i < n; ++i)
        p[i] = ' ';
    p[n - 1] = 0;
    if (n < 2)
        return;
    u32 idx = n - 2;
    if (v == 0)
    {
        p[idx] = '0';
        return;
    }
    while (v > 0 && idx < n)
    {
        p[idx] = u8('0' + (v & 7u));
        v >>= 3;
        if (idx == 0)
            break;
        --idx;
    }
}

void StrFill(u8* p, u32 cap, const char* s)
{
    u32 i = 0;
    for (; s[i] != '\0' && i < cap; ++i)
        p[i] = u8(s[i]);
    for (; i < cap; ++i)
        p[i] = 0;
}

u32 BuildEntry(u8* buf, u32 off, const char* name, const u8* data, u64 data_len, char typeflag)
{
    u8* h = buf + off;
    for (u32 i = 0; i < kTarBlockBytes; ++i)
        h[i] = 0;
    StrFill(h + kFieldName, 100, name);
    WriteOctal(h + kFieldMode, 8, 0644);
    WriteOctal(h + kFieldUid, 8, 0);
    WriteOctal(h + kFieldGid, 8, 0);
    WriteOctal(h + kFieldSize, 12, data_len);
    WriteOctal(h + kFieldMtime, 12, 0);
    h[kFieldTypeflag] = u8(typeflag);
    h[kFieldMagic + 0] = 'u';
    h[kFieldMagic + 1] = 's';
    h[kFieldMagic + 2] = 't';
    h[kFieldMagic + 3] = 'a';
    h[kFieldMagic + 4] = 'r';
    h[kFieldMagic + 5] = 0;
    h[kFieldVersion + 0] = '0';
    h[kFieldVersion + 1] = '0';
    // Real tar fills checksum; the parser doesn't validate it (POSIX
    // says it's optional for readers). Leave as spaces (the canonical
    // initial state during checksum compute).
    for (u32 i = 0; i < 8; ++i)
        h[kFieldChksum + i] = ' ';
    u32 cur = off + kTarBlockBytes;
    for (u64 i = 0; i < data_len; ++i)
        buf[cur + i] = data[i];
    cur = off + kTarBlockBytes + RoundUp512(data_len);
    return cur;
}

struct VisitState
{
    u32 calls;
    u64 first_size;
    char first_first_byte;
    char second_typeflag;
};

bool CountVisitor(const TarEntry& entry, void* ctx)
{
    auto* st = static_cast<VisitState*>(ctx);
    if (st->calls == 0)
    {
        st->first_size = entry.data_len;
        if (entry.data_len > 0)
            st->first_first_byte = char(entry.data[0]);
    }
    else if (st->calls == 1)
    {
        st->second_typeflag = entry.typeflag;
    }
    ++st->calls;
    return true;
}

} // namespace

void TarSelfTest()
{
    // Build a 2-entry archive plus the dual-zero-block trailer:
    //   entry 1: "hello.txt" 5 bytes "hello"
    //   entry 2: "subdir/"   directory (typeflag '5', size 0)
    u8 archive[2048];
    for (u32 i = 0; i < sizeof(archive); ++i)
        archive[i] = 0;
    const u8 hello[5] = {'h', 'e', 'l', 'l', 'o'};
    u32 off = 0;
    off = BuildEntry(archive, off, "hello.txt", hello, 5, '0');
    off = BuildEntry(archive, off, "subdir/", nullptr, 0, '5');
    // Trailer (two zero blocks).
    off += 2 * kTarBlockBytes;
    KASSERT(off <= sizeof(archive), "util/tar", "self-test buffer overflow");

    VisitState st = {};
    const bool ok = TarForEach(archive, off, CountVisitor, &st);
    KASSERT(ok, "util/tar", "happy-path walk failed");
    KASSERT(st.calls == 2, "util/tar", "wrong entry count");
    KASSERT(st.first_size == 5, "util/tar", "first entry size wrong");
    KASSERT(st.first_first_byte == 'h', "util/tar", "first entry byte wrong");
    KASSERT(st.second_typeflag == '5', "util/tar", "second typeflag wrong");

    // Negative: bad ustar magic.
    {
        u8 buf[2048];
        for (u32 i = 0; i < sizeof(buf); ++i)
            buf[i] = archive[i];
        buf[kFieldMagic + 0] = 'X';
        VisitState st2 = {};
        const bool bad = TarForEach(buf, off, CountVisitor, &st2);
        KASSERT(!bad, "util/tar", "bad magic not rejected");
    }

    // Negative: missing trailer (truncate just before zero blocks).
    {
        VisitState st3 = {};
        const u32 missing_off = off - 2 * kTarBlockBytes;
        const bool missing = TarForEach(archive, missing_off, CountVisitor, &st3);
        KASSERT(!missing, "util/tar", "missing trailer not rejected");
    }

    // Visitor short-circuit: returning false stops cleanly.
    {
        struct ShortCtx
        {
            u32 calls;
        };
        auto stop = [](const TarEntry&, void* c)
        {
            auto* sc = static_cast<ShortCtx*>(c);
            ++sc->calls;
            return false;
        };
        ShortCtx sc = {};
        const bool short_ok = TarForEach(archive, off, stop, &sc);
        KASSERT(short_ok, "util/tar", "early-stop should return true");
        KASSERT(sc.calls == 1, "util/tar", "early-stop should fire once");
    }

    // Bad-octal in size field.
    {
        u8 buf[2048];
        for (u32 i = 0; i < sizeof(buf); ++i)
            buf[i] = archive[i];
        buf[kFieldSize] = '8'; // not in 0..7
        VisitState st4 = {};
        const bool bad = TarForEach(buf, off, CountVisitor, &st4);
        KASSERT(!bad, "util/tar", "bad-octal not rejected");
    }
}

} // namespace duetos::util
