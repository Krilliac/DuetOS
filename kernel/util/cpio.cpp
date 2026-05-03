#include "util/cpio.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

// newc header field layout (POSIX.1-1988 / Linux Documentation/early-userspace).
// Every field is 8 ASCII-hex characters and is read big-endian-encoded
// (i.e. high-order nibble first).
constexpr u32 kFieldMagic = 0; // 6 bytes (not 8)
constexpr u32 kFieldIno = 6;
constexpr u32 kFieldMode = 14;
constexpr u32 kFieldUid = 22;
constexpr u32 kFieldGid = 30;
constexpr u32 kFieldNlink = 38;
constexpr u32 kFieldMtime = 46;
constexpr u32 kFieldFilesize = 54;
constexpr u32 kFieldDevMajor = 62;
constexpr u32 kFieldDevMinor = 70;
constexpr u32 kFieldRdevMajor = 78;
constexpr u32 kFieldRdevMinor = 86;
constexpr u32 kFieldNamesize = 94;
constexpr u32 kFieldCheck = 102; // newc-CRC only; ignored on newc

bool HexDigit(char c, u32& out)
{
    if (c >= '0' && c <= '9')
    {
        out = u32(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f')
    {
        out = u32(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F')
    {
        out = u32(c - 'A' + 10);
        return true;
    }
    return false;
}

// Read an 8-character ASCII-hex field at `hdr+off`, returning
// the unsigned 32-bit value. Returns false on any non-hex byte.
bool ReadHex8(const u8* hdr, u32 off, u32& v)
{
    v = 0;
    for (u32 i = 0; i < 8; ++i)
    {
        u32 d;
        if (!HexDigit(char(hdr[off + i]), d))
            return false;
        v = (v << 4) | d;
    }
    return true;
}

bool MagicValid(const u8* hdr)
{
    // newc:    "070701"
    // newc-CRC:"070702"
    if (hdr[0] != '0' || hdr[1] != '7' || hdr[2] != '0' || hdr[3] != '7' || hdr[4] != '0')
        return false;
    return hdr[5] == '1' || hdr[5] == '2';
}

// Round `n` up to the next multiple of 4 (newc payload alignment).
u32 PadTo4(u32 n)
{
    return (n + 3u) & ~3u;
}

bool NameMatches(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

} // namespace

bool CpioForEach(const u8* archive, u32 archive_len, CpioVisitor visit, void* ctx)
{
    u32 off = 0;
    while (true)
    {
        if (off + kCpioHeaderBytes > archive_len)
            return false; // truncated header
        const u8* hdr = archive + off;
        if (!MagicValid(hdr))
            return false;

        CpioEntry entry = {};
        u32 c_namesize = 0;
        u32 c_filesize = 0;
        if (!ReadHex8(hdr, kFieldIno, entry.ino) || !ReadHex8(hdr, kFieldMode, entry.mode) ||
            !ReadHex8(hdr, kFieldUid, entry.uid) || !ReadHex8(hdr, kFieldGid, entry.gid) ||
            !ReadHex8(hdr, kFieldNlink, entry.nlink) || !ReadHex8(hdr, kFieldMtime, entry.mtime) ||
            !ReadHex8(hdr, kFieldFilesize, c_filesize) || !ReadHex8(hdr, kFieldDevMajor, entry.dev_major) ||
            !ReadHex8(hdr, kFieldDevMinor, entry.dev_minor) || !ReadHex8(hdr, kFieldRdevMajor, entry.rdev_major) ||
            !ReadHex8(hdr, kFieldRdevMinor, entry.rdev_minor) || !ReadHex8(hdr, kFieldNamesize, c_namesize))
        {
            return false; // bad ASCII-hex
        }
        // Suppress -Wunused-variable when only newc-CRC consumers care.
        (void)kFieldCheck;

        // c_namesize INCLUDES the trailing NUL.
        if (c_namesize == 0)
            return false;
        const u32 name_off = off + kCpioHeaderBytes;
        if (name_off + c_namesize > archive_len)
            return false;

        // The name region (header+name) is padded to 4-byte boundary,
        // counted from the start of the header.
        const u32 name_padded = PadTo4(kCpioHeaderBytes + c_namesize) - kCpioHeaderBytes;
        const u32 data_off = name_off + name_padded;
        if (data_off > archive_len)
            return false;
        if (data_off + c_filesize > archive_len)
            return false;
        const u32 data_padded = PadTo4(c_filesize);
        if (data_off + data_padded > archive_len)
        {
            // Tolerant: the spec lets the very last entry omit
            // padding before EOF if the file size is already aligned.
            // If it isn't aligned and we'd run off, bail.
            if (c_filesize != data_padded)
                return false;
        }

        entry.name = reinterpret_cast<const char*>(archive + name_off);
        entry.name_len = c_namesize - 1; // exclude NUL
        entry.data = archive + data_off;
        entry.data_len = c_filesize;

        // Trailer entry stops the walk cleanly.
        if (NameMatches(entry.name, kCpioTrailerName))
            return true;

        if (!visit(entry, ctx))
            return true;

        off = data_off + data_padded;
        if (off >= archive_len)
            return false; // missing trailer
    }
}

namespace
{

// Helper for the self-test: append a hex-formatted u32 to `buf`.
void AppendHex8(u8* buf, u32 v)
{
    static const char kDigits[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (i32 i = 7; i >= 0; --i)
    {
        buf[i] = u8(kDigits[v & 0xFu]);
        v >>= 4;
    }
}

// Helper for the self-test: append a single newc entry into `buf`,
// returning the new buffer offset.
u32 AppendEntry(u8* buf, u32 off, const char* name, const u8* data, u32 data_len, u32 mode)
{
    // Magic "070701".
    buf[off + 0] = '0';
    buf[off + 1] = '7';
    buf[off + 2] = '0';
    buf[off + 3] = '7';
    buf[off + 4] = '0';
    buf[off + 5] = '1';
    AppendHex8(buf + off + kFieldIno, 0); // ino
    AppendHex8(buf + off + kFieldMode, mode);
    AppendHex8(buf + off + kFieldUid, 0);
    AppendHex8(buf + off + kFieldGid, 0);
    AppendHex8(buf + off + kFieldNlink, 1);
    AppendHex8(buf + off + kFieldMtime, 0);
    AppendHex8(buf + off + kFieldFilesize, data_len);
    AppendHex8(buf + off + kFieldDevMajor, 0);
    AppendHex8(buf + off + kFieldDevMinor, 0);
    AppendHex8(buf + off + kFieldRdevMajor, 0);
    AppendHex8(buf + off + kFieldRdevMinor, 0);
    u32 name_len = 0;
    while (name[name_len] != '\0')
        ++name_len;
    const u32 namesize = name_len + 1; // include NUL
    AppendHex8(buf + off + kFieldNamesize, namesize);
    AppendHex8(buf + off + kFieldCheck, 0);

    u32 cur = off + kCpioHeaderBytes;
    for (u32 i = 0; i < namesize; ++i)
    {
        buf[cur + i] = (i < name_len) ? u8(name[i]) : 0;
    }
    cur += namesize;
    // Pad name + header to 4-byte alignment.
    while (((cur - off) & 3u) != 0)
        buf[cur++] = 0;
    for (u32 i = 0; i < data_len; ++i)
        buf[cur + i] = data[i];
    cur += data_len;
    while ((cur & 3u) != 0)
        buf[cur++] = 0;
    return cur;
}

struct VisitState
{
    u32 calls;
    u32 first_data_len;
    u8 first_data_byte;
    bool saw_second;
    u32 second_data_len;
};

bool CountVisitor(const CpioEntry& entry, void* ctx)
{
    auto* st = static_cast<VisitState*>(ctx);
    if (st->calls == 0)
    {
        st->first_data_len = entry.data_len;
        if (entry.data_len > 0)
            st->first_data_byte = entry.data[0];
    }
    else if (st->calls == 1)
    {
        st->saw_second = true;
        st->second_data_len = entry.data_len;
    }
    ++st->calls;
    return true;
}

} // namespace

void CpioSelfTest()
{
    // Build a synthetic 2-entry newc archive in memory:
    //   1. "hello.txt"  contents "hi\n"  (3 bytes)
    //   2. "empty.bin"  contents ""       (0 bytes)
    // Followed by the canonical "TRAILER!!!" entry.
    u8 archive[512];
    for (u32 i = 0; i < sizeof(archive); ++i)
        archive[i] = 0;

    const u8 hello_data[3] = {'h', 'i', '\n'};
    u32 off = 0;
    off = AppendEntry(archive, off, "hello.txt", hello_data, 3, 0100644u);
    off = AppendEntry(archive, off, "empty.bin", nullptr, 0, 0100644u);
    off = AppendEntry(archive, off, "TRAILER!!!", nullptr, 0, 0);
    KASSERT(off <= sizeof(archive), "util/cpio", "self-test buffer overflow");

    VisitState st = {};
    st.first_data_byte = 0xFF;
    const bool ok = CpioForEach(archive, off, CountVisitor, &st);
    KASSERT(ok, "util/cpio", "happy-path walk failed");
    KASSERT(st.calls == 2, "util/cpio", "wrong entry count");
    KASSERT(st.first_data_len == 3, "util/cpio", "first entry size wrong");
    KASSERT(st.first_data_byte == 'h', "util/cpio", "first entry content wrong");
    KASSERT(st.saw_second && st.second_data_len == 0, "util/cpio", "empty entry wrong");

    // Negative: bad magic.
    archive[0] = 'X';
    {
        VisitState st2 = {};
        const bool bad = CpioForEach(archive, off, CountVisitor, &st2);
        KASSERT(!bad, "util/cpio", "bad magic not rejected");
    }
    archive[0] = '0';

    // Negative: truncated header (claim we have only 50 bytes).
    {
        VisitState st3 = {};
        const bool tr = CpioForEach(archive, 50, CountVisitor, &st3);
        KASSERT(!tr, "util/cpio", "truncated header not rejected");
    }

    // Negative: missing trailer (truncate just before the trailer).
    {
        // Find the trailer offset: it's the third entry. After two
        // AppendEntry calls we know off1 + off2 worth of bytes.
        u8 short_archive[512];
        for (u32 i = 0; i < sizeof(short_archive); ++i)
            short_archive[i] = 0;
        u32 short_off = AppendEntry(short_archive, 0, "hello.txt", hello_data, 3, 0100644u);
        VisitState st4 = {};
        const bool missing = CpioForEach(short_archive, short_off, CountVisitor, &st4);
        KASSERT(!missing, "util/cpio", "missing trailer not rejected");
    }

    // Visitor short-circuit: returning false stops the walk cleanly
    // (returns true overall — not a parse error).
    {
        struct ShortCtx
        {
            u32 calls;
        };
        auto stop_fn = [](const CpioEntry&, void* c)
        {
            auto* sc = static_cast<ShortCtx*>(c);
            ++sc->calls;
            return false;
        };
        ShortCtx sc = {};
        const bool short_ok = CpioForEach(archive, off, stop_fn, &sc);
        KASSERT(short_ok, "util/cpio", "early-stop should return true");
        KASSERT(sc.calls == 1, "util/cpio", "early-stop should fire once");
    }
}

} // namespace duetos::util
