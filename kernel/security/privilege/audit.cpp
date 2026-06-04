#include "security/privilege/audit.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "mm/kheap.h"

namespace duetos::security::privilege
{
using duetos::i64;
using duetos::u32;
using duetos::u64;

// The Privilege Engine's own append-only audit trail on the boot volume.
// Deliberately at the volume root and deliberately OUTSIDE the fs scope:
// scope.cpp refuses the basename "audit.log" anywhere, so page JS can never
// reach this path through the broker. The engine writes it directly here.
namespace
{
constexpr const char* kAuditLogPath = "/AUDIT.LOG";
// Bound the on-disk log so a long-running session can't grow it without
// limit on a small boot volume. When the existing log exceeds this, the
// oldest bytes are dropped (we keep the tail) before the new line is added.
constexpr u64 kAuditLogMaxBytes = 256u * 1024u;
} // namespace

namespace
{
u32 PutRaw(char* out, u32 pos, u32 cap, const char* s)
{
    if (s == nullptr)
        return pos;
    for (; *s != '\0' && pos + 1 < cap; ++s)
        out[pos++] = *s;
    return pos;
}

// Append a JSON-escaped string value (escape '"' and '\\'; drop control bytes).
u32 PutEsc(char* out, u32 pos, u32 cap, const char* s)
{
    if (s == nullptr)
        return pos;
    for (; *s != '\0'; ++s)
    {
        const char c = *s;
        if (c == '"' || c == '\\')
        {
            if (pos + 2 >= cap)
                break;
            out[pos++] = '\\';
            out[pos++] = c;
        }
        else if (static_cast<unsigned char>(c) < 0x20)
        {
            // drop control bytes
        }
        else
        {
            if (pos + 1 >= cap)
                break;
            out[pos++] = c;
        }
    }
    return pos;
}

u32 PutU32(char* out, u32 pos, u32 cap, u32 v)
{
    char tmp[12];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    while (v != 0)
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n != 0 && pos + 1 < cap)
        out[pos++] = tmp[--n];
    return pos;
}
} // namespace

u32 FormatAuditLine(const AuditEntry& e, char* out, u32 cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    u32 p = 0;
    p = PutRaw(out, p, cap, "{\"ts\":\"");
    p = PutEsc(out, p, cap, e.iso8601);
    p = PutRaw(out, p, cap, "\",\"client\":\"");
    p = PutEsc(out, p, cap, e.client);
    p = PutRaw(out, p, cap, "\",\"origin\":\"");
    p = PutEsc(out, p, cap, e.origin);
    p = PutRaw(out, p, cap, "\",\"tab\":");
    p = PutU32(out, p, cap, e.tab);
    p = PutRaw(out, p, cap, ",\"cap\":\"");
    p = PutEsc(out, p, cap, e.cap);
    p = PutRaw(out, p, cap, "\",\"args\":\"");
    p = PutEsc(out, p, cap, e.argsSummary);
    p = PutRaw(out, p, cap, "\",\"ok\":");
    p = PutRaw(out, p, cap, e.ok ? "true" : "false");
    p = PutRaw(out, p, cap, "}");
    out[(p < cap) ? p : cap - 1] = '\0';
    return p;
}

namespace
{
// Append one already-formatted line (plus a trailing newline) to the engine's
// own AUDIT.LOG via a DIRECT fat32 call — NOT through the broker. FAT32's
// Fat32AppendInRoot refuses a zero-size file, so we use the robust
// read-existing → concatenate → delete → create pattern instead (the same
// shape browser.cpp uses for SaveBookmarks). Fail-closed and silent: a missing
// volume or any I/O failure is a no-op — it must NEVER crash and must NEVER
// prevent the serial mirror that already ran.
void AuditLogFileAppend(const char* line, u32 lineLen)
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr || line == nullptr || lineLen == 0)
        return; // early boot: volume not mounted yet — serial mirror suffices.

    // Buffer holds (kept tail of existing log) + new line + '\n'. Bounded.
    char* buf = static_cast<char*>(mm::KMalloc(kAuditLogMaxBytes));
    if (buf == nullptr)
        return;

    u64 used = 0;
    fat::DirEntry e;
    const bool exists = fat::Fat32LookupPath(v, kAuditLogPath, &e) && (e.attributes & 0x10) == 0;
    if (exists && e.size_bytes > 0)
    {
        // Reserve room for the new line + newline; keep the TAIL of the old log
        // if it would otherwise overflow the bound.
        const u64 reserve = static_cast<u64>(lineLen) + 1;
        const u64 keepCap = (reserve < kAuditLogMaxBytes) ? (kAuditLogMaxBytes - reserve) : 0;
        const u64 oldSize = e.size_bytes;
        const u64 toRead = (oldSize < keepCap) ? oldSize : keepCap;
        if (toRead > 0)
        {
            const u64 skip = oldSize - toRead; // drop oldest bytes on overflow
            const i64 n = fat::Fat32ReadAt(v, &e, skip, buf, toRead);
            if (n > 0)
                used = static_cast<u64>(n);
        }
    }

    for (u32 i = 0; i < lineLen && used + 1 < kAuditLogMaxBytes; ++i)
        buf[used++] = line[i];
    if (used + 1 < kAuditLogMaxBytes)
        buf[used++] = '\n';

    if (exists)
        fat::Fat32DeleteAtPath(v, kAuditLogPath);
    fat::Fat32CreateAtPath(v, kAuditLogPath, buf, used);
    mm::KFree(buf);
}
} // namespace

void AuditAppend(const AuditEntry& e)
{
    char line[512];
    const u32 lineLen = FormatAuditLine(e, line, sizeof(line));
    // Serial mirror FIRST — a security audit must ALWAYS be visible (the same
    // justification the structural sentinels carry), and it must survive even
    // if the file sink below fails or the volume isn't mounted.
    arch::SerialWrite("[priv/audit] ");
    arch::SerialWrite(line);
    arch::SerialWrite("\n");
    // Then the durable file sink. Directly to AUDIT.LOG (excluded from the fs
    // scope, so unreachable by page JS). No-ops gracefully if the volume is
    // absent; a failed append never crashes and never blocks the mirror above.
    AuditLogFileAppend(line, lineLen);
}

} // namespace duetos::security::privilege
