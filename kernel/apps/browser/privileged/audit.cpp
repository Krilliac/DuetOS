#include "apps/browser/privileged/audit.h"

#include "arch/x86_64/serial.h"

namespace duetos::apps::browser::priv
{
using duetos::u32;

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

void AuditAppend(const AuditEntry& e)
{
    char line[512];
    FormatAuditLine(e, line, sizeof(line));
    // v0 mirror: raw serial — a security audit must ALWAYS be visible (the
    // same justification the structural sentinels carry). GAP (broker
    // execution task): also append to audit.log via the cap-gated fs path
    // (audit.log excluded from scope) and add a KBP_PROBE on a denied call.
    arch::SerialWrite("[priv/audit] ");
    arch::SerialWrite(line);
    arch::SerialWrite("\n");
}

} // namespace duetos::apps::browser::priv
