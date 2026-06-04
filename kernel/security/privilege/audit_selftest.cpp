#include "security/privilege/audit.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::security::privilege
{
namespace
{
bool Contains(const char* hay, const char* needle)
{
    for (duetos::u32 i = 0; hay[i] != '\0'; ++i)
    {
        duetos::u32 j = 0;
        for (; needle[j] != '\0' && hay[i + j] == needle[j]; ++j)
        {
        }
        if (needle[j] == '\0')
            return true;
    }
    return false;
}
} // namespace

void AuditSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-audit-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    char out[512];

    // 1: an allowed entry — all fields present, client-tagged, ok:true.
    AuditEntry a{"2026-06-04T18:22:07Z",        "browser", "https://claude.ai/code", 3, "fs.write",
                 "path=/home/user/x bytes=412", true};
    FormatAuditLine(a, out, sizeof(out));
    if (!Contains(out, "\"client\":\"browser\"") || !Contains(out, "\"origin\":\"https://claude.ai/code\"") ||
        !Contains(out, "\"tab\":3") || !Contains(out, "\"cap\":\"fs.write\"") ||
        !Contains(out, "\"args\":\"path=/home/user/x bytes=412\"") || !Contains(out, "\"ok\":true"))
    {
        fail(1);
        return;
    }

    // 2: a denied entry formats ok:false.
    AuditEntry d{"2026-06-04T18:22:08Z", "browser", "https://claude.ai/code", 3, "fs.write", "path=/etc/shadow", false};
    FormatAuditLine(d, out, sizeof(out));
    if (!Contains(out, "\"ok\":false") || !Contains(out, "\"args\":\"path=/etc/shadow\""))
    {
        fail(2);
        return;
    }

    // 3: JSON escaping — a quote and a backslash in a value are escaped.
    AuditEntry q{"t", "headless", "o", 1, "fs.read", "a\"b\\c", true};
    FormatAuditLine(q, out, sizeof(out));
    if (!Contains(out, "a\\\"b\\\\c") || !Contains(out, "\"client\":\"headless\""))
    {
        fail(3);
        return;
    }

    arch::SerialWrite("[priv-audit-selftest] PASS (client-tagged JSON line, allow/deny ok field, quote+backslash "
                      "escaping)\n");
}

} // namespace duetos::security::privilege
