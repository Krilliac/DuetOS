#include "security/privilege/config.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::security::privilege
{
namespace
{
bool StrEqZ(const char* a, const char* b)
{
    duetos::u32 i = 0;
    for (; a[i] != '\0' && b[i] != '\0'; ++i)
        if (a[i] != b[i])
            return false;
    return a[i] == b[i];
}
} // namespace

void PrivConfigSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-config-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    PrivConfig cfg;

    // 1: absent flag → not available.
    PrivConfigParse("root=/dev/sda console=ttyS0", cfg);
    if (cfg.available)
    {
        fail(1);
        return;
    }
    // 2: bare flag → available + single default root.
    PrivConfigParse("quiet --allow-claude-system-access splash", cfg);
    if (!cfg.available || cfg.roots.count != 1 || !StrEqZ(cfg.roots.root[0], "/home/user"))
    {
        fail(2);
        return;
    }
    // 3: flag with one explicit root.
    PrivConfigParse("--allow-claude-system-access=/work", cfg);
    if (!cfg.available || cfg.roots.count != 1 || !StrEqZ(cfg.roots.root[0], "/work"))
    {
        fail(3);
        return;
    }
    // 4: flag with two colon-separated roots, among other args.
    PrivConfigParse("foo --allow-claude-system-access=/work:/data bar", cfg);
    if (!cfg.available || cfg.roots.count != 2 || !StrEqZ(cfg.roots.root[0], "/work") ||
        !StrEqZ(cfg.roots.root[1], "/data"))
    {
        fail(4);
        return;
    }
    // 5: a longer look-alike token must NOT match.
    PrivConfigParse("--allow-claude-system-accessX", cfg);
    if (cfg.available)
    {
        fail(5);
        return;
    }

    arch::SerialWrite(
        "[priv-config-selftest] PASS (absent / bare-default / one-root / two-roots / lookalike-rejected)\n");
}

} // namespace duetos::security::privilege
