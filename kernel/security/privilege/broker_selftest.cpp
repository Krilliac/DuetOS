#include "security/privilege/broker.h"

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

void BrokerSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-broker-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    Roots roots;
    roots.root[0] = "/home/user";
    roots.count = 1;
    char canon[512];

    PrivTab armed;
    armed.Arm(DefaultArmScope());

    // 1: armed + FsWrite in scope + in-roots path + ok bytes → ok, canonicalised.
    Verdict v = ValidateRequest(armed, roots, PrivRequest{Cap::FsWrite, "/home/user/x", 100}, canon, sizeof(canon));
    if (!v.ok || !StrEqZ(canon, "/home/user/x"))
    {
        fail(1);
        return;
    }

    // 2: a disarmed tab → refused.
    PrivTab disarmed;
    v = ValidateRequest(disarmed, roots, PrivRequest{Cap::FsWrite, "/home/user/x", 100}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EPERM: not armed"))
    {
        fail(2);
        return;
    }

    // 3: a capability NOT in the armed scope → refused (arm only FsRead, ask FsWrite).
    PrivTab readonly;
    CapSet ro;
    ro.Add(Cap::FsRead);
    readonly.Arm(ro);
    v = ValidateRequest(readonly, roots, PrivRequest{Cap::FsWrite, "/home/user/x", 1}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EPERM: capability not granted"))
    {
        fail(3);
        return;
    }

    // 4: an escape path → refused by containment.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::FsWrite, "/home/user/../etc/x", 1}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EPERM: outside scoped roots"))
    {
        fail(4);
        return;
    }

    // 5: an oversize write → refused by bounds.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::FsWrite, "/home/user/x", kMaxPrivWriteBytes + 1}, canon,
                        sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EINVAL: oversize write"))
    {
        fail(5);
        return;
    }

    // 6: a null path on an fs cap → refused.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::FsRead, nullptr, 0}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EINVAL: null path"))
    {
        fail(6);
        return;
    }

    // 7: proc.spawn at an in-root target → ok, canonicalised.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::ProcSpawn, "/home/user/bin/t.elf", 0, nullptr}, canon,
                        sizeof(canon));
    if (!v.ok || !StrEqZ(canon, "/home/user/bin/t.elf"))
    {
        fail(7);
        return;
    }

    // 8: proc.spawn at an escape target → refused by containment.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::ProcSpawn, "/home/user/../etc/x", 0, nullptr}, canon,
                        sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EPERM: spawn target outside exec roots"))
    {
        fail(8);
        return;
    }

    // 9: proc.spawn at a device node → refused (out of roots).
    v = ValidateRequest(armed, roots, PrivRequest{Cap::ProcSpawn, "/dev/sda", 0, nullptr}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EPERM: spawn target outside exec roots"))
    {
        fail(9);
        return;
    }

    // 10: net.fetch at a well-formed https URL → ok.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::Net, nullptr, 0, "https://api.example.com/x"}, canon,
                        sizeof(canon));
    if (!v.ok)
    {
        fail(10);
        return;
    }

    // 11: net.fetch at a non-http(s) scheme → refused.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::Net, nullptr, 0, "ftp://nope"}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EINVAL: malformed url"))
    {
        fail(11);
        return;
    }

    // 12: net.fetch at an empty URL → refused.
    v = ValidateRequest(armed, roots, PrivRequest{Cap::Net, nullptr, 0, ""}, canon, sizeof(canon));
    if (v.ok || !StrEqZ(v.error, "EINVAL: null url"))
    {
        fail(12);
        return;
    }

    arch::SerialWrite("[priv-broker-selftest] PASS (armed+in-scope+contained ok; not-armed / cap-not-granted / "
                      "escape / oversize / null-path refused; non-fs cap ok)\n");
}

} // namespace duetos::security::privilege
