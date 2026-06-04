#include "apps/browser/privileged/scope.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser::priv
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

// Full adversarial battery for the privileged path canonicaliser +
// scoped-root containment (the broker's security keystone).
void ScopeSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-path-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    Roots roots;
    roots.root[0] = "/home/user";
    roots.count = 1;
    char out[512];
    auto allow = [&](const char* in) { return CanonicalizeAndContain(in, roots, out, sizeof(out)); };

    // 1: default scope holds the five caps (and there is no 6th / installHandler).
    const CapSet sc = DefaultArmScope();
    if (!sc.Has(Cap::FsRead) || !sc.Has(Cap::FsWrite) || !sc.Has(Cap::ProcSpawn) || !sc.Has(Cap::KernelRead) ||
        !sc.Has(Cap::Net))
    {
        fail(1);
        return;
    }

    // --- ALLOWED (legitimate) ---
    // 2: a plain path within the root, canonicalised verbatim.
    if (!allow("/home/user/p/notes.md") || !StrEqZ(out, "/home/user/p/notes.md"))
    {
        fail(2);
        return;
    }
    // 3: '.' / legit '..' within the root collapse correctly.
    if (!allow("/home/user/./a/b/../c") || !StrEqZ(out, "/home/user/a/c"))
    {
        fail(3);
        return;
    }
    // 4: redundant + trailing slashes collapse.
    if (!allow("/home//user///x/") || !StrEqZ(out, "/home/user/x"))
    {
        fail(4);
        return;
    }
    // 8: the root dir itself is reachable.
    if (!allow("/home/user") || !StrEqZ(out, "/home/user"))
    {
        fail(8);
        return;
    }
    // 22: percent / double encoding is NOT decoded — `%2e%2e` stays a literal
    //     filename within the root (proves it cannot decode into `../`).
    if (!allow("/home/user/%2e%2e/etc") || !StrEqZ(out, "/home/user/%2e%2e/etc"))
    {
        fail(22);
        return;
    }

    // --- REFUSED (adversarial) ---
    // 5/6: `..`-escape (sibling and all-the-way-to-root).
    if (allow("/home/user/../etc/shadow"))
    {
        fail(5);
        return;
    }
    if (allow("/home/user/../../etc/shadow"))
    {
        fail(6);
        return;
    }
    // 7: sibling-prefix bypass — `/home/userX` must NOT match root `/home/user`.
    if (allow("/home/userX/y"))
    {
        fail(7);
        return;
    }
    // 9/10/11/12: audit.log basename + case-fold + trailing-dot + NTFS `::$DATA`.
    if (allow("/home/user/audit.log"))
    {
        fail(9);
        return;
    }
    if (allow("/home/user/AUDIT.LOG"))
    {
        fail(10);
        return;
    }
    if (allow("/home/user/audit.log."))
    {
        fail(11);
        return;
    }
    if (allow("/home/user/audit.log::$DATA"))
    {
        fail(12);
        return;
    }
    // 13-16: device / kernel pseudo-fs / boot nodes.
    if (allow("/dev/sda"))
    {
        fail(13);
        return;
    }
    if (allow("/proc/1/mem"))
    {
        fail(14);
        return;
    }
    if (allow("/sys/x"))
    {
        fail(15);
        return;
    }
    if (allow("/boot/efi"))
    {
        fail(16);
        return;
    }
    // 17: the filesystem root itself.
    if (allow("/"))
    {
        fail(17);
        return;
    }
    // 18: backslash separator (FAT/NTFS confusion).
    if (allow("/home/user\\x"))
    {
        fail(18);
        return;
    }
    // 19: a control byte (here '\n'); NUL is impossible mid-C-string.
    {
        const char p[] = {'/', 'h', 'o', 'm', 'e', '/', 'u', 's', 'e', 'r', '/', 'x', '\n', 'y', '\0'};
        if (allow(p))
        {
            fail(19);
            return;
        }
    }
    // 20: a non-ASCII byte (conservatively closes NFD/NFC + homoglyph aliasing).
    {
        const char p[] = {'/', 'h', 'o', 'm', 'e', '/', 'u', 's', 'e', 'r', '/', 'x', static_cast<char>(0xC3), '\0'};
        if (allow(p))
        {
            fail(20);
            return;
        }
    }
    // 21: a segment with a trailing space (FAT/NTFS strips it → alias).
    if (allow("/home/user/x /y"))
    {
        fail(21);
        return;
    }
    // 23: a non-absolute path.
    if (allow("home/user/x"))
    {
        fail(23);
        return;
    }
    // 24: a legitimate absolute path that lies outside every scoped root.
    if (allow("/etc/passwd"))
    {
        fail(24);
        return;
    }

    arch::SerialWrite("[priv-path-selftest] PASS (24 checks: 5 allowed incl. no-decode literal; 19 refused — escapes, "
                      "sibling-prefix, audit.log fold/dot/ADS, dev/proc/sys/boot, backslash, control, non-ASCII, "
                      "trailing-space, non-absolute, out-of-roots)\n");
}

} // namespace duetos::apps::browser::priv
