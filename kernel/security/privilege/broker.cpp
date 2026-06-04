#include "security/privilege/broker.h"

#include "net/http.h"

namespace duetos::security::privilege
{
Verdict ValidateRequest(const PrivTab& tab, const Roots& roots, const PrivRequest& r, char* canonOut, duetos::u32 cap)
{
    // 1: the tab must be armed (spec §13.1 — arming skips the prompt, not this).
    if (!tab.IsArmed())
        return Verdict{false, "EPERM: not armed"};

    // 2: the requested capability must be in the armed scope.
    if (!tab.scope.Has(r.cap))
        return Verdict{false, "EPERM: capability not granted"};

    // 3: filesystem caps must reference a path within the scoped roots, with
    //    full canonicalisation + structural-invariant refusals (Task 2).
    if (r.cap == Cap::FsRead || r.cap == Cap::FsWrite)
    {
        if (r.path == nullptr)
            return Verdict{false, "EINVAL: null path"};
        if (!CanonicalizeAndContain(r.path, roots, canonOut, cap))
            return Verdict{false, "EPERM: outside scoped roots"};
        // 4: bound a write.
        if (r.cap == Cap::FsWrite && r.byteLen > kMaxPrivWriteBytes)
            return Verdict{false, "EINVAL: oversize write"};
    }

    // 5: proc.spawn — the target must canonicalise + contain within the exec
    //    roots (v1: exec-roots == scoped-roots, spec §13.6). Reuses the fs keystone.
    if (r.cap == Cap::ProcSpawn)
    {
        if (r.path == nullptr)
            return Verdict{false, "EINVAL: null spawn path"};
        if (!CanonicalizeAndContain(r.path, roots, canonOut, cap))
            return Verdict{false, "EPERM: spawn target outside exec roots"};
    }

    // 6: net.fetch — the URL must parse as http/https with a non-empty host.
    //    Arbitrary hosts allowed (same policy as a page fetch, §13.6); the kernel
    //    firewall remains the final net authority.
    if (r.cap == Cap::Net)
    {
        if (r.url == nullptr || r.url[0] == '\0')
            return Verdict{false, "EINVAL: null url"};
        bool https = false;
        char host[256];
        duetos::u16 port = 0;
        char path[1024];
        if (!duetos::net::http::ParseUrl(r.url, &https, host, sizeof(host), &port, path, sizeof(path)) ||
            host[0] == '\0')
            return Verdict{false, "EINVAL: malformed url"};
        // Only host-validity gates the verdict; the parsed scheme/port/path are
        // not re-used here (the kernel firewall is the final net authority).
        (void)https;
        (void)port;
        (void)path;
    }

    return Verdict{true, ""};
}

} // namespace duetos::security::privilege
